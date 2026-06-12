# rameerez ecosystem conventions & trackdown/footprinted integration spec

Research memo for the `sessions` gem (drop-in session & login-activity tracking, device management, Rails 8+).
Sources: read-only study of 10 local repos — `trackdown`, `footprinted` (deep dives), `usage_credits`,
`pricing_plans`, `api_keys`, `nondisposable`, `profitable`, `wallets` (mature, trust most), `moderate`, `chats`
(newer, best for UI-shipping + host hooks). All 10 repos present. Citations are `path:line` under `/Users/javi/GitHub/`.

## Top findings

1. **One config pattern everywhere**: memoized `Configuration.new` + `Gem.configure { |config| }` (`trackdown/lib/trackdown.rb:20-26`, `footprinted/lib/footprinted.rb:15-21`, `wallets/lib/wallets.rb:24-30`). Newer gems add **validating setters** that normalize input and raise plain-English errors at the assignment line — explicitly documented as "the ecosystem-wide convention" (`moderate/lib/moderate/configuration.rb:21-22,277-284`; `chats/lib/chats/configuration.rb:172-237`).
2. **Macro grammar is consistent**: ownership = `has_*` (`has_credits`, `has_wallets`, `has_api_keys`, `has_trackable`, `has_reporting_and_blocking`); capability/role = `acts_as_*` (chats); per-field verb = `moderates :body`. There is **no `pays_with`** anywhere — pricing_plans uses `include PricingPlans::PlanOwner` (`pricing_plans/README.md:73-75`). moderate's docstring states the goal: declarations that "sit alongside the rest of a host's stack (`has_credits`, `has_wallets`, `has_api_keys`)" (`moderate/lib/moderate/macros.rb:24`).
3. Macros are registered via `ActiveSupport.on_load(:active_record) { extend Gem::Macros }` in the engine (`moderate/lib/moderate/engine.rb:124-128`, `chats/lib/chats/engine.rb:68-72`), each macro a thin `include Concern` forwarder (`moderate/lib/moderate/macros.rb:44-46`). **Footprinted gets this wrong** (`extend Footprinted::Model` of an AS::Concern — ineffective, `footprinted/lib/footprinted/engine.rb:5-9`); its README requires explicit `include Footprinted::Model` (`footprinted/README.md:62-69`). Copy moderate/chats, not footprinted.
4. **Install generator is sacred**: `rails g <gem>:install` creates (1) one **adaptive migration copied into the app** (uuid/bigint + jsonb/json detection — never engine-loaded), (2) a fully-annotated initializer, (3) an emoji + numbered-steps post-install message with a yellow "run migrations!" warning (`footprinted/lib/generators/footprinted/install_generator.rb:18-44`, `chats/lib/generators/chats/install_generator.rb:21-53`).
5. **Trackdown's soft-probe API**: `Trackdown.locate(ip, request: nil) → LocationResult` (`trackdown/lib/trackdown.rb:32-34`) and `Trackdown.database_exists?` (`trackdown/lib/trackdown.rb:41-43`). There is **no `Trackdown.configured?`** — the sibling contract is `defined?(Trackdown)` + rescue-everything, exactly what footprinted does (`footprinted/lib/footprinted/model.rb:71-92`).
6. **Trackdown is graceful in `:auto` mode** (returns `'Unknown'` result, `trackdown/lib/trackdown/providers/auto_provider.rb:59-61`) but **raises on invalid/private IPs** (`trackdown/lib/trackdown/ip_locator.rb:17-21`) and on forced `:maxmind` without a DB (`trackdown/lib/trackdown/providers/maxmind_provider.rb:40`). Geo lookups must always be rescue-wrapped (`footprinted/lib/footprinted/footprint.rb:51-53`).
7. **Footprinted's killer async-geo trick**: pre-extract Cloudflare-header geo **at enqueue time** so background workers never need MaxMind (`footprinted/lib/footprinted/model.rb:71-92`, `footprinted/README.md:313-326`); the model's `before_save` geolocation skips if `country_code` is already present (`footprinted/lib/footprinted/footprint.rb:38-40`).
8. **Host hooks = the moderate pattern**: `attr_accessor :audit, :notify, :on_block, :ban_handler`, all **no-op lambdas by default**; event-envelope hooks take 1 arg, action hooks take kwargs (`moderate/lib/moderate/configuration.rb:60,115-121`). This is the template for sessions' `on_new_device` / `on_suspicious_login`.
9. **No rameerez gem ships a mailer.** Notification fan-out always goes through host hooks ("Sending the actual emails/push (that's goodmail / noticed — moderate just emits events)", `moderate/README.md:136`). Jobs ship inside the gem when internal (`footprinted/app/jobs/footprinted/track_job.rb`) and are **generated into `app/jobs/`** when the host must schedule them (`trackdown/lib/generators/trackdown/install_generator.rb:10-12`, `nondisposable/lib/generators/nondisposable/install_generator.rb:25-27`), documented with solid_queue `config/recurring.yml` snippets (`trackdown/README.md:130-138`).
10. **Auth abstraction = configurable method-name symbols with Devise defaults**: `current_owner_method = :current_user` / `authenticate_owner_method = :authenticate_user!` (`api_keys/lib/api_keys/configuration.rb:160-161`), `current_messager_method`/`authenticate_method` (`chats/lib/chats/configuration.rb:136-137`), plus `config.parent_controller` indirection — "the same `parent_controller` indirection Devise and api_keys use" (`moderate/lib/moderate/configuration.rb:126-129`). **No existing gem handles Rails 8 native auth (`Current.session`) explicitly** — a gap `sessions` must close.
11. **Table naming**: `<gem>_` prefix (`usage_credits_wallets`, `moderate_reports`, `chats_conversations`); wallets makes it configurable (`@table_prefix = "wallets_"`, `wallets/lib/wallets/configuration.rb:37`). Two unprefixed exceptions: `api_keys` and footprinted's bare `footprints` (`footprinted/lib/footprinted/footprint.rb:5`). Rails 8 omakase auth owns the bare `sessions` table → the gem **must** prefix.
12. **UI shipping, two tiers**: full mounted engine UI (api_keys dashboard, profitable dashboard, chats inbox) vs primitives + BYOUI (moderate admin). UI gems ship Devise-style `rails g <gem>:views` ejection (`moderate/lib/moderate/views_generator.rb:7-17`) and chats ships no-build Stimulus via importmap-path `unshift` so host pins win (`chats/lib/chats/engine.rb:114-120`).
13. **Models always live inside the gem** (`lib/<gem>/models/` or engine `app/models/`); only migrations are generated into the host. moderate/chats wire `lib/<gem>/models` into the **host's Zeitwerk loader** with `push_dir`/`collapse`/`ignore` (`moderate/lib/moderate/engine.rb:61-99`, `chats/lib/chats/engine.rb:29-52`).
14. **Errors**: top-level `Error < StandardError` + meaningful subclasses (`Chats::BlockedError`, `Wallets::InsufficientBalance`); api_keys' `BaseError` (`api_keys/lib/api_keys/errors.rb:6`) is the lone deviation — don't copy.
15. **2026-era targets** (moderate 1.0.0.beta1, chats 0.1.1 — the newest): ruby `>= 3.2.0`, deps on `activerecord`/`activesupport`/`railties >= 7.1, < 9.0` rather than full `rails` (`chats/chats.gemspec:15,41-45`, `moderate/moderate.gemspec:15,43-46`); Minitest + Appraisals (7.1/7.2/8.1) + `test/dummy` host app.

## 1. Per-gem conventions table

| Gem | Model macro / entry API | Install generator creates | Engine | isolate_namespace | Tables | UI shipped | Jobs | Ruby / framework constraint |
|---|---|---|---|---|---|---|---|---|
| trackdown 0.3.1 | `Trackdown.locate(ip, request:)` module fn (`lib/trackdown.rb:32`) | initializer + `TrackdownDatabaseRefreshJob` into `app/jobs/` + `*.mmdb` gitignore; **no migration** (`lib/generators/trackdown/install_generator.rb:6-20`) | **none** (plain module + generator) | n/a | none | none | job template → app | ≥3.0; no rails dep; `countries ~>7.0` only (`trackdown.gemspec:15,38`) |
| footprinted 0.3.1 | `include Footprinted::Model` + `has_trackable :downloads` (`lib/footprinted/model.rb:12`) | migration + initializer (`lib/generators/footprinted/install_generator.rb:18-25`) | `Rails::Engine` | **no** (`lib/footprinted/engine.rb:4`) | bare `footprints` | none | `Footprinted::TrackJob` in gem | ≥3.0; rails ≥7.0; **trackdown ~>0.3 hard dep** (`footprinted.gemspec:15,38-39`) |
| usage_credits | `has_credits` (`lib/usage_credits/models/concerns/has_wallet.rb:54`); Kernel DSL `operation`/`credit_pack`/`subscription_plan` (`lib/usage_credits.rb:179-191`) | migration + initializer (`lib/generators/usage_credits/install_generator.rb:17-23`); + `upgrade` generator | Engine **+ Railtie** (view helper, `lib/usage_credits/railtie.rb:9-14`) | yes (`engine.rb:6`) | `usage_credits_*` ×5 | none | `FulfillmentJob` in gem, host schedules (`README.md:115-123`) | ≥3.1; rails ≥6.1 <9.0; pay ≥8.3 <12; wallets ~>0.1 (`usage_credits.gemspec:15,48-50`) |
| wallets | `has_wallets(**options)` → `user.wallet(:eur)` (`lib/wallets/models/concerns/has_wallets.rb:11,44`) | migration + initializer | Engine + Railtie (`lib/wallets/engine.rb:4-5`) | yes | `wallets_*` via config `table_prefix` (`lib/wallets/configuration.rb:37`) | none | none | ≥3.1; rails ≥6.1 <9.0 (`wallets.gemspec:15,54`) |
| pricing_plans | `include PricingPlans::PlanOwner`; `has_many :projects, limited_by_pricing_plans:`; `before_action :enforce_api_access!` (`README.md:73-94`) | migration + initializer (nested `lib/generators/pricing_plans/install/install_generator.rb`) | Engine (`lib/pricing_plans/engine.rb:4-5`) | yes | `pricing_plans_*` ×3 | none (view helpers only) | none | **≥3.2**; AR/AS ≥7.1 <9.0 (`pricing_plans.gemspec:15,38-39`) |
| api_keys | `has_api_keys do max_keys 10 end` kwargs+block DSL (`lib/api_keys/models/concerns/has_api_keys.rb:29-65`); `include ApiKeys::Controller` + `authenticate_api_key!` (`lib/api_keys/authentication.rb:45`) | migration + initializer (`lib/generators/api_keys/install_generator.rb:24-32`); + `add_key_types` generator | Engine, `config.parent_controller` (`lib/api_keys/engine.rb:8-13`) | yes | bare `api_keys` | **full dashboard**: `resources :keys` + revoke + `root keys#index` (`config/routes.rb:3-18`), mount `/settings/api-keys` (`README.md:63`) | `UpdateStatsJob`, `CallbacksJob` in gem | ≥3.1; rails ≥6.1; bcrypt, base58 (`api_keys.gemspec:17,39-41`) |
| nondisposable | `validates :email, nondisposable: true` (`lib/nondisposable/email_validator.rb:5`); `Nondisposable.disposable?` (`README.md:105`) | migration + initializer + job → `app/jobs/` (`lib/generators/nondisposable/install_generator.rb:17-27`) | Engine (`lib/nondisposable/engine.rb:4-5`) | yes | `nondisposable_disposable_domains` | none | job template → app | ≥3.0; rails ≥7.0 (`nondisposable.gemspec:15,36`) |
| profitable | module fns: `Profitable.mrr`, `.churn`, `.estimated_valuation(at: "3x")` (`README.md:73-113`) | **no generator** | Engine (`lib/profitable/engine.rb:2-3`) | yes | none | **mounted dashboard**, `root "dashboard#index"` (`config/routes.rb:1-3`); host wraps mount in `authenticate` block (`README.md:58-63`) | none | ≥3.0; pay ≥7.0 (`profitable.gemspec:15,36-37`) |
| moderate 1.0.0.beta1 | `has_reporting_and_blocking` / `has_reportable_content(*fields)` / `moderates(*fields, mode:, with:)` (`lib/moderate/macros.rb:44,55,77`) | migration + initializer (`lib/generators/moderate/install_generator.rb:18-24`); **+ views generator** | Engine, lib/-models Zeitwerk wiring (`lib/moderate/engine.rb:19-99`) | yes (`engine.rb:20`) | `moderate_*` ×4 | mountable **public forms only** (DSA notices/appeals/transparency); admin BYOUI (`README.md:63`) | `ClassifyJob` in gem; **events, never mailers** (`README.md:136`) | **≥3.2**; AR/AS/railties ≥7.1 <9.0 + globalid (`moderate.gemspec:15,43-46`) |
| chats 0.1.1 | `acts_as_messager` / `acts_as_chat_subject` (`lib/chats/macros.rb:20-27`); `alice.message!(bob, "hola!")` (`README.md:23`) | migration + initializer (`lib/generators/chats/install_generator.rb:21-27`); **+ views generator** | Engine, same Zeitwerk wiring (`lib/chats/engine.rb:10-52`) | yes (`engine.rb:11`) | `chats_*` ×4 | **full Hotwire UI**: views, 3 Stimulus controllers, CSS, Turbo Streams; `path: ""` mount trick (`config/routes.rb:4-7`) | none (host `config.notifier`) | **≥3.2**; AR/AS/railties ≥7.1 <9.0 + turbo-rails ≥2.0 (`chats.gemspec:15,41-45`) |

House-style notes that cut across the table:

- **Spine + autoload split** (current best practice): value objects (`version`, `errors`, `configuration`, `macros`, `engine`) are `require_relative`'d from `lib/<gem>.rb`; AR models/jobs live under `lib/<gem>/models|jobs/` and are registered on the host's main Zeitwerk loader (`push_dir(lib/<gem>, namespace: Gem)` + `collapse` + `ignore` of spine files) in an initializer `before: :set_autoload_paths` (`moderate/lib/moderate/engine.rb:61-99`). So `lib/moderate/models/report.rb → Moderate::Report`.
- Engine loaded conditionally: `require "<gem>/engine" if defined?(Rails)` (`footprinted/lib/footprinted.rb:28`, `wallets/lib/wallets.rb:43-44`).
- **Class names stored as strings**, constantized lazily, "so the initializer works no matter when the app loads" (`moderate/lib/moderate/configuration.rb:10-12`; `@user_class = "User"` `:84-85`; `@messager_class = "User"` `chats/lib/chats/configuration.rb:134`).
- Migrations belt-and-suspenders: generator copy is primary, engine also appends its `db/migrate` path (`moderate/lib/moderate/engine.rb:106-112`, `chats/lib/chats/engine.rb:59-65`).
- Error taxonomies: `Wallets::Error / InsufficientBalance / InvalidTransfer` (`wallets/lib/wallets.rb:17-19`); `UsageCredits::Error / InsufficientCredits / InvalidOperation / InvalidTransfer` (`usage_credits/lib/usage_credits.rb:65-68`); `PricingPlans::FeatureDenied` carries `feature_key`/`plan_owner` context (`pricing_plans/lib/pricing_plans.rb:10-18`); `Chats::Error / ConfigurationError / BlockedError / NotAllowedError` (`chats/lib/chats/errors.rb:6-19`).
- **README formula** — the section order is identical in all 10:
  1. Emoji + `` `gem` `` + plain-value title ("👣 `footprinted` - Simple event tracking for Rails apps", `footprinted/README.md:1`)
  2. Gem Version + Build Status badges (`:3`)
  3. RailsFast `> [!TIP]` plug (`:5-6`)
  4. 1-3 sentence pitch, sometimes a live-demo link (`usage_credits/README.md:14`, `api_keys/README.md:10`)
  5. **"## 👨‍💻 Example"** candy section — reads-like-English snippets before any setup (`usage_credits/README.md:25-84`, `moderate/README.md:18-60`, `chats/README.md:14-39`)
  6. Quickstart: `gem` → `bundle install` → `rails g <gem>:install` → `rails db:migrate` → macro → (mount) — ends "That's it." (`moderate/README.md:103`, `chats/README.md:69`)
  7. Feature deep-dives
  8. "What it does / doesn't do" with an explicit *Doesn't* list delegating to sibling gems (`moderate/README.md:124-139`, `chats/README.md:83-87`)
  9. "Why this gem exists" rant about DIY plumbing (`pricing_plans/README.md:138-158`, `moderate/README.md:107-122`)
  10. "Why the models?" schema-justification section (`moderate/README.md:365-376`, `pricing_plans/README.md:161-176`)
  11. Testing → Development → Contributing with the signature "just be nice and make your mom proud" line (`trackdown/README.md:378`, `chats/README.md:380`) → MIT.
- **Initializers are documentation**: every generated initializer is a fully-annotated, mostly-commented-out reference manual with `====` section banners (`moderate/lib/generators/moderate/templates/initializer.rb:3-198`, `trackdown/lib/generators/trackdown/templates/trackdown.rb:3-74`, `usage_credits/lib/generators/usage_credits/templates/initializer.rb:1-173`). Footprinted's is the minimal outlier (4 lines, `footprinted/lib/generators/footprinted/templates/footprinted.rb:1-4`). Sessions should ship the annotated kind.
- **Testing**: Minitest everywhere; Appraisals matrices (footprinted 7.2/8.1 `footprinted/Appraisals:3-9`; moderate & chats 7.1/7.2/8.1; wallets 6.1→8.0; usage_credits/profitable also appraise pay 7.3→11); `test/dummy` host app ("mounts the engine at /messages exactly like a real host", `chats/README.md:376`); chats asserts "every authorization negative … plain 404s; existence never leaks" (`chats/README.md:365`).
- **Release discipline**: footprinted documents a 3-place version-bump checklist (version.rb + appraisal lockfiles + a hardcoded version test) with CI failing on drift (`footprinted/README.md:383-389`).
- **gemspec**: authors `["rameerez"]`, email `rubygems@rameerez.com`, MIT, `rubygems_mfa_required`, files via `git ls-files` reject-list (`trackdown/trackdown.gemspec:8-32`).

## 2. trackdown deep dive (our soft dependency)

### Complete public API

```ruby
Trackdown.configure { |config| ... }          # trackdown/lib/trackdown.rb:24-26
Trackdown.locate(ip, request: nil)            # → LocationResult     trackdown/lib/trackdown.rb:32-34
Trackdown.update_database                     # MaxMind download     trackdown/lib/trackdown.rb:37-39
Trackdown.database_exists?                    # File.exist?(db path) trackdown/lib/trackdown.rb:41-43
Trackdown.ensure_database_exists!             # legacy raiser        trackdown/lib/trackdown.rb:47-51
```

`LocationResult` (`trackdown/lib/trackdown/location_result.rb:7-9`) returns:
`country_code` ("US"), `country_name`, `city`, `flag_emoji` ("🇺🇸"), `region` ("California"), `region_code` ("CA"),
`continent` ("NA"), `timezone` ("America/Los_Angeles"), `latitude`, `longitude`, `postal_code`, `metro_code`.
Aliases `country` / `emoji` / `emoji_flag` / `country_flag` (`:29-32`); `country_info` → `ISO3166::Country` (`:34-37`); `to_h` (`:39-55`).
Optional fields are `nil` when the provider lacks them (`trackdown/README.md:195`).

Config knobs (`trackdown/lib/trackdown/configuration.rb:23-33`): `provider :auto` (validated against `[:auto, :cloudflare, :maxmind]`, `:21,35-40`), `maxmind_account_id/license_key`, `database_path` default `db/GeoLite2-City.mmdb` (`:27`), `timeout` 3s, `pool_size` 5, `pool_timeout` 3s, `memory_mode MODE_MEMORY` (`:31`), `reject_private_ips true` (`:32`).

### Providers

- **Cloudflare**: reads 10 `HTTP_CF_*` request-env headers (`trackdown/lib/trackdown/providers/cloudflare_provider.rb:14-23`); `available?` needs a request with a non-`XX` `CF-IPCountry` (`:31-36`); special codes `XX` unknown / `T1` Tor (`:26-27`). Zero overhead, zero deps.
- **MaxMind**: `maxmind-db` + `connection_pool` gems are **optional, conditionally required** (`maxmind_provider.rb:7-13`; documented as Gemfile add-ons in `trackdown/trackdown.gemspec:40-45`); `available?` = gem loaded AND db file exists (`:28-33`).
- **Auto** (default): Cloudflare first — but only if `CF-Connecting-IP` matches the passed IP (upstream-proxy detection, `auto_provider.rb:40-57,66-76`) — else MaxMind, else graceful `LocationResult.new(nil, 'Unknown', 'Unknown', '🏳️')` (`:59-61`).

### Database lifecycle

`Trackdown.update_database` streams the GeoLite2-City tar.gz with HTTP basic auth and extracts the `.mmdb` to `database_path` (`trackdown/lib/trackdown/database_updater.rb:7-39`), mapping 401/403 to friendly messages (`:40-50`). The generator writes the initializer, a `TrackdownDatabaseRefreshJob` (7-line ApplicationJob calling `Trackdown.update_database`, `templates/trackdown_database_refresh_job.rb:1-7`), and gitignores `*.mmdb` (`install_generator.rb:14-20`). Scheduling: solid_queue `config/recurring.yml`, "every Saturday at 4am" (`trackdown/README.md:130-138`); Docker = persistent volume or download-on-boot (`README.md:302-355`).

### Failure modes & thread-safety

- `:auto` with no providers → 'Unknown' + **once-per-process** warning behind `@@warn_mutex` (`auto_provider.rb:25-27,113-131`) — README: "Trackdown fails gracefully… so your app doesn't crash due to a missing geolocation provider" (`trackdown/README.md:49-50`).
- Forced `:maxmind` without DB → raises `Trackdown::Error` (`maxmind_provider.rb:40-41`).
- Invalid IP → `IpValidator::InvalidIpError` (`trackdown/lib/trackdown/ip_validator.rb:7-17`); **private/loopback IPs raise too** when `reject_private_ips` (`trackdown/lib/trackdown/ip_locator.rb:19-21`) — fires constantly in dev, so callers must rescue.
- Lookup timeout → `MaxmindProvider::TimeoutError`; DB problems → `DatabaseError` (`maxmind_provider.rb:20-21,76-83`).
- Perf: class-level `ConnectionPool` of `MaxMind::DB` readers built lazily under `@@pool_mutex` (`maxmind_provider.rb:23-24,85-99`); per-lookup `Timeout.timeout` (`:70-77`); DB in RAM by default. **Background jobs have no request → no CF headers → MaxMind or nothing** (`trackdown/README.md:356-368`).

### The precise soft-integration contract for `sessions`

1. **No hard dependency** (footprinted hard-depends, `footprinted/footprinted.gemspec:39` — sessions diverges by design). Guard call sites with `defined?(Trackdown)` exactly as `footprinted/lib/footprinted/model.rb:72` does (`return unless request && defined?(Trackdown)`), and rescue + log everything (`footprinted/lib/footprinted/footprint.rb:51-53`): a geo failure must never block a login write.
2. **Always pass `request:` through** — `Trackdown.locate(ip.to_s, request: request)` (`footprinted/lib/footprinted/footprint.rb:42`) — so Cloudflare is used whenever present.
3. **Sync vs async**: extract synchronously at request time when CF headers exist (free header read); when persisting async, pre-enrich attrs **before enqueue** (footprinted's `enrich_with_geo_data!`, `model.rb:31,56,71-92`) so workers don't need MaxMind. Skip lookup if `country_code` already present (`footprint.rb:39`).
4. **Columns to store** — footprinted's proven set/types (`footprinted/lib/generators/footprinted/templates/create_footprinted_footprints.rb.erb:6-14`): `t.inet :ip`; `country_code` string limit 2 (indexed, `:30`); `country_name`; `city`; `region`; `continent` limit 2; `timezone`; `latitude`/`longitude` decimal precision 10 scale 7. Skip `postal_code`/`metro_code`/`region_code` (footprinted skips them too). Flag emoji is derivable at render time from `country_code`, no column needed (`Trackdown.locate(...).emoji`, or ISO3166).

## 3. footprinted deep dive (closest sibling in shape)

### API & macro mechanics

```ruby
class Product < ApplicationRecord
  include Footprinted::Model        # base has_many :footprints, as: :trackable  (model.rb:7-9)
  has_trackable :downloads          # scoped assoc + track_download               (model.rb:12-43)
end
@product.track_download(ip: request.remote_ip, request: request,
                        performer: current_user, metadata: { v: "2.1" },
                        occurred_at: 2.hours.ago)                    # model.rb:21, README.md:121-129
@user.track(:signup, ip: request.remote_ip)                          # generic, model.rb:46-67
```

`has_trackable :downloads` ⇒ association `.downloads` (where `event_type: "download"`) + method `track_download` (pluralize/singularize table, `footprinted/README.md:111-117`). Scopes: `by_event`, `by_country`, `recent`, `between`, `last_days`, `performed_by`; class methods `event_types`/`countries` (`footprinted/lib/footprinted/footprint.rb:17-30`).

### Schema (`create_footprinted_footprints.rb.erb:5-31`)

```ruby
create_table :footprints, id: primary_key_type do |t|
  t.inet :ip
  t.string :country_code, limit: 2;  t.string :country_name;  t.string :city
  t.string :region;  t.string :continent, limit: 2;  t.string :timezone
  t.decimal :latitude, precision: 10, scale: 7;  t.decimal :longitude, precision: 10, scale: 7
  t.references :trackable, polymorphic: true, null: false   # the thing acted on
  t.references :performer, polymorphic: true                # who did it (optional)
  t.string :event_type, null: false
  t.jsonb :metadata, null: false, default: {}               # GIN-indexed (:31)
  t.datetime :occurred_at, null: false
  t.timestamps
end
# + composite idx [trackable_type, trackable_id, event_type, occurred_at] (:26-27)
```

Adaptive keys via in-migration `primary_and_foreign_key_types` reading `Rails.configuration.generators` (`:36-42`).

### Capture & trackdown usage

- IP is **explicitly passed** (`ip: request.remote_ip`) — no controller hook or middleware. **No user_agent column**: device/OS/app-version data goes in JSONB `metadata` (`footprinted/README.md:193-204`), with a documented "promote hot metadata keys to real columns in the host app" recipe for scale (`footprinted/README.md:236-282`).
- Geolocation is a model concern: `before_save :set_geolocation_data` (`footprint.rb:15`) → guards (`country_code` blank, `ip` present) → `Trackdown.locate(ip.to_s, request: @_request)` → copy 8 fields → rescue + `Rails.logger.error` (`footprint.rb:38-53`). The request rides a transient ivar set by the track method (`model.rb:38`) — never persisted.
- Async (`config.async`, sole config knob, `footprinted/lib/footprinted/configuration.rb:5-9`): enqueue `Footprinted::TrackJob.perform_later(class_name, id, attrs)` with `occurred_at.iso8601` (`model.rb:30-35`); job re-parses and `create!`s (`footprinted/app/jobs/footprinted/track_job.rb:7-22`). If `country_code` is known, pass it and geolocation is skipped (`footprinted/README.md:345-349`).

### Mirror vs diverge for `sessions`

**Mirror**: geo column set + adaptive migration; pass-`request:`-through; rescue-wrapped enrichment; pre-enqueue CF extraction; polymorphic owner; chainable scopes (`downloads.by_country("US").last_days(30).count`, `footprinted/README.md:20`); post-install message tone (`install_generator.rb:27-44`, "Happy tracking! 👣").

**Diverge**: footprints are **append-only events** — presence validations only, no state, no revoke (`footprint.rb:10-12`). Sessions are **stateful & revocable**: needs `last_seen_at`, `revoked_at`, token/device digests, uniqueness constraints, an `active` scope, `revoke!` verbs. Footprinted has no UI, no controller concern, no auth coupling — sessions needs all three. UA/device fields should be **first-class columns** (the devices page queries them), heeding footprinted's own promote-to-columns advice. And table naming cannot follow footprinted's bare-noun liberty (§5/implication 2).

## 4. Cross-gem idioms: the candy

```ruby
@user.give_credits(100, reason: "referral")                        # usage_credits/README.md:360
@user.spend_credits_on(:process_image, size: 5.megabytes) { ... }  # usage_credits/README.md:259
subscription_plan(:pro) { gives 1_000.credits.every :month }       # usage_credits/README.md:64-67
user.wallet(:mb).transfer_to(friend.wallet(:mb), 3_072)            # wallets/README.md:33
current_user.block!(@other_user); current_user.blocks?(@other)     # moderate/README.md:31-33
alice.message!(bob, "hola!")                                       # chats/README.md:23
validates :email, nondisposable: true                              # nondisposable/README.md:13
Trackdown.locate('8.8.8.8').emoji  # => '🇺🇸'                       # trackdown/README.md:169-171
@file.track_download(ip: request.remote_ip)                        # footprinted/README.md:17
@product.downloads.by_country("US").last_days(30).count            # footprinted/README.md:20
before_action :enforce_api_access!                                 # pricing_plans/README.md:94
Profitable.mrr.to_readable  # => "$1,234"                          # profitable/README.md:119
```

Shared grammar: bang verbs for state changes (`block!`, `resolve!`, `message!`), `?` predicates (`blocks?`, `has_enough_credits_to?`, `database_exists?`), kwargs over positionals, symbols for domain nouns, chainable scopes, numeric sugar where it reads like English (`1_000.credits.every :month` — with an honest "Kernel pollution" disclosure, `usage_credits/README.md:895`, `usage_credits/lib/usage_credits.rb:179-191`).

**Generator UX**: green emoji headline ("🎉 The `footprinted` gem has been successfully installed!"), "To complete the setup:" numbered steps, yellow `⚠️  You must run migrations before starting your app!`, inline code of the macro + mount line, green sign-off (`footprinted/lib/generators/footprinted/install_generator.rb:27-44`; `chats/.../install_generator.rb:29-53`; `api_keys/.../install_generator.rb:35-71`).

## 5. Host hooks — the template for `on_new_device` / `on_suspicious_login`

moderate's `Configuration` is the leading pattern (`moderate/lib/moderate/configuration.rb:60,115-121`):

```ruby
attr_accessor :audit, :notify, :on_block, :ban_handler   # :60
# defaults — "every hook defaults to a no-op, so the gem works untouched" (:18-19)
@audit       = ->(_event) {}                              # :118
@notify      = ->(_event) {}                              # :119
@on_block    = ->(blocker:, blocked:, at:) {}             # :120  action hooks take kwargs
@ban_handler = ->(user:, by:, reason:) {}                 # :121
```

What the host writes (`moderate/lib/generators/moderate/templates/initializer.rb:96,115-124,133,144`):

```ruby
config.audit  = ->(event) { AuditLog.record!(event_type: event.name, data: event.payload) }
config.notify = ->(event) do
  case event.name
  when :report_received, :report_decision
    ModerationMailer.with(event: event).public_send(event.name).deliver_later   # goodmail
  when :content_flagged
    Telegrama.send_message("🚩 #{event.payload[:summary]}")                      # admin alert
  end
end
config.on_block    = ->(blocker:, blocked:, at:) { CancelPendingInvites.call(blocker, blocked, at: at) }
config.ban_handler = ->(user:, by:, reason:) { user.suspend!(reason: reason) }
```

Event envelope: `event.name / .subject / .actor / .recipients / .payload / .to_h` (`initializer.rb:88-94`); fixed event vocabulary listed in the initializer (`:106-110`: `:report_received`, `:report_decision`, `:user_blocked`, `:user_banned`, `:content_flagged`, `:content_removed`, …).

Variants across the ecosystem:

- **chats**: a single notifier `config.notifier = ->(event, **payload) {}` — README insists on `**payload` since payloads vary per event, and the hook is "error-isolated and logged" (`chats/README.md:209-227`, `chats/lib/chats/configuration.rb:162`).
- **usage_credits / wallets**: block-setters with a `ctx` struct — `config.on_low_balance_reached do |ctx|` where `ctx.owner / .wallet / .amount / .previous_balance / .new_balance / .transaction / .metadata / .to_h` (`usage_credits/README.md:283-346`). Full vocabulary: `on_credits_added`, `on_credits_deducted`, `on_low_balance_reached`, `on_balance_depleted`, `on_insufficient_credits`, `on_credit_pack_purchased`, `on_subscription_credits_awarded` (`usage_credits/README.md:294-302`); wallets mirrors with `on_balance_credited/debited`, `on_transfer_completed`, etc. (`wallets/lib/wallets/configuration.rb:20-25,88-110`).
- **pricing_plans**: per-key registration — `config.on_block(:projects) { |ctx| ... }`, `on_warning/on_grace_start/on_block(limit_key = nil, &block)` (`pricing_plans/lib/pricing_plans/configuration.rb:125-146`).
- **api_keys**: lifecycle callbacks enqueued **asynchronously** via `CallbacksJob` so they never block authentication (`api_keys/lib/api_keys/authentication.rb:48-49,84`).

Cross-gem seam to copy verbatim — one line wires two gems, "no hard dependency in either direction" (`chats/README.md:115-124`):

```ruby
config.blocked_messager_ids = ->(user) { Moderate.blocked_ids_for(user) }
```

Universal rules: no-op defaults so the gem works untouched; keep hooks fast / enqueue jobs inside (`usage_credits/README.md:308-309`); callback errors are isolated and never break the core operation (`usage_credits/README.md:306`).

## 6. Auth abstraction: Devise + Rails 8 native auth

- **Configurable method symbols, Devise defaults**: `@current_owner_method = :current_user # Default to current_user for backward compatibility` / `@authenticate_owner_method = :authenticate_user! # Default … for Devise compatibility` (`api_keys/lib/api_keys/configuration.rb:160-161`); the engine controller invokes them dynamically (`api_keys/app/controllers/api_keys/application_controller.rb:16-25`). chats: `current_messager_method :current_user`, `authenticate_method :authenticate_user!` (`chats/lib/chats/configuration.rb:136-137`); "Devise works out of the box" (`chats/README.md:69`).
- **`parent_controller` indirection**: chats defaults `"::ApplicationController"` so the engine inherits host layout/auth/locale (`chats/lib/chats/configuration.rb:135`, `:29-31` "the same pattern api_keys uses"); moderate defaults `"::ActionController::Base"` for its public forms — "exactly the `config.parent_controller` trick Devise and `api_keys` use" — resolved at class-definition time with a NameError fallback for API-only apps (`moderate/app/controllers/moderate/application_controller.rb:8-35`).
- **Graceful viewer detection** in view helpers: `return current_user if respond_to?(:current_user); nil`, override point `moderate_current_viewer` (`moderate/app/helpers/moderate/engine_helper.rb:124-131`); admin actor `moderation_actor → current_user`, overridable in one method (`moderate/app/controllers/concerns/moderate/moderation.rb:85-91`).
- **Gap**: no gem mentions Rails 8 omakase auth (`Current.session`, the generated `Session` model, `authenticate` concern) or OAuth. moderate's "Doesn't" list literally says "Authentication / current-user (that's Devise — you tell `moderate` your user class)" (`moderate/README.md:135`).
- **Hotwire Native precedent**: per-request skip procs sniffing `request.user_agent.to_s.match?(/Hotwire Native/i)` (`moderate/lib/generators/moderate/templates/initializer.rb:155-161`) and host-owned native path-configuration guidance (`moderate/README.md:213`).

The complete host-integration block chats documents — the closest existing model for sessions' initializer (`chats/README.md:279-318`, defaults at `chats/lib/chats/configuration.rb:133-169`):

```ruby
Chats.configure do |config|
  config.messager_class = "User"
  # Controller integration (Devise-compatible defaults)
  config.parent_controller = "::ApplicationController"
  config.current_messager_method = :current_user
  config.authenticate_method = :authenticate_user!
  config.layout = nil                       # nil inherits the parent controller's
  # Feature flags, limits, policies (procs), ecosystem seams (no-op procs)…
  config.blocked_messager_ids = ->(messager) { [] }
  config.notifier = ->(event, **payload) {}
end
```

## Implications for the sessions gem

1. **Macro**: `has_sessions` on the auth model (grammar of `has_credits`/`has_api_keys`); registered via `ActiveSupport.on_load(:active_record) { extend Sessions::Macros }`; macro = thin `include` forwarder with moderate-quality docstrings (`moderate/lib/moderate/macros.rb:35-46`). Optional kwargs/block DSL like api_keys if knobs emerge.
2. **Hard naming constraint**: Rails 8 native auth owns the bare `sessions` table and the `Session` constant. Prefix everything: e.g. `sessions_logins` (append-only attempts, footprints-shaped) + `sessions_devices`/`sessions_records` (stateful). Avoid `Sessions::Session` ↔ host `::Session` confusion in docs. Migration must be adaptive (uuid/bigint + jsonb/json, `create_footprinted_footprints.rb.erb:36-42`).
3. **Two-table shape**: (a) login-activity audit trail mirroring footprinted's schema (geo columns, polymorphic user, jsonb metadata, occurred_at, composite index, success/failure as event/status); (b) a revocable device/session table footprinted has no precedent for — `last_seen_at`, `revoked_at`, token digest, **first-class UA/platform/device columns** (per footprinted's promote-to-columns advice, `footprinted/README.md:236-247`).
4. **Trackdown**: soft dependency per the §2 contract — `defined?(Trackdown)` guard, rescue-everything, `request:` pass-through, skip-if-`country_code`, CF-sync/MaxMind-async split, store the 9 footprinted geo fields. README gets footprinted's IMPORTANT call-out box pointing at trackdown setup (`footprinted/README.md:56-57`).
5. **Config**: `Sessions.configure do |config|` with validating setters; `user_class = "User"` stored as string; Devise-compatible defaults (`current_user_method :current_user`, `authenticate_method :authenticate_user!`) **plus a Rails-8-native resolver chain** (configured symbol → `current_user` → `Current.session&.user`) — the first rameerez gem to close that gap; `parent_controller "::ApplicationController"` for the devices page.
6. **Hooks**: `config.on_new_device = ->(user:, session:, request:) {}`, `config.on_suspicious_login = ->(user:, session:, reasons:) {}`, `config.on_session_revoked = ->(...) {}` — kwargs, no-op defaults, error-isolated, `ensure_callable` setters (`chats/lib/chats/configuration.rb:231-237`); optionally a 1-arg `notify`/`audit` envelope pair if the event vocabulary grows (moderate §5). Never ship mailers; point at goodmail/noticed.
7. **UI**: ship the "your devices" page chats-style — isolated engine, `mount Sessions::Engine => "/settings/sessions"`, `path: ""` root resources, semantic `sessions-*` CSS classes + variables, `rails g sessions:views` ejection (`moderate/lib/generators/moderate/views_generator.rb:7-17`), any JS as importmap-unshifted Stimulus (`chats/lib/chats/engine.rb:114-129`). Admin audit trail = primitives + BYOUI/madmin recipe (`moderate/README.md:288-323`).
8. **Generator**: `rails g sessions:install` = adaptive migration + annotated initializer + emoji/numbered/yellow-warning post-install ending green; if a geo-refresh or session-pruning job is needed, generate it into `app/jobs/` with a `config/recurring.yml` snippet in the README (trackdown/nondisposable pattern).
9. **Gemspec/CI**: ruby ≥3.2; `activerecord`/`activesupport`/`railties` constraints (≥7.1 or ≥8.0 given the Rails-8-first goal — moderate/chats prove a 7.1 floor is cheap); Minitest + Appraisals + `test/dummy` mounting the engine; errors `Sessions::Error < StandardError` with `ConfigurationError` etc.
10. **Hotwire Native device intelligence** is the differentiator: existing precedent is only UA-regex seams (`moderate/.../initializer.rb:155-161`) — sessions should make platform/native-app detection first-class (parsed columns + predicates), not a metadata afterthought.
