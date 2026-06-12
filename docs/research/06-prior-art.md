# Prior art: authtrail, authie, authentication-zero, rodauth

> Research date: 2026-06-11. Clones at `/tmp/sessions-research/` (read-only). All `path:line` cites are relative to that root. Versions inspected: authtrail 1.0.0 (2026-04-04), authie 5.0.x (last commit 2025-12-17), authentication-zero 4.0.3 (last commit 2024-12-05), rodauth 2.44.0 (last commit 2026-06-10), rodauth-rails (last commit 2026-05-11).

## Top findings

1. **Nobody owns the middle ground.** Authtrail is an append-only *log* with zero linkage to live sessions (no session id column at all: `authtrail/lib/generators/authtrail/templates/login_activities_migration.rb.tt:1-22`). Authie and Rodauth own a live *registry* but log nothing about failures. Authentication-zero generates both (sessions + events) but it's a one-shot code dump with no upgrades, no touching, no failure log. A gem that decorates *existing* auth with **log + registry + revocation + UI** has no direct competitor.
2. **Authtrail's whole integration is two Warden hooks registered at `require` time** (`authtrail/lib/authtrail.rb:71-77`) — no Railtie, no Engine. The model is generated *into the app* and referenced lazily by name. That's why it's frictionless for Devise and useless for everything else.
3. **Rodauth active_sessions is the security gold standard**: random 32-byte key in the Rack session, **HMAC-SHA256 stored in DB** (`rodauth/lib/rodauth/features/active_sessions.rb:200`, `rodauth/lib/rodauth/features/base.rb:861`), per-request liveness check that *also* prunes expired rows and bumps `last_use` in one UPDATE (`active_sessions.rb:42-54`). But its registry stores **no IP, no user-agent** — it can't render a "your devices" page.
4. **Rodauth audit_logging cannot capture unknown-identity failures**: it only logs when an account row exists (`rodauth/lib/rodauth/features/audit_logging.rb:34`; FK `null: false` at `rodauth/README.rdoc:486`). Authtrail is the only one that records *attempted* identities (`authtrail/lib/authtrail.rb:23-30`).
5. **Authentication-zero's design became Rails 8's omakase auth** (signed permanent cookie holding a `sessions` row id; `user_agent`/`ip_address`(`ip_address:string user_agent:string`) columns — compare `authentication-zero/.../controllers/html/sessions_controller.rb.tt` `cookies.signed.permanent[:session_token]` with rails-stable `railties/.../concerns/authentication.rb.tt` `cookies.signed.permanent[:session_id]`). It already ships a user-facing **"Devices & Sessions"** page (`erb/sessions/index.html.erb.tt:3`) — but sessions have **no last-activity tracking**, so the page shows creation-time data forever.
6. **Authie's per-request `around_action` touch writes to the DB on every request** (`authie/lib/authie/controller_extension.rb:12`, `session.rb:97-111`) and its engine force-includes itself into **every controller** (`authie/lib/authie/engine.rb:13-16`). Powerful (live `last_activity_at`, request counter, path) but invasive — a key DX lesson.
7. **Nobody does**: UA/device parsing, Hotwire Native awareness, new-device email, admin UI, or automated retention (authie has a `cleanup` you must cron: `authie/lib/authie/session_model.rb:140-149`; rodauth self-prunes only the active-sessions table inline: `active_sessions.rb:45`).

---

## 1. AuthTrail — full walkthrough

Tiny: 4 lib files + 1 generator + 4 templates. Gemspec deps: only `railties >= 7.2` + `warden` (`authtrail/authtrail.gemspec:20-21`). 566 GitHub stars; "Battle-tested at Instacart" (`README.md:5`).

### 1.1 Warden hooks (the entire integration)

```ruby
# authtrail/lib/authtrail.rb:71-77
Warden::Manager.after_set_user except: :fetch do |user, auth, opts|
  AuthTrail::Manager.after_set_user(user, auth, opts)
end

Warden::Manager.before_failure do |env, opts|
  AuthTrail::Manager.before_failure(env, opts) if opts[:message]
end
```

- `except: :fetch` — session restores from cookie are **not** tracked; only fresh authentications (`set_user` events). So one row ≈ one login, not one request.
- `before_failure` is guarded by `opts[:message]` — failures without a Devise failure message (e.g. plain unauthenticated redirects) produce no row.
- Hooks are registered at **require time**, top-level, no Railtie/Engine anywhere in the gem.

### 1.2 Success/failure capture & identity extraction

`Manager.after_set_user` wraps `auth.env` in `ActionDispatch::Request` and calls `AuthTrail.track(success: true, user: user, scope: opts[:scope].to_s, strategy: detect_strategy(auth), ...)` (`authtrail/lib/auth_trail/manager.rb:4-15`). `before_failure` does the same with `success: false, failure_reason: opts[:message].to_s` (`manager.rb:17-28`) — `opts` here is Warden's `env["warden.options"]` (carries `:scope`, `:message`, `:attempted_path`).

Identity (works even when no user exists):

```ruby
# authtrail/lib/authtrail.rb:23-30
self.identity_method = lambda do |request, opts, user|
  if user
    user.try(:email)
  else
    scope = opts[:scope]
    request.params[scope] && request.params[scope][:email] rescue nil
  end
end
```

Strategy detection handles OmniAuth first (`auth.env["omniauth.auth"]["provider"]`), then Warden's `winning_strategy` class name underscored, falling back to reverse lookup in `Warden::Strategies._strategies` and finally `"database_authenticatable"` (`manager.rb:32-46`; the `_strategies` rescue was the 0.7.1 fix, `CHANGELOG.md:5-7`).

### 1.3 Track pipeline & config surface

`AuthTrail.track` builds `{strategy, scope, identity, success, failure_reason, user, ip: request.remote_ip, user_agent, referrer}` + `context: "controller#action"` (`authtrail/lib/authtrail.rb:32-47`), then:
1. `transform_method.call(data, request)` — mutate/add fields (`authtrail.rb:51`; request passed because `exclude_method` doesn't get it, comment at `authtrail.rb:49-50`).
2. `exclude_method.call(data)` — skip row; exceptions are swallowed by `AuthTrail.safely` and default to **not excluding** (`authtrail.rb:53-54, 61-68`).
3. `track_method.call(data)` — default builds `LoginActivity` with **tolerant assignment** `login_activity.try("#{k}=", v)` then `save!`, and enqueues `GeocodeJob.perform_later` if `AuthTrail.geocode` (`authtrail.rb:15-22`). The `try(=)` means users can drop/add columns freely — schema is duck-typed.

Geocoding: `AuthTrail::GeocodeJob < ActiveJob::Base`, `queue_as { AuthTrail.job_queue }` (`authtrail/lib/auth_trail/geocode_job.rb:2-5`), calls `Geocoder.search(login_activity.ip).first` and raises a helpful error if the `geocoder` gem is missing (`geocode_job.rb:9-12`); writes `city/region/country/country_code/latitude/longitude` via `try(=)` (`geocode_job.rb:19-30`). **Quirk:** the migration has no `country_code` column (`login_activities_migration.rb.tt`), so that value is silently discarded — masked by the tolerant-assignment pattern.

### 1.4 Migration & model templates (verbatim)

```ruby
# authtrail/lib/generators/authtrail/templates/login_activities_migration.rb.tt:3-20
create_table :login_activities<%= primary_key_type %> do |t|
  t.string :scope
  t.string :strategy
  <%= identity_column %>          # string indexed | lockbox ciphertext+bidx (install_generator.rb:35-46)
  t.boolean :success
  t.string :failure_reason
  t.references :user<%= foreign_key_type %>, polymorphic: true
  t.string :context
  <%= ip_column %>                # string indexed | lockbox ciphertext+bidx (install_generator.rb:48-55)
  t.text :user_agent
  t.text :referrer
  t.string :city
  t.string :region
  t.string :country
  t.float :latitude
  t.float :longitude
  t.datetime :created_at          # append-only: no updated_at
end
```

Generator requires `--encryption=lockbox|activerecord|none` (`install_generator.rb:9, 57-64`); MySQL identity gets `limit: 510` for AR encryption (`install_generator.rb:40-42`); respects `primary_key_type` config (`install_generator.rb:74-84`). Model templates: AR-encryption variant uses `encrypts :identity, :ip, deterministic: true`; both encrypted variants round lat/lng to 1 decimal "to protect IP" via `reduce_precision` (`model_activerecord.rb.tt`, `model_lockbox.rb.tt`); plain variant is just `belongs_to :user, polymorphic: true, optional: true` (`model_none.rb.tt`).

### 1.5 README guidance, 1.0.0, limitations

- README's recommended uses: "use this information to detect suspicious behavior" (`README.md:42`), store user on failed attempts via `transform_method` (`README.md:74-80`), LB-header geocoding (`README.md:189-197`), manual retention queries (`README.md:203-213`), and pairing with Devise `Lockable` + `Rack::Attack` (`README.md:217`). **There is no "notify on suspicious login" example in the README** — no notification code ships at all; the closest is the "Hardening Devise" blog link (`README.md:219`).
- **1.0.0 (2026-04-04) changed nothing functional**: "Removed support for Rails < 7.2 and Ruby < 3.3" (`CHANGELOG.md:1-3`). No Rails-8-specific features, no breaking API change — it's a maturity stamp on a finished design.

**Verified limitations** (each checked against source):
- Warden/Devise-only: hard `require "warden"` (`authtrail.rb:2`) + gemspec dependency; no path for Rails 8 omakase auth, which has no Warden.
- Append-only log, no live-session linkage: no session id/token column; nothing to revoke.
- No revocation, no devices UI, no admin UI: gem contains zero controllers/views/routes (file list).
- Logs logins only, not logouts/password changes/2FA events (only two hooks exist).
- No UA/device parsing: raw `t.text :user_agent`.
- No Hotwire/Turbo Native awareness: `grep -ri "native\|turbo"` over `lib/` → nothing.
- Geocoding via geocoder gem only (`geocode_job.rb:10`), else DIY headers.
- Retention manual (`README.md:206`).
- Session restores invisible (`except: :fetch`), message-less failures invisible (`authtrail.rb:76`).

---

## 2. Authie — DB-backed session ownership

245 stars. Active-ish: v5.0.0 2025-02-20 (Rails ≥ 7.1, `CHANGELOG.md:3-9`), configurable IP lookup added 2025-12-17 (`git log`: `feat(session/config): add configurable request ip lookup method (#52)`). Design goals: server-side invalidation, "see who is logged in", inactivity expiry, temporary vs persistent sessions (`README.md:28-34`).

### 2.1 Schema (accreted via 9 migrations, `authie/db/migrate/`)

Base table (`20141012174250_create_authie_sessions.rb`): `token`, `browser_id`, `user_id`, `active` (default true), `data` (serialized Hash), `expires_at`, `login_at`, `login_ip`, `last_activity_at`, `last_activity_ip`, `last_activity_path`, `user_agent`, timestamps. Later: `user_type` (polymorphic by hand), `parent_id` (impersonation), `two_factored_at/_ip`, `requests` counter, `password_seen_at` (sudo), **`token_hash`** (2017), `host`, `skip_two_factor`, and `login_ip_country`/`two_factored_ip_country`/`last_activity_ip_country` (2023). Note the plaintext `token` column was never dropped — only abandoned.

### 2.2 Token security & validation

- Token: `SecureRandom.alphanumeric(64)` kept only in `attr_accessor :temporary_token`; DB stores `Digest::SHA256.hexdigest(token)` (`authie/lib/authie/session_model.rb:123-126, 151-154`). Lookup: `active.where(token_hash: hash_token(token))` (`session_model.rb:133-137`).
- Cookie: hardcoded `cookies[:user_session]` httponly/secure-if-ssl with `expires: @session.expires_at` (`session.rb:162-171`).
- Browser binding: a separate 5-year `browser_id` UUID cookie set by `before_action set_browser_id` (`controller_delegate.rb:26-42`); `validate_browser_id` invalidates the session and raises `BrowserMismatch` if the cookie doesn't match the row (`session.rb:177-185`). Starting a session **invalidates all other active sessions for the same browser_id** (`session.rb:245-247`).
- `validate` = browser_id → active → expiry → inactivity → host, each raising a typed error and invalidating the row (`session.rb:55-62, 187-226`). Expiry semantics: persistent sessions expire by `expires_at` (default length 2 months); transient ones by `last_activity_at < 12.hours.ago` (`session_model.rb:45-54`, defaults `config.rb:33-43`).

### 2.3 Controller integration & per-request behavior

`Authie::Engine` initializer includes `ControllerExtension` into **all** of ActionController on load (`authie/lib/authie/engine.rb:7-16`), which installs `before_action :set_browser_id, :validate_auth_session` and `around_action :touch_auth_session` plus delegated helpers `current_user / logged_in? / create_auth_session / invalidate_auth_session` (`controller_extension.rb:8-22`). `touch` writes `last_activity_at/_ip/_path`, increments `requests`, optionally re-extends expiry + re-sets cookie (`session.rb:97-111, 228-236`) — **one UPDATE per authenticated request**; opt-out is per-controller `skip_touch_auth_session!` (`controller_extension.rb:31-33`).

Extras worth stealing: `invalidate_others!` (logout-everywhere: `session_model.rb:83-85`), sudo via `recently_seen_password?` (10-min window, `session_model.rb:88-90`, `config.rb:36`), anomaly primitives `first_session_for_browser?` / `first_session_for_ip?` (`session_model.rb:98-105`), `parent_id` for impersonation (`session_model.rb:13`), 13 `ActiveSupport::Notifications` events (`config.rb:56-58`, e.g. `session.rb:109,147,179`), pluggable `lookup_ip_country_backend` + `ip_lookup_method` (`config.rb:19-31`).

### 2.4 Key lesson (DX)

Authie **replaces** cookie auth: you must write your own login UI and call `create_auth_session(user)`; it is "just a session manager" (`README.md:55`). Consequences: it can't coexist with Devise/Rails-8 auth (both would fight over who is the session of record), it force-instruments every controller, it writes per request, and it ships **no UI** (no `app/` dir in repo). That's why it stayed niche at 245 stars despite having the best live-session model of its era. Decorate, don't replace.

---

## 3. Authentication-zero — generated auth with a devices page

1872 stars (GitHub API). Initial commit 2022-02-14; last commit 2024-12-05 (dormant ~18 months). Philosophy: "generating code into the user's application instead of using a library" → total freedom, **but** "it will not be updated after it's been generated" (`authentication-zero/README.md:3, 30`).

### 3.1 CLI options

`rails generate authentication` with flags: `--api`, `--pwned`, `--sudoable`, `--lockable`, `--passwordless`, `--omniauthable`, `--trackable` (activity log), `--two-factor`, `--webauthn` (requires two_factor, `authentication_generator.rb:232-234`), `--invitable`, `--masqueradable`, `--tenantable` (`lib/generators/authentication/authentication_generator.rb:6-17`). Most HTML-only flags are disabled under `--api` (`authentication_generator.rb:220-246`).

### 3.2 Sessions: schema, cookie, controller, view

Migration (`templates/migrations/create_sessions_migration.rb.tt`): `t.references :user, null: false, foreign_key: true; t.string :user_agent; t.string :ip_address; [t.datetime :sudo_at if sudoable]; t.timestamps`. Model fills UA/IP from `Current` in `before_create` (`models/session.rb.tt:4-8`); `Current` is set by a `before_action` (`controllers/html/application_controller.rb.tt:17-20`).

Cookie = **signed permanent cookie containing the row id**: `cookies.signed.permanent[:session_token] = { value: @session.id, httponly: true }` (`controllers/html/sessions_controller.rb.tt`, create action); auth = `Session.find_by_id(cookies.signed[:session_token])` (`application_controller.rb.tt:9-14`). Nothing secret stored in DB; revocation = `destroy` the row. API flavor returns `@session.signed_id` in an `X-Session-Token` header instead (`controllers/api/sessions_controller.rb.tt:19`).

Routes: `resources :sessions, only: [:index, :show, :destroy]` (`authentication_generator.rb:200`). **It generates a user-facing devices page**:

```erb
<%# templates/erb/sessions/index.html.erb.tt:3-27 %>
<h1>Devices & Sessions</h1>
...
  <p><strong>User Agent:</strong> <%= session.user_agent %></p>
  <p><strong>Ip Address:</strong> <%= session.ip_address %></p>
  <p><strong>Created at:</strong> <%= session.created_at %></p>
  <%= button_to "Log out", session, method: :delete %>
```

with `SessionsController#index` = `Current.user.sessions.order(created_at: :desc)` and `#destroy` scoped through `Current.user.sessions.find` (`sessions_controller.rb.tt`). **No `last_activity` touching exists anywhere** — the page shows login-time data forever, and a row's `updated_at` never moves.

### 3.3 Sudo, events, mailers, logout-others

- Sudo: `before_action :require_sudo` redirects to a password re-entry screen carrying `proceed_to_url`; success does `session_record.touch(:sudo_at)`; window is `sudo_at > 30.minutes.ago` (`controllers/html/sessions/sudos_controller.rb.tt`, `application_controller.rb.tt:22-26`, `models/session.rb.tt:15-17`).
- Events (`--trackable`): `events` table (`user_id, action (null:false), user_agent, ip_address, timestamps`, `migrations/create_events_migration.rb.tt`); actions are only **signed_in / signed_out** (Session callbacks, `models/session.rb.tt:11-13`) and **email_verification_requested / password_changed / email_verified** (User callbacks, `models/user.rb.tt:60-71`). **No failed-attempt logging.** User-facing "Activity Log" page at `authentications/events` (`erb/authentications/events/index.html.erb.tt:1`).
- Mailers: only `password_reset`, `email_verification`, plus optional `passwordless` and `invitation_instructions` (`mailers/user_mailer.rb.tt`). **No new-device / sign-in alert email.**
- Log out other sessions — done implicitly on password change, *deleting* (not signing out gracefully) all but current:

```ruby
# templates/models/user.rb.tt:57-59
after_update if: :password_digest_previously_changed? do
  sessions.where.not(id: Current.session).delete_all
end
```

### 3.4 Relationship to the Rails 8 generator (verified)

Auth-zero predates it (initial commit 2022-02-14 vs Rails 8.0 in late 2024). The Rails 8.1-stable generator is a strict subset of the same design: `generate "migration", "CreateSessions", "user:references ip_address:string user_agent:string"` (`rails-stable/railties/lib/rails/generators/rails/authentication/authentication_generator.rb:55`), `cookies.signed.permanent[:session_id] = { value: session.id, httponly: true, same_site: :lax }` and `start_new_session_for`/`terminate_session`/`resume_session` in a concern (`rails-stable/.../templates/app/controllers/concerns/authentication.rb.tt:40-52`), bare `Session < ApplicationRecord` model. Rails generates only `resource :session` (singular) — **no index page, no per-device revocation, no events, no touching**: exactly the gap a sessions gem fills *without* fighting the omakase structure (the `sessions` table with `ip_address`/`user_agent` already exists in every Rails 8 app!).

---

## 4. Rodauth — the feature gold standard

1914 stars, 54 features (`ls rodauth/lib/rodauth/features | wc -l`), commit activity same-day as this research. Taxonomy reference: `otp.rb`, `sms_codes.rb`, `webauthn.rb`(+autofill/login/verify variants), `recovery_codes.rb`, `remember.rb`, `lockout.rb`, `password_pepper.rb`, `session_expiration.rb`, `single_session.rb`, `active_sessions.rb`, `audit_logging.rb` (features dir listing).

### 4.1 active_sessions

Table (`rodauth/README.rdoc:577-583`):

```ruby
create_table(:account_active_session_keys) do
  foreign_key :account_id, :accounts, type: :Bignum
  String :session_id
  Time :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
  Time :last_use,  null: false, default: Sequel::CURRENT_TIMESTAMP
  primary_key [:account_id, :session_id]
end
```

- **Stored hashed**: on login `add_active_session` generates `random_key` (= `SecureRandom.urlsafe_base64(32)`, `base.rb:713-715`), puts the raw key in the Rack session under `:active_session_id`, inserts `compute_hmac(key)` (HMAC-SHA256 with `hmac_secret`, `base.rb:855-862`) into the table (`active_sessions.rb:70-77, 199-201`). DB leak ⇒ no usable session ids; supports secret rotation via `compute_hmacs` (old+new, `base.rb:290-298`, used at `active_sessions.rb:47`).
- **Per-request check**: app calls `rodauth.check_active_session` in the route block; `currently_active_session?` first `remove_inactive_sessions` (self-pruning), then matches the HMAC'd id — and when an inactivity deadline is configured the *match itself* is an `UPDATE ... SET last_use = CURRENT_TIMESTAMP` returning rowcount (`active_sessions.rb:42-54, 203-211, 232-234`). One statement: validate + touch + prune trigger.
- Deadlines: `session_inactivity_deadline` 86400s, `session_lifetime_deadline` 30 days, OR'd into the prune condition (`active_sessions.rb:18-20, 213-230`); both nil-able.
- Semantics: `remove_current_session` on logout, `remove_all_active_sessions` for **global logout** — exposed as a checkbox injected into the logout form (`logout_additional_form_tags` + `global_logout_param`, `active_sessions.rb:16-17, 120-122, 168-176`); `remove_all_active_sessions_except_current` runs from `clear_tokens` (i.e., password change/reset flows) and after fresh 2FA setup (`active_sessions.rb:130-133, 148-166`); `remove_active_session(session_id)` is documented as the hook "for implementing session revoking" (`rodauth/doc/active_sessions.rdoc:57`). No UA/IP/device columns, no UI — registry only.

### 4.2 audit_logging

Table (`rodauth/README.rdoc:484-494`): `id`, `account_id` FK **`null: false`**, `at` timestamp default now, `String :message, null: false`, `metadata` (jsonb on Postgres / json / String fallback — mirrored in `rodauth-rails/lib/generators/rodauth/migration/active_record/audit_logging.erb:10-17`), indexes `[account_id, at]` and `at`.

Mechanism: every feature's `before_*`/`after_*` hook funnels through generated methods that call `hook_action(hook_type, action)` (`rodauth/lib/rodauth.rb:274`); audit_logging overrides it:

```ruby
# rodauth/lib/rodauth/features/audit_logging.rb:31-37
def hook_action(hook_type, action)
  super
  # In after_logout, session is already cleared, so use before_logout in that case
  if (hook_type == :after || action == :logout) && (id = account ? account_id : session_value)
    add_audit_log(id, action)
  end
end
```

So **all** auth events get logged automatically — login, logout, password change, otp setup, login_failure (`after_login_failure` exists at `rodauth/lib/rodauth/features/login.rb:81`), etc. Message defaults to the action name (`audit_logging.rb:59-61`); per-action overrides via DSL `audit_log_message_for :login_failure { "Login failure on domain #{request.host}" }` and `audit_log_metadata_for :login_failure { {'ip'=>request.ip} }` (`rodauth/doc/audit_logging.rdoc:19-24`) — **note: IP/UA are NOT captured by default, only via metadata blocks**. Setting a message to nil skips logging that action. Clever ops touch: on Postgres it appends `RETURNING NULL` so the app DB user needs INSERT but not SELECT on the log table (`audit_logging.rb:83-96`). **Gap:** failures for unknown identities are unlogged (guard above + FK null:false) — no attempted-identity capture.

### 4.3 single_session

One-session-per-account via `account_session_keys (id FK PK, key)` (`README.rdoc:571-574`): a per-account `key` is regenerated on each login (`update_single_session_key`, `single_session.rb:66-80`), stored HMAC'd in the session when `hmac_secret` set (`single_session.rb:99-102`), compared timing-safely on `check_single_session` (`single_session.rb:28-56`); logout just rotates the key, kicking everyone (`single_session.rb:94-97`). Doc notes active_sessions is "a more flexible version" (general knowledge of the docs; mechanism above verified in source).

### 4.4 rodauth-rails & the DX lesson

Install (`rodauth-rails/lib/generators/rodauth/install_generator.rb:21-24` options `--prefix/--argon2/--json/--jwt`) generates: migration, initializer, **`app/misc/rodauth_app.rb`** (a Roda app with a `route` block where you call `rodauth.require_account` for protected path prefixes — `templates/app/misc/rodauth_app.rb.tt`), **`app/misc/rodauth_main.rb`** (an `enable :create_account, :verify_account, ... :login, :logout, :remember` DSL config wired to Sequel **reusing the AR connection**: `db Sequel.postgres(extensions: :activerecord_connection, keep_reference: false)`, `templates/app/misc/rodauth_main.rb.tt:1-27`), mailer + 40+ view templates (bootstrap & tailwind variants). Rodauth runs as **Rack middleware** ahead of Rails routes, wrapped per-request for reloadability (`rodauth-rails/lib/rodauth/rails/middleware.rb:10-21`).

Why it stays niche despite being technically best: auth lives in a Roda app inside `app/misc/`, configured via a 600-symbol DSL, persisted via Sequel — three foreign idioms stacked on the hot path of a Rails app. The features are the reference; the integration shape is the cautionary tale. A lighter-touch gem should deliver rodauth's *table designs and semantics* through plain AR models, a Rails concern, and zero new routing layers.

---

## 5. Comparative feature matrix

| Capability | rails8 omakase gen | devise +trackable | authtrail | authie | authentication-zero | rodauth (active_sessions + audit_logging) |
|---|---|---|---|---|---|---|
| Live session registry | partial — rows, no UI | ✗ — last/current only (`devise/lib/devise/models/trackable.rb:10-14`) | ✗ — log only | ✓ — authie_sessions | ✓ — sessions table | ✓ — hashed keys, no UA/IP |
| Per-session remote revocation | ✗ — current only | ✗ | ✗ | ✓ — `invalidate!`, no UI | ✓ — destroy + button | ✓ — `remove_active_session`, no UI |
| Logout-everywhere | ✗ — DIY delete | ✗ | ✗ | ✓ — `invalidate_others!` | partial — on pw change only | ✓ — global_logout checkbox |
| Failed-attempt log | ✗ | ✗ (lockable counts only) | ✓ — with reason | ✗ | ✗ — events lack failures | partial — known accounts only |
| Attempted-identity capture | ✗ | ✗ | ✓ — params dig | ✗ | ✗ | ✗ — FK requires account |
| Device/UA parsing | ✗ — raw string | ✗ | ✗ — raw text | ✗ — raw, 255-truncated | ✗ — raw string | ✗ — not stored |
| Geolocation | ✗ | ✗ | ✓ — geocoder job | partial — country callback | ✗ | ✗ |
| Last-active touching | ✗ — created_at only | partial — at sign-in | n/a — append log | ✓ — every request | ✗ — created_at only | ✓ — on check, 1 UPDATE |
| Token hashing at rest | n/a — signed id cookie | n/a | n/a | ✓ — SHA-256 | n/a — signed id cookie | ✓ — HMAC-SHA256 |
| End-user UI shipped | ✗ | ✗ | ✗ | ✗ | ✓ — devices + log pages | ✗ — auth views only |
| Admin UI / scopes | ✗ | ✗ | ✗ — data only | partial — scopes only | ✗ | ✗ |
| New-device email | ✗ | ✗ (pw/email change only) | ✗ | ✗ | ✗ | ✗ (pw-change notify only) |
| Retention / pruning | ✗ | n/a | ✗ — manual SQL | partial — cron `cleanup` | ✗ | ✓ auto (sessions); ✗ logs |
| Multi-auth-system support | own only | devise only | warden only | own only | own only | own only |
| Hotwire Native awareness | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| API/token sessions | ✗ | partial (DIY) | partial — logs any warden strategy | ✗ — cookie hardcoded | ✓ — `--api` signed_id header | ✓ — json/jwt/jwt_refresh |

---

## 6. Steal / Improve / Avoid

### Steal
- **Two-callback Warden integration + `except: :fetch`** for the Devise adapter, verbatim semantics (`authtrail/lib/authtrail.rb:71-77`).
- **Lambda config surface** — `exclude_method` / `transform_method` / `track_method` / `identity_method`, with `safely` error isolation so tracking never breaks login (`authtrail.rb:12-30, 53-57, 61-68`).
- **Tolerant column assignment** `try("#{k}=", v)` so users add/drop columns without gem releases (`authtrail.rb:17-19`).
- **Polymorphic `user` + `scope` column** for multi-model auth (`login_activities_migration.rb.tt:9`, `README.md:104-110`).
- **Geocode-in-a-job** with pluggable queue + lat/lng precision reduction for privacy (`geocode_job.rb:5`, `model_activerecord.rb.tt` `reduce_precision`) — map onto trackdown instead of geocoder.
- **HMAC-SHA256 session ids at rest + secret rotation** (`rodauth/lib/rodauth/features/active_sessions.rb:47,200`, `base.rb:290-298,855-862`).
- **Validate+touch+prune in one UPDATE** (`active_sessions.rb:42-54`) — last-active freshness without authie's every-request write amplification.
- **Dual deadline model** (inactivity + absolute lifetime, both nil-able) (`active_sessions.rb:18-20, 225-230`).
- **`hook_action` funnel** — one chokepoint where every auth event becomes an audit row; per-event message/metadata override DSL (`audit_logging.rb:31-37`, `doc/audit_logging.rdoc:19-24`).
- **"Logout everywhere" as a logout-form checkbox** and **kill-others on password change / 2FA enrollment** (`active_sessions.rb:120-122, 130-133, 153-166`).
- **Auth-zero's devices page shape** — `Devices & Sessions`, per-row `button_to "Log out"`, destroy scoped via `Current.user.sessions.find` (`erb/sessions/index.html.erb.tt`, `sessions_controller.rb.tt`) — ship it as real engine views.
- **Sudo recipe**: `sudo_at` timestamp on the session + `require_sudo` + `proceed_to_url` round-trip (`sudos_controller.rb.tt`; authie equivalent `recently_seen_password?`, `authie/lib/authie/session_model.rb:88-90`).
- **Anomaly primitives** `first_session_for_browser?` / `first_session_for_ip?` — the cheap basis for "new device?" (`session_model.rb:98-105`).
- **AS::Notifications on every lifecycle event** (`authie/lib/authie/config.rb:56-58`).
- **`browser_id` long-lived cookie** as a device identifier across sessions (`authie/lib/authie/controller_delegate.rb:26-42`) — great for device continuity, make it optional.
- **Postgres `RETURNING NULL` insert-only audit writes** (`audit_logging.rb:83-96`).

### Improve (gaps no one fills)
- **Link log ↔ live session**: add `session_id` to login_activity rows so a suspicious login can be revoked in one click (authtrail has no linkage; rodauth's registry has no context).
- **Capture attempted identity on failures even for unknown accounts** (authtrail does; rodauth can't — `audit_logging.rb:34` + FK `README.rdoc:486`).
- **Store UA/IP on the registry** (rodauth omits) and **parse UA into device/browser/OS** (nobody does) for human-readable device names.
- **Touch last-active sanely**: auth-zero/rails8 never touch (`create_sessions_migration.rb.tt` has only timestamps); authie touches every request (`session.rb:97-111`). Improve with throttled touch (e.g. ≥1/min) à la rodauth's conditional UPDATE.
- **New-device/new-location notification**: zero competitors ship one; combine authie's `first_session_for_*` + authtrail-style geo + a mailer.
- **Automated retention** for both registry and log (authtrail: manual SQL `README.md:206`; authie: un-cron'd `cleanup` `session_model.rb:140-149`).
- **Adapter layer over existing auth** instead of one system: detect Rails 8 `Session` model / Devise+Warden / OAuth callbacks — the Rails 8 generator already creates a `sessions` table with `ip_address`/`user_agent` (`rails-stable/.../authentication_generator.rb:55`) begging to be decorated.
- **Hotwire Native awareness** (UA `Turbo Native`/bridge detection, device naming for app installs) — absent in all five codebases (grepped).
- **Graceful revocation semantics**: auth-zero `delete_all`s rows on password change (`user.rb.tt:57-59`) with no event trail; emit events + reason codes instead (rodauth's `set_error_reason :inactive_session`, `active_sessions.rb:65`).

### Avoid
- **Owning auth-session storage / replacing the auth system** — authie's fate: no UI, every-controller injection (`engine.rb:13-16`), per-request writes, 245 stars. Decorate the session of record; don't become it.
- **Foreign-idiom integration** — rodauth-rails' Roda-app-in-`app/misc` + Sequel-on-AR + DSL config (`rodauth_app.rb.tt`, `rodauth_main.rb.tt:14-21`, `middleware.rb`) is the documented adoption barrier.
- **Devise-only coupling** — authtrail's hard `require "warden"` (`authtrail.rb:2`) made it instantly irrelevant for Rails 8 omakase apps.
- **One-shot generated code** — auth-zero's own README admits generated code "will not be updated" (`README.md:30`); ship an engine + migrations, generate only the thin config.
- **Schema columns the code silently ignores** — authtrail's `country_code` written by the job but missing from the migration (`geocode_job.rb:23` vs `login_activities_migration.rb.tt`); validate schema↔writer drift in CI.
- **Plaintext or leftover token columns** — authie's abandoned `token` column lingers next to `token_hash` (`db/migrate/20141012174250` vs `20170417170000`); never store raw tokens, and clean up migrations.
- **Silent truncation of forensic data** — authie chops UA to 255 chars (`session_model.rb:118-121`); use `text`.
- **Failure tracking gated on framework internals** — authtrail misses message-less failures (`authtrail.rb:76`); define our own failure taxonomy.
- **Per-request unthrottled DB writes** (authie `touch`) and **global before_actions injected into every controller** — make instrumentation opt-in per scope.

---

## Implications for the sessions gem

1. **Positioning**: be the layer every auth system lacks — *registry + audit log + revocation + UI* — over Rails 8 omakase (decorate its existing `sessions` table), Devise (Warden two-hook adapter, authtrail-compatible columns for migration stories), and OAuth/passwordless (strategy column à la authtrail). Authtrail's 4.1M downloads prove demand for the log; its 1.0.0 freeze (`CHANGELOG.md:1-3`) and Warden-only design leave the field open.
2. **Two tables, linked**: `sessions`-registry (HMAC'd token or adopted host-app session id, UA/IP, device fields, `last_seen_at`, `revoked_at`, parent_id for impersonation) + `login_activities`-style append-only log with `session_id` FK. Rodauth proves the deadline/prune/touch mechanics (`active_sessions.rb:42-54`); authtrail proves the log schema; nobody has the join.
3. **DX bar**: `bundle add` + one generator + one initializer of lambdas (authtrail's config surface), engine-shipped `/sessions` devices page (auth-zero's view, done properly with last-active + friendly device names), `revoke!`/`revoke_all_others!` model API (authie naming), logout-everywhere on password change (rodauth/auth-zero semantics), notifications via AS::Notifications + optional mailer. Geolocation = optional trackdown hook mirroring `AuthTrail.geocode` + job-queue config (`authtrail.rb:21`, `geocode_job.rb:5`).
4. **Security defaults**: never store raw tokens (SHA-256 minimum, HMAC+rotation ideal), optional AR-encryption/lockbox path for identity+IP (authtrail generator flags), lat/lng precision rounding, append-only log with insert-only DB grants on PG, built-in retention job — each default lifted from a cited precedent above.
