# HostApp audit: auth, sessions & device detection

Read-only audit of `/path/to/repos/hostapp` (Rails 8.1.1, RailsFast, Devise), its native shells `/path/to/repos/hostapp-ios` + `/path/to/repos/hostapp-android`, and (addendum) `/path/to/repos/licenseseat`. Audited 2026-06-11. All paths relative to each repo root unless absolute. Facts cite `path:line`; anything inferred is marked as such.

## Top findings

- Devise 5.0.4 with `:trackable` **on** (`app/models/user.rb:74-76`) — but trackable only stores 1 current + 1 last sign-in on the `users` row. **There is no sessions table, no devices table, no login-attempt log anywhere in `db/schema.rb`.** That is the gem's hole to fill.
- Admin is a `users.admin` boolean (`db/schema.rb:1260`) gated by `authenticate :user, lambda { |u| u.admin? }` (`config/routes.rb:26`). Single Devise scope; no OmniAuth, no passkeys, no 2FA, no magic links.
- Session store is Rails' default CookieStore — no `session_store` initializer exists anywhere in `config/` (verified by grep). Sessions are therefore **unenumerable and unrevocable server-side** today.
- Native apps get silent 1-year remember-me: `remember_hotwire_native_session` (`app/controllers/users/sessions_controller.rb:187-198`) + `config.remember_for = 1.year` (`config/initializers/devise.rb:175`).
- HostApp already has a world-class **signup-time** device fingerprint: 22 `signup_*` columns on `users` (`db/schema.rb:1306-1322`), populated by `SignupAttribution` (DeviceDetector + UA Client Hints, `app/services/signup_attribution.rb`) and `SignupDisplayMetrics`. It is one-shot — never refreshed at login.
- Per-user "what client is this user running NOW" exists as `last_seen_*` columns (`db/schema.rb:1280-1284`), written only by the native JSON API via a race-safe throttled SQL `UPDATE ... WHERE IS DISTINCT FROM` (`app/controllers/api/v1/base_controller.rb:32-57`). Web requests never touch it; one row per user, not per device.
- Native shells announce themselves via load-bearing UA tokens: Android WebView prefix `"HostApp Android;"` (`hostapp-android .../HostAppApplication.kt:169`), iOS `"HostApp iOS; RailsFast Native iOS;"` (`hostapp-ios RailsFast/Core/AppConfiguration.swift:10-12`). Server matches `/\b(?:HostApp\s+Android|Hotwire Native Android|Turbo Native Android)\b/i` (`app/services/signup_attribution.rb:315-324`).
- Both shells also stamp **exact** `X-Client-Platform/Version/Build/OS` headers on native JSON calls (Android OkHttp interceptor `NativeHttpClient.kt:47-80`; iOS `NativeHttpClient.swift:12-56`), parsed server-side by `ClientVersionInfo` (`app/controllers/concerns/client_version_info.rb`).
- **No push notifications anywhere**: no FCM/APNs code in either shell (grep for `UNUserNotificationCenter|registerForRemoteNotifications|Firebase` returned nothing), no device-token tables, no push gems.
- IP geolocation = `trackdown` 0.2.0, **no initializer** (default `:auto` provider → Cloudflare `CF-IPCountry`/`CF-IPCity` headers), called exactly once in the whole app: synchronously at signup (`app/controllers/users/registrations_controller.rb:45`).
- Real client IP behind Cloudflare = `cloudflare-rails` 7.0.0, production group only (`Gemfile:86-89`); it prepends CF ranges into `ActionDispatch::RemoteIp` so plain `request.remote_ip` is correct in prod.
- `AuditLog` (`app/models/audit_log.rb`) is a SHA-256 hash-chained, immutable, advisory-lock-serialized ledger with a `AuditLog.log(event_type:, data:, auditable:, user:, request:)` API capturing `remote_ip` + `user_agent` — wired to the `moderate` gem (`config/initializers/moderate.rb:32-41`). It logs **moderation** events only; login/logout events are never audited.
- The user-facing surface for a "your devices" page exists and has clear conventions: `GET /settings` → `SettingsController#show` → `app/views/settings/show.html.erb` built from `<section>` + `shared/setting_row` partials; admin surface = madmin resources in `app/madmin/resources/` drawn at `/admin/dashboard` (`config/routes.rb:38-40`).
- Bot/abuse protection at the auth boundary is Cloudflare Turnstile (`rails_cloudflare_turnstile` 0.4.4) on sign-in/sign-up `create`, **skipped for native apps** (`app/controllers/application_controller.rb:32-46`). No rack-attack.
- LicenseSeat (second target app) runs the same RailsFast Devise wiring (same modules, same 4 custom controllers) but devise 4.9.4, no native shell, no `last_seen_*`/UA columns — and adds `api_keys` 0.3.0 token auth + an **active** `footprinted` 0.3.1 install used for product telemetry, not login tracking.

---

## 1. Auth stack

**Modules** — `app/models/user.rb:74-76`:

```ruby
devise :database_authenticatable, :registerable,
:recoverable, :rememberable, :validatable,
:confirmable, :lockable, :trackable
```

`:omniauthable` and `:timeoutable` are explicitly not used (comment at `user.rb:72-73`). devise `5.0.4`, warden `1.2.9` (`Gemfile.lock:162,580`).

**`config/initializers/devise.rb` notable active settings** (line-cited): `stretches = 12` (:128), `allow_unconfirmed_access_for = 3.days` (:154), `reconfirmable = true` (:168), `remember_for = 1.year` (:175), `expire_all_remember_me_on_sign_out = true` (:178), `extend_remember_period = true` (:181), `rememberable_options = { same_site: :lax }` (:185), `password_length = 6..128` (:189), `reset_password_within = 6.hours` (:235), `sign_out_via = :delete` (:277), custom Warden failure app `Devise::CurrentHostFailureApp` (:288-294, required at :11), Turbo-era responder statuses 422/303 (:317-318), `config.mailer = "DeviseGoodmailer"` (:325).

**Custom failure app** — `lib/devise/current_host_failure_app.rb:7-20`: overrides `route(scope)` to return `:"new_#{scope}_session_path"` (path, not URL) so Android-emulator hosts (`10.0.2.2`) aren't bounced to `localhost`. Any gem middleware that redirects on auth failure must respect this same current-host constraint.

**Custom Devise controllers** — `config/routes.rb:2-7`: `users/confirmations`, `users/registrations`, `users/sessions`, `users/passwords`; plus `POST users/confirmation/resend` (:9-15) — an authenticated, throttled in-app resend (`app/controllers/users/confirmations_controller.rb:9,48`; cooldown columns `confirmation_resend_email`/`confirmation_resend_sent_at`, `db/schema.rb:1262-1263`).

- `Users::RegistrationsController`: Turnstile gate (:4), captures `request.remote_ip` + `SignupAttribution.from_request(request)` + display metrics *before* Devise mutates state (:21-23), persists via `update_columns` post-create (:36-42), geolocates synchronously with `Trackdown.locate(ip, request: request)` writing `signup_country/_code/_city` (:45-52, rescue→log), and sets `Accept-CH` to request high-entropy UA Client Hints (:66-68).
- `Users::SessionsController`: Turnstile on `create` for browsers only (:6); a `manual_sign_in_flow?` branch (native app or pending org invitation, :136-138) re-implements lookup/`valid_password?`/`active_for_authentication?` so native sheets render 422 form errors instead of Devise's failure app (:42-118); auto remember-me for native at :187-198 (`remember_me(resource)` whenever `hotwire_native_app?`).
- `ApplicationController` owns `after_sign_in/up/out_path_for` with native handoff routing (:61-152) and a read-only Warden peek `warden.user(scope: :user, run_callbacks: false)` (:360) used to inspect sessions without waking rememberable.

**Other login methods**: none. No OmniAuth gem, no Google One Tap, no Sign in with Apple, no WebAuthn/passkeys, no TOTP/2FA, no magic links (verified: zero `omniauth|webauthn|rotp|devise-` hits in `Gemfile`/`Gemfile.lock`). Twilio SMS OTP exists (`phonelib 0.10.18`, `twilio-ruby 7.10.5`, `app/services/phone_verification_service.rb`) but it is onboarding **phone verification**, not login 2FA. Dev-only auto-login endpoint for screenshot capture: `appstore/demo_sessions#create` (`config/routes.rb:53`). `POST invitation_account_switch/:token` (`config/routes.rb:21`) signs out the current user to accept an org invitation as another account.

**Admin**: no second Devise scope. `users.admin` boolean + routes lambda (`config/routes.rb:26-41`) wrapping Profitable, Mission Control Jobs, and madmin.

## 2. Existing session/login tracking

**There is no `sessions`, `devices`, `login_activities`, or push/device-token table** in `db/schema.rb` (full `create_table` list inspected). What exists:

`users` (`db/schema.rb:1259-1338`), the relevant columns verbatim:

```ruby
t.datetime "current_sign_in_at"            # :1269  (Devise trackable)
t.string   "current_sign_in_ip"            # :1270
t.integer  "failed_attempts", default: 0, null: false   # :1275 (lockable)
t.integer  "last_seen_app_build"           # :1280
t.string   "last_seen_app_version", limit: 32
t.datetime "last_seen_client_at"
t.string   "last_seen_os_version", limit: 64
t.string   "last_seen_platform", limit: 16 # :1284
t.datetime "last_sign_in_at"               # :1285
t.string   "last_sign_in_ip"               # :1286
t.datetime "remember_created_at"           # :1295
t.integer  "sign_in_count", default: 0, null: false     # :1298
t.string   "signup_bot_name", limit: 128   # :1299
t.string   "signup_browser_name", limit: 64
t.string   "signup_browser_version", limit: 64
t.string   "signup_city"
t.string   "signup_client", limit: 32
t.string   "signup_country"
t.string   "signup_country_code"
t.string   "signup_device_brand", limit: 64
t.string   "signup_device_category", limit: 32
t.string   "signup_device_model", limit: 128
t.decimal  "signup_device_pixel_ratio", precision: 6, scale: 3
t.string   "signup_device_platform", limit: 32
t.string   "signup_ip"
t.string   "signup_os_version", limit: 64
t.integer  "signup_screen_height"
t.string   "signup_screen_orientation", limit: 32
t.integer  "signup_screen_width"
t.boolean  "signup_touch_capable"
t.text     "signup_user_agent"
t.integer  "signup_viewport_height"
t.integer  "signup_viewport_width"         # :1322
```

Indexes: `[signup_client, signup_device_platform]` partial, `signup_client` partial, `signup_country_code` (`db/schema.rb:1333-1335`).

**`audit_logs`** (`db/schema.rb:46-66`) — the `moderate` `config.audit` target and the strongest in-house pattern reference:

```ruby
create_table "audit_logs", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
  t.uuid "auditable_id"
  t.string "auditable_type"
  t.datetime "created_at", null: false
  t.jsonb "event_data", default: {}, null: false
  t.string "event_type", null: false
  t.inet "ip_address"
  t.string "previous_hash", null: false
  t.string "record_hash", null: false
  t.datetime "recorded_at", null: false
  t.bigint "sequence_id", null: false
  t.datetime "updated_at", null: false
  t.text "user_agent"
  t.uuid "user_id"
  t.index ["auditable_type", "auditable_id"], ...
  t.index ["event_type"], ...
  t.index ["recorded_at"], ...
  t.index ["sequence_id"], ..., unique: true
  t.index ["user_id"], ...
end
```

`AuditLog` model (`app/models/audit_log.rb`): immutable (`before_update`/`before_destroy` raise, :21-23), genesis row + SHA-256 hash chain with canonicalized JSON (:94-117), single-writer ordering via `pg_advisory_xact_lock` (:127-131), `verify_chain` (:64-92), and the API the sessions gem should imitate — `AuditLog.log(event_type:, data:, auditable:, user:, request:)` auto-capturing `request&.remote_ip` / `request&.user_agent` (:30-41). Wired in `config/initializers/moderate.rb:32-41`; only `moderation.*` events flow through it today.

**Other ip/UA captures** (scattered, per-feature, all one-shot): `waitlist_entries` (`db/schema.rb:1361-1374`: `inet ip_address`, `platform`, `text user_agent`; written at `app/controllers/waitlist_entries_controller.rb:11-13`); `identity_verifications` `ip_address`/`user_agent` (`db/schema.rb:582,590`); `energy_savings_user_transfer_contracts` has `device_fingerprint`, `ip_address`, `user_agent` (`db/schema.rb:553-566`); `ride_participants.client_platform` limit 16 (`db/schema.rb:1026`).

**Parsers** worth lifting into the gem: `SignupAttribution` (`app/services/signup_attribution.rb`) — `DeviceDetector.new(ua, client_hint_headers)` (:120-124) normalized into business buckets `client` (desktop_web/mobile_web/tablet_web/android_native_app/ios_native_app/bot), `platform`, `device_category`, `browser`, versions, brand/model, bot name (:138-151 `to_user_attributes`); extensive fallback regexes incl. iPad-desktop-mode detection (:341). `SignupDisplayMetrics` (`app/services/signup_display_metrics.rb:7-15`) bounds-checks screen/viewport/DPR/touch/orientation from hidden signup-form fields.

## 3. Hotwire Native: detection, UA contracts, identity routes

**Server-side detection** is turbo-rails' `hotwire_native_app?` (UA `~ /(Turbo|Hotwire) Native/`; cited in-code at `app/controllers/application_controller.rb:195-196`). Per-platform: `HotwireNativeHelper#hotwire_native_platform` (`app/helpers/hotwire_native_helper.rb:63-69`) checks UA for literal `"Hotwire Native Android"` / `"Hotwire Native iOS"`. Bridge-component capability sniffing parses the UA's `bridge-components: [...]` list (:78-94) — e.g. the toast component decides flash handling at `app/controllers/native/entries_controller.rb:40-45`.

**iOS WebView UA** — prefix built at `hostapp-ios/RailsFast/Core/AppConfiguration.swift:10-12`:

```swift
static var userAgentPrefix: String {
    "\(applicationName) iOS; RailsFast Native iOS;"
}
```

`applicationName` = `CFBundleDisplayName` = `HostApp` (`hostapp-ios/project.yml:63`), set via `Hotwire.config.applicationUserAgentPrefix` (`hostapp-ios/RailsFast/App/AppDelegate.swift:102`). Per the comment at `AppDelegate.swift:90-93`, the framework appends `"Hotwire Native iOS"`, `"Turbo Native iOS"`, and the bridge-component list — so the effective WebView UA starts `HostApp iOS; RailsFast Native iOS; Hotwire Native iOS; Turbo Native iOS; bridge-components: [...]` followed by the WebKit UA (final composed string is framework behavior — inference from those comments, not observed at runtime).

**iOS native-JSON UA + headers** — `hostapp-ios/RailsFast/Core/NativeHttpClient.swift:12-15,61-72`: headers `X-Client-Platform: ios`, `X-Client-Version` (CFBundleShortVersionString), `X-Client-Build` (CFBundleVersion), `X-Client-OS` (`"iOS \(version)"`), and UA:

```swift
return "\(applicationName) iOS \(version) (build \(build); iOS \(osVersion); \(resolvedModel))"
```

**Android WebView UA** — `hostapp-android/.../HostAppApplication.kt:169`: `Hotwire.config.applicationUserAgentPrefix = "HostApp Android;"`.

**Android OkHttp UA + headers** — `hostapp-android/.../ClientHeaders.kt:25-28,66-77`:

```kotlin
return "HostApp Android $versionName (build $versionCode; Android $osRelease; sdk $sdkInt; $device)"
```

stamped by an application-level interceptor with `.header()` replace-not-append semantics (`hostapp-android/.../NativeHttpClient.kt:47-80`). `ClientHeaders.kt:17-21` documents the **critical contract**: the UA must contain the literal space-separated token `HostApp Android` because the server matches `/\bHostApp\s+Android\b/i` — `SignupAttribution#detect_native_platform` (`app/services/signup_attribution.rb:315-324`) accepts `HostApp Android|Hotwire Native Android|Turbo Native Android` and `HostApp iOS|iPhone|iPad|Hotwire Native iOS|Turbo Native iOS`.

**Header parsing server-side** — `ClientVersionInfo` concern (`app/controllers/concerns/client_version_info.rb`): platform allow-list `%w[android ios web]`, semver regex, build clamped to Play's 2.1B cap, 64-char OS cap; explicit "spoofable, diagnostics-only, never authorization" doctrine (:7-12). Fallback path delegates to `SignupAttribution` (:66-75). Consumed by `Api::V1::BaseController#touch_last_seen_client` (:32-57) — the throttled, race-safe `update_all` with `IS DISTINCT FROM` predicates that maintains `users.last_seen_*`.

**Session-relevant native routes** (`config/routes.rb:84-95`): `/native/entry` (canonical signed-out bootstrap), `/native/handoff` (auth-success), `/native/auth/welcome` (legacy alias), `/native/configurations/{ios,android}/v1` (server-driven path configuration, version-gated auth sheet/handoff rules in `app/controllers/native/configurations_controller.rb:67-75,196-205,344-352,494`). Native bootstrap defensively consumes **stale remember cookies of now-inactive users** before Warden runs: `consume_inactive_native_remembered_user!` reads `cookies.signed["remember_user_token"]` via `User.serialize_from_cookie` without firing strategies (`app/controllers/application_controller.rb:371-417`) — a subtle Devise+native lifecycle edge any session gem must not break.

**One cookie = one session across surfaces.** Native JSON requests authenticate with the *same Rails session cookie* as the WebView: Hotwire Native syncs WKWebView cookies into `HTTPCookieStorage.shared` after every page load and the iOS URLSession is explicitly configured to use it (`hostapp-ios/RailsFast/Core/NativeHttpClient.swift:75-100`, with source links in-code); Android's OkHttp client follows the same posture. Consequence for the gem: a "device" is one shared cookie jar spanning WebView navigations *and* native HTTP calls — per-request UA strings differ (WebView UA vs `ClientHeaders` UA) while the session identity stays constant, so device identity must key off the session/remember cookie, never off the UA.

**Push device registration: none.** No notification code in either shell, no token model, no `/native` push route. (Verified: zero `UNUserNotificationCenter`/`registerForRemoteNotifications`/Firebase hits in either repo.)

## 4. IP & geolocation

- `trackdown` pinned `>= 0.2.0`, locked `0.2.0` (`Gemfile:95`, `Gemfile.lock:560`). **No `config/initializers/trackdown.rb` exists** → gem defaults: `provider = :auto` (try Cloudflare headers, fall back to MaxMind; gem source `trackdown-0.2.0/lib/trackdown/configuration.rb:25`), no MaxMind keys configured, so effectively Cloudflare-header-only: reads `HTTP_CF_IPCOUNTRY` / `HTTP_CF_IPCITY` from the request (gem `providers/cloudflare_provider.rb:14-15`).
- Single call site: signup, synchronous, inline, best-effort (`app/controllers/users/registrations_controller.rb:45-53`). No jobs, no per-login lookups, no geo columns outside `users.signup_country/_code/_city`.
- `cloudflare-rails 7.0.0` in `group :production` (`Gemfile:86-89`): its railtie prepends `CheckTrustedProxies` into Rack and `RemoteIpProxies` into `ActionDispatch::RemoteIp` (gem `lib/cloudflare_rails/railtie.rb:18-29`), fetching/caching CF IP ranges — so `request.remote_ip` is the real client IP behind Cloudflare in production with zero app code. No hand-rolled `CF-Connecting-IP` middleware. In development/test the gem is absent, so `remote_ip` is the raw socket peer.
- `request.remote_ip` consumers: registrations (:21), `AuditLog.log` (:38), waitlist (:12). `footprinted` is present but **commented out** (`Gemfile:205`).

## 5. Where the UI would live

**End-user**: `get/patch/delete "settings"` inside `authenticate :user` (`config/routes.rb:215-217`) → `SettingsController` (`app/controllers/settings_controller.rb`), `layout "app"`, JSON CSRF-skip for native preference writes (:14). View `app/views/settings/show.html.erb` is a stack of `<section>` blocks with uppercase `h2` labels and `shared/setting_row` partial rows (:49-62, :72), `<details>` accordions deep-linkable via `?section=` (:126), plus a native overflow menu partial (:8). All copy is Spanish. A "Sesiones y dispositivos" section is one more `<section>` of `setting_row`s, or its own route in the same pattern. RailsFast components live at `app/views/components/railsfast` (copy-up-to-customize convention, `.cursor/rules/0-overview.mdc`).

**Admin**: madmin resources at `app/madmin/resources/*.rb`, custom fields at `app/madmin/fields/`, drawn at `/admin/dashboard` behind the admin lambda (`config/routes.rb:38-40`), menu groups pre-seeded in `config/initializers/madmin_menu.rb` ("Trust & Safety", position 90). Template to copy: `audit_log_resource.rb` (`menu label: "Audit Logs", parent: "Compliance"`, `default_sort_column = "sequence_id"` desc, RelativeTimeField). `user_resource.rb` already curates security columns: `signup_location`/`signup_attribution` custom fields (:23-25), `last_seen_*` block (:25-32), `failed_attempts`, `last_sign_in_ip` shown, `current_sign_in_*`/`remember_created_at` hidden (:63-71). A `SessionResource`/`LoginActivityResource` slots in alongside with a "Security" parent.

## 6. Conventions (from AGENTS.md → .cursor/rules)

`CLAUDE.md` (symlinked as `AGENTS.md`) defers to `.cursor/rules/{0-overview,1-quality,3-project-specifics}.mdc`.

- **Stack** (`0-overview.mdc`): RailsFast omakase — Postgres, importmaps/no-build, Tailwind 4 + heroicons, Solid Queue/Cache/Cable (no Redis), Kamal deploys behind Cloudflare, AWS SES mail, madmin admin, goodmail emails, `moderate` for T&S. Inline comments must carry rationale + source URLs ("Document as you go").
- **Quality** (`1-quality.mdc`): DRY/KISS/YAGNI, "the best part is no part", no enterprise architecture, idiomatic Rails, syntactic sugar valued.
- **Project specifics** (`3-project-specifics.mdc`): mobile-first Hotwire Native hybrid; minimize native code, maximize Rails-rendered surface; sister repos `../hostapp-android`, `../hostapp-ios`; design parity native↔web.
- **Namespacing**: domain modules as dirs — `Ride::` (`app/models/ride/*.rb`), `User::TripFeed` (`app/models/user/trip_feed.rb`), controllers under `users/`, `native/`, `ride/`, `compliance/`; jobs namespaced (`app/jobs/operations/`, `Operations::ReportAlertJob` per `config/initializers/moderate.rb:52`) on Solid Queue.
- **Mailers**: `*Goodmailer` classes; `DeviseGoodmailer < Devise::Mailer` rebuilds every Devise email with goodmail's DSL (`text`/`button`/`code_box`/`sign`) (`app/mailers/devise_goodmailer.rb`); brand config in `config/initializers/goodmail.rb`.
- **Testing**: Minitest, `parallelize(workers: :number_of_processors)`, `fixtures :all`, helpers `create_user`/`create_organization_for`, PostGIS SRID bootstrap (`test/test_helper.rb:8-40`).
- **Logging**: `[SignupAttribution]`/`[HotwireNative]` tagged single-line key=value logs (`application_controller.rb:255-259`, dev-only for native traces).

## 7. Auth/security-adjacent gems (locked versions)

| Gem | Version | Where / role |
|---|---|---|
| devise | 5.0.4 | `Gemfile:98`; core auth |
| warden | 1.2.9 | transitive |
| cloudflare-rails | 7.0.0 | `Gemfile:88` (production group); real IP behind CF |
| rails_cloudflare_turnstile | 0.4.4 | `Gemfile:92`; bot gate on auth forms, skipped for native |
| trackdown | 0.2.0 | `Gemfile:95`; signup geolocation via CF headers |
| device_detector | 1.1.3 | `Gemfile:107`; UA parsing inside SignupAttribution |
| nondisposable | 0.1.0 | `Gemfile:104`; disposable-email validator on User (`user.rb:142`) |
| organizations | 0.4.3 | `Gemfile:101`; invitation-aware sign-in branches |
| moderate | 1.0.0.beta1 | `Gemfile:165`; T&S; `config.audit` → AuditLog |
| madmin | 2.3.2 | `Gemfile:153`; admin panel |
| goodmail | 0.4.0 | `Gemfile:162`; transactional email DSL |
| telegrama | 0.3.0 | `Gemfile:149-150`; admin Telegram alerts |
| phonelib / twilio-ruby | 0.10.18 / 7.10.5 | onboarding phone OTP |
| brakeman, bundler-audit | dev group | static security |

**Absent** (verified): rack-attack, invisible_captcha, omniauth-*, webauthn, rotp, any devise-* extension, browser gem, footprinted (commented, `Gemfile:205`), api_keys (commented, `Gemfile:212`).

## 8. Gaps the sessions gem must fill

1. **No per-session records.** Devise trackable keeps exactly 2 sign-ins (current/last) on `users` (`db/schema.rb:1269-1286`); history is destroyed on every login.
2. **No login-attempt audit.** Failures only increment `failed_attempts` (lockable); no record of who/where/when failed, no AuditLog hook on Warden events. Admin fraud triage relies on signup columns only.
3. **No device registry / "your devices" page.** Settings has account/password/deletion but zero session visibility; users cannot see or revoke anything.
4. **No remote revocation primitive.** CookieStore sessions can't be invalidated server-side; `expire_all_remember_me_on_sign_out` rotates remember tokens only on an explicit sign-out from a browser that still has the cookie. A stolen 1-year native remember cookie is irrevocable today short of a password change.
5. **No "log out everywhere".**
6. **No per-login device/geo enrichment.** The excellent UA+geo capture runs once at signup; a user who signs up on desktop and lives in the Android app forever still shows `signup_client: desktop_web`, and sign-in IPs are stored raw, never geolocated.
7. **No new-device / new-location notification emails** (DeviseGoodmailer makes adding one cheap).
8. **`last_seen_*` is single-slot and native-API-only** — web sessions never update it; two devices overwrite each other.
9. **No push/device tokens** — when push ships, it needs a per-device row to hang tokens off; none exists.
10. **No session concurrency/limit controls, no impossible-travel or anomaly signals.**

---

## LicenseSeat (second target app: plain-web RailsFast SaaS)

`/path/to/repos/licenseseat` — Rails 8 licensing SaaS, same RailsFast template, **no Hotwire Native shell**, UI in English.

- **Auth stack is the same RailsFast wiring**: identical Devise module list incl. `:trackable` (`app/models/user.rb:6-8`), identical 4 custom controllers (`config/routes.rb:2-7`), `DeviseGoodmailer`, Turnstile, madmin drawn at `/admin/dashboard` (`config/routes.rb:36-37`), `users.admin` boolean. Differences: devise **4.9.4** (`Gemfile.lock:167`) and a leaner initializer — `allow_unconfirmed_access_for = 6.hours`, **no** `remember_for`/`extend_remember_period`/`rememberable_options` overrides, **no** custom failure app (verified non-comment lines of `config/initializers/devise.rb`). So the gem must span devise 4.x and 5.x.
- **Leaner users table**: trackable columns + `signup_ip/_city/_country/_country_code` only — none of HostApp's 18 UA/device/display `signup_*` columns, no `last_seen_*` (users table in `db/schema.rb`, cols at offsets :2-26 of the block). No `SignupAttribution`; `device_detector` not in the Gemfile.
- **Trackdown 0.3.1 with a full initializer** (`config/initializers/trackdown.rb`): `provider = :auto`, MaxMind account/license from credentials, `db/geodata/GeoLite2-City.mmdb`, `reject_private_ips` in prod, auto-download on boot, plus `TrackdownDatabaseRefreshJob` (`app/jobs/trackdown_database_refresh_job.rb:1-5`). Same single sync call site at signup (`app/controllers/users/registrations_controller.rb:80-87`). This is the MaxMind-backed config shape the gem's soft dependency should also support (vs HostApp's zero-config CF-header mode).
- **`footprinted` 0.3.1 is ACTIVE** (`Gemfile:181`): `footprints` table (`db/schema.rb:119-160`) is polymorphic geo+device telemetry — `event_type`, `inet ip`, lat/lng, country/city/continent, plus promoted device columns `device_id`, `app_version`, `platform`, `os_name/_version`, `device_type`, `architecture`, `cpu_cores`, `memory_gb`, `jsonb metadata`. Configured async (`config/initializers/footprinted.rb`: `config.async = true`), metadata→column promotion monkey-patch (`config/initializers/footprinted_extensions.rb`), used for **product/licensing telemetry** (DAU/MAU by `device_id`, `app/models/concerns/product_analytics.rb:13-27`; intake via `app/controllers/concerns/license_seat_telemetry.rb`) — *not* for login tracking. It's the closest existing schema to a "device" row in either app.
- **Token auth exists**: `api_keys` 0.3.0 (git main; `Gemfile:190`) — org-owned `pk_`/`sk_` keys with per-key permissions (`config/initializers/api_keys.rb:1-25`), `api_keys` table with `last_used_at`/`revoked_at`/`token_digest` (`db/schema.rb:45-75`), self-serve UI under `namespace :settings { resources :api_keys ... }` (`config/routes.rb:160-162`) and madmin resources at `app/madmin/resources/api_keys/`. The licensing API authenticates with these keys, not cookies — session tracking must not swallow those requests. `license_seat_activations` even stores `ip_address` per machine activation (`db/schema.rb:192-198`).
- **Settings layout differs**: single `settings#show` (`config/routes.rb:157`) + a `settings` namespace for sub-resources; views are form partials (`app/views/settings/_account_form.html.erb`, `_organization_form.html.erb`) rather than HostApp's setting_row sections. A sessions page here would naturally be `settings/sessions` inside that namespace.
- No `moderate`/`AuditLog` (moderate commented at `Gemfile:184`); audit needs are gem-owned (`license_seat_audit_events`, `db/schema.rb:214`).

## Implications for the sessions gem (opinion)

1. **Own the truth in a DB-backed session/device registry** (à la Rails 8 `Session` model): a signed per-device cookie (or session-id claim) checked against a `sessions` row each request. That's the only way to get enumeration + revocation on top of CookieStore — and it must also bind/rotate with Devise's remember-me, since HostApp's native sessions are effectively 1-year remember cookies (`sessions_controller.rb:187-198`). Per-device remember tokens or a session-epoch column on the row is the revocation primitive.
2. **Hook Warden, not Devise controllers**: `after_set_user`/`after_authentication`/`before_logout` covers stock + HostApp's manual native branch (which still calls `sign_in`); ship a separate adapter for Rails 8 omakase auth (no Warden there). Never run model callbacks in the hot path — see the read-only `warden.user(run_callbacks: false)` pattern and the stale-remember-cookie bootstrap (`application_controller.rb:360-417`) the gem must coexist with.
3. **Record failures too**: subscribe to `warden.authenticate` failure / Devise lockable paths; HostApp's manual branch renders 422 without touching Warden's failure app (`sessions_controller.rb:96-118`), so the gem needs an explicit `track_failed_attempt` seam callable from custom controllers.
4. **Adopt the AuditLog.log signature** (`event_type:, data:, user:, request:`) for its event API and `inet ip_address` + `text user_agent` column types; offer an optional sink so apps can tee login events into their own AuditLog.
5. **Lift SignupAttribution into the gem as the per-session parser** (device_detector + Client Hints + Hotwire Native tokens incl. configurable app-prefix regexes like `HostApp Android`, plus `bridge-components:` parsing) and honor `X-Client-Platform/Version/Build/OS` with `ClientVersionInfo`-style validation. That turns HostApp's signup-only intelligence into every-session intelligence and lets the gem name devices "HostApp en Pixel 7 (Android 14)".
6. **Copy the throttled `update_all ... IS DISTINCT FROM` touch** (`api/v1/base_controller.rb:32-57`) for per-session `last_seen_at` — hot-row safe, callback-free.
7. **Geo = trackdown soft dependency, both modes**: sync CF-header path when free (HostApp), async job fallback for MaxMind lookups (LicenseSeat shape); never block sign-in on geo (mirror the rescue at `registrations_controller.rb:45-53`).
8. **UI**: ship a controller + plain-Tailwind views/partials apps can render inside their own settings shell (HostApp's `setting_row` sections vs LicenseSeat's `settings` namespace prove one fixed page won't fit); i18n-first (HostApp is Spanish). Provide a madmin resource template mirroring `audit_log_resource.rb`. New-device email should be a plain ActionMailer that apps can override with a `*Goodmailer`.
9. **Stay out of token-auth lanes**: skip tracking for `api_keys`-authenticated and other non-cookie requests by default (LicenseSeat's licensing API).
10. **Schema suggestion**: `sessions` (per device/browser: user, token/epoch, ip `inet`, ua `text`, parsed client/platform/browser/os/app_version/app_build/device_model, geo country/city, created/last_seen/revoked_at, revoked_reason) + `login_attempts` (success+failure, email-as-typed, user nullable, ip, ua, geo, failure_reason) — append-only like AuditLog but without the hash chain in v1 (advisory-lock serialization is explicitly unsuitable for high-frequency writes per `audit_log.rb` comments echoed in `api/v1/base_controller.rb:29-30`). Use UUID PKs — every table in both apps is `id: :uuid, default: gen_random_uuid()` — but don't hard-require Postgres types if SQLite support matters. Leave a `push_token` column or a `session_devices`-style association point for the push registration neither app has yet.

*(Items 1-10 above are recommendations/opinion; sections 1-8 and the LicenseSeat section are observed fact except where marked as inference.)*
