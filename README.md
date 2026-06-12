# 🔐 `sessions` - GitHub-style device management & login tracking for Rails

[![Gem Version](https://badge.fury.io/rb/sessions.svg)](https://badge.fury.io/rb/sessions) [![Build Status](https://github.com/rameerez/sessions/workflows/Tests/badge.svg)](https://github.com/rameerez/sessions/actions)

> [!TIP]
> **🚀 Ship your next Rails app 10x faster!** I've built **[RailsFast](https://railsfast.com/?ref=sessions)**, a production-ready Rails boilerplate template that comes with everything you need to launch a software business in days, not weeks. Go [check it out](https://railsfast.com/?ref=sessions)!

`sessions` is the missing session layer for Rails: a **"Your devices" page** like GitHub's (every active session, "log out of that device", "sign out everywhere else") plus an **audit trail of every login attempt** — successful *and failed* — with parsed device names, IP geolocation, and the auth method that started each session.

It **decorates the session storage your app already has** instead of replacing it. On Rails 8+ omakase auth (`rails generate authentication`) it enriches the `sessions` table the generator already created — Rails captures `ip_address` and `user_agent` on every session and then never looks at them again; this gem is the product on top of that data. On Devise, it turns the proven one-session-per-user revocation trick into true per-device remote logout via Warden hooks. Either way: one `bundle add`, one generator, one `has_sessions`.

And it's built for how people actually sign in now: password, OAuth (Google, Apple, GitHub… any OmniAuth provider — including *failed* OAuth attempts), Google One Tap, passkeys, magic links — plus first-class [Hotwire Native](https://native.hotwired.dev) awareness, so a session shows up as "MyApp 2.4.1 on Pixel 8 (Android 16)", not as a WebView mystery string.

## 👨‍💻 Example

```ruby
current_user.sessions.active          # every live device, most recent first

session = current_user.sessions.first
session.device_name                   # => "Chrome 137 on macOS"
                                      # => "MyApp 2.4.1 on iPhone15,2 (iOS 19.5)"
session.location                      # => "Madrid, Spain"     (via the trackdown gem)
session.country_flag                  # => "🇪🇸"
session.last_seen_at                  # => 3 minutes ago       (throttled touch)
session.current?                      # => true for the request's own session
session.hotwire_native?               # session.native_ios? / session.native_android? / session.web?
session.auth_method                   # => "oauth"  ·  session.auth_provider # => "google"

session.revoke!                       # remote logout — that device is signed out on its next request
current_user.revoke_other_sessions!   # GitHub's "sign out everywhere else"
current_user.revoke_all_sessions!     # the account-takeover hammer

current_user.session_events.recent                    # the login trail
current_user.session_events.failed_logins.last_24_hours

# Admin / fraud triage — scopes are the product:
Sessions::Event.failed_logins.last_24_hours.group(:ip_address).count
Sessions::Event.for_identity("victim@example.com")    # ATO investigation
Sessions::Event.by_country("RU").logins
```

And the drop-in devices page:

```
Your devices
────────────────────────────────────────────────────────────
🖥  Chrome 137 on macOS — This device
    🇪🇸 Madrid, Spain · Active now · Signed in May 2 via Google

📱  MyApp 2.4.1 on iPhone15,2 (iOS 19.5)           [Log out]
    🇪🇸 Madrid, Spain · Active 3 minutes ago · Signed in Apr 28

           [ Sign out of all other sessions ]

Login history
────────────────────────────────────────────────────────────
✓ Signed in · Chrome on macOS · Madrid, Spain · today 09:12
✗ Failed sign-in attempt (wrong credentials) · yesterday 23:48
⊘ Session revoked (you signed out everywhere) · Apr 30
```

## Quickstart

```ruby
# Gemfile
gem "sessions"
```

```bash
bundle install
rails generate sessions:install   # detects Rails 8 auth vs Devise, writes the right migrations
rails db:migrate
```

```ruby
# app/models/user.rb
class User < ApplicationRecord
  has_sessions
end
```

```ruby
# config/routes.rb — Rails 8 auth apps:
mount Sessions::Engine => "/settings/sessions"

# Devise apps — wrap the mount in your auth:
authenticate :user do
  mount Sessions::Engine => "/settings/sessions"
end
```

That's it. Every sign-in from now on lands on the devices page and in the trail — on Rails 8 auth there is literally nothing else to wire (the gem decorates the generated `Session` model automatically; your app code stays untouched).

## What `sessions` does (and doesn't) do

**Does:**

- **Live device registry** — one row per signed-in device on the (Rails-8-shaped) `sessions` table, enriched with parsed device intelligence, geolocation, auth method, and a throttled `last_seen_at`.
- **Remote revocation that actually works** — destroy the row, and that device is logged out on its very next request, on both auth stacks. Revoking a Devise session also rotates remember-me credentials so a stolen long-lived cookie can't quietly revive it.
- **Append-only login trail** — logins, *failed* logins (with the typed identity, even for accounts that don't exist), logouts, revocations, expirations. Each trail row links to the live session it created: a suspicious login is one lookup away from the kill switch.
- **Every 2026 login method** — password and OAuth classify automatically (OmniAuth failures get captured too, via a composed `on_failure`); One Tap / passkeys / magic links / SSO take one `Sessions.tag` line.
- **Hotwire Native device intelligence** — platform, OS version, and (on Android) device model work with zero setup; add the [UA prefix convention](#-hotwire-native) for app versions and iOS hardware models.
- **Security hygiene as defaults** — revoke-on-password-change (OWASP ASVS 3.3.3), per-user session caps with oldest-eviction, opt-in idle/absolute timeouts with NIST presets, bounded trail retention with a generated sweep job.

**Doesn't:**

- **Authentication itself** — passwords, 2FA, lockout, sign-up. That's Rails auth / [Devise](https://github.com/heartcombo/devise) / rodauth; `sessions` observes whichever you chose and never replaces it.
- **Rate limiting** — Rails 8's `rate_limit` already guards the generated login (and this gem records when it trips); use rack-attack for more.
- **Send emails** — the `on_new_device` hook hands you the moment; your mailer ([goodmail](https://github.com/rameerez/goodmail), noticed) sends the "Was this you?" email.
- **API/token auth tracking** — that's [`api_keys`](https://github.com/rameerez/api_keys)' lane. Token-authenticated requests (Warden `store: false`) are deliberately never tracked as sessions.
- **Client-side fingerprinting** — ever. Server-observed UA + IP only (the GitLab/Mastodon/Discourse line); fingerprinting is consent-gated under ePrivacy and would poison the drop-in pitch.

## 🖥 The "Your devices" page

Three ways to ship it, pick your layer:

1. **Mount the engine** (the quickstart) — a complete page: device list with "This device" badge, per-row Log out, "Sign out of all other sessions", login history. Semantic `sessions-*` classes with minimal styles; looks decent unstyled inside any Tailwind app. All copy through i18n (English + Spanish shipped).
2. **Render the partials inside your own settings page** — no mount needed for display:

   ```erb
   <%= render "sessions/devices", user: current_user %>
   <%= render "sessions/history", user: current_user, limit: 10 %>
   ```

   (Revoke buttons render when the engine is mounted; without it you get the read-only registry.)
3. **Eject and restyle** — `rails generate sessions:views` copies every template into `app/views/sessions/`, where your copies shadow the gem's automatically (the Devise move).

The engine inherits from your `ApplicationController` (configurable via `config.parent_controller`), so your layout, auth and locale apply automatically. The current session is resolved on both stacks; destructive actions can be gated behind your own sudo/password-confirm flow with `config.require_reauthentication`. One heads-up: if your app layout leans heavily on host route helpers, isolated-engine rendering means those resolve through `main_app.*` — rendering the partials in your own page (layer 2) sidesteps the whole topic.

A hard rule the page enforces: **you can never touch a session you don't own** (foreign ids 404 — existence never leaks), and the current session is never revocable from the page (that's what sign-out is for).

## 🕵️ The trail: every login attempt, kept honest

`Sessions::Event` is an append-only table written through an error-isolated pipeline:

```ruby
Sessions::Event.logins / .failed_logins / .logouts / .revocations / .expirations
Sessions::Event.recent.last_days(90).for_ip("203.0.113.7")
event.session       # the live row it created — nil once revoked (that's the point)
event.new_device?   # flagged when the login matched no prior device
```

Failed attempts record the **identity as typed** (normalized) even when no such account exists — brute-force and credential-stuffing triage needs exactly that — but they never link to an account (no enumeration oracle), never store the password, and store the auth stack's failure reason verbatim (Devise paranoid mode stays `:invalid`).

Tee every event into your own audit system with one line — `event.summary` is the audit-shaped projection (device, identity, reasons, ip, country; compacted, no raw blobs):

```ruby
config.events = ->(event) do
  AuditLog.log(event_type: "session.#{event.name}", user: event.user,
               request: event.request, data: event.summary)
end
```

And for custom UIs, events and sessions share the display vocabulary so you never re-derive it: `event.label` / `event.reason` / `event.reason_label` (localized), `event.device_name`, `event.source_line` (the location-first one-liner — "🇪🇸 Madrid, Spain · IP 83.45.112.7 · Firefox 139 on Windows" — ready for security emails and notification bodies; pass `ip: false` for compact rows), `session.active_now?`, plus `sessions_device_icon_name(session)` / `sessions_event_icon_name(event)` view helpers (Heroicons-vocabulary names for whatever icon system you use).

## 📱 Hotwire Native

Detection works out of the box (`Hotwire Native` UA marker — same contract as turbo-rails' `hotwire_native_app?`): platform, real OS version, and on Android the real device model (WebViews are exempt from Chrome's UA reduction). To also get **app version and iOS hardware model**, set the documented prefix convention in your shells:

```swift
// iOS — AppDelegate, before creating the Navigator
var u = utsname(); uname(&u)
let model = withUnsafeBytes(of: &u.machine) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
Hotwire.config.applicationUserAgentPrefix =
  "MyApp/\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0") (\(model); iOS \(UIDevice.current.systemVersion));"
```

```kotlin
// Android — Application.onCreate, before any HotwireActivity
Hotwire.config.applicationUserAgentPrefix =
    "MyApp/${BuildConfig.VERSION_NAME} (${Build.MODEL}; Android ${Build.VERSION.RELEASE}; build ${BuildConfig.VERSION_CODE});"
```

Sessions now read "MyApp/2.4.1 (iPhone15,2; iOS 19.5; build 241)". Validated `X-Client-Platform/-Version/-Build/-OS` headers are honored too, and legacy prefixes (like `"MyApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)"`) parse once you declare them: `config.native_app_names = ["MyApp"]`.

One identity rule the gem follows: a native device is **one cookie jar**, not one user agent — WebView navigations and native HTTP calls share the session, so they're one device row, not two.

## 🏷 Auth methods: how each session started

Password and OAuth logins classify automatically (so do devise-passwordless magic links and remember-me re-auths). Flows that can't self-identify take one line *before* signing the user in:

```ruby
# Google One Tap endpoint:
Sessions.tag(request, method: :google_one_tap, detail: { select_by: params[:select_by] })

# Passkey verification:
Sessions.tag(request, method: :passkey, detail: { user_verified: credential.user_verified? })
```

…and custom failure paths (a native-app sign-in branch that renders 422s, a passkey `SignCountVerificationError` — a possible cloning signal) get the manual seam:

```ruby
Sessions.record_failed_attempt(request, scope: :user, identity: params[:email],
                               reason: :invalid_password)
```

Custom Warden strategies map with `config.strategy_methods = { "OtpAuthenticatable" => :otp }`. Everything else is `unknown` — the gem never guesses.

### Two-factor flows (TOTP apps, security keys, Touch ID)

Every mainstream Ruby 2FA setup creates the session at **full** authentication — we verified each one against its source — so the registry and trail stay correct without configuration. What varies is the labeling, and where a recipe is needed it's one line:

- **[devise-two-factor](https://github.com/devise-two-factor/devise-two-factor)** (GitLab/Mastodon-style TOTP + backup codes): **fully automatic.** It's single-phase — its strategy subclasses Devise's `DatabaseAuthenticatable` and consumes `params[scope][:otp_attempt]` in the same request as the password (its `strategies/two_factor_authenticatable.rb`), so Warden signs in exactly once. The gem classifies `password` and stamps `auth_detail: { second_factor: "totp" }` (or `"backup_code"` for `TwoFactorBackupable` wins) when a second factor was actually used.
- **[devise-otp](https://github.com/wmlele/devise-otp)**: two-phase. Its replaced `database_authenticatable` strategy `redirect!`s OTP-enabled users to a challenge instead of `success!` (no session yet — nothing recorded, correctly), and the challenge's `OtpCredentialsController#update` then calls plain `sign_in` with **no Warden strategy** — the row records, but classifies `unknown` (the gem never guesses). One initializer block labels it:

  ```ruby
  Rails.application.config.to_prepare do
    DeviseOtp::Devise::OtpCredentialsController.before_action only: :update do
      Sessions.tag(request, method: :password, detail: { second_factor: "totp" })
    end
  end
  ```
- **[authentication-zero](https://github.com/lazaronixon/authentication-zero) `--two-factor`** (the generator Rails 8's authentication was modeled on): its `sessions` table is Rails-8-shaped, so the install generator adopts it and the model concern tracks every `user.sessions.create!` — which its challenge controllers call only **after** the second factor verifies (password-phase requests stash a signed `challenge_token` and create nothing). Tag each `create` so rows don't classify `unknown`:

  ```ruby
  Sessions.tag(request, method: :password)                                          # SessionsController (password-only branch)
  Sessions.skip!(request)                                                              # …and its challenge-redirect branch: the password
                                                                                       # was RIGHT — without this, the no-session outcome
                                                                                       # would read as a failed login
  Sessions.tag(request, method: :password, detail: { second_factor: "totp" })          # Challenge::TotpsController
  Sessions.tag(request, method: :password, detail: { second_factor: "webauthn" })      # Challenge::SecurityKeysController
  Sessions.tag(request, method: :password, detail: { second_factor: "recovery_code" }) # Challenge::RecoveryCodesController
  ```
- **[webauthn-rails](https://github.com/cedarcode/webauthn-rails) second-factor mode** (YubiKeys, Touch ID, Windows Hello — all WebAuthn authenticators): the session starts in `SecondFactorAuthenticationsController#create` after verification — tag it there:

  ```ruby
  Sessions.tag(request, method: :password, detail: { second_factor: "webauthn" })
  start_new_session_for user
  ```
- **[devise-passkeys](https://github.com/ruby-passkeys/devise-passkeys) / [warden-webauthn](https://github.com/ruby-passkeys/warden-webauthn)** (passkey-**first**, passwordless): **fully automatic.** That's not a second factor, it's the method — their `PasskeyAuthenticatable` / `Warden::WebAuthn::Strategy` strategies classify as `passkey` by name. devise-passkeys' sudo confirm (`reauthenticate`, a `sign_in` with `event: :passkey_reauthentication`) is recognized as a reauthentication of the live session — never a duplicate device row.
- **[rotp](https://github.com/mdp/rotp) / [active_model_otp](https://github.com/heapsource/active_model_otp)** (the DIY primitives — pure TOTP math / model mixin, no strategies, no controllers): your controllers own the flow, so label it at the seam that fits. Verifying **before** creating the session: `Sessions.tag(request, method: :password, detail: { second_factor: "totp" })`. A **post-login step-up gate** (session already live, OTP unlocks sensitive areas): `Sessions.current(request)&.second_factor!("totp")`.
- **Email/SMS login codes**: `Sessions.tag(request, method: :otp)`.

Either way, `session.second_factor?` / `session.second_factor` (also on events) answer "was this login 2FA-protected?" — useful for step-up gates and admin triage. Failed second-factor attempts surface through the same seams as everything else: devise-two-factor failures land in the trail automatically (Warden failure, message verbatim); WebAuthn rescues should call `Sessions.record_failed_attempt(request, reason: e.class.name, method: :password, detail: { second_factor: "webauthn" })` — a `SignCountVerificationError` there is a possible credential-cloning signal worth alerting on.

### Repeated failed attempts ("someone is trying to get in")

Per-attempt alerts are notification fatigue *and* an abuse vector (an attacker hammering the form would flood the victim's inbox), so the gem ships **threshold-crossing** detection instead — the hook fires exactly once when an identity crosses the line inside the window:

```ruby
config.repeated_failed_logins = { threshold: 5, within: 15.minutes }
config.on_repeated_failed_logins = ->(identity:, count:, event:) do
  user = User.find_by(email: identity) or next  # identity is AS TYPED — may match no account
  SecurityMailer.with(user: user, event: event).repeated_failed_logins.deliver_later
end
```

The `event` is the attempt that tripped the threshold — IP, location and device included. This complements (not replaces) Devise's `:lockable` and Rails 8's `rate_limit`: they *stop* the attacker; this tells the *user*.

## 🌍 Geolocation (via `trackdown`, soft dependency)

If the [`trackdown`](https://github.com/rameerez/trackdown) gem is in your bundle, sessions and events get country/city automatically: behind Cloudflare the answer is read synchronously from request headers (free); with a MaxMind database, lookups run asynchronously in `Sessions::GeolocateJob` so logins never wait on geo. No trackdown → locations stay blank and the UI omits them cleanly.

> [!IMPORTANT]
> Locations are approximate by nature (they come from the IP) and the page labels them as such. Coordinates are only stored on trail events, precision-reduced (~1km) by default.

**Behind Cloudflare?** `request.remote_ip` returns a Cloudflare edge IP unless CF ranges are trusted. Best: add [cloudflare-rails](https://github.com/modosc/cloudflare-rails) and everything just works. Alternatively set `config.ip_resolver = ->(request) { request.headers["CF-Connecting-IP"] || request.remote_ip }` — but only if your origin is unreachable except through Cloudflare.

## 🔔 The "Was this you?" moment

When a login matches no device the user has signed in from before (coarse, server-observed matching — never fingerprinting), the gem hands you the moment; you send the email:

```ruby
config.on_new_device = ->(user:, session:, event:) do
  SecurityMailer.with(event: event).new_device.deliver_later
end
```

Pass the **event** to your mailer, not the session: the event is a persisted, GlobalID-able record that survives revocation (the session row may already be destroyed by the time an async job runs), and it carries everything the email needs — `event.user`, `event.device_name`, `event.location`, `event.country_flag`, `event.source_line`, `event.occurred_at`:

```ruby
class SecurityMailer < ApplicationMailer
  def new_device
    @event = params.fetch(:event)
    mail to: @event.user.email, subject: "New sign-in from #{@event.device_name}. Was this you?"
  end
end
```

A user's very first login doesn't fire it (nobody wants a security alert on signup), and like every hook in this gem it's error-isolated: a broken mailer can never break a login.

**In-app notifications too?** Don't fan out from the hook — that's your notification system's job. With [noticed](https://github.com/excid3/noticed), one notifier owns every channel (feed row, push, email) and the hook stays one line:

```ruby
config.on_new_device = ->(user:, session:, event:) do
  NewDeviceNotifier.with(record: event, event: event).deliver(user)
end

class NewDeviceNotifier < Noticed::Event
  deliver_by :email do |config|
    config.mailer = "SecurityMailer"
    config.method = :new_device
    config.if = -> { recipient.email.present? }
  end

  notification_methods do
    # NOT `def event` — Noticed::Notification delegates #record to its own
    # `event` association (the Noticed::Event row); shadowing it recurses.
    def session_event = record
    def title = "New sign-in"
    def body = "New sign-in from #{session_event&.source_line(ip: false)}. Was this you?"
    def url = "/settings/sessions"
  end
end
```

The trail event is the `record:` — persisted and GlobalID-safe, so delivery jobs render fine even after the session row is revoked, and the feed preloads it without N+1s. (X and Google run exactly this pattern: a new-device login lands in the notifications tab of every other device you're still signed in on.)

## 🛠 Admin: triage surfaces in one command

Scopes are the admin product — `Sessions::Event.failed_logins.last_24_hours.group(:ip_address).count` works in any console or admin framework. If your app uses [madmin](https://github.com/excid3/madmin):

```bash
rails generate sessions:madmin
```

…generates the two resources (the live registry with a per-row **Revoke session** action, and the login trail with its triage scopes as filters) plus their controllers, with madmin's two namespacing footguns pre-solved. The generated files use only stock madmin APIs and are yours to restyle. For a per-user security panel (devices + trail on the user's show page), load `user.sessions.by_recency` and `user.session_events.recent` in a member action — including the user's *failed* attempts by matching `Sessions::Event.where(identity: Sessions::Event.normalize_identity(user.email))` (failures never link to accounts; matching the signed-in user's own identity is the safe way to show them).

## 🧹 Retention & the sweep

The install generator drops a `SessionsSweepJob` into `app/jobs/` — schedule it daily:

```yaml
# config/recurring.yml (Solid Queue)
production:
  sessions_sweep:
    class: SessionsSweepJob
    schedule: every day at 4am
```

It purges trail rows past `config.events_retention` (12 months by default — CNIL's recommendation for security logs), evicts per-user overflow beyond `config.max_sessions_per_user` (100, GitLab's number), and — only if you opted into `config.idle_timeout` / `config.max_session_lifetime` (or `config.timeout_preset = :nist_aal2`) — expires stale sessions. Worth knowing: the Rails 8 auth cookie lives 20 years, so this sweep is the only real session expiry most omakase apps will ever have.

## 🔏 Security & privacy posture

- **Tracking never breaks login.** Every adapter path, parser, geo lookup and hook is error-isolated; the test suite includes a chaos test that detonates every pipeline stage at once and asserts sign-in still works.
- **No usable credential is ever persisted.** Devise-mode session tokens are random 32-byte values stored as SHA-256 digests; the raw token lives only in the user's own session. Rails-8-mode rows store nothing secret (the signed cookie is the credential). Nothing secret is ever logged.
- **Revocation is server-side and immediate** (checked on the very next request, both stacks) — OWASP ASVS 7.4.1; "view and terminate any or all currently active sessions" is literally ASVS 3.3.4 / 7.5.2, the requirement this gem exists to satisfy.
- **IPs and UAs are personal data** (GDPR Recital 30), processed under the network-security legitimate interest (Recital 49 / Art. 6(1)(f)). The gem ships bounded retention, optional IP truncation *before persistence* (`config.ip_mode = :truncated` — zeroes the last IPv4 octet / 80 IPv6 bits, the Google Analytics precedent), data minimization (no bodies, no referrers), and `Sessions.forget(user)` for erasure requests.
- Want encryption at rest? `Session.encrypts :ip_address, deterministic: true` (deterministic keeps equality queries working — the documented Rails tradeoff) and non-deterministic for `user_agent`.

## Configuration reference

Everything lives in one annotated initializer (`config/initializers/sessions.rb`, written by the install generator). The defaults work untouched:

```ruby
Sessions.configure do |config|
  # — Behavior —
  config.touch_every             = 5.minutes  # last_seen_at throttle (nil = never touch)
  config.max_sessions_per_user   = 100        # oldest-eviction; nil = unlimited
  config.idle_timeout            = nil        # opt-in expiry…
  config.max_session_lifetime    = nil        # …or config.timeout_preset = :nist_aal2
  config.revoke_on_password_change = true     # ASVS 3.3.3
  config.revoke_remember_me      = true       # Devise: revoke also rotates remember-me
  config.track_failed_logins     = true

  # — Device intelligence —
  config.ua_parser               = :browser   # :device_detector | ->(ua, headers) { {...} }
  config.request_client_hints    = false      # Accept-CH for real platform versions / Android models
  config.native_app_names        = []         # legacy native UA prefixes to recognize

  # — IP & geo —
  config.ip_resolver             = ->(request) { request.remote_ip }
  config.ip_mode                 = :full      # | :truncated (anonymize before persistence)
  config.geolocate               = :auto      # trackdown when present | :off
  config.geo_precision           = 2          # lat/lng decimals on events (~1km)

  # — Retention —
  config.events_retention        = 12.months  # trail purge horizon (nil = keep forever)

  # — Hooks (kwargs, no-op defaults, error-isolated) —
  config.on_new_device           = ->(user:, session:, event:) {}
  config.on_session_revoked      = ->(session:, by:, reason:) {}
  config.events                  = ->(event) {}  # catch-all tee → AuditLog / analytics

  # — Integration —
  config.parent_controller       = "::ApplicationController"
  config.current_user_method     = :current_user   # chain: this → current_user → Current.session&.user
  config.authenticate_method     = :authenticate_user!
  config.layout                  = nil             # nil inherits the parent controller's layout
  config.require_reauthentication = nil            # ->(controller) { ... } sudo gate
  config.session_class           = "Session"
  config.strategy_methods        = {}              # { "OtpAuthenticatable" => :otp }
end
```

## 🧱 Why the models?

Two primitives, linked — **rows are active sessions; events are history**:

- **`sessions`** (the registry — *your* table, Rails-8-shaped on both stacks): one row = one signed-in device. Destroyed on logout/revocation/expiry, which is what makes revocation instant — both adapters resolve the row on every request, so a missing row *is* a remote logout. No soft-delete state machine.
- **`sessions_events`** (the trail — gem-owned, append-only): what happened and from where, surviving the rows it describes. Its `session_id` is a plain column with no foreign key *on purpose*: history must outlive the registry.

On Rails 8 auth, the gem **adopts** the generated table and model: one migration adds columns (the `add_devise_to_users` precedent), and the 2-line `Session` model is decorated via a concern at boot — your generated code stays byte-identical. On Devise, the install generator creates the same Rails-8-shaped table and a 3-line shell model — so if you ever migrate Devise → Rails auth, your sessions table is already exactly where Rails expects it.

## Why this gem exists

Rails 8's authentication generator creates a database-backed `sessions` table with `ip_address` and `user_agent` on every row — and then ships zero UI, no session listing, no per-device revocation, no failed-login log. The Rails security guide literally recommends a `Session.sweep` based on `updated_at` *that the generated code can never satisfy*, because nothing ever touches a session row after creation. Devise stores even less: two sign-in slots on the users table, overwritten on every login, with cookie sessions that are unenumerable and unrevocable server-side — people have been asking for a decade.

Meanwhile Laravel ships "Browser Sessions" in its starter kit, Phoenix's `mix phx.gen.auth` tracks every session token in a table, OWASP ASVS makes "view and terminate your sessions" a Level-2 requirement, and GitLab, Mastodon and Discourse have each independently hand-rolled (and maintain, forever) this exact feature set. Every serious Rails app eventually rebuilds the same thing: a sessions page, a login trail, a revocation mechanism, a device parser. `sessions` is that rebuild, done once, done right — on top of the auth you already own, never instead of it.

## Database support

PostgreSQL (including PostGIS), MySQL, and SQLite. The migrations adapt automatically: they honor your app's configured primary key type (**uuid or bigint** — same detection `rails g model` uses) and pick `jsonb` on Postgres / `json` elsewhere, resolved at migration run time so one migration file survives a dev-SQLite/prod-Postgres split. Works on Rails 7.1+ and shines on the Rails 8 omakase.

## Testing

The gem is tested with Minitest against a real dummy host app whose auth files are **vendored verbatim from `rails generate authentication`** — so the adapter's duck-detection and prepends run against the actual generated shapes, and upstream template drift breaks CI here instead of login there. The Warden adapter runs against a real `Warden::Manager` rack stack (the exact hook ABI Devise rides), and a chaos test detonates every hook and pipeline stage at once to prove sign-in survives.

```bash
bundle exec rake test            # full suite
bundle exec appraisal install    # then test across Rails versions:
bundle exec appraisal rails-7.1 rake test
bundle exec appraisal rails-8.1 rake test
```

**Testing your own app with the engine mounted** — one Rails gotcha worth knowing: in an integration test, after a request to any engine route, the test session keeps that request's `url_options` (including the engine's mount point as `script_name`), so *host* route helpers called next generate prefixed paths (`settings_path` → `/settings/sessions/settings`). Use literal paths (`get "/settings"`) after driving engine routes — real requests are unaffected (script_name resolves per request).

## Development

After checking out the repo, run `bundle install`, then `bundle exec rake test`. The dummy app lives in `test/dummy` and mounts the engine at `/settings/sessions` exactly like a real host.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/rameerez/sessions. Our code of conduct is: just be nice and make your mom proud of what you do and post online.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
