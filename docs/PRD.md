# `sessions` — Product Requirements Document

> **Status**: Draft v1 for review (Javi). **Date**: 2026-06-11.
> **Research base**: every claim and shape in this document is backed by the nine research memos in [`docs/research/`](research/) — read-only audits of HostApp, LicenseSeat, the rameerez gem ecosystem, rails/rails (v8.1.3 + main), Devise 5.0.4 + Warden + devise-security, OmniAuth + google_sign_in + webauthn-ruby, authtrail + authie + authentication-zero + Rodauth, the `browser`/`device_detector` parsers, hotwire-native-ios/android, plus live web research (all sources fetched 2026-06-10/11, exact URLs inline and in the memos). Citations below use the form `(→ research/NN §X)` plus direct URLs where load-bearing.

---

## 0. TL;DR

**`sessions` is the missing session layer for Rails.** Rails 8's omakase auth generator creates a database-backed `sessions` table with `ip_address` and `user_agent` on every row — and then ships zero UI, no session listing, no per-device revocation, no failed-login log, no device intelligence, and never touches a row after creation (→ research/03 §2). Devise — still growing at ~239k downloads/day (→ research/08 §Adoption) — stores even less: two sign-in slots on the `users` table, overwritten on every login. Meanwhile Laravel ships "Browser Sessions" in its starter kit, Phoenix's `mix phx.gen.auth` tracks every session token in a table, and OWASP ASVS makes "users can view and terminate any or all currently active sessions" a literal Level-2 requirement (ASVS 4.0.3 §3.3.4, 5.0 §7.5.2) (→ research/09).

`sessions` gives every Rails 8+ app, in one `bundle add` + one generator + one `has_sessions` macro:

1. **A live device registry** — every active session, enriched with parsed device intelligence ("Chrome 137 on macOS", "HostApp 2.4.1 on iPhone 15 Pro (iOS 19.5)"), IP geolocation (via `trackdown`, soft dependency), auth method ("via Google", "via passkey"), and throttled last-seen tracking.
2. **Per-session remote revocation** — "log out of that device", "sign out everywhere else" — that actually works on Rails 8 omakase auth (end the lifecycle row), on Devise (token-per-row generalization of devise-security's proven `session_limitable` mechanism), and on remember-me cookies.
3. **An append-only login-activity trail** — every successful *and failed* login attempt, logout, and revocation, with attempted identity, device, geo, and failure reason — linked to the live session it created (the linkage no prior art has, → research/06 §Improve).
4. **A drop-in "Your devices" page** — engine-mounted, Tailwind-friendly, i18n'd (en + es), matching the GitHub/Google/Stripe UX contract — plus admin-grade scopes for fraud triage and a madmin recipe.
5. **First-class citizenship for every 2026 login method**: Rails 8 native auth, Devise (4.x & 5.x), OmniAuth/OAuth (with failed-OAuth capture), Google One Tap (FedCM-era), Sign in with Apple, passkeys, magic links — via automatic classification plus a one-line `Sessions.tag` API for the flows that can't self-identify (→ research/05).
6. **Hotwire Native device intelligence** — platform/OS/app-version/device-model detection out of the box, a documented UA convention + 3-line client snippets to make it perfect (→ research/07 §B).

The gem **decorates the session of record; it never becomes it** (the #1 lesson from prior art: authie owned auth-session storage and died at 245 stars; authtrail decorated Devise and got 4.1M downloads, → research/06). Tracking is error-isolated and can never break login. Privacy is a feature: configurable retention with a purge job (CNIL 6–12 months), optional IP truncation, no fingerprinting ever (→ research/09 §Privacy).

**The name `sessions` is unregistered on RubyGems** (API 404, 2026-06-10), and no living competitor occupies the space (→ research/09 §Demand).

---

## 1. Why now: the 2026 Rails auth landscape

### 1.1 Rails 8 omakase auth: a substrate, deliberately unfinished

- Rails 8.0 (2024-11-07) shipped `bin/rails generate authentication`: a `Session < ApplicationRecord` model (2 lines), a `sessions` table (`user:references ip_address:string user_agent:string`), an `Authentication` concern, and a signed **permanent** cookie holding the Session row id — `cookies.signed.permanent[:session_id]`, httponly, SameSite=Lax, 20-year expiry ([authentication.rb.tt](https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/authentication/templates/app/controllers/concerns/authentication.rb.tt), → research/03 §1).
- **Every request resolves the row** (`Session.find_by(id: cookies.signed[:session_id])`), so a lifecycle row can be made server-revocable without changing Rails' cookie shape. Rails built the substrate and shipped no product on top of it: the only generated route is singular `resource :session` — no index, no devices page; ip/user_agent are written once and never read again; **no code path ever UPDATEs a session row**, so `updated_at == created_at` forever (grep-verified, → research/03 §2).
- The punchline: Rails' own security guide recommends an `updated_at`-based `Session.sweep` for expiry ([security guide §sessions](https://guides.rubyonrails.org/security.html)) **that the generated code can never satisfy because nothing touches `updated_at`** (→ research/03 §5). The framework documents the hole this gem fills.
- The gaps are **policy, not backlog**. DHH on the PR: *"This is not intended to be an all-singing, all-dancing answer to every possible authentication concern… do not expect magic links or passkeys or 2FA. That's not going to happen with this generator"* ([rails/rails#52328](https://github.com/rails/rails/pull/52328)). Rails 8.1 (2025-10-22) added zero auth features (only: password reset now `sessions.destroy_all`s, and passwords#create got `rate_limit`); 8.2 edge adds only Argon2 + Sec-Fetch-Site CSRF. The `Authentication` concern is **byte-identical from 8.0.5 through 8.1.3 to main** — an exceptionally stable instrumentation target (→ research/03 §4, research/08 §Timeline).

### 1.2 Devise: the compounding installed base

- Devise is **not dying — it's growing**: 280.9M total downloads, v5.0.4 (2026-05-08), actively maintained (HEAD committed 2026-06-10), daily installs up ~20–25% from mid-2024 to mid-2026 (BestGems API, → research/08 §Adoption). Realistic 2026 model: new apps start on the Rails 8 generator, the Devise base keeps compounding — **two large installed bases, both lacking session/device management**.
- Devise's `:trackable` stores exactly two sign-ins (current + last) *on the users row*; history is destroyed on every login. Its cookie sessions are server-side unenumerable and unrevocable (Devise issues [#5262](https://github.com/heartcombo/devise/issues/5262), [#5027](https://github.com/heartcombo/devise/issues/5027), [#4607](https://github.com/heartcombo/devise/issues/4607) — users have asked for a decade, → research/09 §Demand).
- The attachment surface is proven and frozen-stable: Warden 1.2.9 (unchanged since 2020) class-level hooks; authtrail (4.1M downloads) runs entirely on two of them; devise-security's `session_limitable` is a complete 55-line revocation mechanism whose only structural flaw is one-token-per-user — moving the token to a row generalizes it to N devices (→ research/04 §5).

### 1.3 OAuth and modern login methods

- OmniAuth 2.x deliberately stops at `env['omniauth.auth']` and lets the app create the session — **OAuth logins always land in the same app-side seam the gem already hooks**; failures funnel through a swappable `OmniAuth.config.on_failure` we can compose-wrap to capture provider + error type + IP/UA for every failed OAuth attempt (→ research/05 §1).
- Google One Tap went **FedCM-mandatory in August 2025** (even though Chrome kept third-party cookies after the April 2025 reversal); the One Tap POST includes a `select_by` field that tells us exactly *how* the user signed in (`fedcm_auto` vs `btn` vs …) — recordable gold (→ research/05 §4).
- Apple's guideline 4.8 still effectively forces a privacy-preserving login option on any iOS app with third-party login — `apple` must be a first-class provider (→ research/05 §5).
- Passkeys: `webauthn-ruby` is healthy; the omakase story (`webauthn-rails`) funnels into `start_new_session_for` — our hook fires automatically, only the method label needs tagging. Devise still has no built-in passkeys. Rails core has none planned (→ research/05 §6).
- Conclusion: **no flow self-identifies at the session-row level** → the gem needs automatic classification (omniauth env, warden strategy class) *plus* an explicit `Sessions.tag` annotate API (→ research/05 §Implications).

### 1.4 Hotwire Native

- Hotwire Native UA construction is deterministic and documented in SDK source: iOS *appends* `"Hotwire Native iOS; Turbo Native iOS; bridge-components: […]"`; Android *prepends* its segment to the stock Chromium WebView UA. `turbo_native_app?` matches `/(Turbo|Hotwire) Native/` (→ research/07 §B).
- **Android WebView is exempt from Chrome's UA reduction** — native Android UAs still carry real device model + OS version for free. iOS carries real OS version but never the hardware model; app version appears nowhere by default. HostApp's native HTTP clients already use a richer convention (`"HostApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)"` + validated `X-Client-*` headers) that the gem should formalize (→ research/07 §B, research/01 §3).

### 1.5 The gap, in one table

Condensed from the full prior-art matrix (→ research/06 §5):

| Capability | rails8 gen | devise +trackable | authtrail | authie | auth-zero | rodauth |
|---|---|---|---|---|---|---|
| Live session registry | rows, no UI | ✗ | ✗ (log only) | ✓ | ✓ | ✓ (no UA/IP) |
| Per-session remote revocation | primitive only | ✗ | ✗ | ✓ | ✓ | ✓ |
| Failed-attempt log w/ identity | ✗ | ✗ | ✓ | ✗ | ✗ | partial |
| Log ↔ live-session linkage | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Device/UA parsing | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Geolocation | ✗ | ✗ | ✓ | partial | ✗ | ✗ |
| Last-active touching | ✗ | partial | n/a | every request (!) | ✗ | ✓ |
| End-user devices UI | ✗ | ✗ | ✗ | ✗ | ✓ (static) | ✗ |
| New-device notification | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Multi-auth-system support | own only | devise only | warden only | own only | own only | own only |
| Hotwire Native awareness | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Automated retention | ✗ | n/a | ✗ | partial | ✗ | partial |

**Nobody owns the middle ground** of registry + trail + revocation + UI over *existing* auth. The bottom three rows are uncontested everywhere.

---

## 2. Market validation

### 2.1 Cross-framework precedent (the strongest signal)

- **Laravel**: the default starter migration creates a sessions table with `user_id`, `ip_address`, `user_agent`, `last_activity`; Jetstream ships "Browser Sessions" ("logout other browser sessions"); the framework itself ships `Auth::logoutOtherDevices($password)` ([laravel.com/docs/12.x/session](https://laravel.com/docs/12.x/session), [jetstream.laravel.com/features/browser-sessions.html](https://jetstream.laravel.com/features/browser-sessions.html), → research/09 §Laravel).
- **Phoenix**: `mix phx.gen.auth` tracks every session token in a `users_tokens` table — "you could even expose this information to users if desired"; password change deletes all tokens ([hexdocs.pm/phoenix/mix_phx_gen_auth.html](https://hexdocs.pm/phoenix/mix_phx_gen_auth.html)).
- **Django**: `django-user-sessions` (Jazzband) proved demand, then went stale (last release 2020) — the maintenance gap a fresh gem avoids.
- Rails ships the schema; **nobody ships the product**.

### 2.2 Every serious Rails app hand-rolled it

- **GitLab**: `ActiveSession` (Redis), 100-session cap, per-row revoke that *also revokes remember-me tokens*, device parsing via a hardened `DeviceDetector` subclass (UA truncated at 1024) (→ research/09 §GitLab).
- **Mastodon**: `SessionActivation` (Postgres) — `session_id`, `ip`, `user_agent`, browser/platform via the **`browser` gem**, `exclusive(id)` = sign out everywhere else (→ research/09 §Mastodon).
- **Discourse**: `UserAuthToken` — rotating SHA-1-hashed tokens (raw token never persisted), 60-session cap, companion `UserAuthTokenLog` audit table, "Recently Used Devices" UI (→ research/09 §Discourse).
- Three flagship codebases independently built and maintain the exact feature set; none is extractable. Textbook gem opportunity.

### 2.3 The UX bar end-users already expect

GitHub (Settings → Sessions + security log), Google ("Your devices" + the canonical "Was this you?" new-device email), Slack, Stripe ("Login sessions" + sign-out-all), Shopify (Devices + per-device logout). The standardized contract: **device label (parsed UA) + approximate location (IP) + last-active + per-row revoke + "sign out everywhere" + new-device alert** (→ research/09 §UX bar). The gem's default views replicate exactly this, nothing more.

### 2.4 Demand signals in the Rails ecosystem

- **authtrail: 4.11M downloads**, 1.0.0 on 2026-04-04, ~1.3k downloads/day — the market already pays (in installs) for login-activity tracking alone, with no live-session features at all (→ research/09 §Demand).
- A decade-deep tutorial cottage industry (SupeRails twice — once per auth stack; rails.substack multi-device tracking; Jon Leighton 2013 → PentesterLab 2025) keeps re-teaching the same hand-rolled build; WorkOS's 2026 Rails auth guide frames our literal pitch: *"You're logged in on iPhone, MacBook, and Windows PC – sign out others?"* (→ research/08 §Demand, research/09 §Demand).
- GoRails' impersonation episode extends the generated `Session` model — proof the community treats it as *the* extension point (→ research/08 §Demand).

### 2.5 Compliance drivers (this is a requirement, not a nice-to-have)

- **OWASP ASVS 4.0.3 §3.3.4 (L2)**: "users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices" — carried into **ASVS 5.0 §7.5.2**. Terminate-others on password change: 3.3.3 / 7.4.3 (→ research/09 §Compliance).
- **OWASP Session Management Cheat Sheet**: recommends user-facing session controls outright; mandates server-side invalidation; **never log raw session IDs** ("log a salted-hash… instead").
- **NIST 800-63B-4**: named reauth timeouts (AAL2 ≤24h absolute / ≤1h idle) — exposed as config presets.
- **SOC 2 CC6.x/CC7.x**: queryable login-attempt evidence + admin revocation is standard audit material.

### 2.6 Competitive scan & naming

`sessions` → RubyGems API **404 (available)**, as are `active_sessions`, `user_sessions`, `login_activity`, `sessionable`. `authtrail` = events-only; `devise-security` (20.8M downloads, policy modules) = one-session-per-user limiting, no listing; `session_tracker` dead since 2021 (→ research/09 §Demand). One discoverability bonus: DHH's PR was literally titled "Add basic **sessions** generator" — the word now means "DB-backed auth session rows" in Rails mindshare (→ research/08 §Implications). Docs must disambiguate from `ActionDispatch::Session` (the Rack cookie store) early and clearly.

---

## 3. Product vision & design principles

1. **Decorate the session of record. Never become it.** We enhance the host's existing auth (Rails 8 rows, Devise cookies); we never replace session storage or authentication. Authie replaced and died; authtrail decorated and won (→ research/06 §Avoid).
2. **Omakase-maximalist.** Where Rails has a shape, we adopt it: the Rails 8 `sessions` table *is* our registry when present; when absent (Devise apps), we generate the same Rails-8-shaped table and model — `sessions` makes every Rails app converge on the omakase shape, so a future Devise→omakase migration finds its sessions table already in place. Precedent for extending host-owned tables via copied migrations: Devise itself (`add_devise_to_users`).
3. **Tracking must never break login.** Every hook body is error-isolated (authtrail's `safely` pattern; ecosystem rule: "callback errors are isolated and never break the core operation", → research/02 §5). A bug in `sessions` may lose a log row; it may never 500 a sign-in.
4. **Zero-config magic, with explicit escape hatches.** Install generator auto-detects the auth stack and adapts. Auto-classification covers password/OAuth/devise-passwordless; `Sessions.tag` covers the rest. Every default is overridable in a fully-annotated initializer (ecosystem convention, → research/02 §1).
5. **DX is candy.** `has_sessions`, `session.device_name`, `session.revoke!`, `user.revoke_other_sessions!` — bang verbs, `?` predicates, kwargs, chainable scopes, reads like English (→ research/02 §4).
6. **Soft dependencies everywhere.** `trackdown` (geo), `device_detector` (parser upgrade), Devise/Warden, OmniAuth — all optional, detected with `defined?()`, rescued everywhere. Only hard runtime deps: Rails frameworks + `browser` (MIT, zero-dep, 15 KB) (→ research/07 §A, research/02 §2).
7. **Privacy as a feature.** Bounded retention + purge job, optional IP truncation, optional AR encryption, no client-side fingerprinting ever (WP224 consent trap), lat/lng precision reduction (→ research/09 §Privacy).
8. **Incubated in production.** Built against HostApp (Devise 5 + Hotwire Native + Cloudflare + Spanish UI) and LicenseSeat (Devise 4.9 + MaxMind trackdown + api_keys), extracted only when the shapes survive contact with both (→ research/01).

---

## 4. Personas & jobs-to-be-done

| Persona | Job | What v1 gives them |
|---|---|---|
| **End user** | "Is my account safe? What's logged in? Kick that device." | `/settings/sessions` devices page: friendly device names, location, last seen, current-session badge, per-row Log out, "Sign out everywhere else", and a "Was this you?" email on new-device logins. |
| **Developer** | "Give me GitHub-style session security without building it for the third time." | `bundle add sessions` → `rails g sessions:install` → `has_sessions` → done. Works identically on Rails 8 auth and Devise; OAuth/native just work; one initializer of lambdas to integrate mailers/audit (goodmail, noticed, AuditLog…). |
| **Admin / T&S** | "Who tried to brute-force us last night? Is this account being taken over? Kill every session this user has." | `Sessions::Event` scopes (failed logins, by IP, by identity, velocity), per-user session admin + `revoke_all!`, new-device/new-country signals, madmin resource recipe, optional tee into the host's AuditLog (HostApp pattern). |

Three installed bases to serve from day one: (a) Rails 8 generator apps, (b) Devise apps (HostApp, LicenseSeat, RailsFast), (c) any of the above with OAuth/One Tap/passkeys/magic links layered on (→ research/08 §Implications).

---

## 5. Scope

### 5.1 v1.0 (the launchable core)

- Session registry (adopt-or-generate Rails-8-shaped `sessions` table) + extension columns (device, geo, auth method, `last_seen_at`).
- Append-only `sessions_events` trail: `login`, `failed_login`, `logout`, `revoked`, `expired` — successes *and* failures with attempted identity, linked to the session row they created.
- Adapters: Rails 8 omakase (model callbacks + controller prepend), Devise/Warden (4 hooks), OmniAuth (classification + failure composer), explicit APIs (`Sessions.tag`, `Sessions.record_failed_attempt`, `Sessions.track_login`).
- Revocation: `session.revoke!`, `user.revoke_other_sessions!`, revoke-on-password-change (default on), Devise remember-me invalidation on revoke (default on).
- Device intelligence: native matcher (Hotwire Native + UA convention + `X-Client-*` headers) → `browser` gem → optional `device_detector` adapter; raw UA + client hints always stored; `Accept-CH` opt-in.
- Geolocation via `trackdown` soft dep (CF-headers sync / MaxMind async, footprinted enqueue-time enrichment pattern).
- Throttled `last_seen_at` touch (single conditional UPDATE; default every 5 minutes).
- Hooks: `on_new_device`, `on_session_revoked`, plus a catch-all `config.events` tee (for AuditLog/telegrama/goodmail wiring). **No mailers shipped** (house rule, → research/02 §Top 9) — README recipes for goodmail/noticed instead.
- "Your devices" engine page (mountable), partials, `rails g sessions:views` ejection, i18n (en, es).
- Retention: `config.events_retention` (default 12 months, CNIL) + generated `Sessions::SweepJob` (+ `config/recurring.yml` snippet); session cap per user with oldest-eviction (default 100, GitLab-style).
- Admin scopes + madmin resource recipe; optional idle/absolute timeout enforcement with NIST presets (default **off** — see §12).
- Privacy: `config.ip_mode = :full | :truncated`, AR-encryption recipe, lat/lng rounding.

### 5.2 v1.x fast-follows

- `sessions:reparse` rake task (re-run UA parsing with newer parsers over stored raw UAs).
- Browser-continuity cookie (authie's `browser_id`) to re-link remember-me re-auths to a stable "device" identity.
- First-party Google One Tap + webauthn-rails integration generators (auto-`Sessions.tag` injection).
- Authtrail migration recipe (`INSERT … SELECT` mapping LoginActivity → `sessions_events`).
- Suspicious-activity primitives: `first_session_for_ip?`, new-country flag, failed-attempt velocity scope; `on_suspicious_login` hook.
- Avo/Administrate recipes; ActiveSupport::Notifications instrumentation of all lifecycle events.

### 5.3 v2+ / explicit non-goals

- **Non-goals (forever)**: authentication itself (passwords, 2FA, lockout — that's Rails/Devise/rodauth); rate limiting (Rails `rate_limit` / rack-attack); client-side fingerprinting (WP224 consent trap); push-notification token management (we leave a clean per-device row to hang tokens off later); API/JWT token auth tracking (that's `api_keys`' lane — we explicitly skip non-cookie auth, → research/01 §LicenseSeat).
- **v2 candidates**: impossible-travel detection (Entra model — the data model already stores geo+timestamps to make it computable), org/team-level admin dashboards, WebSocket presence ("online now"), session notes/labels.

---

## 6. Architecture

### 6.1 Two primitives, linked

```
┌─────────────────────────────┐         ┌──────────────────────────────────┐
│  sessions (registry)        │         │  sessions_events (trail)         │
│  host-owned, Rails-8-shaped │◄────────│  gem-owned, append-only          │
│  LIFECYCLE state: one row = │ session │  HISTORY: logins (ok+failed),    │
│  one signed-in device;      │   _id   │  logouts, revocations, expiry.   │
│  ended_at NULL means live.  │         │  Survives cleanup/erasure.       │
└─────────────────────────────┘         └──────────────────────────────────┘
```

- **One mental model**: *rows = session lifecycle state; events = audit history.* `revoke!` ends the registry row in place (`ended_at`/`ended_reason`) and writes a `revoked` event in the same transaction. Devise/Warden never infers security intent from a missing row; it kicks only when a token-backed row has an explicit kicking lifecycle reason.
- The trail's `session_id` column (plain id, deliberately **no FK constraint** — account erasure and legacy host deletes may still remove the registry row) is the linkage no prior art has: a suspicious login event is one click away from revoking the live session it created (→ research/06 §Improve).

### 6.2 Adopt-or-generate: the registry is always the Rails 8 shape

| Host situation | What `rails g sessions:install` does |
|---|---|
| **Rails 8 omakase auth** (`Session` model + `sessions` table exist) | Adopts them. One migration **adds columns to the existing `sessions` table** (precedent: Devise's `add_devise_to_users`). Model decorated via concern at `to_prepare` — app code untouched. |
| **Devise (no sessions table)** | Generates the Rails-8-shaped `sessions` table (+ our columns, with `token_digest` populated) and a 3-line app-owned shell model: `class Session < ApplicationRecord; include Sessions::Model; end`. Devise stays the authenticator; Warden hooks maintain the rows. The app is now omakase-shaped — a future Devise→Rails-auth migration finds its table waiting. |
| **Existing conflicting `sessions` table** (e.g. legacy `activerecord-session_store`) | Generator detects, aborts with guidance: `config.session_class = "SessionRecord"` + `--table=session_records` escape hatch. |
| **No auth at all** | Generator says: run `bin/rails generate authentication` (or install Devise) first, then re-run. We never generate authentication. |

All gem logic lives in `Sessions::Model` (the concern) and `Sessions::Event` (gem-owned model under `lib/sessions/models`, wired into the host's Zeitwerk loader exactly like moderate/chats do, → research/02 §1). The generated `Session` file is a 3-line shell, so it never goes stale — dodging authentication-zero's "generated code will not be updated" trap (→ research/06 §Avoid).

### 6.3 The adapter layer

```
                         ┌──────────────────────────────────────────┐
                         │            Sessions.record               │
                         │  (one internal pipeline: classify auth   │
                         │   method → parse device → resolve IP →   │
                         │   geo-enrich → persist row + event →     │
                         │   detect new device → fire hooks)        │
                         └──────────────────────────────────────────┘
                              ▲             ▲              ▲
        ┌─────────────────────┤             │              ├──────────────────────┐
┌───────┴────────┐  ┌─────────┴────────┐  ┌─┴──────────┐  ┌┴─────────────────────┐
│ Rails8 adapter │  │ Devise adapter   │  │ OmniAuth   │  │ Explicit API         │
│ Session model  │  │ 4 Warden hooks   │  │ on_failure │  │ Sessions.tag         │
│ callbacks +    │  │ (class-level,    │  │ composer + │  │ Sessions.track_login │
│ controller     │  │ live-read, load- │  │ env sniff  │  │ Sessions.record_     │
│ prepend        │  │ order safe)      │  │            │  │   failed_attempt     │
└────────────────┘  └──────────────────┘  └────────────┘  └──────────────────────┘
```

Both first-class adapters activate automatically and independently (an app can have both — e.g. Devise app that later adds omakase auth for a second scope). Activation is duck-typed and guarded:

- **Rails 8 adapter** (→ research/03 §Implications): `Rails.application.config.to_prepare` → if `defined?(::Session)` && table has `ip_address`/`user_agent` → `Session.include(Sessions::Model)`; if `ApplicationController.private_method_defined?(:start_new_session_for)` → `ApplicationController.prepend(Sessions::OmakaseControllerHooks)`. The prepend sits in front of the included `Authentication` concern in the ancestor chain, so `super`-wrapping `resume_session` (throttled touch/expiry/end-state refusal) and `terminate_session` (logout lifecycle end) is clean, name-stable-since-8.0, and requires zero app edits. Login events ride **model callbacks** (`after_create_commit`: ip/UA already on the row); explicit logout/revocation uses `end!`; host-side `destroy_all` remains covered by the compatibility callback (→ research/03 §Top 6).
- **Devise adapter** (→ research/04 §Implications): registered from a Railtie initializer guarded by `defined?(::Warden::Manager)` (Bundler.require precedes initializers; hooks live on the Manager *class* and are read live per request — no load-order coupling, no `require "warden"`). The four hooks:
  1. `after_set_user except: :fetch` — any fresh login (form, remember-me, OmniAuth, sign-up auto-login, post-password-reset). Guards: `warden.authenticated?(scope)` && `opts[:store] != false` (**critical**: token/HTTP-Basic auth fires this hook *every request* with `store: false` — without the guard we'd mint a session row per API call) && our skip flags. Creates the registry row, stores `[row_id, raw_token]` in `warden.session(scope)` (survives Warden's `:renew` SID rotation; auto-deleted by Warden on logout).
  2. `after_set_user only: :fetch` — per-request resume: look up row by id, `secure_compare` token digest; missing/revoked → `warden.raw_session.clear; warden.logout(scope); throw :warden, scope:, message: :session_revoked` (the proven session_limitable sequence); else throttled touch.
  3. `before_failure` — failed logins: persist scope/action/message/attempted_path from `env['warden.options']`; attempted identity from `request.params[scope]` **only when `request.post?` && credentials hash present** (filters out plain 401 page-hits and timeouts); never read the password key. Store Devise's failure symbol verbatim (`:invalid` under paranoid mode — don't infer account existence).
  4. `before_logout` — mark row ended + `logout` event (fires once per scope; also on forced logouts like timeout).
- **OmniAuth integration** (→ research/05 §1): no hook needed for successes (the callback lands in the same controller seam either adapter already covers; we classify by sniffing `env['omniauth.auth']`). Failures: compose-wrap `OmniAuth.config.on_failure` in an after-Devise initializer — record `omniauth.error.type` + provider + origin + IP/UA, then call the original endpoint.
- **Explicit API**: the universal seam for everything else — HostApp's manual native sign-in branch renders 422s without touching Warden's failure app, so it needs `Sessions.record_failed_attempt` (→ research/01 §Implications 3); One Tap/passkey/magic-link controllers call `Sessions.tag(request, method: :passkey, detail: {...})` before signing in.

### 6.4 Auth-method classification pipeline

At session-creation time, first match wins (→ research/05 §Implications b):

1. Explicit `Sessions.tag(request, …)` (stored in `request.env["sessions.auth"]`).
2. `env['omniauth.auth']` present → `method: :oauth`, `provider:` normalized strategy name (`google_oauth2` → `google`), detail: `{origin:, scopes:, email_verified:, hd:}`.
3. Warden `winning_strategy` class → mapping table: `DatabaseAuthenticatable → :password`, `Rememberable → :password` (+ `detail: {remembered: true}`), `MagicLinkAuthenticatable → :magic_link` (devise-passwordless auto-detected), extensible via `config.strategy_methods`.
4. `flash[:google_sign_in]` present → `:oauth` / `google` (Basecamp google_sign_in gem).
5. Omakase `SessionsController#create` via `authenticate_by` → `:password`.
6. Fallback `:unknown` (never guess).

Taxonomy (two indexed columns + one JSON): `auth_method` ∈ `password, oauth, google_one_tap, passkey, magic_link, otp, sso, token, unknown`; `auth_provider` (nullable: `google`, `github`, `apple`, IdP entity…); `auth_detail` (JSON: `select_by` for One Tap, UV/BS flags + `sign_count` for passkeys, etc.). Apple is `oauth` + `provider: "apple"` — method values are reserved for transport-distinct flows so the enum stays stable (→ research/05 §Implications a).

### 6.5 Device intelligence pipeline

Raw-first, three layers (→ research/07 §Implications):

1. **Persist raw**: `user_agent` as `text` (no 255 truncation — authie's footgun; Hotwire Native UAs with bridge-components exceed 255), plus interesting headers (`Sec-CH-UA*`, `X-Client-*`) in a `client_hints` JSON column. Parsing is a projection; `sessions:reparse` (v1.x) can re-run it as parsers improve.
2. **Native matcher first** (the moat — no third-party parser does this): `/(Turbo|Hotwire) Native (iOS|Android)/` (same contract as turbo-rails' `turbo_native_app?`) → platform; then the documented prefix convention `AppName/1.2.3 (iPhone15,2; iOS 19.5; build 241);` → app name/version/build/model/OS; HostApp's legacy shapes (`"HostApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)"`) and validated `X-Client-Platform/Version/Build/OS` headers accepted as input too; on Android, fall back to the embedded WebView UA for model/OS (UA-reduction-exempt).
3. **Web parser**: `browser` gem (hard dep: MIT, zero-dep, ~15 KB, maintained, ships `ios_app?`/`android_app?` webview heuristics — also what Mastodon uses) for browser name/version, OS family, device type, bot flag. **`device_detector` auto-upgrade adapter** when the host bundles it (better Android device names, Client-Hints-native, 108 KB bot list — but LGPL, 1.5 MB data, stale since 2024-07, which is also why it's not the default; GitLab wraps it with a 1024-char truncation we mirror). `config.ua_parser` accepts `:browser`, `:device_detector`, or a lambda.

**Honest display names** (frozen-UA reality, → research/07 §C): never render frozen tokens as facts — "Chrome 137 on macOS" (no version), "Safari on iOS 19.5 · iPhone", "HostApp 2.4.1 on Pixel 8 (Android 16)". iPads on Safari display as "Safari on macOS" (no server-side tell; documented). Optional `config.request_client_hints = true` sets `Accept-CH` to recover real platform versions + Android models on Chromium; login POSTs are rarely first-navigations, so hints are reliably present exactly when we need them.

### 6.6 Geolocation via `trackdown` (soft dependency)

The contract, lifted verbatim from footprinted's proven integration (→ research/02 §2):

- Guard every call with `defined?(Trackdown)`; rescue **everything** and log (trackdown raises on private/loopback IPs in dev — a geo failure must never block a login write).
- Always `Trackdown.locate(ip.to_s, request: request)` so Cloudflare headers win when present (HostApp mode: zero-config, free, synchronous header read).
- MaxMind mode (LicenseSeat shape): geolocate in the gem's enrichment job, and **pre-extract CF-header geo at enqueue time** so workers never need the MaxMind DB.
- Skip lookup when `country_code` already present. Store footprinted's proven column set (country_code/name, city, region; lat/lng on events only, precision-reduced). Flag emoji derives from `country_code` at render time — no column.

### 6.7 Touch, expiry & lifecycle

- **Throttled touch**: `last_seen_at` updated at most every `config.touch_every` (default 5 minutes) via one conditional `update_all` statement (hot-row-safe, callback-free — HostApp's `IS DISTINCT FROM` pattern generalized; Rodauth's validate+touch-in-one-UPDATE proves the shape; authie's touch-every-request and devise-security's per-request `update_column` are the documented anti-patterns) (→ research/01 §Implications 6, research/06 §Steal).
- This finally makes the Rails security guide's own `Session.sweep` recommendation implementable (→ research/03 §5).
- **Expiry**: `config.idle_timeout` / `config.max_session_lifetime` (both default `nil` — a tracking gem must not silently change login lifetimes; see §12) with `config.timeout_preset = :nist_aal2` sugar (24h absolute / 1h idle). Enforced inline at resume (both adapters) and by the generated `Sessions::SweepJob` (also prunes per-user overflow beyond `config.max_sessions_per_user`, default 100 — GitLab's number — and purges trail rows past retention).

### 6.8 Performance budget (hard requirements)

- **Unauthenticated requests**: zero overhead.
- **Authenticated resume**: Rails 8 mode — zero extra queries (we piggyback the host's own `Session.find_by`; touch adds ≤1 UPDATE per 5 min per session). Devise mode — exactly one indexed PK lookup per request (row id rides in the warden session next to the token; digest compared in Ruby with `secure_compare`) + the same throttled touch.
- **Login**: +1 INSERT (event) +1 INSERT/row-create (registry, omakase already does it) + UA parse (µs–ms, memoized) + optional geo job enqueue. All hook bodies error-isolated.
- No model callbacks on the host's hot path beyond what we register; no `before_action` injected into every controller (authie's mistake).

---

## 7. Data model

Two migrations, both **copied into the app** (adaptive: uuid/bigint PKs, jsonb/json, detected from the host — ecosystem convention, → research/02 §1). Column types chosen for cross-DB portability (`ip_address` is `string limit: 45` everywhere — `inet` is PG-only; the generator may upgrade to `:inet` on Postgres, → research/07 §D).

### 7.1 Registry: extend (or create) `sessions`

```ruby
# When the Rails 8 table exists → add_column calls on the existing table.
# In Devise mode → create_table with the Rails 8 base (user:references,
# ip_address:string, user_agent:text, timestamps) plus all of the below.

t.string   :token_digest            # Devise/Warden mode only: SHA-256 of a random 32-byte
                                    # token; raw token lives ONLY in the user's Rack session.
                                    # Unique index. NULL for omakase rows (cookie holds row id;
                                    # nothing secret to store — OWASP: never persist raw IDs).
t.string   :scope                   # warden scope ("user"); multi-scope Devise apps
t.string   :auth_method             # §6.4 taxonomy — indexed
t.string   :auth_provider           # "google", "apple", "github"… — indexed
t.json     :auth_detail             # select_by, oauth scopes, passkey UV/BS flags…
t.string   :browser_name, :browser_version
t.string   :os_name, :os_version
t.string   :device_type             # desktop / smartphone / tablet / native_ios /
                                    # native_android / bot / unknown
t.string   :device_model            # "iPhone15,2", "Pixel 8" (when knowable, §6.5)
t.string   :app_name, :app_version, :app_build    # Hotwire Native
t.json     :client_hints            # raw Sec-CH-UA* + X-Client-* headers
t.string   :country_code, limit: 2  # via trackdown — indexed
t.string   :country_name, :city, :region
t.datetime :last_seen_at            # indexed; the column the security guide's sweep needs
t.string   :last_seen_ip, limit: 45 # refreshed with touch (roaming devices)
```

Notes: Rails 8's generated `ip_address`/`user_agent` are kept as-is (login-time values; `user_agent` is `string` there — MySQL 255-char truncation risk documented; our Devise-mode table uses `text`). `user_id` stays a plain FK for omakase parity; multi-scope/polymorphic owners are an install flag (`--polymorphic`), while the **events** table is polymorphic always.

### 7.2 Trail: `sessions_events` (gem-owned, append-only)

```ruby
create_table :sessions_events do |t|
  t.string     :event, null: false           # login / failed_login / logout / revoked / expired
  t.references :authenticatable, polymorphic: true   # nullable: unknown-identity failures
  t.string     :scope
  t.bigint     :session_id                   # ← the linkage. Plain column, NO FK constraint:
                                             # lifecycle rows can be erased; history must survive.
  t.string     :identity                     # email-as-typed (normalized), even for unknown accounts
  t.string     :auth_method, :auth_provider
  t.json       :auth_detail
  t.string     :failure_reason               # devise message symbol / omniauth error type, verbatim
  t.string     :revoked_reason               # user_revoked / admin_revoked / password_change /
                                             # logout_everywhere / expired / pruned
  t.string     :ip_address, limit: 45
  t.text       :user_agent
  t.json       :client_hints
  t.string     :browser_name, :browser_version, :os_name, :os_version,
               :device_type, :device_model, :app_name, :app_version
  t.string     :country_code, limit: 2
  t.string     :country_name, :city, :region
  t.decimal    :latitude,  precision: 10, scale: 7   # rounded per config.geo_precision
  t.decimal    :longitude, precision: 10, scale: 7   # (default 2 decimals ≈ 1km) — privacy + future
                                                     # impossible-travel math (Entra model)
  t.string     :request_id, :context          # X-Request-Id, "controller#action"
  t.json       :metadata                      # transform-hook extras
  t.datetime   :occurred_at, null: false      # append-only: no updated_at
end
# Indexes: [authenticatable_type, authenticatable_id, occurred_at], [event, occurred_at],
#          :identity, :ip_address, :session_id, :occurred_at
```

Schema lineage, deliberately: authtrail's LoginActivity (scope/strategy/identity/success/failure_reason/context — its 4.1M downloads validate the trail schema; a v1.x migration recipe maps it 1:1) + footprinted's geo column set + Discourse's `UserAuthTokenLog` + our device columns (→ research/06 §1.4, research/02 §3, research/09 §Discourse). Events are written through one tolerant pipeline (authtrail's `try("#{k}=")` pattern) so hosts can add/drop columns without gem releases.

---

## 8. Public API (the candy)

### 8.1 Install (any Rails 8+ app)

```ruby
# Gemfile
gem "sessions"
```

```bash
rails generate sessions:install   # detects Rails 8 auth vs Devise, writes the right migration
rails db:migrate                  # + annotated initializer + SweepJob + recurring.yml snippet
```

```ruby
class User < ApplicationRecord
  has_sessions   # that's it — on Rails 8 apps this enriches the existing has_many :sessions;
end              # on Devise apps it also declares it
```

Post-install message: ecosystem house style (emoji headline, numbered steps, yellow migration warning, the mount line, green sign-off) (→ research/02 §4).

### 8.2 The model API

```ruby
current_user.sessions.live              # live devices, most recent first
current_user.sessions.inactive          # stale live rows > 30 days (UI grouping, not enforcement)

session = current_user.sessions.find(params[:id])
session.device_name        # => "Chrome 137 on macOS"
                           # => "HostApp 2.4.1 on iPhone 15 Pro (iOS 19.5)"
session.location           # => "Madrid, Spain"  (+ session.country_flag => "🇪🇸")
session.last_seen_at       # => 3 minutes ago
session.current?           # => true for the request's own session
session.hotwire_native?    # session.native_ios? / session.native_android? / session.web?
session.via_oauth?         # session.auth_method / .auth_provider / "Signed in with Google"
session.suspicious?        # v1.x: new-IP/new-country heuristics

session.revoke!(reason: :user_revoked, by: current_user)   # ends row + writes event
current_user.revoke_other_sessions!                         # GitHub's "sign out everywhere else"
current_user.revoke_all_sessions!                           # admin hammer (account takeover response)

current_user.session_events.recent      # the trail
current_user.session_events.failed_logins.last_24_hours
Sessions::Event.failed_logins.for_ip("203.0.113.7")         # admin: brute-force triage
Sessions::Event.for_identity("j@example.com")               # admin: ATO investigation
Sessions::Event.by_country("RU").logins                     # admin: geo filtering
```

### 8.3 Request-side API

```ruby
Sessions.current(request)                       # the registry row for this request (both adapters)
Sessions.tag(request, method: :passkey, detail: { user_verified: true })   # before sign-in
Sessions.record_failed_attempt(request, scope: :user, identity: params[:email],
                               reason: :invalid_password)   # manual seams (HostApp's native branch)
Sessions.track_login(user, request, method: :sso)           # fully manual integrations
```

### 8.4 Configuration (annotated initializer, abridged)

```ruby
Sessions.configure do |config|
  # — Behavior —
  config.touch_every            = 5.minutes      # last_seen_at throttle (nil = never touch)
  config.max_sessions_per_user  = 100            # oldest-eviction (GitLab's number); nil = unlimited
  config.idle_timeout           = nil            # opt-in enforcement; or config.timeout_preset = :nist_aal2
  config.max_session_lifetime   = nil
  config.revoke_on_password_change = true        # ASVS 3.3.3 / 7.4.3 (omakase 8.1 already does this)
  config.revoke_remember_me     = true           # Devise: revoking a session also invalidates
                                                 # remember-me cookies (GitLab semantics — see §9.2)
  # — Device intelligence —
  config.ua_parser              = :browser       # :device_detector | ->(ua, headers) { ... }
  config.request_client_hints   = false          # set Accept-CH for real platform versions / Android models
  config.native_app_names       = ["HostApp"]     # extra UA prefixes to recognize (auto-learned from convention)
  # — IP & geo —
  config.ip_resolver            = ->(request) { request.remote_ip }   # CF-Connecting-IP setups override
  config.ip_mode                = :full          # :truncated → zero last IPv4 octet / last 80 v6 bits (GA precedent)
  config.geolocate              = :auto          # :auto (trackdown if present; CF sync, MaxMind async) | :off
  config.geo_precision          = 2              # lat/lng decimals stored on events
  # — Retention (CNIL: 6–12 months for security logs) —
  config.events_retention       = 12.months      # SweepJob purges older trail rows
  # — Hooks (kwargs, no-op defaults, error-isolated — never break login) —
  config.on_new_device          = ->(user:, session:, event:) {}   # wire goodmail/noticed here
  config.on_session_revoked     = ->(session:, by:, reason:) {}
  config.events                 = ->(event) {}   # catch-all tee → AuditLog.log / Telegrama / analytics
  # — Integration —
  config.parent_controller      = "::ApplicationController"   # devices page inherits host auth/layout
  config.current_user_method    = :current_user  # resolver chain: configured → current_user → Current.session&.user
  config.authenticate_method    = :authenticate_user!
  config.require_reauthentication = nil          # ->(controller) { ... } sudo gate for destructive actions (ASVS 3.3.4)
end
```

Every knob follows the house rules: validating setters with plain-English errors, class names as strings, no-op lambdas, hooks isolated (→ research/02 §1, §5).

### 8.5 The "Your devices" page

```ruby
# config/routes.rb
authenticate :user do                       # host's own auth gate (profitable's mount pattern)
  mount Sessions::Engine => "/settings/sessions"
end
```

- chats-style isolated engine: `path: ""` root resources, semantic `sessions-*` CSS classes with minimal default styles (Tailwind-friendly, themeable), no JS beyond Turbo (`button_to` + `turbo_confirm`), `rails g sessions:views` ejection for full control (→ research/02 §7).
- Alternatively, render the partials inside an existing settings shell (HostApp's `<section>`/`setting_row` pages; LicenseSeat's `settings` namespace): `render "sessions/devices", user: current_user`.
- Contents per the standardized UX contract (§2.3): device icon by `device_type`, `device_name`, approximate location (labeled approximate), `last_seen_at` in words, "This device" badge, per-row **Log out** button, **Sign out of all other sessions** button, link to login history. i18n: `en` + `es` shipped (HostApp's UI is Spanish, → research/01 §5).

### 8.6 Generators

- `sessions:install` — adaptive migration(s) + initializer + SweepJob into `app/jobs/` + `recurring.yml` snippet (trackdown/nondisposable pattern).
- `sessions:views` — eject engine views/partials.
- v1.x: `sessions:madmin` (resource files mirroring HostApp's `audit_log_resource.rb`), `sessions:one_tap`, `sessions:passkeys` integration injectors.

---

## 9. Integration specs per stack

### 9.1 Rails 8 omakase (zero-touch)

- **Login events**: `Session.after_create_commit` — ip/UA already on the row from `start_new_session_for`; classification pipeline runs against `Sessions::Current.request` (set by a tiny gem middleware that stores the request reference per-request — needed because model callbacks lack request context; reset automatically by the executor).
- **Logout/revocation events**: `end!`/`revoke!` writes lifecycle state plus audit event transactionally; `after_destroy_commit` remains only as a compatibility hook for host-side raw deletes and Rails-generated `destroy_all` paths (→ research/03 §Top 6).
- **Touch**: prepend-wrap `resume_session` → after `super`, throttled touch of `Current.session`.
- **Failed logins**: two automatic layers + one manual: (a) prepend `SessionsController#create` when the generated duck-shape is detected — after `super`, if no new session was started and the request was a credentials POST, record `failed_login` with the permitted identity param; (b) subscribe to the `rate_limit.action_controller` notification (8.1+) for brute-force-threshold events — free signal, no code; (c) `Sessions.record_failed_attempt` for custom controllers. Opt-out: `config.track_failed_logins = false`.
- **Edge cases encoded** (→ research/03 §Implications 8): the generated `sign_in_as` test helper creates rows with nil ip/UA — all parsing is nil-tolerant; `--api` apps lack `helper_method` — engine helpers are Base/API-aware; signed-not-encrypted cookie exposes sequential row ids (informational; revocation security rests on the signature); 20-year permanent cookie means our sweep + optional idle timeout is the only real expiry; `ip_address` truthfulness depends on `trusted_proxies` (README "Behind Cloudflare" section: cloudflare-rails / replacement-semantics warning / CF-Connecting-IP only when origin-locked).

### 9.2 Devise / Warden (4.x and 5.x — HostApp is 5.0.4, LicenseSeat 4.9.4)

- The four hooks of §6.3, with the full guard set lifted from Devise's own hooks: skip flags (`env['sessions.skip']`, per-call `sign_in(user, sessions_skip: true)`, sticky session flag — mirroring session_limitable's three layers), `opts[:store] != false`, `warden.authenticated?(scope)`.
- **Fixation-safe by construction**: Warden's `set_user` renews the Rack SID but keeps session *data* — our token, stored in `warden.session(scope)`, survives login rotation and is deleted by Warden on logout. We never key on the Rack SID (→ research/04 §Top 3).
- **Remember-me**: a cookie re-auth is a real `:authentication` event (strategy `Rememberable`) arriving with a fresh Rack session → new registry row; stale rows get swept (v1) or re-linked via the browser-continuity cookie (v1.x). **Revocation closes the remember-me hole**: with `config.revoke_remember_me = true` (default), `revoke!` also rotates the user's remember credentials (Devise `forget_me!`/salt semantics — user-wide, documented: other devices keep their live sessions but cannot auto-revive after those end; GitLab does exactly this). HostApp's silent 1-year native remember-me makes this non-negotiable (→ research/01 §8 gap 4).
- **Multi-scope**: rows carry `scope`; `Devise.sign_out_all_scopes` fires `before_logout` once per scope — handled.
- **Coexistence**: `:trackable` keeps working (we never set `devise.skip_trackable`); `has_sessions` simply supersedes it — README suggests dropping trackable columns when ready. `bypass_sign_in` runs no callbacks → same session continues, token stays valid (documented). Timeoutable may `throw` on the same `:fetch` event — we tolerate both hook orders. HostApp's read-only `warden.user(run_callbacks: false)` peeks and its stale-remember-cookie native bootstrap never fire our hooks (correct — no login happens) (→ research/01 §3, research/04 §Implications).

### 9.3 OAuth / OmniAuth

Successes auto-classified (§6.4) on whichever adapter is active. Failures: the `on_failure` composer records `failed_login` with `auth_method: :oauth`, `auth_provider`, `failure_reason` (`:invalid_credentials`, `:access_denied` = user hit Cancel, `:authenticity_error` = CSRF), `omniauth.origin`, IP/UA — then delegates to the original endpoint (Devise's or OmniAuth's). Not capturable (documented): which local user, and abandonments at the provider (→ research/05 §1.3).

### 9.4 One Tap, passkeys, magic links, OTP

- **Google One Tap** (FedCM-era): `Sessions.tag(request, method: :google_one_tap, detail: { select_by: params[:select_by] })` in the app's credential endpoint — README ships the full verified pattern (GIS script → POST → `googleauth`'s `Google::Auth::IDTokens.verify_oidc` → tag → sign in). `select_by` distinguishes auto-sign-in from explicit taps (→ research/05 §4).
- **Passkeys**: webauthn-rails funnels into `start_new_session_for` → row exists automatically; tag adds the label + `{user_verified:, backed_up:, sign_count:}`. AAGUID is registration-time-only — belongs on the app's credential record, joined at display (→ research/05 §6). `SignCountVerificationError` rescues should call `record_failed_attempt(method: :passkey)` — a possible-cloning signal.
- **Magic links**: devise-passwordless = warden strategy → fully automatic. Omakase tutorial pattern (`generates_token_for` → controller → `start_new_session_for`) → row automatic, tag the method.
- **OTP/SSO**: explicit tag; `config.strategy_methods` maps custom warden strategies.

### 9.5 Hotwire Native

- Detection/parsing per §6.5. **Device identity = the cookie jar, never the UA**: Hotwire Native shares one session cookie between WebView navigations and native HTTP calls while presenting two different UAs — HostApp's NativeHttpClient explicitly syncs cookies — so one device = one registry row, with `client_hints` capturing the richer native-client headers (→ research/01 §3 "One cookie = one session across surfaces").
- README ships the 3-line iOS/Android `applicationUserAgentPrefix` snippets (app version everywhere, hardware model on iOS — Android model is free). Without them, the gem still yields platform + OS (+ Android model) from SDK defaults (→ research/07 §B).
- The signed `session_id` cookie is readable from middleware (`request.cookie_jar.signed[:session_id]` — the generated ActionCable Connection uses the same trick) for native-API contexts outside controllers (→ research/03 §Implications 5).

### 9.6 trackdown modes

- **HostApp mode** (zero config, Cloudflare): synchronous CF-header read at request time — free.
- **LicenseSeat mode** (MaxMind initializer + refresh job): geo enrichment in `Sessions::GeolocateJob` with CF pre-extraction at enqueue.
- No trackdown → geo columns stay nil; UI omits location cleanly; README points to trackdown setup (footprinted's call-out box pattern).

### 9.7 API-only & token auth

Out of scope by design: requests authenticated via `api_keys`/bearer tokens (`store: false` in warden, or no session cookie) are never tracked as sessions (→ research/01 §Implications 9). The `store: false` guard makes this automatic in Devise; omakase API apps simply have no session rows for token requests.

---

## 10. End-user UI spec ("Your devices")

Layout (one page, two sections — the GitHub/Google contract, → research/09 §UX bar):

```
Your devices
────────────────────────────────────────────────────────────
🖥  Chrome on macOS — This device                    [badge]
    Madrid, Spain · Active now · Signed in May 2 via Google

📱  HostApp 2.4.1 on iPhone 15 Pro (iOS 19.5)        [Log out]
    Madrid, Spain · Active 3 minutes ago · Signed in Apr 28

🖥  Firefox on Windows                               [Log out]
    Lisbon, Portugal · Active 12 days ago · Signed in Apr 12 via password

           [ Sign out of all other sessions ]

Login history (last 90 days)                       [see all]
────────────────────────────────────────────────────────────
✓ Signed in · Chrome on macOS · Madrid, ES · today 09:12
✗ Failed attempt (wrong password) · Lisbon, PT · yesterday 23:48
⊘ Session revoked (you signed out everywhere) · Apr 30
```

Requirements:

- Current session always first, never revocable from this page (GitLab rule — prevents foot-guns; "log out" of the current device is the app's normal sign-out).
- Locations labeled approximate ("based on IP address"); omitted cleanly when geo unavailable.
- Destructive actions: `button_to` + `data: { turbo_confirm: }`; optional sudo gate via `config.require_reauthentication` (ASVS 3.3.4's "having re-entered login credentials" — host wires its own password-confirm flow; README recipe for both stacks).
- Revocation responses handle the self-race: if a user revokes the session a stale tab is on, next request signs out gracefully (already inherent in both adapters).
- All copy through i18n (`sessions.devices.*`); `en` + `es` shipped; relative times via `time_ago_in_words`.
- Default markup = semantic classes + tiny optional stylesheet; looks decent unstyled inside any Tailwind app (chats precedent).

## 11. Admin & fraud toolkit

- **Scopes are the product** (BYOUI, moderate's posture): `Sessions::Event.failed_logins.last_24_hours.group(:ip_address).count`, `.for_identity`, `.for_ip`, `.by_country`, `.new_devices`, `user.sessions.active`, `Sessions::Event.velocity(identity:, within: 10.minutes)` (v1.x).
- **Admin verbs**: `user.revoke_all_sessions!(by: admin, reason: :admin_revoked)` — the account-takeover response; every admin action lands in the trail with `by`.
- **madmin recipe** (`sessions:madmin` generator, v1.x): SessionResource + EventResource mirroring HostApp's `audit_log_resource.rb` (menu parent "Security", recent-first, RelativeTimeField) (→ research/01 §5).
- **AuditLog tee**: `config.events = ->(event) { AuditLog.log(event_type: "session.#{event.name}", data: event.to_h, user: event.user, request: event.request) }` — one line wires HostApp's hash-chained ledger; same envelope works for Telegrama alerts (→ research/01 §2, research/02 §5).
- **New-device detection** (v1, powers `on_new_device`): a login is a *new device* when no prior session/event for that user matches on (device_type, os_name, app/browser identity) — deliberately coarse UA+IP-derived matching, never fingerprinting. New-country flag rides the same check when geo is present.

## 12. Security & privacy requirements (hard, each cited)

1. **Never persist a usable session credential.** Devise-mode tokens: random 32-byte, stored as SHA-256 digest, raw value only in the user's Rack session (OWASP Cheat Sheet "log a salted-hash"; Discourse/Rodauth precedent; high-entropy random ⇒ plain SHA-256 suffices — no pepper KDF theater). Omakase mode stores nothing secret (cookie signature is the credential). Never log raw tokens or cookie values anywhere (→ research/09 §Compliance, research/06 §Steal).
2. **Tracking is error-isolated** — every adapter body wrapped (authtrail `safely` pattern), failures logged at `warn`, login proceeds. A geo/parser/DB hiccup must never 500 a sign-in (→ research/02 §5).
3. **Revocation is server-side and immediate** (ASVS 7.4.1): lifecycle end state is checked on the very next request in both adapters; Devise revoke also invalidates remember-me by default (§9.2).
4. **Terminate-others on password change** default-on (ASVS 3.3.3/7.4.3; Phoenix/Laravel/omakase-8.1 precedent). In Devise, the salt-embedded session value already kills cookie sessions on password change — our rows follow via the `:fetch` validation; we also emit the events.
5. **Failed-attempt logging is enumeration-safe**: store Devise's message symbol verbatim (paranoid mode stays `:invalid`); never echo whether the identity exists in any UI; never store the password or its length; identity normalized (`strip.downcase`) for correlation (→ research/04 §3).
6. **Data minimization** (GDPR Art. 5(1)(c)): no request bodies, no referrer trails (drop authtrail's `referrer` column), nullable IP, UA + IP + derived columns only. IPs and UAs are personal data (*Breyer* C-582/14, Recital 30) processed under Art. 6(1)(f)/Recital 49 (network security) — stated in README with a balancing-test note (→ research/09 §Privacy).
7. **Bounded retention**: trail default 12 months (CNIL 6–12), purge job generated and scheduled; live registry rows end with their sessions, then retention/account-erasure cleanup can remove them. Right-to-erasure: `dependent: :destroy`/`delete_all` wiring + `Sessions.forget(user)` helper that also nulls identity on retained failure rows.
8. **Optional hardening**: `config.ip_mode = :truncated` (GA precedent: zero last IPv4 octet / last 80 v6 bits, applied *before* persistence); AR-encryption recipe (`encrypts :ip_address, deterministic: true` — deterministic needed for equality queries, tradeoff documented per the Rails guide; non-deterministic for `user_agent`); lat/lng precision reduction default-on (→ research/09 §Privacy).
9. **No client-side fingerprinting, ever** — scope guardrail (WP224: consent-gated under ePrivacy 5(3)). Server-observed UA + IP only — the GitLab/Mastodon/Discourse line (→ research/09 §Fraud).
10. **Timeout enforcement is opt-in** — a tracking gem must not silently shorten anyone's sessions; presets (`:nist_aal2` etc.) make opting in one line. Defaults documented loudly. The 20-year omakase cookie means *our* sweep is the only expiry most apps will have — the README says so.
11. **UA input hardening**: parse at most 1024 chars (GitLab's `SafeDeviceDetector` bound) while storing the full raw text; `IPAddr`-normalize and validate IPs before persistence.
12. **Fixation interplay**: we change nothing about Rack session rotation (Warden `:renew` stays; omakase auth doesn't use the Rack session for auth) and never key state on the Rack SID (→ research/04 §Top 3).

## 13. Packaging & compatibility

- **Gem name**: `sessions` (RubyGems 404 verified 2026-06-10). Tagline: *"Every session, every device, every login — tracked, revocable, visible. The missing session layer for Rails."*
- **Structure**: `Rails::Engine` with `isolate_namespace Sessions`; spine files `require_relative`'d; models/jobs under `lib/sessions/{models,jobs}` wired into the host Zeitwerk loader (`push_dir`/`collapse`/`ignore` before `:set_autoload_paths` — moderate/chats pattern). Never defines a top-level `Session` constant in the gem itself (→ research/02 §1, research/03 §Implications 7).
- **Dependencies**: `activerecord`/`activesupport`/`actionpack`/`railties >= 7.1, < 9.0` (Rails-8-first, 7.1 floor is cheap per moderate/chats); `browser >= 6` (hard); everything else soft (`trackdown`, `device_detector`, Devise/Warden, OmniAuth). Ruby `>= 3.2`. MIT. `rubygems_mfa_required`. Authors/email per house gemspec (→ research/02 §1).
- **Errors**: `Sessions::Error < StandardError`, `Sessions::ConfigurationError`, `Sessions::UnknownAuthSystemError` (generator-time).
- **DB support**: PostgreSQL, MySQL, SQLite via portable column types + adaptive migration (uuid/bigint, jsonb/json, optional `:inet` upgrade on PG). Both HostApp and LicenseSeat are uuid-PK Postgres apps; dummy apps test bigint+SQLite too.

## 14. Testing & quality strategy

- **Minitest 6**, TDD-style: write the candy-API tests first (define the DX we wish existed), then implement (project rule, `.cursor/rules/0-overview.mdc`).
- **Appraisals matrix**: Rails 7.1 / 7.2 / 8.0 / 8.1 (+ edge allowed-failure lane), Devise 4.9 + 5.0 lanes, with/without trackdown + device_detector + omniauth (soft-dep lanes assert graceful absence).
- **Two dummy apps** (the novel requirement vs sibling gems): `test/dummy_omakase` (generated `rails g authentication` code vendored in, pinned per Rails version — asserts our prepend/duck-detection against the *real* templates) and `test/dummy_devise` (Warden hook integration, multi-scope, remember-me, timeoutable interplay, `store: false` API guard). Engine UI tested mounted in both.
- **Edge-case suite** (each from a cited memo finding): nil ip/UA rows (`sign_in_as` helper), 2000-char native UAs, `bypass_sign_in`, paranoid-mode failures, `sign_out_all_scopes`, rate-limit notification capture, password-reset `destroy_all` events, revoked-session stale-tab race, CF header vs MaxMind geo, private-IP trackdown raise, MySQL 255-char UA truncation.
- **Security tests**: token digest never round-trips, no raw token in logs (log scrubber assertion), enumeration-safety of failure rows, purge job respects retention, `ip_mode: :truncated` truly truncates pre-persistence.
- Release discipline: version-bump checklist + CI drift check (footprinted pattern, → research/02 §1).

## 15. Rollout plan

1. **Phase 0 — Gem core** (this repo): registry + trail + both adapters + device intel + UI, built TDD against the two dummy apps. README written early in the house formula (emoji title → candy example → quickstart → deep dives → "what it doesn't do" → "why the models").
2. **Phase 1 — Incubate in HostApp** (Devise 5 + native + Cloudflare + Spanish): point Gemfile at the sibling checkout (`moderate` precedent); wire `config.events → AuditLog`, goodmail new-device recipe, madmin resources; "Sesiones y dispositivos" section in `/settings`; native UA-prefix snippets into hostapp-ios/android. Validates: Warden adapter, manual-branch failure seam, remember-me revocation, CF geo, native parsing, i18n.
3. **Phase 2 — Validate in LicenseSeat** (Devise 4.9, MaxMind, api_keys, English): validates devise 4.x, MaxMind async geo, token-auth exclusion, `settings` namespace UI fit.
4. **Phase 3 — Omakase proof**: a RailsFast-adjacent demo app on `rails g authentication` (zero-touch story, screenshots for README/launch post).
5. **Phase 4 — Extract & launch**: cut 0.1.0 → rubygems; launch content timed to the ecosystem calendar: Planet Argon 2026 survey results land **July 2026** (fresh auth-share data to cite) and **Rails World Austin is 2026-09-23/24** (→ research/08 §Implications 6).

## 16. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Rails core ships session management itself | Exclusions are stated policy (PR #52328 quotes); 8.1/8.2 added nothing; concern byte-stable since 8.0. If core ever moves, our omakase adapter rides the same shapes — and adoption by then is our moat. |
| Prepend/duck-detection breaks on a host's customized auth code | Detection is capability-based (`private_method_defined?`), every layer degrades to the explicit API; integration test lane against vendored generator output per Rails version catches upstream drift early. |
| Extending the host-owned `sessions` table feels invasive | Devise-extends-`users` precedent; migration is copied (visible, editable); escape hatch `config.session_class` + `--table=`. PRD Open Question 1 keeps this reviewable. |
| Devise per-request row lookup adds latency | PK lookup on an indexed id riding the warden session + Ruby digest compare; measured budget in §6.8; touch throttled. |
| Trail table grows unbounded on big apps | Indexed append-only writes, default 12-month purge, documented `INSERT`-heavy posture; events pipeline is `tolerant-assign`, so hosts can prune columns. |
| `device_detector` staleness / `browser` mis-parses new UAs | Raw UA always stored; `sessions:reparse`; parser pluggable; honest display-name rules avoid over-claiming. |
| Gem name squatting before launch | Reserve `sessions` on RubyGems with a 0.0.1 placeholder **immediately** (Open Question 7). |
| Remember-me revocation (user-wide) surprises Devise apps | Default documented loudly; `config.revoke_remember_me = false` opt-out; per-device remember tokens explored in v1.x (browser-continuity cookie). |

## 17. Open questions for Javi

1. **Registry model ownership in Devise mode**: PRD recommends generating an app-owned 3-line `Session` shell (omakase convergence; gem concern carries all logic). Alternative: gem-namespaced `Sessions::Record` + `sessions_records` table (ecosystem "models live in the gem" purity, zero collision risk, but two shapes forever and no convergence story). **Recommendation: app-owned shell.** Confirm.
2. **Macro name**: `has_sessions` (recommended; matches `has_credits`/`has_api_keys` grammar and literally declares the `has_many`) vs `tracks_sessions` (verb-y, avoids implying it's just an association). Confirm `has_sessions`.
3. **Devices page default**: mounted engine at `/settings/sessions` (recommended, chats precedent) — or partials-first with the engine optional? Both ship either way; question is what the README leads with.
4. **New-device email**: house rule is hooks-only, no mailers (→ research/02 §Top 9). PRD follows it (`on_new_device` + goodmail/noticed recipes). OK, or does `sessions` warrant breaking the rule with an optional built-in mailer (Google-style "Was this you?" out of the box would be the single most magical default)?
5. **Trail writes: inline vs async**: PRD says inline INSERT (simple, ordered, authtrail-proven) with async geo enrichment only. footprinted-style `config.async = true` for the whole event write could be a v1.x knob. OK?
6. **`Sessions::Event` vs `Sessions::Login` naming** for the trail model (events include logouts/revocations — `Event` recommended). Confirm.
7. **Reserve the gem name now?** Push a 0.0.1 stub to RubyGems this week to lock `sessions` (and optionally `sessionable`/`login_activity` as redirect-stubs? — probably unnecessary). Recommended: yes, immediately.
8. **Sudo mode**: ship only the `require_reauthentication` hook (recommended for v1) or build a first-party password-confirm flow (auth-zero-style `sudo_at` on the session row is cheap and we have the column budget — could be the v1.x headline)?
9. **Scope of `signup` enrichment**: HostApp's 22 `signup_*` columns overlap heavily with what every session row now carries. Should the gem also expose a `Sessions.attribution_for(user)` (first-session) helper so HostApp can eventually drop SignupAttribution, or is that HostApp's own cleanup later?
10. **License/positioning detail**: any appetite for a paid `sessions_pro` tier later (impossible travel, org dashboards)? Affects how much fraud tooling lands in the open core roadmap.

## 18. Research appendix

| Memo | Covers |
|---|---|
| [research/01-host-app.md](research/01-host-app.md) | HostApp + LicenseSeat audit: Devise setup, native UA/header contracts, AuditLog pattern, trackdown modes, UI conventions, gaps |
| [research/02-ecosystem.md](research/02-ecosystem.md) | rameerez house style: macros, config, generators, hooks, UI shipping, trackdown/footprinted deep dives |
| [research/03-rails-core.md](research/03-rails-core.md) | Rails 8.1.3 + main auth generator internals, verbatim templates, supporting APIs, integration points |
| [research/04-devise-warden.md](research/04-devise-warden.md) | Warden hook ABI, Devise sign-in flow, session_limitable revocation template, edge cases, Devise 2026 state |
| [research/05-oauth.md](research/05-oauth.md) | OmniAuth mechanics, One Tap/FedCM 2026, Apple 4.8, passkeys, auth-method taxonomy + interception matrix |
| [research/06-prior-art.md](research/06-prior-art.md) | authtrail/authie/authentication-zero/Rodauth dissections, feature matrix, Steal/Improve/Avoid |
| [research/07-device-detection.md](research/07-device-detection.md) | browser vs device_detector, Hotwire Native UA construction, UA convention + client snippets, client hints, IP capture |
| [research/08-rails8-landscape.md](research/08-rails8-landscape.md) | Rails 8 auth timeline, DHH quotes with receipts, community tutorials, adoption data 2026 |
| [research/09-market-security.md](research/09-market-security.md) | Laravel/Phoenix/Django precedent, GitLab/Mastodon/Discourse internals, SaaS UX bar, ASVS/NIST/SOC2/GDPR requirements |

**Reading order for implementation**: 03 + 04 (the two adapters) → 06 (what to steal) → 07 (device pipeline) → 02 (house style) → 01 (incubation targets) → 05 (classification) → 09 (security requirements as acceptance criteria).


---

## Is there a real market gap for this gem? Or existing projects already solve all the needs?

Honest answer: **yes, the gap is real — but it's narrower and differently-shaped than the PRD's enthusiasm might suggest.** Let me give you the unvarnished version.

**Where the gap is genuinely empty.** Go need by need and check who solves it today:

| Need                                                             | Best existing answer                                                                        | Honest verdict                                                                                                                        |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| List + revoke individual sessions on **Devise**                  | Nothing. devise-security only does "one session per user"; cookie sessions are unenumerable | **Truly unsolved** — and the DIY (warden hooks, token-in-session, races, remember-me hole) is the trickiest code in this whole domain |
| Devices page on **Rails 8 auth**                                 | Hand-roll (~a day for basics)                                                               | Solvable DIY, but nobody packages it                                                                                                  |
| Login trail incl. failures                                       | **authtrail** — 4.1M downloads, ankane, alive                                               | **Solved for Devise apps.** Be honest: if all you want is the log, authtrail is fine. Our wedge is *not* the log                      |
| Trail ↔ live session linkage, revoke-from-alert                  | Nobody                                                                                      | Empty                                                                                                                                 |
| Device intelligence (parsed names, Hotwire Native, app versions) | Nobody — every gem stores raw UA strings                                                    | Empty, and it's the demo-able magic                                                                                                   |
| New-device "was this you?" email                                 | Nobody in gem form                                                                          | Empty                                                                                                                                 |
| All of the above on *both* auth stacks                           | Nobody                                                                                      | Empty — SupeRails hand-rolled it twice, once per stack                                                                                |

So "existing projects already solve all the needs" is false — but "authtrail already solves the most-validated single need for the biggest segment" is *true*, and we should respect that: our reason to exist is the registry + revocation + UI + multi-stack layer, with the trail as a component, not the headline.

**The bear case, stated plainly:**

1. **This is a vitamin, not a painkiller, for most apps.** Sessions pages are security hygiene — rarely visited, never revenue. Unlike `usage_credits` or `pricing_plans` (which touch money), nobody's launch is blocked on this. Demand concentrates in serious production apps: B2B SaaS facing SOC2/ASVS checklists, consumer apps fighting fraud/ATO (HostApp's exact case), and anyone selling upmarket. Hobby apps will skip it.
2. **The ceiling is authtrail-magnitude, not Devise-magnitude.** Millions of downloads over years, not hundreds of millions. That's a successful rameerez gem, not a breakout — *unless* distribution changes the math (shipping it default-on in RailsFast, where a devices page becomes a template selling point, is genuinely your unfair advantage).
3. **Part of the value is thinner on Rails 8 than Devise.** Rails has a first-party session row and signed cookie; on omakase our value is breadth and polish (failure capture has no hook, touch has write-amplification traps, lifecycle state, retention/GDPR, native parsing), not inventing the primitive. On Devise the value is capability. The technical moat is Devise; the marketing wedge is Rails 8.
4. **Teams who want zero effort already have an answer: hosted auth** (Clerk/WorkOS sell session management as a feature). Our market is specifically the own-your-auth majority that the Rails 8 wave is actively growing — which is the right side of the trend, but it's a real boundary.

**What makes me land on "build it" despite all that:** the validation isn't vibes — Laravel and Phoenix ship this *by default*, OWASP ASVS makes it a literal L2 requirement, GitLab/Mastodon/Discourse each pay ongoing maintenance on hand-rolled versions, and authtrail proves people install adjacent tooling at scale while leaving the harder 70% of the feature unserved. And your economics are unusually favorable: **HostApp needs this regardless** (it currently has unrevocable 1-year native remember-me cookies and zero login history — a genuine security gap), so the incubation cost is sunk; gem-ifying is marginal cost on top.

If I had to bet: solid, durable, "obvious in retrospect" ecosystem gem with authtrail-or-better adoption — not a rocket. The two things that would most change the odds upward: RailsFast default inclusion, and nailing the 60-second zero-config demo on a fresh Rails 8 app. The one thing that would kill it: scope creep into auth itself.

---

## How do we win? How do we become better than the competition?

You don't beat authtrail head-on — you make its category obsolete. authtrail is a log table; ankane gems win by being tiny, frozen, and perfect, and you will not out-minimal ankane at his own game. The winning move is making "login activity log" a *feature inside* a category he structurally cannot follow you into. Here's the playbook, in order of how much each move actually matters:

**1. Win the Rails 8 cohort — the ground authtrail literally cannot stand on.** authtrail's first line is `require "warden"`; every omakase app is unreachable for it, and ankane's 1.0.0 was a freeze, not a foundation (zero features added, → research/06). Meanwhile every `rails new` since Nov 2024 starts on the generator, and the "what do I do after `rails g authentication`" content wave is cresting *right now*. Defaults in gem-land are set by what new-app tutorials reach for: be the answer in that cohort for 2026–2027 and you own the installed base of 2030. This is a timing window, not a permanent condition — ship while it's open.

**2. Be a strict superset with a one-command exit.** `rails g sessions:migrate_from_authtrail` — schema maps 1:1 by design, data preserved, delete the gem. The 5-years-from-now quote happens when the answer to "why would you even use authtrail?" is mechanical: *"sessions does everything it does, migrated my data in one command, and gave me the devices page, revocation, and Rails 8 support authtrail will never have."* Make switching cost zero and the comparison becomes unfair.

**3. Win the 60-second demo.** Fresh Rails 8 app → `bundle add sessions` → install → sign in from laptop + phone → devices page shows "Safari on iPhone 15 Pro · Madrid 🇪🇸 · Active now" → click **Log out** → the phone visibly dies. That GIF at the top of the README is the whole sales pitch. Nobody can GIF a log table. Device intelligence (the parsed names, the Hotwire Native awareness) isn't a feature here — it's what makes the demo *feel* like magic, and demos set defaults.

**4. Never, ever break login.** This gem sits on the auth hot path, and the failure mode that ends you permanently is one HN thread titled "sessions gem logged out all our users." Five-year defaults are built on "it never once hurt us" — that's how Sidekiq became infrastructure. Concretely: provable error-isolation in the test suite, an appraisal lane that tests against *vendored real generator output per Rails version* (so upstream drift breaks CI, not production), boring API stability, instant CVE response. Trust compounds slower than features and is worth more.

**5. Rig distribution — templates set defaults more than READMEs do.** RailsFast ships it default-on: every RailsFast app instantly has a devices page, which is both a showcase and a template selling point. Then pitch the others: Jumpstart Pro and Bullet Train are obvious targets — Chris Oliver has *already* done GoRails episodes extending the generated Session model, and SupeRails has hand-rolled this twice; these people have demonstrated demand and audiences. One GoRails episode titled "Device management in 5 minutes with the sessions gem" replaces the entire hand-roll tutorial corpus with you as the answer.

**6. Own the compliance search result.** When a SOC 2 questionnaire or pen-test report says "users must be able to view and revoke active sessions," the dev who googles it must land on you. That's literal demand — ASVS 3.3.4 is the requirement, and the search queries already exist ("rails list active sessions", "devise sign out all devices"). Write the canonical page for each; the gem is the punchline. Compliance-driven installs are the highest-intent, least price-sensitive adopters.

**7. Let data gravity do the retention.** After a year, `sessions_events` *is* the app's security history — ripping the gem out means losing the audit trail. Paradoxically, you get this stickiness by being maximally un-locked-in: plain ActiveRecord tables in their DB, readable schema, no SaaS callback. "Your data, your tables" lowers the adoption barrier *and* raises the exit cost. Then deepen it: future things hang off session rows (push tokens per device, fraud signals, your `moderate` gem consuming login events). The moment other tools build on your rows, you're infrastructure, not a feature.

**8. The new-device email is the viral surface.** Almost nobody visits a devices page; *everybody* reads "New sign-in from Chrome on Windows — was this you?" Every such email an app sends is invisible marketing that the app takes security seriously — and devs notice which gem powered it. This is why I'd revisit open question #4 and consider shipping the Google-grade email as a one-config-line default (even if via a goodmail/noticed recipe), not just a hook: it's the single feature end users ever see.

**How we lose, so we don't:** scope creep into authentication itself (the moment you're an auth framework, you're competing with Rails core and Devise instead of complementing both — that's rodauth's cautionary tale); shipping late and letting someone else catch the Rails 8 wave; one login-breaking incident; or ankane shipping a Rails 8 adapter first (low probability given his freeze pattern, but the mitigation is the same: speed + superset + migration path means even then you're ahead on everything except his name).

If I compress it to one sentence: **be the obvious answer in every fresh Rails 8 tutorial, be a free upgrade from authtrail, demo like magic, and never break login once — do those four for three consecutive years and the 2031 default is arithmetic.**

---

## Do we provide views? Do we provide an engine? How does this all work, exactly?

Both — it's a four-layer stack where each layer is optional and built on the one below. This is the synthesis of how your own gems already do it (chats = engine + ejection, moderate = primitives + BYOUI, api_keys = mounted dashboard, profitable = authenticated mount), picked per layer for this gem's reality: HostApp wants Spanish `setting_row` sections inside its existing settings page, LicenseSeat wants a page in its `settings` namespace — so one fixed page can't be the only offering (→ research/01 §5).

**Layer 0 — Model API, no UI at all.** Everything works headless: `user.sessions.active`, `session.device_name`, `session.revoke!`, `Sessions::Event` scopes. A host can build 100% custom UI in ~20 lines of their own controller. This layer is the contract; everything above is convenience.

**Layer 1 — Partials, renderable inside the host's own pages.** Rails automatically appends every engine's `app/views` to the host's view lookup path, so the gem ships partials that any host view can render directly with locals:

```erb
<%# inside HostApp's app/views/settings/show.html.erb, in its own <section> %>
<%= render "sessions/devices", user: current_user %>
<%= render "sessions/history", user: current_user, limit: 10 %>
```

No mount, no routes from us — the revoke buttons are `button_to`s pointing at engine routes *or* host-provided routes (configurable URL helper, so HostApp can route revocation through its own controller if it wants). This is the layer HostApp actually uses.

**Layer 2 — The mounted engine (the README headline).** A complete drop-in page for apps that just want it done:

```ruby
# Devise apps — wrap the mount, profitable-style:
authenticate :user do
  mount Sessions::Engine => "/settings/sessions"
end

# Rails 8 omakase apps — just mount it:
mount Sessions::Engine => "/settings/sessions"
```

Mechanics, exactly:

- `isolate_namespace Sessions`, with the chats `path: ""` trick inside the engine's routes (`root "devices#index"`, `resources :devices, path: "", only: :destroy`, `delete :others`, `get :history`) so the mount point *is* the page — `GET /settings/sessions`, `DELETE /settings/sessions/:id`, etc.
- The engine's `ApplicationController` inherits from `config.parent_controller` (default `"::ApplicationController"`, the Devise/api_keys/chats indirection, resolved lazily with an API-only fallback). This is the magic that makes auth free on *both* stacks: an omakase host's `ApplicationController` already has `before_action :require_authentication` from the generated concern, and a typical Devise host has `authenticate_user!` — inheriting gets you their layout, auth, locale, and flash handling without us knowing which stack we're on. The current-user lookup inside the engine uses the resolver chain (configured method → `current_user` → `Current.session&.user`).
- Scoping is enforced regardless of auth: every query goes through `resolved_user.sessions.find(...)` — you can never revoke a row you don't own, even if the host's mount is misconfigured.
- Zero JS shipped. The page is forms: `button_to` + `data: { turbo_confirm: }`. Semantic `sessions-*` classes + one tiny optional stylesheet so it looks decent unstyled in a Tailwind app (chats precedent). No Stimulus, no importmap pins to manage in v1.
- All copy via I18n (`sessions.devices.*`), `en` + `es` shipped; hosts override keys in their own locale files like any Rails app.

**Layer 3 — Ejection, exactly Devise/chats-style.** `rails g sessions:views` copies the engine's views into `app/views/sessions/` — and because application view paths take precedence over engine view paths, the copies shadow the gem's automatically. Edit freely; gem updates never touch them (the documented tradeoff, same as `devise:views`). Controllers stay ours and deliberately trivial — if you need custom controller behavior, you've graduated to Layer 0/1 rather than us supporting a controller-override matrix (Devise's `scoped_views`/custom-controllers surface is a maintenance tarpit we're explicitly not replicating).

**Admin is *not* a layer** — that stays primitives + recipes (moderate's posture): `Sessions::Event` scopes plus the `sessions:madmin` generator producing resource files modeled on HostApp's `audit_log_resource.rb`. No shipped admin UI; admin frameworks vary too much and madmin/Avo/Administrate all want to own that surface.

So the gem tree looks like: `app/views/sessions/` (partials + engine pages), `app/controllers/sessions/` (two small controllers), `config/routes.rb` (engine routes), `lib/sessions/models/` (Zeitwerk-wired models), `lib/generators/sessions/{install,views,madmin}`. The README leads with Layer 2 (the 60-second demo needs the mount), then immediately shows Layer 1 ("or render it inside your own settings page") — because that's the path both of your production apps will actually take.

---
