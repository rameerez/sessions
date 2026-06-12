# OAuth & modern login methods: tracking integration points

Research memo for the `sessions` gem — where a session/login-activity tracker can intercept each modern auth flow (OAuth via OmniAuth, Google One Tap, Sign in with Apple, passkeys, magic links/OTP) in both Rails 8 omakase and Devise apps, and what metadata exists at that moment.

- Date: 2026-06-11. All web sources accessed 2026-06-10/11 (dates inline). Code citations are `repo/path:line` against read-only clones in `/tmp/sessions-research/`:
  - `omniauth` @ `2ad2d0d` (2026-02-27, post-v2.1.4 master), `omniauth-rails_csrf_protection` @ `c4f53d7` (v2.0.1, 2025-12-11), `google_sign_in` @ `e7f2a9a` (v1.3.1, 2025-08-29), `omniauth-google-oauth2` @ `5559071` (v1.2.2, 2026-02-23), `webauthn-ruby` @ `ff4be43` (v3.4.3, 2026-01-15); plus pre-existing clones `devise` @ `372b295` (2026-06-10), `warden`, `rails` (main).

## Top findings

1. **OmniAuth is pure Rack and deliberately stops at the callback**: it only sets `env['omniauth.auth']` (the AuthHash) and lets the app create the session (`omniauth/lib/omniauth/strategy.rb:424-427`, README:100-103). So OAuth session creation **always happens in an app controller** — the same place our gem already hooks session creation. We just need to sniff `request.env['omniauth.auth']` at that moment to get `method: :oauth, provider: auth.provider`.
2. **Failed OAuth is a first-class, interceptable event**: every strategy failure funnels through `fail!`, which sets `env['omniauth.error']`, `env['omniauth.error.type']`, `env['omniauth.error.strategy']` and then calls the swappable `OmniAuth.config.on_failure` rack endpoint (`strategy.rb:542-554`). Wrapping `on_failure` (composing, not replacing) gives us provider + error type + origin + IP/UA for every failed OAuth attempt — including CSRF-blocked initiations (`strategy.rb:263-264`).
3. **Warden gives a clean discriminator in Devise apps**: password logins run `authenticate!` → `set_user(..., event: :authentication)` with `winning_strategy` set (`warden/lib/warden/proxy.rb:339`); OmniAuth logins go through Devise `sign_in` → `set_user` with default `event: :set_user` and **no** winning strategy (`devise/lib/devise/controllers/sign_in_out.rb:44`, `warden/lib/warden/proxy.rb:175`). One `after_set_user` hook + env sniffing classifies both.
4. **FedCM became mandatory for Google One Tap in August 2025** ("August 2025 Mandatory adoption of FedCM APIs by the Google Sign-in platform library… any `use_fedcm` settings are ignored" — https://developers.google.com/identity/sign-in/web/gsi-with-fedcm, accessed 2026-06-11) — even though Chrome **kept third-party cookies** (April 22, 2025 reversal; no choice prompt either: https://www.didomi.io/blog/google-chrome-third-party-cookies-april-2025, https://www.onetrust.com/blog/google-drops-plans-for-third-party-cookie-choice-prompt-in-chrome/, accessed 2026-06-10).
5. **One Tap hands the server a `select_by` field that says exactly HOW the user signed in** (`fedcm`, `fedcm_auto`, `btn`, `btn_confirm`, `user`, `auto`, `itp`…) alongside the `credential` JWT (https://developers.google.com/identity/gsi/web/reference/js-reference, accessed 2026-06-11). This is gold for our taxonomy — one endpoint, but we can record one-tap vs button vs auto-sign-in.
6. **Basecamp's `google_sign_in` is alive (v1.3.1, 2025-08-29) and immune to the FedCM/GIS-JS churn** — it's a pure server-side OAuth code flow (`google_sign_in/app/controllers/google_sign_in/authorizations_controller.rb:6-9`), not the GIS JS. But it does **not** do One Tap, and its ID-token validator dependency `google-id-token` last shipped **2017-09-11** (https://rubygems.org/gems/google-id-token, accessed 2026-06-11) — a real (if so-far-functional) liability.
7. **Apple's guideline 4.8 no longer literally mandates Sign in with Apple** — it requires "another login service" with privacy guarantees (data limited to name/email, email hiding, no ad tracking without consent) whenever third-party login sets up the primary account; SiwA is the canonical qualifier (https://developer.apple.com/app-store/review/guidelines/, accessed 2026-06-10). `omniauth-apple` shipped v1.4.0 on 2026-01-06 (https://rubygems.org/gems/omniauth-apple/versions, accessed 2026-06-10).
8. **Passkeys at login time yield flags + sign_count but NOT the AAGUID** — AAGUID arrives only at registration (attested credential data; `webauthn-ruby/lib/webauthn/authenticator_data.rb:94-100`). At authentication our gem can record `user_verified?`, `credential_backed_up?`, `sign_count`, credential id (`authenticator_data.rb:53-67`) and join to a registration-time AAGUID.
9. **The omakase passkey story is cedarcode's `webauthn-rails`** (v0.1.0 2025-09-26 … v0.1.2 2025-10-10), a generator **built on the Rails 8 auth generator** — its sign-in funnels into `start_new_session_for`, i.e. our existing hook (https://github.com/cedarcode/webauthn-rails, accessed 2026-06-10). Rails core auth generator still has no passkey/magic-link/OAuth support.
10. **No flow self-identifies at the `Session#create` row level** — the inevitable conclusion is a two-layer design: automatic inference (omniauth env, warden strategy class) + an explicit annotate API (`Sessions.tag(request, method: :passkey)`) for One Tap, passkeys, magic links, OTP.

## 1. OmniAuth 2.x mechanics

### 1.1 Request phase: POST-only + CSRF (why)

- Default config: `allowed_request_methods => %i[post]` and `request_validation_phase => OmniAuth::AuthenticityTokenProtection` (`omniauth/lib/omniauth.rb:51`, `:43`). GET on `/auth/:provider` is dead by default; re-enabling it logs a loud warning citing **CVE-2015-9284** (login CSRF: attacker silently links *their* OAuth account to the victim's app session) (`omniauth/lib/omniauth/strategy.rb:205-223`).
- The request phase (`request_call`) stores `session['omniauth.params'] = request.GET`, runs the validation phase, then captures **origin**: `request.params[origin_param]` or `HTTP_REFERER` into `session['omniauth.origin']` (`strategy.rb:233-259`, origin at `:252-256`). CSRF failures raise `OmniAuth::AuthenticityError` → `fail!(:authenticity_error)` (`strategy.rb:263-264`) — i.e. even pre-redirect failures flow through the failure pipeline our gem can observe.
- `omniauth-rails_csrf_protection` exists because the built-in `AuthenticityTokenProtection` (rack-protection) doesn't understand Rails' masked/per-form tokens. Its `TokenVerifier` literally includes `ActionController::RequestForgeryProtection`, delegates config to `ActionController::Base`, and raises `ActionController::InvalidAuthenticityToken` unless `verified_request?` (`omniauth-rails_csrf_protection/lib/omniauth/rails_csrf_protection/token_verifier.rb:19-64`; Rails 8.1 config shim at `:20-34`). A railtie installs it as the global `request_validation_phase` (`lib/omniauth/rails_csrf_protection/railtie.rb:7-9`). README: "provides a mitigation against CVE-2015-9284 … by implementing a CSRF token verifier that directly uses `ActionController::RequestForgeryProtection`" (`README.md:3-6`). Practical consequence for apps: OAuth links must be `button_to`/POST forms (`README.md` Usage).

### 1.2 Callback phase: what exists at session-creation time

`callback_call` restores `env['omniauth.origin']` and `env['omniauth.params']` from the session, runs the `before_callback_phase` hook, then the strategy's `callback_phase` sets the AuthHash and passes the request down to the app (`strategy.rb:268-276`, `:424-427`):

```ruby
def callback_phase
  env['omniauth.auth'] = auth_hash   # strategy.rb:425
  call_app!
end
```

AuthHash construction (`strategy.rb:398-406`): `AuthHash.new(provider: name, uid: uid)` + `info`, `credentials`, `extra`. Validity requires `uid && provider && info` (`omniauth/lib/omniauth/auth_hash.rb:18-20`). Shape, with `omniauth-google-oauth2` as the concrete example (`omniauth-google-oauth2/lib/omniauth/strategies/google_oauth2.rb:45-86`):

| Key | Contents | Tracking value |
|---|---|---|
| `provider` | strategy name, e.g. `"google_oauth2"` | → our `provider` column |
| `uid` | stable provider user id (`raw_info['sub']`, `:45`) | identity linking |
| `info` | `name`, `email` (verified only), `unverified_email`, `email_verified`, `first_name`, `last_name`, `image` (`:47-60`) | display + email-verified signal |
| `credentials` | token, refresh_token, expires_at (from OAuth2 base) + granted `scope` (`:62-65`) | scope auditing; do NOT store tokens |
| `extra` | `id_token`, claim-verified `id_info` (iss/aud/exp checked, `:71-83`), `raw_info` | `id_info` has `hd` (workspace domain), `auth_time`-ish claims |

Also at callback time: `env['omniauth.origin']` (page that initiated login — record it), `env['omniauth.params']`, `env['omniauth.strategy']` (`strategy.rb:187`). Docs: README:93-98 ("The `omniauth.auth` key … provides an Authentication Hash").

### 1.3 Failure endpoint: failed OAuth is fully interceptable

`fail!` (`strategy.rb:542-554`):

```ruby
env['omniauth.error']          = exception
env['omniauth.error.type']     = message_key.to_sym   # :invalid_credentials, :access_denied, :csrf_detected…
env['omniauth.error.strategy'] = self                  # strategy instance → .name = provider
OmniAuth.config.on_failure.call(env)
```

Default `on_failure` is `OmniAuth::FailureEndpoint` (`omniauth/lib/omniauth.rb:41`): raises in development (`failure_endpoint.rb:20`, envs list `omniauth.rb:42`), otherwise 302-redirects to `/auth/failure?message=<type>&origin=<origin>&strategy=<name>` (`failure_endpoint.rb:28-33`). **Devise replaces it** at require time with a proc that dispatches to the mapped `OmniauthCallbacksController.action(:failure)` (`devise/lib/devise/omniauth.rb:15-20`); that action reads `omniauth.error` / `error.type` / `error.strategy` and extracts `error_reason`/`error` off the exception (`devise/app/controllers/devise/omniauth_callbacks_controller.rb:17-27`). Interception options for us, best first:

1. Wrap `OmniAuth.config.on_failure` in our railtie *after* Devise/app initializers (compose: record, then call original). Captures: error type symbol, provider, `omniauth.origin`, IP/UA, timestamp. No user identity (auth hash usually absent on failure).
2. Rack middleware watching responses on `/auth/failure` (works even if apps swap `on_failure` later, but misses `failure_raise_out_environments`).

## 2. Canonical Rails integration

### 2.1 Without Devise (omakase apps) — README pattern, quoted

`omniauth/README.md:113-160` ("Rails (without Devise)") — Gemfile `omniauth` + `omniauth-rails_csrf_protection` (`:118-119`); middleware `Rails.application.config.middleware.use OmniAuth::Builder do … end` (`:126-128`); then:

```ruby
# config/routes.rb                       README.md:137-138
get 'auth/:provider/callback', to: 'sessions#create'
get '/login', to: 'sessions#new'

# app/controllers/sessions_controller.rb  README.md:143-152
class SessionsController < ApplicationController
  def create
    user_info = request.env['omniauth.auth']
    raise user_info # Your own session management should be placed here.
  end
end
```

…with a POST login form `form_tag('/auth/developer', method: 'post', data: {turbo: false})` (`README.md:157-159`). So the omakase recipe is: **OAuth callback lands in the same `SessionsController#create`-style action that calls Rails 8's `start_new_session_for`** (`rails/railties/lib/rails/generators/rails/authentication/templates/app/controllers/concerns/authentication.rb.tt:41-46` — `user.sessions.create!(user_agent:, ip_address:)` + `Current.session` + signed permanent cookie; password path at `templates/app/controllers/sessions_controller.rb.tt:8-15` via `User.authenticate_by`). Note the callback route is `get` — fine, because CSRF protection applies to the *request* phase, and the callback carries provider `state`.

### 2.2 With Devise (omniauthable)

- Model `devise :omniauthable, omniauth_providers: [:google_oauth2]`; routes auto-generate `user_google_oauth2_omniauth_authorize_path` (POST) and callback routed to the app's `Users::OmniauthCallbacksController` (Devise README "OmniAuth" section; URL helpers at `devise/lib/devise/omniauth/url_helpers.rb:6-13`).
- The app implements an action **named after the provider** which reads `request.env["omniauth.auth"]`, finds/creates the user, and calls `sign_in_and_redirect @user` → `sign_in` → `warden.set_user(resource, scope:)` (`devise/lib/devise/controllers/sign_in_out.rb:33-46`). Default warden event is `:set_user` (`warden/lib/warden/proxy.rb:175`), **not** `:authentication` — so naive `Warden::Manager.after_authentication` hooks miss OAuth logins; hook `after_set_user` instead and exclude `:fetch` (`warden/lib/warden/hooks.rb:53-59`).
- Failures: Devise's `failure` action (see §1.3). The base `Devise::OmniauthCallbacksController` also defines `passthru` (404) (`devise/app/controllers/devise/omniauth_callbacks_controller.rb:6-8`).

## 3. `google_sign_in` (Basecamp): state & viability

- What it is: a Rails engine doing the **server-side OAuth 2 auth-code flow** against Google, no GIS JavaScript at all. Routes: `resource :authorization, only: :create; resource :callback, only: :show` under `/google_sign_in` (`google_sign_in/config/routes.rb:1-4`). Button helper renders a plain POST form with hidden `proceed_to` (`app/helpers/google_sign_in/button_helper.rb:2-6`). `AuthorizationsController#create` redirects to Google's auth URL with `scope: 'openid profile email'` + random `state` stashed in flash (`app/controllers/google_sign_in/authorizations_controller.rb:6-18`).
- **Flash handoff**: the callback exchanges the code for an **id_token only** and redirects to `proceed_to` with `flash[:google_sign_in] = { id_token: }` or `{ error: }` (`app/controllers/google_sign_in/callbacks_controller.rb:4-25`, token exchange `:31-33`, state check `:27-29`). Your controller then builds `GoogleSignIn::Identity.new(flash[:google_sign_in]["id_token"])` exposing `user_id` (sub), `name`, `email_address`, `email_verified?`, `avatar_url`, `hosted_domain`… (`lib/google_sign_in/identity.rb:15-49`), validated via the `google-id-token` gem's `GoogleIDToken::Validator` (`identity.rb:1,8,61-62`).
- Maintenance: last release v1.3.1, last commit 2025-08-29 (clone `git log`); deps `rails >= 6.1`, `google-id-token >= 1.4.0`, `oauth2 >= 1.4.0` (gemspec). **Viability**: works with current Google Identity Services because the deprecations hit the old `gapi`/GIS *JavaScript* libraries and One Tap rendering — the OAuth2 web-server flow it uses is untouched. Caveats: (a) no One Tap/FedCM support and README never mentions GIS (grep confirms), (b) `google-id-token` is dormant since 2017-09-11 though still functional at 11.3M downloads (https://rubygems.org/gems/google-id-token, accessed 2026-06-11). For tracking: the session is created in the app's `proceed_to` action — `flash[:google_sign_in]` present at session-creation time is our detection signal (method `oauth`/`google`, or its own tag).

## 4. Google Identity Services, One Tap & FedCM (mid-2026)

- **One Tap is alive and FedCM-backed.** Timeline (https://developers.googleblog.com/federated-credential-management-fedcm-migration-for-google-identity-services/, published 2024-02-13, accessed 2026-06-10): phased FedCM migration from April 2024; "GIS begins migrating all One Tap traffic to FedCM" October 2024; opt-out exemption expired February 2025. The hard cutover: "**August 2025 Mandatory adoption** of FedCM APIs by the Google Sign-in platform library… After the transition period, FedCM APIs are mandatory for all web apps using the Google Sign-In library. … any `use_fedcm` settings are ignored" (https://developers.google.com/identity/sign-in/web/gsi-with-fedcm, accessed 2026-06-11).
- **Third-party cookie saga ended in anticlimax**: 2024-07 Google pivoted from deprecation to a "user choice" prompt; 2025-04-22 it cancelled even the prompt — third-party cookies stay, Privacy Sandbox refocused (https://www.didomi.io/blog/google-chrome-third-party-cookies-april-2025; https://www.onetrust.com/blog/google-drops-plans-for-third-party-cookie-choice-prompt-in-chrome/, both accessed 2026-06-10). FedCM went mandatory for GIS anyway — implementer impact: `prompt()` display-moment callbacks removed, custom One Tap positioning unsupported, cross-origin iframes need `allow="identity-credentials-get"` (https://developers.google.com/identity/gsi/web/guides/fedcm-migration, accessed 2026-06-10).
- **What a Rails app needs for One Tap in 2026** (verified pattern: https://blog.superails.com/google-onetap-oauth (Rails 8 + Devise); https://www.t27duck.com/posts/10-integrating-google-one-tap-in-a-rails-application; both accessed 2026-06-10):
  1. Load `https://accounts.google.com/gsi/client`, configure `g_id_onload` with `client_id` + `login_uri` (or JS callback).
  2. Google POSTs to your endpoint: `credential` (JWT id_token), `g_csrf_token` (double-submit: must equal the `g_csrf_token` cookie — t27duck, above), and **`select_by`** (https://developers.google.com/identity/gsi/web/reference/js-reference, accessed 2026-06-11 — values incl. `auto`, `user`, `user_1tap`, `user_2tap`, `btn`, `btn_confirm`, `itp`, `fedcm`, `fedcm_auto`).
  3. Server-side verification: `googleauth` gem — `Google::Auth::IDTokens.verify_oidc(params[:credential], aud: ENV["GOOGLE_CLIENT_ID"])` (module docs: https://docs.cloud.google.com/ruby/docs/reference/googleauth/latest/Google-Auth-IDTokens, accessed 2026-06-10). `google-id-token`'s validator also works but is dormant (2017) — recommend `googleauth` in our docs.
  4. Skip Rails CSRF for that endpoint (cross-site POST), verify `g_csrf_token` manually, then create the session yourself — **no gem mediates this flow**; `google_sign_in` (Basecamp) does not cover it.
- There is no OmniAuth strategy involvement in One Tap; an app *may* hand the verified payload to a Devise-omniauthable user model, but the rack env carries no `omniauth.*` keys. → explicit tagging required.

## 5. Sign in with Apple

- **Guideline 4.8 "Login Services", current text** (https://developer.apple.com/app-store/review/guidelines/, accessed 2026-06-10): "Apps that use a third-party or social login service (such as Facebook Login, Google Sign-In, Log in with X, Sign In with LinkedIn, Login with Amazon, or WeChat Login) to set up or authenticate the user's primary account with the app must also offer as an equivalent option another login service with the following features: the login service limits data collection to the user's name and email address; the login service allows users to keep their email address private as part of setting up their account; and the login service does not collect interactions with your app for advertising purposes without consent." Exceptions: own-account-only apps, alternative app marketplaces, education/enterprise accounts, government/industry eID, and clients for a specific third-party service. (Marked "ASR & NR" — applies to App Store Review & Notarization.) Net: SiwA itself is no longer the only compliance path, but remains the de-facto one — any SaaS with an iOS app shipping Google login effectively ships Apple login too, so our gem must treat `apple` as a first-class provider.
- **omniauth-apple**: v1.4.0 released 2026-01-06 after a 3-year gap since 1.3.0 (2023-01-17) — maintained but slow (https://rubygems.org/gems/omniauth-apple/versions, accessed 2026-06-10; repo https://github.com/nhosoya/omniauth-apple).
- Practical Rails notes: standard OmniAuth strategy (so §1/§2 interception applies verbatim: AuthHash `provider: "apple"`). Apple-specific quirks to document (well-known; not re-verified in this pass — verify against the omniauth-apple README when writing gem docs): callback uses `response_mode=form_post` (cross-site POST → cookie `SameSite=Lax` issues with session/state), user's name+email are delivered **only on first authorization**, and email may be a private relay address — i.e. `info.email` can be relay, `extra` carries the decoded id_token.

## 6. Passkeys / WebAuthn in Rails (2026)

### 6.1 webauthn-ruby API at a glance

- **Registration**: `WebAuthn::Credential.options_for_create(user:, exclude:)` → stash `options.challenge` in session → browser `navigator.credentials.create` → `WebAuthn::Credential.from_create(params)` → `verify(session[:creation_challenge])` → persist `webauthn_id`, `public_key`, `sign_count` (`webauthn-ruby/README.md:171-218`).
- **Authentication**: `options_for_get(allow:)` → challenge in session → `navigator.credentials.get` → `from_get(params)` → look up stored credential by id → `verify(challenge, public_key:, sign_count:)`; raises `WebAuthn::SignCountVerificationError` on counter regression, `WebAuthn::Error` subclasses otherwise (`README.md:224-277`).
- **Metadata a passkey login yields** (authenticator data flags: `webauthn-ruby/lib/webauthn/authenticator_data.rb:19-28`, accessors `:53-67`): `user_verified?` (UV — biometric/PIN vs mere presence), `user_present?`, `credential_backup_eligible?` + `credential_backed_up?` (BE/BS — synced iCloud/Google passkey vs device-bound), `sign_count` (`:29`), credential id. **AAGUID** (authenticator model, e.g. iCloud Keychain vs 1Password) is only present when attested credential data is included — i.e. at **registration**, via `attestation_object` delegation (`lib/webauthn/attestation_object.rb:44`, `lib/webauthn/authenticator_attestation_response.rb:58`, zeroed-AAGUID guard `authenticator_data.rb:94-100`). → Our gem should record AAGUID on the *credential* at registration and join at login; per-login we record UV/BS flags + sign_count + credential id.

### 6.2 Ecosystem reality

- `webauthn-ruby` v3.4.3 (2026-01-15 clone log) is the foundation everything builds on.
- **Omakase**: `webauthn-rails` (cedarcode) — generator on top of the Rails 8 auth generator (`--with-rails-authentication`), Stimulus controller, passkey-first or 2FA routes (`/passkeys/new`, sign-in integrated into `/session/new`); v0.1.0 2025-09-26, v0.1.2 2025-10-10 (https://github.com/cedarcode/webauthn-rails; https://medium.com/cedarcode/passkey-authentication-in-rails-8-with-webauthn-rails-c58333abae26, accessed 2026-06-10). Because it modifies the generated `SessionsController` and reuses `start_new_session_for`, **our session-creation hook fires automatically** — only the method label needs tagging.
- **Rodauth**: first-class `webauthn` features (passwordless login + MFA) on webauthn-ruby (https://janko.io/passkey-authentication-with-rodauth/, accessed 2026-06-10).
- **Devise**: still no built-in passkeys (https://github.com/heartcombo/devise/issues/5527, accessed 2026-06-10); `devise-passkeys` (https://github.com/ruby-passkeys/devise-passkeys) exists but requires customizing controllers/views; maintenance cadence not verified — check before recommending.
- **Rails core**: no passkey support in the auth generator; nothing concrete in rails/rails beyond the original generator issue (#50446). Community pressure is visible (Rails World 2025 talk "Passkeys Have Problems, but So Will You If You Ignore Them", https://rubyonrails.org/world/2025/day-2/jason-meller, accessed 2026-06-10). Claims of core adoption: **unverified/none found**.
- `authentication-zero --passkeys`: not verified this pass — flag existence should be checked before citing in docs.

## 7. Magic links & email OTP

- **passwordless** (mikker, https://github.com/mikker/passwordless, accessed 2026-06-10): standalone session-based magic links; creates its own `Passwordless::Session` records and `sign_in` helper — i.e. session creation in *its* controllers; integration via our annotate API or a documented override.
- **devise-passwordless** (https://github.com/devise-passwordless/devise-passwordless, updated as recently as 2025-05-20 per search results, accessed 2026-06-10): adds `:magic_link_authenticatable` **as a Warden strategy** — so in Devise apps the login runs through `warden.authenticate!` and `warden.winning_strategy` is the magic-link strategy class. Our Warden hook can label `method: :magic_link` with zero app code. Tokens are stateless; Rails filters `:token` from logs by default.
- Rails 8 omakase: no generator support; the common tutorial pattern (e.g. https://avohq.io/blog/magic-link-authentication-with-rails, accessed 2026-06-10) is a signed/`generates_token_for` token in email → dedicated controller → `start_new_session_for user` — again our hook fires; method needs tagging. Email/SMS OTP: no dominant gem (devise-otp/rotp exist for TOTP 2FA, distinct from login OTP); treat `otp` as a method label apps set explicitly.

## 8. Ecosystem health snapshot (mid-2026)

| Gem | Latest | Date | Signal |
|---|---|---|---|
| omniauth | 2.1.4 | 2025-10-01 (https://rubygems.org/gems/omniauth, accessed 2026-06-11) | Healthy; master prepping Ruby 4 (clone `2ad2d0d`, 2026-02-27) |
| omniauth-rails_csrf_protection | 2.0.1 | 2025-12-11 (clone tag/log) | Healthy; Rails 8.1-ready (`token_verifier.rb:20-34`) |
| omniauth-google-oauth2 | 1.2.2 | 2026-02-24 (https://rubygems.org/gems/omniauth-google-oauth2, accessed 2026-06-11) | Healthy |
| omniauth-apple | 1.4.0 | 2026-01-06 (rubygems, accessed 2026-06-10) | Maintained, slow cadence |
| omniauth-github | 2.0.1 | 2022-09-23 (https://rubygems.org/gems/omniauth-github, accessed 2026-06-11) | Dormant but stable/ubiquitous |
| google_sign_in | 1.3.1 | 2025-08-29 (clone log) | Maintained by 37signals; no One Tap |
| google-id-token | 1.4.2 | 2017-09-11 (rubygems, accessed 2026-06-11) | Dormant — prefer `googleauth` |
| webauthn-ruby | 3.4.3 | 2026-01-15 (clone log) | Healthy (cedarcode) |
| webauthn-rails | 0.1.2 | 2025-10-10 (rubygems via search, accessed 2026-06-10) | New, active, omakase-native |

## Implications for the sessions gem

### (a) Recommended taxonomy (grounded in what each flow exposes)

Two columns + one JSON blob on the session/login-event record:

- **`auth_method`** (string enum): `password`, `oauth`, `google_one_tap`, `passkey`, `magic_link`, `otp`, `sso` (SAML/OIDC enterprise), `token` (API/PAT), `unknown`. Apple is **not** a method — web Sign in with Apple arrives as `oauth` + `provider: "apple"` via omniauth-apple (§5); reserving method values for transport-distinct flows keeps the enum stable. One Tap *is* a distinct method: different endpoint, different artifact (GIS JWT POST, no OAuth dance), and its own sub-detail.
- **`auth_provider`** (nullable string): omniauth strategy name normalized (`google_oauth2` → `google`), `apple`, `github`, IdP entity for `sso`, `nil` for `password`/`passkey`/`magic_link`.
- **`auth_detail`** (jsonb): per-method extras actually available at session creation:
  - oauth: `{ origin:, scopes:, email_verified:, hd: }` (from `omniauth.origin` + AuthHash credentials/extra, §1.2)
  - google_one_tap: `{ select_by: }` (§4 — distinguishes `fedcm_auto` auto-sign-in from `btn` clicks)
  - passkey: `{ credential_id:, user_verified:, backed_up:, sign_count: }`; AAGUID lives on the credential record from registration (§6.1)
  - magic_link/otp: `{ delivery: "email" }`; token ids if app provides.

### (b) Interception matrix — where we see "session created via X"

| Flow | Omakase (Rails 8 auth gen) | Devise |
|---|---|---|
| Password | Hook `start_new_session_for` (prepend on `Authentication` concern, `authentication.rb.tt:41-46`) or AR `after_create` on app's `Session`. Default label `password` when no other signal present | Warden `after_set_user` (excluding `:fetch`): event `:authentication` + `winning_strategy` = `DatabaseAuthenticatable` (`warden/proxy.rb:339`) |
| OAuth (any omniauth provider, incl. Apple) | Same `start_new_session_for` hook; classify because `request.env['omniauth.auth']` is present → `oauth` + `auth.provider` + `omniauth.origin` (§1.2, §2.1) | Warden `after_set_user` with event `:set_user`, `winning_strategy` nil, `env['omniauth.auth']` present (§2.2) |
| google_sign_in gem | Session created in app's `proceed_to` action; detect `flash[:google_sign_in]` present → `oauth`/`google` (§3) | same (gem is Devise-agnostic) |
| Google One Tap | App-written controller verifying `params[:credential]`; **no automatic signal** → `Sessions.tag(request, method: :google_one_tap, detail: { select_by: params[:select_by] })` before/around session creation (§4) | same — tag inside the One Tap action even when it then calls `sign_in` |
| Passkey | webauthn-rails funnels into `start_new_session_for`; controller-class heuristic possible but brittle → annotate API (or first-party webauthn-rails integration) | devise-passkeys: warden strategy class detectable; vanilla webauthn-ruby: annotate API |
| Magic link | Tutorial pattern hits `start_new_session_for` → annotate API | devise-passwordless: `winning_strategy` = `MagicLinkAuthenticatable` → automatic (§7) |
| OTP / SSO / token | annotate API | annotate API (or strategy-class mapping table, kept extensible) |

Design: one **classification pipeline** at session-creation time — (1) explicit `Sessions.tag(request, ...)` (stored in `request.env['sessions.auth_method']`) wins; (2) `env['omniauth.auth']` → oauth+provider; (3) warden `winning_strategy` class → mapping table (database_authenticatable→password, magic_link→magic_link, …); (4) `flash[:google_sign_in]` → oauth/google; (5) fallback `password` in the generator's `SessionsController#create`, else `unknown`.

### (c) Failed attempts: what's realistically capturable

- **OAuth — good coverage.** Wrap `OmniAuth.config.on_failure` (compose with the existing endpoint — Devise's proc at `devise/lib/devise/omniauth.rb:15-20`, default `FailureEndpoint` otherwise; install in a late-running initializer). Capturable: `env['omniauth.error.type']` (e.g. `:invalid_credentials`, `:access_denied` = user hit Cancel at provider, `:authenticity_error` = CSRF), provider via `env['omniauth.error.strategy'].name`, `env['omniauth.origin']`, IP/UA. **Not** capturable: which local user (no uid in most failures), and nothing if the user abandons at the provider without redirecting back.
- **Passkey — only via app cooperation.** Failures surface as `WebAuthn::Error` rescues in app code (`webauthn-ruby/README.md:215-217, :271-277`); offer `Sessions.record_failed_attempt(request, method: :passkey, error: e.class.name)`; credential id from `params` can sometimes identify the targeted user. `SignCountVerificationError` is a possible-cloning signal worth flagging distinctly.
- **One Tap** — verification raises (e.g. `Google::Auth::IDTokens::SignatureError`/`AudienceMismatchError`, googleauth docs §4); plus `g_csrf_token` mismatches. Same explicit-record API.
- **Password** — Devise: warden failure app hook (covered in Devise/Warden memo); omakase: the `else` branch of `SessionsController#create` has no hook — document the explicit API, optionally offer a `User.authenticate_by` wrapper.

### (d) Posture

Ship: (1) session-creation hook + classification pipeline (zero-config for password/OAuth/devise-passwordless), (2) `Sessions.tag` / `record_failed_attempt` public API for One Tap/passkeys/magic links/OTP, (3) an `on_failure` composer for OAuth failures, (4) generator-time integrations ("if webauthn-rails detected, inject tag into its controllers"). Store `auth_method`+`auth_provider` as indexed columns — "show me all sessions started via Google" and "alert on first passkey login from new device" are the queries this product exists for.
