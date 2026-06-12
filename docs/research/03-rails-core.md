# Rails 8.1+ native authentication: exact internals

Research date: 2026-06-11. Sources: two shallow clones, dissected file-by-file.

- **[S]** = released stable, tag `v8.1.3` (`RAILS_VERSION` = `8.1.3`, released 2026-03-24) at `/tmp/sessions-research/rails-stable`
- **[M]** = `main` (`RAILS_VERSION` = `8.2.0.alpha`) at `/tmp/sessions-research/rails`
- Latest 8.1.x tags from `git ls-remote`: v8.1.0 (2025-10-22) → v8.1.1 → v8.1.2 → v8.1.2.1 → v8.1.3. 8.0 series ends at v8.0.5. **Next version after 8.1 is 8.2** (not 9.0).

All paths repo-relative. Generator paths shortened: `GEN` = `railties/lib/rails/generators`.

## Top findings

1. **Auth rides a signed *permanent* cookie holding the Session row's DB id** — `cookies.signed.permanent[:session_id]`, 20-year expiry, `httponly: true`, `same_site: :lax` — NOT the Rack session. Every request does `Session.find_by(id: cookies.signed[:session_id])`. **Destroying the row is instant remote revocation** on next request.
2. **The generated code NEVER updates a Session row after creation.** No `touch`, no last-active, nothing. `updated_at` stays equal to `created_at` forever. Verified by grep across every template ([S] exit 1) and by reading the full `resume_session` flow.
3. **`ip_address` + `user_agent` are captured exactly once** — at login, inside `start_new_session_for` ([S] `GEN/rails/authentication/templates/app/controllers/concerns/authentication.rb.tt:42`). Never refreshed, never parsed.
4. **The gap is total**: no failed-login logging, no session listing UI (`resource :session` is *singular* — no index route), no device parsing, no multi-session management beyond "destroy all on password reset", no expiry/sweep job, no `reset_session` call anywhere. The official security guide *recommends* an `updated_at`-based `Session.sweep` (security.md:428-434 [S]) **that the generated code can never satisfy because it never touches `updated_at`** — Rails' own docs point at the hole our gem fills.
5. The **Authentication concern is byte-identical across 8.0.5 → 8.1.3 → main** (verified via `git diff v8.0.5 v8.1.3` and stable↔main diff: empty for concern + models). It is an extremely stable instrumentation target. 8.1's only behavioral additions: password reset now calls `@user.sessions.destroy_all`, and `PasswordsController#create` gained `rate_limit`.
6. `Session` is a **2-line plain ActiveRecord model** (`belongs_to :user`). `start_new_session_for` uses `create!`, `terminate_session` uses `destroy`, reset uses `destroy_all` (instantiates + runs callbacks) → **model callbacks observe 100% of the generated lifecycle with zero app-code patching**.

## 1. The authentication generator ([S] unless noted)

### 1.1 Generator class — `GEN/rails/authentication/authentication_generator.rb`

- `class_option :api` (:10-11): "Generate API-only controllers and models, with no view templates". Its *only* effect is skipping the template-engine hook (:13-15): `hook_for :template_engine, as: :authentication do |template_engine| invoke template_engine unless options.api? end`. Same concern/controllers/models either way.
- Files created (:17-34): models session/user/current; sessions_controller, concerns/authentication, passwords_controller; `app/channels/application_cable/connection.rb` if ActionCable; mailer + 2 mailer views if ActionMailer.
- Injects into app (:36-38): `inject_into_class "app/controllers/application_controller.rb", "ApplicationController", "  include Authentication\n"`.
- Routes (:40-43): `route "resources :passwords, param: :token"` and `route "resource :session"` — **singular resource: new/create/destroy only by convention, no index/show listing**. [M] :42-45 tightens to `resource :session, only: [:new, :create, :destroy]` and `resources :passwords, param: :token, only: [:new, :create, :edit, :update]`.
- Gemfile (:45-52): uncomments or `bundle add bcrypt`.
- Migrations (:54-57):
  ```ruby
  generate "migration", "CreateUsers", "email_address:string!:uniq password_digest:string!", "--force"
  generate "migration", "CreateSessions", "user:references ip_address:string user_agent:string", "--force"
  ```
- `hook_for :test_framework` (:59) → test_unit sub-generator (rspec prints `[not found]`, `railties/test/generators/authentication_generator_test.rb:124-128`).
- [M] additions: `@user_model_exists` guard skips `CreateUsers` migration when `app/models/user.rb` already exists ([M] :18, :55-59; CHANGELOG [M] `railties/CHANGELOG.md:31`).

### 1.2 The Authentication concern — ENTIRE file, `GEN/rails/authentication/templates/app/controllers/concerns/authentication.rb.tt` (identical [S]:1-52 / [M], no ERB conditionals)

```ruby
module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :require_authentication
    helper_method :authenticated?
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :require_authentication, **options
    end
  end

  private
    def authenticated?
      resume_session
    end

    def require_authentication
      resume_session || request_authentication
    end

    def resume_session
      Current.session ||= find_session_by_cookie
    end

    def find_session_by_cookie
      Session.find_by(id: cookies.signed[:session_id]) if cookies.signed[:session_id]
    end

    def request_authentication
      session[:return_to_after_authenticating] = request.url
      redirect_to new_session_path
    end

    def after_authentication_url
      session.delete(:return_to_after_authenticating) || root_url
    end

    def start_new_session_for(user)
      user.sessions.create!(user_agent: request.user_agent, ip_address: request.remote_ip).tap do |session|
        Current.session = session
        cookies.signed.permanent[:session_id] = { value: session.id, httponly: true, same_site: :lax }
      end
    end

    def terminate_session
      Current.session.destroy
      cookies.delete(:session_id)
    end
end
```

Notes: the Rack `session` is used *only* for `return_to_after_authenticating` (:33, :38). API quirk: `helper_method` (:6) is defined by `AbstractController::Helpers` (`actionpack/lib/abstract_controller/helpers.rb:128`), included in `ActionController::Base` (`actionpack/lib/action_controller/base.rb:235`) but **absent from `ActionController::API`'s MODULES** (`actionpack/lib/action_controller/api.rb:116-147`) — API-only apps must delete/guard that line themselves; `--api` doesn't.

### 1.3 SessionsController — `GEN/.../templates/app/controllers/sessions_controller.rb.tt` ([S]:1-21, full)

```ruby
class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_session_path, alert: "Try again later." }

  def new
  end

  def create
    if user = User.authenticate_by(params.permit(:email_address, :password))
      start_new_session_for user
      redirect_to after_authentication_url
    else
      redirect_to new_session_path, alert: "Try another email address or password."
    end
  end

  def destroy
    terminate_session
    redirect_to new_session_path, status: :see_other
  end
end
```

Failed login = redirect + flash, nothing recorded (:12-14).

### 1.4 PasswordsController — `GEN/.../templates/app/controllers/passwords_controller.rb.tt` ([S]:1-39)

- `allow_unauthenticated_access` (:2); `before_action :set_user_by_token, only: %i[ edit update ]` (:3).
- `rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_password_path, alert: "Try again later." }` (:5, wrapped in `<%- if defined?(ActionMailer::Railtie) -%>`).
- `create` (:12-18): `User.find_by(email_address:)` → `PasswordsMailer.reset(user).deliver_later`; always redirects with "Password reset instructions sent (if user with that email address exists)." (enumeration-safe).
- `update` (:24-31): on success **`@user.sessions.destroy_all`** (:26 — global revocation, new in 8.1) then redirect.
- `set_user_by_token` (:34-38): `User.find_by_password_reset_token!(params[:token])` rescuing `ActiveSupport::MessageVerifier::InvalidSignature`.

### 1.5 Models ([S], all identical on [M])

- `session.rb.tt`: `class Session < ApplicationRecord` + `belongs_to :user`. That's the whole file (3 lines).
- `user.rb.tt`: `has_secure_password`; `has_many :sessions, dependent: :destroy`; `normalizes :email_address, with: ->(e) { e.strip.downcase }`.
- `current.rb.tt`: `class Current < ActiveSupport::CurrentAttributes` / `attribute :session` / `delegate :user, to: :session, allow_nil: true` → `Current.user` works everywhere per-request.

### 1.6 Migrations → exact schema

Via the migration generator commands (§1.1): `string!` ⇒ `null: false` (`GEN/generated_attribute.rb:103-108` [S]); `references` ⇒ `null: false` + FK because `belongs_to_required_by_default` (`GEN/generated_attribute.rb:192-193`). Result:

- **users**: `email_address:string NOT NULL` + unique index, `password_digest:string NOT NULL`, timestamps.
- **sessions**: `user_id` (references, NOT NULL, FK, indexed), `ip_address:string` (nullable, plain string — not inet), `user_agent:string` (nullable, raw — `varchar(255)` on MySQL; long UAs can overflow there), `created_at`/`updated_at`.

### 1.7 Views, mailer, ActionCable

- Views come from a hidden sub-generator `GEN/erb/authentication/authentication_generator.rb` (:11-15): exactly three — `sessions/new`, `passwords/new`, `passwords/edit`. `sessions/new.html.erb` is a bare `form_with url: session_path` with `email_field` (`autocomplete: "username"`) + `password_field` (`autocomplete: "current-password"`, `maxlength: 72`). No layout/UI framework. **No "your devices"/session list view exists.**
- `passwords_mailer.rb.tt`: `mail subject: "Reset your password", to: user.email_address`; view links `edit_password_url(@user.password_reset_token)`, "within the next 15 minutes".
- `application_cable/connection.rb.tt`: `identified_by :current_user`; `set_current_user` does `Session.find_by(id: cookies.signed[:session_id])` → same cookie powers ActionCable auth.

### 1.8 Generated tests + SessionTestHelper (`GEN/test_unit/authentication/`)

- `templates/test/test_helpers/session_test_helper.rb.tt`: `sign_in_as(user)` does `Current.session = user.sessions.create!` then writes the signed cookie via `ActionDispatch::TestRequest.create.cookie_jar`; `sign_out` destroys + deletes; included via `ActiveSupport.on_load(:action_dispatch_integration_test)`. Note `sign_in_as` creates a session row with **nil ip/user_agent** — our gem must tolerate that.
- Controller tests for sessions (4 cases) + passwords (7 cases), `users.yml` fixtures with shared `BCrypt::Password.create("password")`, mailer preview. Injected `require_relative "test_helpers/session_test_helper"` into `test/test_helper.rb` (`authentication_generator.rb:26-28`).

### 1.9 Session cookie — exact attributes

Write path: `cookies.signed.permanent[:session_id] = { value: session.id, httponly: true, same_site: :lax }` (concern :44).

- **Signed, not encrypted**: `SignedKeyRotatingCookieJar` (`actionpack/lib/action_dispatch/middleware/cookies.rb:621-649` [S]) — `ActiveSupport::MessageVerifier` with key from `request.key_generator.generate_key(request.signed_cookie_salt)` (:627-628). Payload is **readable** client-side (tamper-proof, not secret) → the integer Session id is visible in the cookie.
- **Permanent = 20 years**: `PermanentCookieJar#commit` sets `options[:expires] = 20.years.from_now` (cookies.rb:558-563). Fixed expiry from login; never re-issued ⇒ **no sliding window**.
- `httponly: true` explicit; `same_site: :lax` explicit (also the framework default: `cookies_same_site_protection = :lax`, `railties/lib/rails/application/configuration.rb:193` [S], applied at cookies.rb:459-461).
- `secure` not set; `write_cookie?` (cookies.rb:448-450) only enforces SSL when the flag is present — `Secure` comes from `config.force_ssl` (ActionDispatch::SSL) in default production.
- Purpose metadata binds value to cookie name: `metadata[:purpose] = "cookie.#{name}"` (cookies.rb:548-552) — can't replay another cookie's payload as `session_id`.

## 2. Key mechanics & gap analysis (the product thesis, verified)

- **Capture point**: ip/UA written exactly at `start_new_session_for` (concern :42) from `request.user_agent` / `request.remote_ip`. Never again.
- **No row updates ever**: `resume_session` → `find_session_by_cookie` → `Session.find_by` (concern :24-30) is read-only; grep for `touch|update|save` across all auth templates matches only the password-reset `@user.update` ([S], grep exit 1 otherwise). **No last-active tracking exists.**
- **Remote revocation works**: cookie holds only the row id; row gone ⇒ `find_by` nil ⇒ `require_authentication` ⇒ `request_authentication` redirect (concern :20-35). Browser keeps a useless signed cookie for 20 years.
- **Absent (confirmed by exhaustive template read)**: failed-login persistence/logging; session index/listing routes or views; device/UA parsing; per-session management UI (only "log out current" + "nuke all on password reset"); session expiry/sweeping; `reset_session`/Rack-session rotation on login (grep exit 1); `Current.session` is the only runtime handle.
- **Rate limiting is the only abuse counter-measure**, and it lives in the cache store, not the DB: 10 req / 3 min / IP on `sessions#create` and `passwords#create`.

## 3. Supporting Rails APIs (all [S])

- **ActiveSupport::CurrentAttributes** — `activesupport/lib/active_support/current_attributes.rb`: "thread-isolated attributes singleton, which resets automatically before and after each request" (:12); `attribute` :115; `resets`/`after_reset`/`before_reset` :145-153. Reset wiring: `app.executor.to_complete { ActiveSupport::CurrentAttributes.clear_all }` (`activesupport/lib/active_support/railtie.rb:60-64`) — jobs/background code outside the executor never get `Current.session`.
- **rate_limit** — `actionpack/lib/action_controller/metal/rate_limiting.rb:66-68`:
  ```ruby
  def rate_limit(to:, within:, by: -> { request.remote_ip }, with: -> { raise TooManyRequests }, store: cache_store, name: nil, scope: nil, **options)
  ```
  Implementation :72-90: cache key `["rate-limit", scope, name, by].compact.join(":")`, `store.increment(..., expires_in: within)`; **when exceeded** it instruments `rate_limit.action_controller` with payload `request,count,to,within,by,name,scope,cache_key` (:78-88) around the `with:` handler. Default 429 via `TooManyRequests` (doc :25-29). 8.1 added symbol `by:`/`with:`, `scope:`, the notification payload (actionpack CHANGELOG 8.1.0 section, :129-142, :239-252, :283-287). [M] adds: `by:` objects responding to `cache_key` use it ([M] actionpack/CHANGELOG.md:1-10) and **dynamic `to:`/`within:` accepting callables/symbols** ([M] :375-395).
- **authenticate_by** — `activerecord/lib/active_record/secure_password.rb:41-57`, doc :10-40: *"Regardless of whether a record is found, `authenticate_by` will cryptographically digest the given password attributes. This behavior helps mitigate timing-based enumeration attacks"*. Returns record or nil; nil/empty password short-circuits (:49); user-missing path still runs `new(passwords)` to burn bcrypt time (:53-55). **No hook/notification on failure** — failures are indistinguishable from the outside.
- **generates_token_for** — `activerecord/lib/active_record/token_for.rb:102-104` (def), doc :57-101: tokens signed via per-class `generated_token_verifier`; `expires_in` is baked into the purpose string (`TokenDefinition#full_purpose`, :14-17) so changing it invalidates old tokens; optional block payload re-evaluated at lookup — mismatch ⇒ invalid (:31-35). `find_by_token_for!` raises `ActiveSupport::MessageVerifier::InvalidSignature` (:50-53). **Stateless: no DB write, can't revoke a single token, only invalidate-by-state-change.**
- **has_secure_password extras** — `activemodel/lib/active_model/secure_password.rb`: signature `has_secure_password(attribute = :password, validations: true, reset_token: true)` (:125). `reset_token: true` auto-defines `generates_token_for :password_reset, expires_in: DEFAULT_RESET_TOKEN_EXPIRES_IN` (= `15.minutes`, :14) keyed on `password_salt&.last(10)` (:171-179) + `find_by_password_reset_token[!]` (:181-191) — so **password change invalidates outstanding reset tokens**. `password_challenge` validation re-checks `password_digest_was` (:149-157). 72-byte bcrypt max validation (:159-165). `password_salt` reader (:228-232).
- **normalizes** — moved to `activemodel/lib/active_model/attributes/normalization.rb:111` in 8.1 (was `active_record/normalization.rb` in 8.0). Applies on assignment + finder values.
- **MessageVerifier rotation** — `activesupport/lib/active_support/message_verifier.rb:90-109` (`rotate(old_secret, digest:, serializer:)` fallback stack). Cookie-level: `config.action_dispatch.cookies_rotations` consumed at cookies.rb:630-635; rotated-on-read cookies are transparently re-written (:638-642). App-level: `Rails.application.message_verifiers.rotate(...)` (`railties/lib/rails/application.rb:196-211`). **Changing `secret_key_base` without rotation kills every login cookie at once.**
- **RemoteIp / request.remote_ip** — `actionpack/lib/action_dispatch/middleware/remote_ip.rb`: picks "the last-set address that is not on the list of trusted IPs" (:11-13); `TRUSTED_PROXIES` = loopback + RFC1918 + link-local ranges (:40-49); custom list replaces (not extends) via `config.action_dispatch.trusted_proxies` wired with `ip_spoofing_check` at `railties/lib/rails/application/default_middleware_stack.rb:55`; spoof-check raises `IpSpoofAttackError` when Client-Ip vs X-Forwarded-For disagree (:34, :129-160). `request.remote_ip` reads env `"action_dispatch.remote_ip"` set by the middleware (`actionpack/lib/action_dispatch/http/request.rb:317-319`). **Our stored `ip_address` is only as truthful as the host app's trusted_proxies config** (Cloudflare etc. need explicit config or the edge IP gets stored).

## 4. History & direction: 8.0 → 8.1 → edge

`git diff v8.0.5 v8.1.3 -- <generator trees>` ([S] clone, fetched tag):

- **8.1.0 (2025-10-22)** generator changes — all in [S] railties/CHANGELOG.md under the 8.1.0 header (line 46):
  - Password reset destroys **all** the user's sessions (`@user.sessions.destroy_all` added to passwords_controller.tt).
  - `rate_limit` added to `PasswordsController#create` ("Rate limit password resets… mitigate abuse", :178-182, Chris Oliver).
  - `SessionTestHelper` with `sign_in_as`/`sign_out` (:173-176); sessions+passwords controller tests generated (:158-160).
  - ActionMailer-less apps: mailer files/actions skipped (:135-137).
  - `sessions#destroy` redirect gained `status: :see_other`; rate-limit lambda `new_session_url`→`new_session_path`.
  - **Concern + all three models byte-identical 8.0→8.1** (empty diff).
- **8.1.0 actionpack**: rate_limit `scope:`, symbol `by:`/`with:`, notification payload (§3). Also `ActionDispatch::Session::CacheStore` got `check_collisions` (actionpack CHANGELOG :486-492 — Rack-session hardening, unrelated to the auth cookie).
- **main / 8.2.0.alpha**: generator = reuse existing User model (skip CreateUsers, [M] railties/CHANGELOG.md:31), routes restricted with `only:`, passwords test mailer-guarded, sessions test uses `@user`. rate_limit: `cache_key` on `by:` + dynamic `to:`/`within:`. **No passkeys/WebAuthn/OmniAuth/account-model work anywhere on main** (grep across railties+actionpack: zero hits); concern still byte-identical. Direction = polish, not expansion — the session-management whitespace stays open.

## 5. Official guidance (guides/source/security.md [S]; identical file size on [M])

- Authentication section (:33-245) documents the generator; explicitly: *"you do need to implement your own sign up flow"* (:105-109); encourages reading generated code, "not treat authentication as a black box" (:238-240). Reset link "valid for 15 minutes by default" (:148-149).
- No dedicated `authentication.md` guide exists ([S]+[M] `guides/source/`); 8.1 added tutorial guides `sign_up_and_settings.md` (sign-up + rate limiting + roles atop the generator) and `wishlists.md`; `getting_started.md` covers the generator.
- Session fixation (:393-420): countermeasure = `reset_session` after login (:412-416) — **the generated code never does this** (it doesn't rotate the Rack session; its own cookie is server-issued so the auth layer itself isn't fixatable). Devise name-checked (:418). Also suggests verifying stored ip/user-agent per request, with proxy caveats (:420).
- Session expiry (:422-440): "Sessions that never expire extend the time-frame for attacks"; recommends DB-side expiry, sample `Session.sweep` using `where(updated_at: ...time.ago)` (:428-434) plus `created_at` cap for kept-alive sessions (:436-440). **The generated Session's `updated_at` is never touched, so this exact recommendation is unimplementable without our gem's last-active tracking.**
- Cookie rotation how-to (:332-375); changing `secret_key_base` expires all sessions (:330).

## Implications for the sessions gem

1. **Decorate the model, don't patch app code.** `Session < ApplicationRecord` with one association. All three lifecycle paths run callbacks: `create!` (login), `destroy` (logout), `destroy_all` (password reset — instantiates each record). So `Rails.application.config.to_prepare { Session.include Sessions::SessionExtensions if defined?(Session) && Session.column_names.include?("ip_address") }` + `after_create_commit` (login event, ip/UA already on the row) + `after_destroy_commit` (revocation event) captures everything. Must use `to_prepare` (app constant, reloader-safe), not `on_load`.
2. **Wrap controller verbs via prepend, no monkey-patching.** `start_new_session_for` / `terminate_session` / `resume_session` are *name-stable since 8.0* private methods on ApplicationController (via the included Authentication concern). `to_prepare { ApplicationController.prepend(Sessions::ControllerHooks) if ApplicationController.private_method_defined?(:start_new_session_for) }` — prepend sits in front of the included concern in the ancestor chain, so `super`-wrapping works cleanly. Duck-detect with `private_method_defined?` for omakase-vs-Devise dispatch.
3. **Last-active tracking is ours to add and the schema is ready**: `updated_at` exists and is dead weight today. Wrap `resume_session` (or an `after_action`) with a throttled `touch` (e.g. ≥ once/5 min) — note before_actions registered at `ActionController::Base` level run *before* the app's `require_authentication`, so `Current.session` is nil there; use prepend-wrap or `after_action`. This directly enables the security guide's own sweep recommendation (security.md:422-440).
4. **Failed logins have no hook**: `authenticate_by` is silent, the controller just redirects. Options: (a) prepend `SessionsController#create` (name-stable), (b) prepend `User.authenticate_by` singleton (semantics stable, secure_password.rb:41-57), (c) subscribe `ActiveSupport::Notifications` `rate_limit.action_controller` for brute-force-exceeded events (payload: count/to/within/by/name/scope/cache_key). Recommend (a)+(c).
5. **Cookie = row id, signed, readable**: any Rack/middleware/Hotwire Native layer can resolve the device's session via `request.cookie_jar.signed[:session_id]` — same trick the generated ActionCable Connection uses. Great for native-app device intelligence without touching controllers.
6. **Revocation UX is free**: "log out this device" = `session.destroy`; "log out everywhere else" = `user.sessions.where.not(id: Current.session.id).destroy_all`. Rails provides the primitive but zero UI — our whole "your devices" layer is additive migration (device columns, last_active_at) + views on a table Rails already owns.
7. **Naming hazard**: the host's model is literally `::Session` and table `sessions` — our gem (`sessions`) must isolate_namespace and never define a top-level `Session`; ride theirs when present, generate a compatible one when absent (Devise/OAuth modes).
8. **Caveats to encode**: `ip_address` truthfulness depends on `trusted_proxies` (offer config + docs); UA `varchar(255)` truncation on MySQL; `sign_in_as` test helper creates nil-ip/UA rows; signed-not-encrypted cookie exposes sequential ids; 20-year cookie means *our* sweep + idle expiry is the only real expiry; API-mode apps lack `helper_method` so our helpers must be Base/API-aware.
