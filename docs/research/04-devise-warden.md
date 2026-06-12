# Devise & Warden internals: attachment surface for session tracking

Research date: 2026-06-11. Sources: shallow clones at `/tmp/sessions-research/{devise,warden,devise-security}`.
Path convention below: `devise/...` = heartcombo/devise @ `372b295` (2026-06-10), `warden/...` = wardencommunity/warden @ `810e520` (2025-09-02), `devise-security/...` = devise-security/devise-security @ `7cbe3fd` (2026-01-05).

## Top findings

1. **Warden hooks are the entire attachment surface and they are class-level + lazily evaluated.** Hook blocks are stored in arrays on `Warden::Manager` itself (`warden/lib/warden/hooks.rb:67-69`, `Manager` extends `Hooks` at `warden/lib/warden/manager.rb:12`) and consulted per-request via `manager._run_callbacks` → `self.class._run_callbacks` (`warden/lib/warden/manager.rb:51-53`). Registration any time before the first request is safe; Gemfile order is irrelevant if we register from a Railtie initializer.
2. **Every "user becomes current" path funnels through `Proxy#set_user`, tagged with an `:event`** — `:authentication` (strategy won: form login AND remember-me cookie), `:fetch` (per-request session resume), `:set_user` (manual `sign_in`: post-signup, post-password-reset, OmniAuth default). `after_set_user except: :fetch` = "a login of any kind happened"; `only: :fetch` = "per-request resume". This is exactly how trackable and session_limitable split their work.
3. **Session fixation protection is in Warden, not Devise, and it's `:renew`, not `reset_session`:** `Proxy#set_user` sets `env['rack.session.options'][:renew] = true` (`warden/lib/warden/proxy.rb:178-186`); the Rack/Rails session middleware rotates the SID at commit while *copying session data over*. Consequence: a token we stash in the warden session survives login rotation, but the Rack session **ID** captured during the login request is stale by response time — never key our session rows on Rack SID; store our own token like session_limitable does.
4. **devise-security's session_limitable is a complete, proven 3-hook revocation template in 55 lines** (`devise-security/lib/devise-security/hooks/session_limitable.rb`): store token on login (`after_set_user except: :fetch`), compare per request (`after_set_user only: :fetch` → `warden.logout` + `throw :warden`), clear on logout (`before_logout`). Its only structural flaw for us: the token lives in a single column on the user row → exactly one valid session per user. Move the token to a sessions table row → N devices + selective remote revocation.
5. **Failed logins:** strategy `fail!` only sets state (`warden/lib/warden/strategies/base.rb:137-141`); `authenticate!` throws (`warden/lib/warden/proxy.rb:134`); `Manager#call` catches and runs `before_failure` with `env["warden.options"] = {scope:, action:, message:, attempted_path:, recall:, locale:}` (`warden/lib/warden/manager.rb:136-147`). The attempted email is NOT in warden.options — extract `Rack::Request.new(env).params[scope.to_s]` (Devise posts `user[email]`). This is the authtrail mechanism, confirmed from source.
6. **Devise is alive and Rails-8-ready:** v5.0.4 (2026-05-08), 5.0.0 (2026-01-23) dropped Rails <7/Ruby <2.7, added Rails 8 lazy-route support; repo HEAD committed 2026-06-10; two CVE patches in 2026. Warden is frozen at 1.2.9 (released 2020-08-31) — stable ABI, ideal attachment target.
7. **Surprise:** devise-security registers a `:session_non_transferable` module (`devise-security/lib/devise-security.rb:108`) whose model file does not exist anywhere in the repo — a broken autoload at HEAD. Also `Devise::Hooks::Proxy` (`devise/lib/devise/hooks/proxy.rb`) is a tiny public-ish helper that gives hooks `sign_out`/`remember_me`/`cookies` powers — we should reuse the pattern, not the class.

## 1. Warden lifecycle & hooks

`Warden::Manager` is Rack middleware; Devise inserts it via `config.app_middleware.use Warden::Manager { |config| Devise.warden_config = config }` (`devise/lib/devise/rails.rb:11-13`). Per request: `env['warden'] = Proxy.new(env, self)`, then `catch(:warden) { env['warden'].on_request; @app.call(env) }` (`warden/lib/warden/manager.rb:30-37`).

### Hook signatures (`warden/lib/warden/hooks.rb`)

- **`after_set_user(options = {}, method = :push, &block)`** — hooks.rb:53-63. Block args `|user, auth, opts|`: user object, the `Warden::Proxy`, and the options passed to `set_user` *including `:scope` and `:event`* (hooks.rb:33-36). Fires "the first time one of those three events happens during a request: `:authentication`, `:fetch` (from session) and `:set_user` (when manually set)" (hooks.rb:19-21). Filtering options: `scope:`, `only:`, `except:` (hooks.rb:28-31). Event filtering is sugar:

  ```ruby
  if options.key?(:only)
    options[:event] = options.delete(:only)
  elsif options.key?(:except)
    options[:event] = [:set_user, :authentication, :fetch] - Array(options.delete(:except))
  end
  ```
  (hooks.rb:56-60). Condition matching: a callback runs unless any condition key mismatches `options` — arrays mean "include?" (`hooks.rb:7-17`, `_run_callbacks`).
- **`after_authentication`** — hooks.rb:76-78: literally `after_set_user(options.merge(:event => :authentication), ...)`.
- **`after_fetch`** — hooks.rb:85-87: `after_set_user(options.merge(:event => :fetch), ...)`.
- **`before_failure(options = {}, method = :push, &block)`** — hooks.rb:110-113. Block args `|env, opts|` (hooks.rb:98-100). Runs "just prior to the failure application being called", after PATH_INFO has been rewritten (hooks.rb:89-91).
- **`after_failed_fetch`** — hooks.rb:138-141. Block `|user, auth, opts|`; runs when no user could be deserialized from the session for a scope (hooks.rb:121). Fired from `Proxy#user` at `warden/lib/warden/proxy.rb:226`.
- **`before_logout`** — hooks.rb:166-169. Block `|user, auth, opts|`, runs "just prior to the logout of each scope" (hooks.rb:149); fired per scope from `Proxy#logout` (`proxy.rb:274`).
- **`on_request`** — hooks.rb:191-194. Block `|proxy|`; runs on *every* request right after the proxy is built (`proxy.rb:34-38`, called at `manager.rb:35`), before any authentication.
- **`prepend_<hook>`** variants exist for all of the above (hooks.rb:202-210) — they `unshift` instead of `push`; hooks run **in declaration order** (hooks.rb:22).

### How scope is passed

Scope rides in the options hash: `set_user` defaults it (`opts[:scope] ||= @config.default_scope`, `proxy.rb:171`) and merges per-scope `scope_defaults` (`proxy.rb:174`; defaults installed by Devise at `devise/lib/devise.rb:493`). Hooks read `opts[:scope]` (e.g. trackable: `options[:scope]`). `before_logout` gets `:scope => scope` explicitly (`proxy.rb:274`). `before_failure` gets it inside `env['warden.options']`/second arg.

### Login vs resume vs remember-me — the event/strategy matrix

`_perform_authentication` returns the session user first if present (`proxy.rb:334`); otherwise runs strategies and on success calls `set_user(winning_strategy.user, opts.merge!(:event => :authentication))` (`proxy.rb:337-340`). Session resume goes through `Proxy#user` → `set_user(user, opts.merge(:event => :fetch))` (`proxy.rb:229`) and skips re-serialization (`opts[:store] != false && opts[:event] != :fetch` guard at `proxy.rb:178`). Manual `set_user` defaults `opts[:event] ||= :set_user` (`proxy.rb:175`).

| Situation | event | `warden.winning_strategy` |
|---|---|---|
| Form login (`warden.authenticate!`) | `:authentication` | `Devise::Strategies::DatabaseAuthenticatable` |
| Remember-me cookie re-auth | `:authentication` | `Devise::Strategies::Rememberable` |
| Per-request session resume | `:fetch` | `nil` (no strategy ran) |
| `sign_in` after signup / password reset / OmniAuth default | `:set_user` | `nil` |
| OmniAuth with `event: :authentication` passed | `:authentication` | `nil` |

`winning_strategy` is a public accessor (`proxy.rb:10`). So: `opts[:event]` + `warden.winning_strategy&.class` fully disambiguates the login method.

### Registration timing / load order

Hook arrays live on the `Warden::Manager` class (`hooks.rb:67-69`); the middleware instance just delegates to the class at callback time (`manager.rb:51-53`). Devise itself loads warden at require time — `require 'warden'` is `devise/lib/devise.rb:529` — and registers its own hooks even later: each `devise/lib/devise/hooks/*.rb` is `require`d from the corresponding model module (e.g. `devise/lib/devise/models/trackable.rb:3`), which is only autoloaded when an app model declares `devise :trackable` — i.e. at class-load/eager-load time, *after* initializers. Conclusion: registering hooks from an initializer is load-order safe and will typically place our hooks *ahead of* Devise's own model hooks in declaration order (see §8 and edge cases).

## 2. Devise sign-in flow end-to-end

1. **`Devise::SessionsController#create`** (`devise/app/controllers/devise/sessions_controller.rb:18-24`):
   ```ruby
   self.resource = warden.authenticate!(auth_options)
   set_flash_message!(:notice, :signed_in)
   sign_in(resource_name, resource)
   ```
   `auth_options = { scope: resource_name, recall: "#{controller_path}#new", locale: I18n.locale }` (sessions_controller.rb:47-49). Note `prepend_before_action ... { request.env["devise.skip_timeout"] = true }` for create/destroy (sessions_controller.rb:7) and `allow_params_authentication!` (line 5) which sets `env["devise.allow_params_authentication"]` checked by the strategy (`devise/lib/devise/strategies/authenticatable.rb:104-106`).
2. **Strategy** — `Devise::Strategies::DatabaseAuthenticatable#authenticate!` (`devise/lib/devise/strategies/database_authenticatable.rb:9-26`):
   ```ruby
   resource = password.present? && mapping.to.find_for_database_authentication(authentication_hash)
   if validate(resource){ hashed = true; resource.valid_password?(password) }
     remember_me(resource)
     resource.after_database_authentication
     success!(resource)
   end
   mapping.to.new.password = password if !hashed && Devise.paranoid   # enumeration defense, line 22
   unless resource
     Devise.paranoid ? fail(:invalid) : fail(:not_found_in_database)  # lines 23-25
   end
   ```
   Registered via `Warden::Strategies.add(:database_authenticatable, ...)` (line 31). `validate` calls `resource.valid_for_authentication?` and on falsy result `fail!(resource.unauthenticated_message)` (`devise/lib/devise/strategies/authenticatable.rb:37-48`) — this is where lockable/confirmable rejections surface. `success!`/`fail!` just set `@result`/`@user`/`@message` and halt (`warden/lib/warden/strategies/base.rb:126-141`).
3. **Warden sets the user**: `set_user(..., event: :authentication)` (`warden/lib/warden/proxy.rb:339`) → stores to session via serializer (`proxy.rb:187`) → runs `after_set_user` callbacks (`proxy.rb:190-191`).
4. **`sign_in` helper** (`devise/lib/devise/controllers/sign_in_out.rb:33-46`): deletes all `devise.*` session keys (`expire_data_after_sign_in!`, lines 38, 99-101), then — key subtlety — **no-ops if `warden.user(scope) == resource`** (lines 40-42). After `warden.authenticate!` the user is already set, so the controller's `sign_in` call does nothing; all hooks fired during step 3. For signup/password-reset flows the user is *not* set yet, so it proceeds to `warden.set_user(resource, options.merge!(scope: scope))` (line 44) → hooks fire with event `:set_user`.

### Session fixation: the exact lines

Devise never calls `reset_session` on sign-in. Warden's `set_user` does this (`warden/lib/warden/proxy.rb:178-187`):

```ruby
if opts[:store] != false && opts[:event] != :fetch
  options = env[ENV_SESSION_OPTIONS]            # 'rack.session.options', proxy.rb:20
  if options
    if options.frozen?
      env[ENV_SESSION_OPTIONS] = options.merge(:renew => true).freeze
    else
      options[:renew] = true
    end
  end
  session_serializer.store(user, scope)
end
```

`:renew` makes the Rack/Rails session middleware generate a fresh SID at commit while keeping the session contents. Complementarily, the CSRF token is rotated by Devise's `csrf_cleaner` hook: `Warden::Manager.after_authentication` → `warden.request.reset_csrf_token` on Rails 7.1+ (`devise/lib/devise/hooks/csrf_cleaner.rb:3-14`), gated by the winning strategy's `clean_up_csrf?` (true for database auth, `devise/lib/devise/strategies/authenticatable.rb:24-26`; false for rememberable, `devise/lib/devise/strategies/rememberable.rb:41-43`). A **full** session wipe happens only on logout-of-all-scopes: `Proxy#logout` sets `reset_session = true` when called with no scopes (`proxy.rb:267-270`) → `reset_session!` (`proxy.rb:280`), which Devise overrides to `request.reset_session` (`devise/lib/devise/rails/warden_compat.rb:8-10`).

### Session serialization: exact keys and shapes

- Key: `"warden.user.#{scope}.key"` (`warden/lib/warden/session_serializer.rb:11-13`), e.g. `"warden.user.user.key"`.
- Value: Devise wires per-scope serializers at `Devise.configure_warden!` (`devise/lib/devise.rb:495-501`), delegating to the model: `serialize_into_session(record)` → **`[record.to_key, record.authenticatable_salt]`** (`devise/lib/devise/models/authenticatable.rb:225-227`), i.e. `[[42], "$2a$12$WCi3OqAFFsR3UN8y..."]` — `authenticatable_salt` is `encrypted_password[0,29]` (`devise/lib/devise/models/database_authenticatable.rb:158-160`). Deserialization re-checks the salt (`authenticatable.rb:229-232`) so password changes invalidate all cookie sessions.
- Scoped per-user session data: `warden.session(scope)` ⇒ `raw_session["warden.user.#{scope}.session"] ||= {}` (`warden/lib/warden/proxy.rb:244-247`); raises `NotAuthenticated` if not logged in (proxy.rb:245). Deleted on logout (`proxy.rb:276`). This is where timeoutable's `last_request_at` and session_limitable's `unique_session_id` live — and where ours should live.
- `configure_warden!` runs at routes finalization (`devise/lib/devise/rails/routes.rb:19`, inside `Devise::RouteSet#finalize!` lines 8-24) because mappings are declared by `devise_for` in routes.
- `bypass_sign_in` writes the serializer directly with **no callbacks** (`devise/lib/devise/controllers/sign_in_out.rb:56-60`).
- Inside hooks, `warden.request` is a full `ActionDispatch::Request` (Devise monkeypatches `Warden::Mixins::Common#request`, `devise/lib/devise/rails/warden_compat.rb:4-6`) → `remote_ip`, `user_agent`, `params` all available.

## 3. Failed logins

Flow: strategy `fail!(message)` sets `@result = :failure` + halts, **does not throw** (`warden/lib/warden/strategies/base.rb:133-141`); `Proxy#authenticate!` does `throw(:warden, opts) unless user` (`warden/lib/warden/proxy.rb:132-136`); `Manager#call`'s `catch(:warden)` receives the hash (`warden/lib/warden/manager.rb:34-44`) → `process_unauthenticated` (manager.rb:112-131; `options[:action] ||= 'unauthenticated'` at 113-116, `options[:message] ||= proxy.message` at 128) → `call_failure_app` (`warden/lib/warden/manager.rb:136-147`):

```ruby
options.merge!(:attempted_path => ::Rack::Request.new(env).fullpath)
env["PATH_INFO"] = "/#{options[:action]}"
env["warden.options"] = options
_run_callbacks(:before_failure, env, options)
config.failure_app.call(env).to_a
```

So in `before_failure`, `env['warden.options']` (== second block arg) contains: **`:scope`**, **`:action`**, **`:message`** (symbol like `:invalid`, `:not_found_in_database`, `:timeout`, `:locked`, `:unconfirmed`, `:session_limited`), **`:attempted_path`** (e.g. `/users/sign_in`), plus whatever `authenticate!` was called with — for Devise: **`:recall`** (`"devise/sessions#new"`) and `:locale` (sessions_controller.rb:47-49).

**Attempted identity**: not in warden.options. Recover it from the request — `Rack::Request.new(env)` (or in a Devise app `ActionDispatch::Request.new(env)`) → `params[opts[:scope].to_s]` is the credentials hash (`{"email" => "...", "password" => "..."}`), because Devise's strategy pulls credentials from `params[scope]` (`devise/lib/devise/strategies/authenticatable.rb:93-95`). This is exactly how authtrail captures failed-login identities. **Filter caveat:** `before_failure` fires for *every* warden failure including plain unauthenticated page hits and timeouts; a real credential failure is distinguished by `request.post? && params[scope].is_a?(Hash)` (and/or `opts[:recall]` presence). Devise's FailureApp then re-dispatches to `sessions#new` via `recall` with the configured error status (`devise/lib/devise/failure_app.rb:45-46, 59-83`; reads `warden.options` at 231-233, `attempted_path` at 247-249).

OmniAuth failures do **not** pass through warden's failure path — they hit `Devise::OmniauthCallbacksController#failure` reading `omniauth.error.*` env keys (`devise/app/controllers/devise/omniauth_callbacks_controller.rb:10-27`). Separate capture needed for OAuth failures.

## 4. Relevant Devise modules

### trackable
Hook (`devise/lib/devise/hooks/trackable.rb:7-11`):
```ruby
Warden::Manager.after_set_user except: :fetch do |record, warden, options|
  if record.respond_to?(:update_tracked_fields!) && warden.authenticated?(options[:scope]) && !warden.request.env['devise.skip_trackable']
    record.update_tracked_fields!(warden.request)
  end
end
```
Columns: `sign_in_count`, `current_sign_in_at`, `last_sign_in_at`, `current_sign_in_ip`, `last_sign_in_ip` (`devise/lib/devise/models/trackable.rb:16-18`); shift-and-set logic at 20-31; `update_tracked_fields!` skips new records and does `save(validate: false)` (33-41); IP = `request.remote_ip` (45-47). **Skip switch: `env['devise.skip_trackable']`** — our gem supersedes trackable and should document coexistence (we must not double-count; we read the same request object).

### rememberable
- Cookie name **`remember_#{scope}_token`** (`devise/lib/devise/strategies/rememberable.rb:55-57`; same default in `devise/lib/devise/controllers/rememberable.rb:51-53`), a **signed** cookie (`cookies.signed`, strategy line 60, controller line 26), `httponly: true` (controller 42-49).
- Shape: **`[record.to_key, record.rememberable_value, Time.now.utc.to_f.to_s]`** (`devise/lib/devise/models/rememberable.rb:134-136`); `rememberable_value` = `remember_token` column or `authenticatable_salt` fallback (73-84).
- Validation `remember_me?(token, generated_at)` (`models/rememberable.rb:103-120`): freshness vs `remember_for`, `generated_at > remember_created_at`, `Devise.secure_compare(rememberable_value, token)`.
- Strategy (`devise/lib/devise/strategies/rememberable.rb:21-34`): `valid?` iff cookie present (13-16); deserializes, deletes cookie + `pass`es if stale (24-27), else `resource.after_remembered; success!(resource)` (31-32). Registered at line 67. **A remember-me re-login is therefore a full warden `:authentication` event** with `winning_strategy` = `Devise::Strategies::Rememberable` — it creates a *new* Rack session mid-GET-request (renew applies), fires trackable/lockable/our hooks, but does **not** clean CSRF (`clean_up_csrf?` false, 41-43).
- Cookie is (re)written on login by the hook `after_set_user except: :fetch` when `record.remember_me` truthy (`devise/lib/devise/hooks/rememberable.rb:3-9`); cleared at `before_logout` via forgetable (`devise/lib/devise/hooks/forgetable.rb:7-11`) → `forget_me!` nils `remember_token`/`remember_created_at` (`models/rememberable.rb:58-63`). `after_remembered` model callback (`models/rememberable.rb:100-101`) is our chance-free zone — prefer the warden event.

### timeoutable
Hook runs on **all** events including `:fetch` (`devise/lib/devise/hooks/timeoutable.rb:8`), guarded by `options[:store] != false && !env['devise.skip_timeoutable']` (line 13). Reads **`warden.session(scope)['last_request_at']`** (line 14) — i.e. inside `raw_session["warden.user.#{scope}.session"]` — with Integer/String coercion (16-19). If `!env['devise.skip_timeout'] && record.timedout?(last_request_at) && !proxy.remember_me_is_active?(record)` → signs out and `throw :warden, scope: scope, message: :timeout` (24-28). Then **touches `last_request_at = Time.now.utc.to_i` every request unless `env['devise.skip_trackable']`** (31-33 — note: it reuses the *trackable* skip flag for the touch). `timedout?` = `last_access <= timeout_in.ago` (`devise/lib/devise/models/timeoutable.rb:30-32`). Interplay for our per-request touch: a cookie-session write already happens every request for timeoutable users, so our touch adds no cookie overhead — but any *DB* touch must be throttled (contrast devise-security's expirable which does `update_column` per request — `devise-security/lib/devise-security/hooks/expirable.rb:7-12`, `models/expirable.rb:30`).

### lockable
Increment happens **inside the strategy's validate call**, in the model: `valid_for_authentication?` override (`devise/lib/devise/models/lockable.rb:102-120`) — on bad password `increment_failed_attempts` (line 112; atomic `increment_counter` + `reload`, 122-125), `lock_access!` when `attempts_exceeded?` (113-115, lock sets `locked_at`, 42-50). Counter reset on successful login via hook `after_set_user except: :fetch` → `reset_failed_attempts!` (`devise/lib/devise/hooks/lockable.rb:5-9`). Columns: `failed_attempts`, `locked_at`, `unlock_token` (`models/lockable.rb:29-36`). Failure messages: `:locked` / `:last_attempt` (127-139). Locked-account *page hits* are enforced by the activatable hook: `after_set_user` (all events) → `!active_for_authentication?` → logout + throw (`devise/lib/devise/hooks/activatable.rb:6-12`). **Our gem records attempts only; lockout stays Devise's job.**

### omniauthable
Model is config-only (`devise/lib/devise/models/omniauthable.rb`). The app's callback controller (user-written, per README pattern) calls `sign_in_and_redirect @user, event: :authentication` → `sign_in(scope, resource, options)` (`devise/lib/devise/controllers/helpers.rb:237-244`) → `warden.set_user`. Without the `event:` option the hooks see `:set_user`; `winning_strategy` is `nil` either way. **Provider info is not passed to hooks — but it's in the env**: read `warden.request.env["omniauth.auth"]` (provider/uid) inside the hook during the callback request. The stock controller sets `devise.skip_timeout` (`devise/app/controllers/devise/omniauth_callbacks_controller.rb:4`).

## 5. devise-security session_limitable — the revocation template

v0.18.0 (`devise-security/lib/devise-security/version.rb:4`), requires devise >= 4.8.1. Column: `unique_session_id` on the user (`devise-security/lib/devise-security/models/session_limitable.rb:17-19`). The whole mechanism is three hooks in `devise-security/lib/devise-security/hooks/session_limitable.rb`:

**(1) Store on login** — lines 6-19:
```ruby
Warden::Manager.after_set_user except: :fetch do |record, warden, options|
  if record.devise_modules.include?(:session_limitable) &&
     warden.authenticated?(options[:scope]) && !record.skip_session_limitable?
    if !options[:skip_session_limitable]
      unique_session_id = Devise.friendly_token
      warden.session(options[:scope])['unique_session_id'] = unique_session_id   # line 13
      record.update_unique_session_id!(unique_session_id)                        # line 14
    else
      warden.session(options[:scope])['devise.skip_session_limitable'] = true    # line 16
    end
  end
end
```
**(2) Validate per request** — lines 25-44: `after_set_user only: :fetch`, guards `options[:store] != false` (line 30); on mismatch `record.unique_session_id != warden.session(scope)['unique_session_id']` (line 31) and not skipped (32-33): logs (34-38), **`warden.raw_session.clear`** (39), **`warden.logout(scope)`** (40), **`throw :warden, scope: scope, message: :session_limited`** (41).
**(3) Clear on logout** — lines 49-55: `before_logout` → `record.update_unique_session_id!(nil)` (53), so zero valid sessions remain after explicit sign-out.

Model plumbing: `update_unique_session_id!` is `update_attribute_without_validatons_or_callbacks` (`models/session_limitable.rb:26-32`); hooks register when the model module is autoloaded — `require 'devise-security/hooks/session_limitable'` at `models/session_limitable.rb:4`.

**Weaknesses to design around:**
- **Single-session only.** Token is one column on the user; each login overwrites it (hook 1, line 14) and hook 2 then kills every other browser. We invert it: token → row in a `sessions` table; per-request check = "row exists and not revoked" → N devices, per-device revocation.
- **Races.** Login overwrite is non-atomic with in-flight `:fetch` checks from other tabs; a request racing a concurrent login can be logged out spuriously. With a sessions table, concurrent logins each get their own row — race disappears except revoke-vs-inflight-request (acceptable: revocation wins next request).
- **Skip surface (3 layers):** per-call `sign_in(user, skip_session_limitable: true)` (option forwarded by `sign_in` → `set_user`; hook line 11), per-model `skip_session_limitable?` (model 37-39), and a sticky session flag `'devise.skip_session_limitable'` (lines 16, 33) so skipped logins don't get nuked on subsequent fetches. We should mirror all three (`sessions_skip:` option, model predicate, session flag).
- **`bypass_sign_in` blind spot:** no callbacks run (`devise/lib/devise/controllers/sign_in_out.rb:56-60`), used by registrations#update after password change (`devise/app/controllers/devise/registrations_controller.rb:60` area) — token in warden session and column both survive unchanged, so it stays consistent; but no fresh-login record is produced. Same applies to our gem (fine — same session continues).
- The `before_logout` nil-clear (hook 3) means "log out one device = invalidate the only token" — meaningless once tokens are per-row; our analog is "mark this row revoked/ended".
- Curiosity: `Devise.add_module :session_non_transferable` is registered at `devise-security/lib/devise-security.rb:108` but no model file exists in the repo — broken autoload at HEAD; don't copy blindly.

## 6. Multi-scope

- `Devise.mappings` is a plain hash scope→`Devise::Mapping` (`devise/lib/devise.rb:276-283`); on Rails 8 it force-loads lazy routes first (`Rails.application.try(:reload_routes_unless_loaded)`, devise.rb:281, added for Rails 8 in 5.0.0.rc — CHANGELOG.md:55-56).
- `mapping.name` = singular scope symbol (`devise/lib/devise/mapping.rb:31`), `mapping.to` = the class (mapping.rb:82-84), `Mapping.find_scope!(obj)` resolves class/record→scope (mapping.rb:35-47).
- Warden is configured per scope at `configure_warden!`: `scope_defaults mapping.name, strategies: mapping.strategies` + per-scope serializers (`devise/lib/devise.rb:492-501`; warden side: `warden/lib/warden/config.rb:74-85`, scope-named serializer methods `warden/lib/warden/manager.rb:69-92`, dispatch in `warden/lib/warden/session_serializer.rb:23-38`).
- Session keys are scope-qualified: `warden.user.user.key`, `warden.user.admin_user.key`; scoped data `warden.user.admin_user.session`. Controller helpers are generated per mapping (`authenticate_admin_user!`, `current_admin_user` — `devise/lib/devise/controllers/helpers.rb:113-142`).
- **What our gem must do:** treat `opts[:scope]` as first-class — store it on every row; make the owner association polymorphic (`record.class.name` + `record.to_key`/`id`); never assume `:user`; resolve per-scope config via `Devise.mappings[scope]` *only when Devise is present* (plain Warden apps have scopes without mappings); remember `Devise.sign_out_all_scopes` (default true) means one `DELETE /users/sign_out` triggers `before_logout` once **per scope** (`warden/lib/warden/proxy.rb:272-278`, `devise/app/controllers/devise/sessions_controller.rb:28`).

## 7. State of Devise, June 2026

- **Version 5.0.4** (`devise/lib/devise/version.rb:4`), released **2026-05-08** (`devise/CHANGELOG.md:1`). Cadence: 5.0.0.rc 2025-12-31 → 5.0.0 2026-01-23 → 5.0.1 2026-02-13 → 5.0.2 2026-02-18 → 5.0.3 2026-03-16 → 5.0.4 2026-05-08 (CHANGELOG.md:1-27). Repo HEAD committed 2026-06-10 — actively maintained.
- Security posture: CVE-2026-40295 (FailureApp open redirect via Referer, 5.0.4, CHANGELOG.md:4) and CVE-2026-32700 (confirmable change-email race, 5.0.3, CHANGELOG.md:9).
- Constraints: `railties >= 7.0`, `warden ~> 1.2.3`, ruby >= 2.7 (`devise/devise.gemspec:29-34`); lockfile resolves warden 1.2.9 (`devise/Gemfile.lock:279`). Warden itself: 1.2.9 since 2020-08-31 (`warden/CHANGELOG.md:3`), `rack >= 2.2.3` (`warden/warden.gemspec`), last commit 2025-09-02 — dormant-but-stable; the hook ABI we attach to hasn't changed in years.
- **Rails 8/8.1**: official support landed in 5.0.0.rc — "Add Rails 8 support. Routes are lazy-loaded by default in test and development environments now so Devise loads them before `Devise.mappings` call" (CHANGELOG.md:55-56, PR #5728). Rack 3.1: new apps get `error_status = :unprocessable_content` (CHANGELOG.md:57-59).
- **Hotwire/Turbo**: fully integrated since 4.9/5.x; 5.0 swapped `[data-turbo-cache=false]` → `[data-turbo-temporary]` in shared error partials (CHANGELOG.md:50-52); failure app responds with the configured `error_status` so Turbo handles 422 re-renders.
- **Rails 8 native auth coexistence: nothing in the CHANGELOG.** No mention of the Rails 8 auth generator — Devise and Rails-native auth are simply parallel worlds; our gem must bridge them itself (Warden hooks for Devise, model/controller concerns for omakase auth).
- `sign_in_after_reset_password?` became a customizable controller hook in 5.0.2 (CHANGELOG.md:16, PR #5826).

## 8. How third-party gems attach cleanly

devise-security's pattern (`devise-security/lib/devise-security.rb`): `require 'devise'` at line 9 (hard dependency, fine for them, **not for us**); adds `Devise.mattr_accessor` config (11-92); registers modules via `Devise.add_module :session_limitable, model: 'devise-security/models/session_limitable'` (104-111) — `add_module` (`devise/lib/devise.rb:397-441`) inserts into `Devise::ALL`/`STRATEGIES`/`ROUTES` and sets up a `Devise::Models` **autoload** (devise.rb:433-437), so the model file (which requires the hook file at its line 3-4) loads only when an app declares `devise :session_limitable`. The engine is minimal: `DeviseSecurity::Engine < ::Rails::Engine` + `ActiveSupport.on_load(:action_controller)` + `to_prepare` patches (`devise-security/lib/devise-security/rails.rb:4-18`). Devise also exposes `Devise.warden { |config| ... }` for warden *config* (strategies, failure app) — blocks stored at `devise/lib/devise.rb:453-455`, executed in `configure_warden!` at devise.rb:504.

**Recommended pattern for the sessions gem** (soft-depend on both Devise and Warden):

```ruby
class Sessions::Railtie < ::Rails::Railtie
  initializer "sessions.warden" do
    # Bundler.require has already loaded every gem in the Gemfile,
    # so defined?(Warden) is reliable here regardless of Gemfile order.
    require "sessions/warden_hooks" if defined?(::Warden::Manager)
  end
end
```

Why this is safe: (a) all gems are loaded before initializers run, so `defined?(::Warden::Manager)` is decisive; (b) hook arrays are class-level on `Warden::Manager` and read live per request (`warden/lib/warden/hooks.rb:67-69`, `warden/lib/warden/manager.rb:51-53`) — registration just has to precede the first request, and middleware insertion (done by Devise's engine, `devise/lib/devise/rails.rb:11-13`) is independent of hook registration; (c) no `require "warden"` from our gem → zero load-order coupling and the gem stays inert in non-Warden apps. Guard Devise-specific lookups (`Devise.mappings`, `Devise.friendly_token`) behind `defined?(::Devise)` inside the hook bodies. Do **not** rely on `ActiveSupport.on_load(:warden)` — no such load hook exists. Ordering note: Devise's own hooks register at model-class load (eager-load, after initializers), so our initializer-registered hooks run **before** trackable/timeoutable in `_run_callbacks` order; if we ever need to run after them, register ours lazily too (e.g. from `to_prepare`) or tolerate both orders (preferred).

## Implications for the sessions gem

Recommended hook set (all in one `sessions/warden_hooks.rb`):

1. **Record login success + create session row** — `Warden::Manager.after_set_user except: :fetch do |record, warden, opts|`, guarded by `warden.authenticated?(opts[:scope])` && `opts[:store] != false` && our skip flags (mirror trackable.rb:8 + rememberable.rb:5 + session_limitable.rb:7-11 guards). Generate token (`SecureRandom`/`Devise.friendly_token`-equivalent), write `warden.session(opts[:scope])['sessions_token'] = token` (template: session_limitable.rb:13), insert row with: scope, polymorphic owner, IP/UA from `warden.request` (an `ActionDispatch::Request` per warden_compat.rb:4-6), login method from `opts[:event]` + `warden.winning_strategy&.class` (§1 matrix), provider from `warden.request.env["omniauth.auth"]` if present.
2. **Record failure with attempted identity** — `Warden::Manager.before_failure do |env, opts|`: persist `opts[:scope]/:action/:message/:attempted_path` (manager.rb:138-142); identity via `request.params[opts[:scope].to_s]` filtered to `request.post? && hash present` to exclude plain 401 page hits and timeouts (§3). Never store the password key.
3. **Per-request validate-and-touch** — `Warden::Manager.after_set_user only: :fetch`: look up row by `warden.session(scope)['sessions_token']`; if missing/revoked → `warden.raw_session.clear; warden.logout(scope); throw :warden, scope: scope, message: :session_revoked` (template: session_limitable.rb:39-41); else touch `last_seen_at` **throttled** (devise-security's expirable does an unthrottled `update_column` every request — expirable.rb:7-12 — don't copy that). Guard `options[:store] != false` (timeoutable.rb:13).
4. **Record logout** — `Warden::Manager.before_logout do |record, warden, opts|`: mark row ended/revoked; remember it fires per scope, also for *forced* logouts (timeout throw at timeoutable.rb:27-28, activatable.rb:9-10, our own revocation) — record a reason when we can infer one (we threw it), else "logout".

Edge cases to handle explicitly:
- **Remember-me**: a cookie re-auth is `:authentication` with `winning_strategy == Devise::Strategies::Rememberable` (§4) — it's a genuinely new Rack session: create a new row (or re-link via the remember cookie's `[id, token, ts]` triple) rather than ignoring it; CSRF is *not* rotated there.
- **Timeoutable**: its hook may `throw` on the same `:fetch` event our hooks use; tolerate running before or after it (a touched-then-timed-out session is harmless noise). Honor `env['devise.skip_timeout']` semantics on sign-in/out requests (sessions_controller.rb:7).
- **`sign_in_after_reset_password` / sign-up auto-login**: both call the `sign_in` helper (`devise/app/controllers/devise/passwords_controller.rb:43`, `registrations_controller.rb:100`) → event `:set_user` → our hook 1 fires (correct: it IS a new login). Confirmations controller never auto-signs-in (no `sign_in` call in `confirmations_controller.rb`).
- **`bypass_sign_in`** (password change keep-alive): zero callbacks (sign_in_out.rb:56-60) — same session continues; our token stays valid. Document it.
- **API / HTTP Basic / token auth**: `skip_session_storage [:http_auth]` makes the strategy `store? == false` (`devise/lib/devise/strategies/authenticatable.rb:13-15`) → `set_user` with `store: false` still fires `after_set_user` **on every request** — without the `opts[:store] != false` guard we'd create a session row per API call. Same guard protects against devise-jwt-style integrations.
- **Paranoid mode**: failure message is `:invalid` instead of `:not_found_in_database` (database_authenticatable.rb:22-25) — store the symbol verbatim, don't infer user existence.
- **Rack SID**: never persist it as the session identifier — `:renew` (proxy.rb:178-186) rotates it at commit after login. Our own token in the warden scoped session is the stable handle; it also gets cleaned up by warden itself on logout (proxy.rb:276).
- **Multi-scope**: rows carry scope + polymorphic owner; `sign_out_all_scopes` produces one `before_logout` per scope (§6).
