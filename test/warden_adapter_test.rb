# frozen_string_literal: true

require "test_helper"
require "rack/test"
require "rack/session"
require "timeout"

# The Devise/Warden adapter, exercised against a REAL Warden::Manager rack
# stack — the same class-level hook ABI Devise rides (warden 1.2.9, frozen
# since 2020). Devise-specific sugar (mappings, paranoid messages) is
# duck-typed on top of these exact hooks; the gem's production incubation
# apps run full Devise on this adapter.
class WardenAdapterTest < ActiveSupport::TestCase
  include Rack::Test::Methods

  self.use_transactional_tests = false

  SESSION_SECRET = SecureRandom.hex(64)

  # A Devise-shaped password strategy: credentials POSTed under the scope
  # key (user[email] / user[password]), fail!(:invalid) on mismatch.
  class PasswordStrategy < Warden::Strategies::Base
    def valid?
      params["user"].is_a?(Hash)
    end

    def authenticate!
      user = User.find_by(email_address: params["user"]["email"].to_s.downcase)
      if user&.authenticate(params["user"]["password"])
        success!(user)
      else
        fail!(:invalid)
      end
    end
  end

  Warden::Strategies.add(:test_password, PasswordStrategy)

  # devise-two-factor's SINGLE-PHASE shape: password AND OTP consumed by one
  # strategy (the real TwoFactorAuthenticatable subclasses Devise's
  # DatabaseAuthenticatable and validates `otp_attempt` before deferring to
  # password validation) — warden signs in exactly once, at full auth.
  class TwoFactorAuthenticatable < PasswordStrategy
    def authenticate!
      otp = params["user"]["otp_attempt"]
      return fail!(:invalid_otp) if otp.present? && otp != "123456"

      super
    end
  end
  Warden::Strategies.add(:test_two_factor, TwoFactorAuthenticatable)

  # Passkey-first shape (devise-passkeys' PasskeyAuthenticatable /
  # warden-webauthn's Strategy): no password anywhere; the class NAME is
  # what the classifier maps.
  class PasskeyAuthenticatable < Warden::Strategies::Base
    def valid? = params.key?("passkey_email")

    def authenticate!
      user = User.find_by(email_address: params["passkey_email"].to_s.downcase)
      user ? success!(user) : fail!(:credential_invalid)
    end
  end
  Warden::Strategies.add(:test_passkey, PasskeyAuthenticatable)

  # Devise rememberable shape: a non-password strategy restores the user
  # from a long-lived cookie and marks the login as "remembered" by class
  # name, exactly what Sessions::Classifier consumes.
  class RememberableAuthenticatable < Warden::Strategies::Base
    def valid? = env["HTTP_X_REMEMBERED_USER_EMAIL"].present?

    def authenticate!
      user = User.find_by(email_address: env["HTTP_X_REMEMBERED_USER_EMAIL"].to_s.downcase)
      user ? success!(user) : fail!(:invalid)
    end
  end
  Warden::Strategies.add(:test_rememberable, RememberableAuthenticatable)

  # devise-otp's TWO-PHASE shape: its replaced database_authenticatable
  # strategy `redirect!`s OTP-enabled users to a challenge INSTEAD of
  # calling success! — no warden sign-in, so no session may exist at the
  # password phase (the OTP flag rides a param here; the real gem checks
  # resource.otp_enabled?).
  class OtpGatedPasswordStrategy < PasswordStrategy
    def authenticate!
      user = User.find_by(email_address: params["user"]["email"].to_s.downcase)
      if user&.authenticate(params["user"]["password"]) && params["user"]["otp_enabled"]
        redirect!("/otp/challenge")
      else
        super
      end
    end
  end
  Warden::Strategies.add(:test_otp_gated, OtpGatedPasswordStrategy)

  # The inner app: a tiny router covering every warden seam the adapter
  # attaches to.
  INNER_APP = lambda do |env|
    warden = env["warden"]
    request = Rack::Request.new(env)

    case [request.request_method, request.path]
    in ["POST", "/login"]
      warden.authenticate!(:test_password)
      [200, {}, ["hello #{warden.user.email_address}"]]
    in ["POST", "/login_api"]
      warden.authenticate!(:test_password, store: false)
      [200, {}, ["api hello"]]
    in ["POST", "/login_skip"]
      user = User.find_by(email_address: request.params["user"]["email"])
      warden.set_user(user, sessions_skip: true)
      [200, {}, ["skipped login"]]
    in ["POST", "/login_admin"]
      user = User.find_by(email_address: request.params["user"]["email"])
      warden.set_user(user, scope: :admin)
      [200, {}, ["admin login"]]
    in ["GET", "/admin_me"]
      user = warden.user(:admin)
      [200, {}, ["admin: #{user&.email_address || "none"}"]]
    in ["POST", "/stash"]
      warden.raw_session["host_data"] = "cart-42"
      [200, {}, ["stashed"]]
    in ["GET", "/current_scope"]
      row = Sessions.current(ActionDispatch::Request.new(env), scope: request.params["scope"])
      [200, {}, ["row scope: #{row&.scope || "none"}"]]
    in ["POST", "/reauth"]
      # devise-passkeys' sudo confirm: `sign_in(..., event:
      # :passkey_reauthentication)` → warden.set_user with that event.
      warden.set_user(warden.user, event: :passkey_reauthentication)
      [200, {}, ["reauthed"]]
    in ["POST", "/login_2fa"]
      warden.authenticate!(:test_two_factor)
      [200, {}, ["2fa hello"]]
    in ["POST", "/login_passkey"]
      warden.authenticate!(:test_passkey)
      [200, {}, ["passkey hello"]]
    in ["POST", "/login_otp_gated"]
      warden.authenticate!(:test_otp_gated)
      [200, {}, ["gated hello"]]
    in ["POST", "/otp/verify"]
      # devise-otp's OtpCredentialsController#update: a plain sign_in with
      # NO strategy — the README recipe tags the request first so the row
      # classifies password + totp instead of unknown.
      user = User.find_by(email_address: request.params["user"]["email"].to_s.downcase)
      Sessions.tag(request, method: :password, detail: { second_factor: "totp" })
      warden.set_user(user, scope: :user)
      [200, {}, ["otp verified"]]
    in ["GET", "/me"]
      warden.authenticate!(:test_password)
      [200, {}, ["me: #{warden.user.email_address}"]]
    in ["GET", "/me.json"]
      warden.authenticate!(:test_password)
      [200, { "content-type" => "application/json" }, [%({"me":"#{warden.user.email_address}"})]]
    in ["GET", "/native/configurations/ios/v1.json"]
      warden.authenticate!(:test_rememberable)
      [200, { "content-type" => "application/json" }, ['{"settings":{}}']]
    in ["GET", "/native/entry"]
      warden.authenticate!(:test_rememberable)
      [200, { "content-type" => "text/html" }, ["native entry: #{warden.user.email_address}"]]
    in ["DELETE", "/logout"]
      warden.user # deserialize first, like Devise's sign_out helper does
      warden.logout
      [200, {}, ["bye"]]
    else
      [404, {}, ["?"]]
    end
  end

  def app
    @app ||= Rack::Builder.new do
      use Rack::Session::Cookie, secret: SESSION_SECRET
      use Warden::Manager do |config|
        config.default_strategies :test_password
        config.default_scope = :user # what Devise configures
        config.failure_app = ->(env) { [401, {}, ["denied: #{env["warden.options"][:message]}"]] }
      end
      run INNER_APP
    end.to_app
  end

  def login!(user, password: "s3kr1t-pass")
    post "/login", { "user" => { "email" => user.email_address, "password" => password } },
         { "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }
  end

  # --- Hook 1: login ------------------------------------------------------------

  test "a warden login mints a token-per-row session" do
    user = create_user
    login!(user)

    assert_equal 200, last_response.status
    row = user.sessions.sole
    assert_equal "user", row.scope
    assert_not_nil row.token_digest
    assert_equal "Chrome", row.browser_name
    assert_equal "password", row.auth_method # nested credentials POST
    assert_equal 1, Sessions::Event.logins.count
  end

  test "the raw token lives only in the rack session, never in the database" do
    user = create_user
    login!(user)

    id, token = last_request.env["rack.session"]["warden.user.user.session"]["sessions"]
    row = Session.find(id)
    assert row.sessions_token_matches?(token)
    refute_equal token, row.token_digest
    refute(row.attributes.values.grep(String).any? { |value| value.include?(token) })
  end

  test "store:false (API/token auth) NEVER mints session rows" do
    user = create_user

    3.times do
      post "/login_api", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass" } }
      assert_equal 200, last_response.status
    end

    assert_equal 0, user.sessions.count
  end

  test "sign_in(user, sessions_skip: true) skips tracking — stickily" do
    user = create_user
    post "/login_skip", { "user" => { "email" => user.email_address } }
    assert_equal 0, user.sessions.count

    get "/me" # the sticky flag must also stop the fetch hook from adopting
    assert_equal 200, last_response.status
    assert_equal 0, user.sessions.count
  end

  test "a reauthentication event (sudo confirm) never mints a second row" do
    user = create_user
    post "/login", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass" } },
         { "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }
    row_ids = user.sessions.ids
    assert_equal 1, row_ids.size

    post "/reauth"

    assert_equal 200, last_response.status
    assert_equal row_ids, user.sessions.ids,
                 "a sudo-style reauth must keep the live tracked row, not orphan or duplicate it"
    assert_equal 1, Sessions::Event.logins.count, "reauth is not a fresh login in the trail"
  end

  # --- Two-factor flows, each mainstream warden shape end to end ----------------

  test "single-phase 2FA (devise-two-factor shape): one sign-in, password + totp" do
    user = create_user
    post "/login_2fa", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass",
                                     "otp_attempt" => "123456" } },
         { "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }

    assert_equal 200, last_response.status
    row = user.sessions.sole
    assert_equal "password", row.auth_method
    assert_equal "totp", row.second_factor
    assert Sessions::Event.logins.sole.second_factor?
  end

  test "single-phase 2FA without an OTP attempt (2FA off for this user) stays plain password" do
    user = create_user
    post "/login_2fa", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass" } }

    row = user.sessions.sole
    assert_equal "password", row.auth_method
    refute row.second_factor?
  end

  test "a wrong OTP in single-phase 2FA records the failure and mints nothing" do
    user = create_user
    post "/login_2fa", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass",
                                     "otp_attempt" => "000000" } }

    assert_equal 401, last_response.status
    assert_equal 0, user.sessions.count
    failure = Sessions::Event.failed_logins.sole
    assert_equal "invalid_otp", failure.failure_reason
    assert_equal user.email_address, failure.identity
  end

  test "passkey-first strategies classify as passkey end to end" do
    user = create_user
    post "/login_passkey", { "passkey_email" => user.email_address },
         { "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }

    assert_equal 200, last_response.status
    row = user.sessions.sole
    assert_equal "passkey", row.auth_method
    assert_equal "passkey", Sessions::Event.logins.sole.auth_method
  end

  test "two-phase 2FA (devise-otp shape): the password phase mints NOTHING" do
    user = create_user
    post "/login_otp_gated", { "user" => { "email" => user.email_address,
                                           "password" => "s3kr1t-pass", "otp_enabled" => "1" } }

    assert_equal 302, last_response.status
    assert_equal "/otp/challenge", URI(last_response.headers["Location"]).path
    assert_equal 0, user.sessions.count, "no session may exist before the second factor"
    assert_equal 0, Sessions::Event.logins.count
  end

  test "completing the two-phase challenge signs in via the tag recipe: password + totp" do
    user = create_user
    post "/login_otp_gated", { "user" => { "email" => user.email_address,
                                           "password" => "s3kr1t-pass", "otp_enabled" => "1" } }
    post "/otp/verify", { "user" => { "email" => user.email_address } },
         { "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }

    assert_equal 200, last_response.status
    row = user.sessions.sole
    assert_equal "password", row.auth_method
    assert_equal "totp", row.second_factor
    assert_equal "totp", Sessions::Event.logins.sole.second_factor
  end

  test "env['sessions.skip'] silences a single request" do
    user = create_user
    post "/login", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass" } },
         { "sessions.skip" => true }

    assert_equal 200, last_response.status
    assert_equal 0, user.sessions.count
  end

  # --- Hook 2: per-request validation + touch -------------------------------------

  test "remembered native JSON bootstrap is deferred until the WebView document request" do
    user = create_user

    get "/native/configurations/ios/v1.json", {}, remembered_json_headers(user)
    assert_equal 200, last_response.status
    assert_equal 0, user.sessions.count
    assert_equal 0, Sessions::Event.count

    get "/native/configurations/ios/v1.json", {}, json_native_headers
    assert_equal 200, last_response.status
    assert_equal 0, user.sessions.count
    assert_equal 0, Sessions::Event.count

    get "/native/entry", {}, html_native_headers
    assert_equal 200, last_response.status

    row = user.sessions.sole
    assert_equal UserAgents::NATIVE_IOS, row.user_agent
    assert_equal "native_ios", row.device_type
    assert_equal "password", row.auth_method
    assert_equal({ "remembered" => true }, row.auth_detail)

    event = Sessions::Event.logins.sole
    assert_equal row.id, event.session_id
    assert_equal "native_ios", event.device_type
    assert_equal "password", event.auth_method
    assert_equal({ "remembered" => true }, event.auth_detail)
  end

  test "remembered HTML requests still record the login immediately" do
    user = create_user

    get "/native/entry", {}, remembered_html_headers(user)

    assert_equal 200, last_response.status
    row = user.sessions.sole
    assert_equal UserAgents::NATIVE_IOS, row.user_agent
    assert_equal({ "remembered" => true }, row.auth_detail)
    assert_equal 1, Sessions::Event.logins.count
  end

  test "remembered restores for an already-live device are quiet housekeeping" do
    user = create_user
    existing = user.sessions.build(
      scope: "user",
      ip_address: "203.0.113.7",
      user_agent: UserAgents::NATIVE_IOS,
      token_digest: Sessions.token_digest(Sessions.generate_token),
      device_id: "device-1",
      auth_method: "password",
      auth_detail: { "remembered" => true }
    )
    existing.sessions_suppress_login_event = true
    Sessions.with_request(fake_request(ua: UserAgents::NATIVE_IOS)) { existing.save! }
    Sessions::Event.delete_all

    Sessions::Adapters::Warden.stubs(:device_id_from_request).returns("device-1")
    get "/native/entry", {}, remembered_html_headers(user)

    assert_equal 200, last_response.status
    assert Session.exists?(existing.id), "known-device remember-me restores reuse the live row"
    assert_equal 1, user.sessions.count
    assert_equal existing.id, user.sessions.sole.id
    assert_equal 0, Sessions::Event.count, "remember-me refreshes for a known device are not user-visible events"

    get "/me", {}, html_native_headers
    assert_equal 200, last_response.status
    assert_equal 1, user.sessions.count
  end

  test "resuming a session validates the token and touches last_seen_at" do
    user = create_user
    login!(user)
    row = user.sessions.sole
    assert_nil row.last_seen_at

    get "/me"

    assert_equal 200, last_response.status
    assert_not_nil row.reload.last_seen_at
  end

  test "revoking the row remotely kicks the device on its next request" do
    user = create_user
    login!(user)
    user.sessions.sole.revoke!(reason: :user_revoked)

    get "/me"

    assert_equal 401, last_response.status
    assert_includes last_response.body, "session_revoked"
    # SCOPE-PRECISE teardown: this scope's warden entries are gone (nothing
    # lingers to retry with), but the kick never nukes the whole rack
    # session — other scopes and unrelated host data survive.
    session_hash = last_request.env["rack.session"].to_hash
    refute session_hash.key?("warden.user.user.key")
    refute session_hash.key?("warden.user.user.session")
  end

  test "a tracking-database outage fails OPEN — never logs anyone out" do
    user = create_user
    login!(user)

    # The sessions table goes away mid-request (an outage, a migration, a
    # timeout). An errored lookup is NOT a revocation: the request must
    # proceed untracked, not kick every active session.
    Session.stubs(:find_by).raises(ActiveRecord::StatementInvalid.new("sessions table unreachable"))

    get "/me"

    assert_equal 200, last_response.status, "a tracking outage must never log anyone out"
    assert_includes last_response.body, "me: #{user.email_address}"
  end

  test "kicking one scope leaves other scopes and host session data alive" do
    user = create_user
    admin = create_user
    login!(user)
    post "/login_admin", { "user" => { "email" => admin.email_address } }
    post "/stash" # unrelated host session data (a cart, a locale…)

    user.sessions.sole.revoke!(reason: :admin_revoked)
    get "/me"
    assert_equal 401, last_response.status, "the user scope is kicked"

    get "/admin_me"
    assert_includes last_response.body, "admin: #{admin.email_address}",
                    "the admin scope must survive a user-scope kick"
    assert_equal "cart-42", last_request.env["rack.session"]["host_data"],
                 "host session data must survive a kick"
  end

  test "Sessions.current(scope:) picks the right row in multi-scope sessions" do
    user = create_user
    admin = create_user
    login!(user)
    post "/login_admin", { "user" => { "email" => admin.email_address } }

    get "/current_scope", { "scope" => "admin" }
    assert_includes last_response.body, "row scope: admin"

    get "/current_scope", { "scope" => "user" }
    assert_includes last_response.body, "row scope: user"
  end

  test "a tampered token digest kicks the session" do
    user = create_user
    login!(user)
    user.sessions.sole.update_columns(token_digest: Sessions.token_digest("attacker"))

    get "/me"

    assert_equal 401, last_response.status
  end

  test "opt-in idle expiry kicks and records at resume" do
    user = create_user
    login!(user)
    Sessions.config.idle_timeout = 1.hour
    user.sessions.sole.update_columns(created_at: 2.hours.ago)

    get "/me"

    assert_equal 401, last_response.status
    assert_equal 0, user.sessions.count
    assert_equal 1, Sessions::Event.expirations.count
  end

  test "sessions that predate the gem are ADOPTED, never kicked" do
    user = create_user
    # A pre-gem login: authenticated rack session with no sessions token.
    post "/login", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass" } },
         { "sessions.skip" => true }
    assert_equal 0, user.sessions.count

    get "/me" # first request after the gem deploys

    assert_equal 200, last_response.status
    row = user.sessions.sole
    assert_equal({ "adopted" => true }, row.auth_detail)
    assert_equal 0, Sessions::Event.logins.count # adoption is not a login

    get "/me" # and the adopted session keeps working
    assert_equal 200, last_response.status
    assert_equal 1, user.sessions.count
  end

  test "pre-gem native JSON requests do not adopt until a document request names the device" do
    user = create_user
    post "/login", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass" } },
         { "sessions.skip" => true }
    frozen_cookie = last_response.headers["Set-Cookie"].to_s.split(";").first

    clear_cookies
    get "/me.json", {}, { "HTTP_COOKIE" => frozen_cookie }.merge(json_native_headers)
    assert_equal 200, last_response.status
    assert_equal 0, user.sessions.count

    get "/me", {}, { "HTTP_COOKIE" => frozen_cookie }.merge(html_native_headers)
    assert_equal 200, last_response.status

    row = user.sessions.sole
    assert_equal UserAgents::NATIVE_IOS, row.user_agent
    assert_equal({ "adopted" => true }, row.auth_detail)
    assert_equal 0, Sessions::Event.count
  end

  test "a client that drops Set-Cookie can't mint unbounded adopted rows" do
    user = create_user
    # A pre-gem login: authenticated rack session with no sessions token…
    post "/login", { "user" => { "email" => user.email_address, "password" => "s3kr1t-pass" } },
         { "sessions.skip" => true, "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }
    frozen_cookie = last_response.headers["Set-Cookie"].to_s.split(";").first

    # …replayed by a client that forwards cookies READ-ONLY (a native HTTP
    # layer that attaches the WebView's cookie but discards our Set-Cookie
    # — the production shape): every request re-enters adoption.
    clear_cookies
    4.times do
      get "/me", {}, { "HTTP_COOKIE" => frozen_cookie, "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }
      assert_equal 200, last_response.status
    end

    assert_equal 1, user.sessions.count,
                 "re-entered adoption must reuse the recent adopted row, never mint per request"
    assert_equal({ "adopted" => true }, user.sessions.sole.auth_detail)
    assert_equal 0, Sessions::Event.count, "and the loop leaves no junk in the trail"
  end

  test "adoption dedupes across webview and native HTTP user agents" do
    user = create_user

    adopt!(user, ua: UserAgents::NATIVE_ANDROID)
    adopt!(user, ua: "MyApp Android 2.4.1 (build 241; Android 16; sdk 36; Pixel 8)")

    assert_equal 1, user.sessions.count,
                 "one physical device can present both WebView and native-client UAs"
    assert_equal({ "adopted" => true }, user.sessions.sole.auth_detail)
  end

  test "adoption reuses adopted rows older than the old 24 hour window" do
    user = create_user
    old_row = create_adopted_row_for(user, ua: UserAgents::NATIVE_ANDROID, created_at: 2.days.ago)

    adopt!(user, ua: UserAgents::NATIVE_ANDROID)

    assert_equal [old_row.id], user.sessions.ids,
                 "adoption is a one-time pre-gem marker, not a one-per-day row"
    assert_not_nil old_row.reload.last_seen_at
  end

  test "concurrent adoption bursts collapse to one adopted row" do
    user = create_user
    thread_count = 4
    errors = Queue.new

    with_create_row_barrier(thread_count) do
      threads = thread_count.times.map do
        Thread.new do
          ActiveRecord::Base.connection_pool.with_connection do
            adopt!(user, ua: UserAgents::NATIVE_ANDROID)
          end
        rescue StandardError => e
          errors << e
        end
      end

      threads.each(&:join)
    end

    raise errors.pop unless errors.empty?

    assert_equal 1, user.sessions.count,
                 "parallel requests with no SESSION_KEY must not all win the adoption insert"
    assert_equal({ "adopted" => true }, user.sessions.sole.auth_detail)
    assert_equal 0, Sessions::Event.count
  end

  # --- Hook 3: failures --------------------------------------------------------------

  test "a wrong password records the failure with the typed identity, verbatim reason" do
    user = create_user
    login!(user, password: "wrong")

    assert_equal 401, last_response.status
    event = Sessions::Event.failed_logins.sole
    assert_equal user.email_address, event.identity
    assert_equal "invalid", event.failure_reason # warden's symbol, never embellished
    assert_equal "user", event.scope
    assert_equal "/login", event.metadata["attempted_path"]
  end

  test "failure identity also reads email_address (the omakase-era key)" do
    # Devise apps configured with `authentication_keys = [:email_address]`
    # post user[email_address]; the strategy fails (it reads "email"), and
    # the failure row must still carry the typed identity for ATO triage and
    # repeated_failed_logins.
    post "/login", { "user" => { "email_address" => "Ghost@Example.com", "password" => "nope" } }

    assert_equal 401, last_response.status
    assert_equal "ghost@example.com", Sessions::Event.failed_logins.sole.identity
  end

  test "plain unauthenticated page hits record NO failure (not a credentials POST)" do
    get "/me"

    assert_equal 401, last_response.status
    assert_equal 0, Sessions::Event.failed_logins.count
  end

  test "the password itself is never persisted on failures" do
    user = create_user
    login!(user, password: "hunter2-secret")

    event = Sessions::Event.failed_logins.sole
    refute(event.attributes.values.grep(String).any? { |value| value.include?("hunter2-secret") })
  end

  # --- Hook 4: logout ------------------------------------------------------------------

  test "logout destroys the row and records a logout event" do
    user = create_user
    login!(user)

    delete "/logout"

    assert_equal 0, user.sessions.count
    assert_equal 1, Sessions::Event.logouts.count
    assert_equal 0, Sessions::Event.revocations.count
  end

  # --- Multi-scope ------------------------------------------------------------------------

  test "a second scope gets its own row carrying the scope" do
    user = create_user
    post "/login_admin", { "user" => { "email" => user.email_address } }

    row = user.sessions.sole
    assert_equal "admin", row.scope
  end

  # Devise's activatable hook logs out + throws from after_set_user when an
  # account is unconfirmed/locked. Warden deletes @users[scope] BEFORE
  # running before_logout callbacks, so a logout hook that touches
  # `warden.session` re-authenticates → re-fires activatable → infinite
  # recursion (found incubating against a real Devise app). Our logout hook
  # must read the raw session; this pins it.
  test "a Devise-activatable-style logout-and-throw hook cannot recurse through our hooks" do
    user = create_user
    login!(user)

    # Registered AFTER the gem's hooks (same order as Devise's model hooks,
    # which load after initializers). Simulates an account turning inactive.
    # Identity-based check: plain Warden's default serializer marshals the
    # whole user into the session, so attribute edits wouldn't be visible.
    inactive_ids = [user.id]
    Warden::Manager.after_set_user do |record, warden, opts|
      if inactive_ids.include?(record.id)
        warden.logout(opts[:scope])
        throw :warden, scope: opts[:scope], message: :unconfirmed
      end
    end

    get "/me" # previously: SystemStackError

    assert_equal 401, last_response.status
    assert_includes last_response.body, "unconfirmed"
    assert_equal 1, Sessions::Event.logouts.count # the forced logout was recorded
    assert_equal 0, user.sessions.count
  ensure
    # The hook arrays are class-level state — drop the throwing hook so it
    # can't leak into other tests.
    hooks = Warden::Manager.instance_variable_get(:@_after_set_user)
    hooks&.pop
  end

  test "hooks are installed exactly once" do
    assert Sessions::Adapters::Warden.installed?

    before = Warden::Manager.instance_variable_get(:@_after_set_user)&.size
    Sessions::Adapters::Warden.install!
    after = Warden::Manager.instance_variable_get(:@_after_set_user)&.size

    assert_equal before, after
  end

  private

  FakeWarden = Struct.new(:request, :session_data) do
    def session(scope)
      session_data[scope.to_s] ||= {}
    end
  end

  def adopt!(user, ua:, scope: :user)
    Sessions::Adapters::Warden.adopt_preexisting_session(user, fake_warden(ua: ua), scope)
  end

  def fake_warden(ua:)
    FakeWarden.new(fake_request(ua: ua), {})
  end

  CFNETWORK_IOS = "RailsFast/5 CFNetwork/3826.500.131 Darwin/24.5.0"

  def remembered_json_headers(user)
    json_native_headers.merge("HTTP_X_REMEMBERED_USER_EMAIL" => user.email_address)
  end

  def remembered_html_headers(user)
    html_native_headers.merge("HTTP_X_REMEMBERED_USER_EMAIL" => user.email_address)
  end

  def json_native_headers
    {
      "HTTP_ACCEPT" => "application/json",
      "HTTP_USER_AGENT" => CFNETWORK_IOS
    }
  end

  def html_native_headers
    {
      "HTTP_ACCEPT" => "text/html,application/xhtml+xml",
      "HTTP_USER_AGENT" => UserAgents::NATIVE_IOS
    }
  end

  def create_adopted_row_for(user, ua:, created_at:)
    row = user.sessions.build(
      scope: "user",
      ip_address: "203.0.113.7",
      user_agent: ua,
      token_digest: Sessions.token_digest(Sessions.generate_token),
      auth_detail: { "adopted" => true }
    )
    row.sessions_suppress_login_event = true
    Sessions.with_request(fake_request(ua: ua)) { row.save! }
    row.update_columns(created_at: created_at, updated_at: created_at, last_seen_at: nil)
    row
  end

  def with_create_row_barrier(thread_count, &block)
    original = Sessions::Adapters::Warden.method(:create_row_for)
    ready = Queue.new
    release = Queue.new

    replacement = lambda do |*args, **kwargs|
      ready << true
      release.pop
      original.call(*args, **kwargs)
    end

    barrier = Thread.new do
      Timeout.timeout(5) { thread_count.times { ready.pop } }
      thread_count.times { release << true }
    end

    Sessions::Adapters::Warden.stub(:create_row_for, replacement, &block)
  ensure
    barrier&.join
  end
end
