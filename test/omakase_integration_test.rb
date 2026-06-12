# frozen_string_literal: true

require "test_helper"

# Full request-cycle tests against the dummy app's VENDORED `rails g
# authentication` code — the zero-app-edits story, end to end.
class OmakaseIntegrationTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email_address: "javi@example.com", password: "s3kr1t-pass")
  end

  teardown do
    Sessions.reset!
    Session.delete_all
    Sessions::Event.delete_all
    User.delete_all
  end

  test "signing in creates an enriched row and a linked login event" do
    sign_in_as @user, ua: UserAgents::SAFARI_IPHONE
    assert_redirected_to "/"

    row = @user.sessions.sole
    assert_equal "Safari", row.browser_name
    assert_equal "iOS", row.os_name
    assert_equal "smartphone", row.device_type
    assert_equal "password", row.auth_method
    assert_equal "127.0.0.1", row.ip_address

    event = Sessions::Event.logins.sole
    assert_equal row.id, event.session_id
    assert_equal @user, event.authenticatable
    assert_equal "sessions#create", event.context
  end

  test "a native app login is recognized end to end" do
    sign_in_as @user, ua: UserAgents::NATIVE_ANDROID

    row = @user.sessions.sole
    assert row.native_android?
    assert_equal "MyApp 2.4.1 on Pixel 8 (Android 16)", row.device_name
  end

  test "browsing touches last_seen_at, throttled" do
    sign_in_as @user
    row = @user.sessions.sole
    assert_nil row.last_seen_at

    get "/"
    assert_response :success
    first_touch = row.reload.last_seen_at
    assert_not_nil first_touch

    get "/"
    assert_equal first_touch, row.reload.last_seen_at # inside the window: no write

    travel 10.minutes do
      get "/"
      assert_operator row.reload.last_seen_at, :>, first_touch
    end
  end

  test "signing out destroys the row and records a logout (not a revocation)" do
    sign_in_as @user

    delete "/session"
    assert_response :see_other

    assert_equal 0, @user.sessions.count
    assert_equal 1, Sessions::Event.logouts.count
    assert_equal 0, Sessions::Event.revocations.count

    get "/"
    assert_redirected_to "/session/new" # the cookie is now worthless
  end

  test "remote revocation logs the device out on its very next request" do
    sign_in_as @user
    get "/"
    assert_response :success

    @user.sessions.sole.revoke!(reason: :user_revoked) # from "another device"

    get "/"
    assert_redirected_to "/session/new"
    assert_equal 1, Sessions::Event.revocations.count
  end

  test "a wrong password records a failed_login with the typed identity" do
    post "/session", params: { email_address: "JAVI@example.com", password: "wrong" },
                     headers: { "HTTP_USER_AGENT" => UserAgents::FIREFOX_WINDOWS }
    assert_redirected_to "/session/new"

    event = Sessions::Event.failed_logins.sole
    assert_equal "javi@example.com", event.identity # normalized
    assert_equal "invalid_credentials", event.failure_reason
    assert_equal "Firefox", event.browser_name
    assert_nil event.authenticatable # never guess whether the account exists
    assert_equal 0, @user.sessions.count
  end

  test "an unknown email's failed attempt is still recorded — with no account linkage" do
    post "/session", params: { email_address: "nobody@example.com", password: "x" }

    event = Sessions::Event.failed_logins.sole
    assert_equal "nobody@example.com", event.identity
    assert_nil event.authenticatable
  end

  test "config.track_failed_logins = false silences the failure trail" do
    Sessions.config.track_failed_logins = false

    post "/session", params: { email_address: "javi@example.com", password: "wrong" }

    assert_equal 0, Sessions::Event.failed_logins.count
  end

  test "successful logins record no failure" do
    sign_in_as @user

    assert_equal 0, Sessions::Event.failed_logins.count
  end

  test "opt-in idle expiry revokes on the next request and kicks the device" do
    sign_in_as @user
    Sessions.config.idle_timeout = 1.hour
    @user.sessions.sole.update_columns(created_at: 2.hours.ago)

    get "/"

    assert_redirected_to "/session/new"
    assert_equal 0, @user.sessions.count
    assert_equal 1, Sessions::Event.expirations.count
  end

  test "without opt-in timeouts, ancient sessions keep working (never silently change lifetimes)" do
    sign_in_as @user
    @user.sessions.sole.update_columns(created_at: 5.years.ago)

    get "/"

    assert_response :success
  end

  test "password change via update revokes the trail-visible way (8.1 parity)" do
    sign_in_as @user
    other_device = create_session_for(@user, ua: UserAgents::FIREFOX_WINDOWS)

    @user.update!(password: "n3w-s3cret-pass")

    assert_equal 0, @user.sessions.count # anonymous-context change nukes everything
    assert Sessions::Event.revocations.where(revoked_reason: "password_change").count >= 2
    assert_nil Session.find_by(id: other_device.id)
  end

  test "the sign_in_as-style bare row (nil ip/UA) flows through the whole stack" do
    row = nil
    assert_nothing_raised { row = @user.sessions.create! }

    assert row.persisted?
    assert_equal "Unknown device", row.device_name
  end

  test "rate-limited sign-in attempts are recorded from the 8.1 notification" do
    skip "rate_limit notification ships in Rails 8.1" unless Rails.gem_version >= Gem::Version.new("8.1")

    11.times do
      post "/session", params: { email_address: "javi@example.com", password: "wrong" }
    end

    assert_operator Sessions::Event.failed_logins.where(failure_reason: "rate_limited").count, :>=, 1
  end

  test "rate limits OUTSIDE the sessions controller are not failed logins" do
    # A throttled password-reset burst (or any API endpoint's rate limit)
    # is not login activity — recording it would pollute the failed_login
    # vocabulary the alerts count on.
    request = ActionDispatch::Request.new(Rack::MockRequest.env_for("/passwords"))
    request.env["action_dispatch.request.path_parameters"] = { controller: "passwords", action: "create" }

    ActiveSupport::Notifications.instrument("rate_limit.action_controller",
                                            request: request, count: 11, to: 10)

    assert_equal 0, Sessions::Event.failed_logins.where(failure_reason: "rate_limited").count
  end

  test "Sessions.tag labels the next login (the passkey/One Tap seam)" do
    # `Sessions.tag(request, ...)` writes the label into the rack env before
    # sign-in; injecting that env key IS the tag, without monkeypatching the
    # controller (whose `create` is reached through the gem's own prepend).
    post "/session",
         params: { email_address: @user.email_address, password: "s3kr1t-pass" },
         env: { Sessions::Classifier::TAG_ENV_KEY => { method: :passkey, detail: { user_verified: true } } }

    row = @user.sessions.sole
    assert_equal "passkey", row.auth_method
    assert_equal({ "user_verified" => true }, row.auth_detail)
  end
end
