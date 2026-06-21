# frozen_string_literal: true

require "test_helper"

# The hard security requirements from the PRD, each as an executable
# assertion. The gem sits on the authentication hot path: a bug here can
# lock users out, leak personal data, or silently break sign-in — these
# tests are the contract that none of that can happen.
class SecurityTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email_address: "user@example.test", password: "s3kr1t-pass")
  end

  teardown do
    Sessions.reset!
    Session.delete_all
    Sessions::Event.delete_all
    User.delete_all
  end

  test "CHAOS: every hook and pipeline stage failing at once still signs the user in" do
    Sessions.configure do |config|
      config.ip_resolver = ->(_request) { raise "ip resolver exploded" }
      config.ua_parser = ->(_ua, _headers) { raise "parser exploded" }
      config.on_new_device = ->(**) { raise "mailer exploded" }
      config.on_session_revoked = ->(**) { raise "webhook exploded" }
      config.events = ->(_event) { raise "audit log exploded" }
    end
    Sessions::Classifier.stubs(:classify).raises(RuntimeError, "classifier exploded")
    Sessions::Geolocation.stubs(:locate).raises(RuntimeError, "geo exploded")

    sign_in_as @user
    assert_redirected_to "/"
    assert_equal 1, @user.sessions.count

    get "/"
    assert_response :success

    delete "/session"
    assert_response :see_other
    assert_equal 0, @user.sessions.live.count
  end

  test "even Event.record! itself failing never breaks a login" do
    Sessions::Event.stubs(:record!).raises(ActiveRecord::StatementInvalid, "events table is on fire")

    sign_in_as @user

    assert_redirected_to "/"
    assert_equal 1, @user.sessions.count
  end

  test "no secret ever reaches the log: not the password, not a session token" do
    log = StringIO.new
    original_logger = Rails.logger
    Rails.logger = ActiveSupport::Logger.new(log)

    # A failed attempt (carries the password in params)…
    post "/session", params: { email_address: @user.email_address, password: "super-secret-pw" }
    # …a successful login (mints omakase cookie credentials)…
    sign_in_as @user
    # …and a Devise-style tokened row.
    token = Sessions.generate_token
    create_session_for(@user, token_digest: Sessions.token_digest(token))

    output = log.string
    refute_includes output, "super-secret-pw"
    refute_includes output, "s3kr1t-pass"
    refute_includes output, token
  ensure
    Rails.logger = original_logger
  end

  test "a tampered signed cookie is an anonymous request, never a 500" do
    cookies[:session_id] = "garbage-not-signed"

    get "/"

    assert_redirected_to "/session/new"
  end

  test "a signed cookie for a raw-deleted session row is a clean redirect" do
    sign_in_as @user
    @user.sessions.sole.delete # raw delete: not even revocation bookkeeping

    get "/"

    assert_redirected_to "/session/new"
  end

  test "MySQL-style 255-char-truncated user agents still parse" do
    truncated = UserAgents::NATIVE_ANDROID[0, 255]

    device = Sessions::Device.parse(truncated)

    assert_equal "native_android", device.device_type
    assert_equal "MyApp", device.app_name
  end

  test "events store the failure symbol verbatim — account existence is never inferred" do
    # Paranoid-mode Devise sends :invalid for both unknown emails and wrong
    # passwords; whatever arrives is stored untouched.
    event = Sessions::Event.record_failure(fake_request(method: "POST"),
                                           identity: "ghost@example.com", reason: :invalid)

    assert_equal "invalid", event.failure_reason
    assert_nil event.authenticatable
  end

  test "the trail keeps no request bodies and no referrers" do
    refute_includes Sessions::Event.column_names, "referrer"
    refute_includes Sessions::Event.column_names, "body"
    refute_includes Sessions::Event.column_names, "params"
  end

  test "ip truncation happens before persistence — nothing un-truncated touches disk" do
    Sessions.config.ip_mode = :truncated

    sign_in_as @user
    row = @user.sessions.sole

    assert_equal "127.0.0.0", row.ip_address

    travel 10.minutes do
      get "/"
    end
    assert_equal "127.0.0.0", row.reload.last_seen_ip
  end

  test "the events purge respects retention to the row" do
    Sessions.config.events_retention = 30.days
    keep = Sessions::Event.record!(event: "login", occurred_at: 29.days.ago)
    purge = Sessions::Event.record!(event: "login", occurred_at: 31.days.ago)

    Sessions.sweep!

    assert Sessions::Event.exists?(keep.id)
    refute Sessions::Event.exists?(purge.id)
  end

  test "bots are visible in the trail but flagged, never named like devices" do
    sign_in_as @user, ua: UserAgents::GOOGLEBOT

    row = @user.sessions.sole
    assert row.bot?
    assert_match(/Bot/, row.device_name)
  end
end
