# frozen_string_literal: true

require "test_helper"

class SessionsFacadeTest < ActiveSupport::TestCase
  test "session_model resolves the configured class" do
    assert_equal Session, Sessions.session_model
  end

  test "tag stores the label on the request env" do
    request = fake_request
    Sessions.tag(request, method: :sso, provider: "okta", detail: { idp: "corp" })

    assert_equal({ method: :sso, provider: "okta", detail: { idp: "corp" } },
                 request.env[Sessions::Classifier::TAG_ENV_KEY])
  end

  test "tag tolerates nil requests" do
    assert_nil Sessions.tag(nil, method: :sso)
  end

  test "current finds the row through the omakase signed cookie" do
    user = create_user
    row = create_session_for(user)

    request = fake_request(env: Rails.application.env_config)
    request.cookie_jar.signed[:session_id] = row.id

    assert_equal row, Sessions.current(request)
  end

  test "current returns nil for an anonymous request" do
    assert_nil Sessions.current(fake_request)
    assert_nil Sessions.current(nil)
  end

  test "current prefers the omakase Current.session when set" do
    user = create_user
    row = create_session_for(user)
    Current.session = row

    assert_equal row, Sessions.current(fake_request)
  ensure
    Current.reset
  end

  test "track_login creates a classified row + event for manual integrations" do
    user = create_user
    request = fake_request(ua: UserAgents::NATIVE_IOS, ip: "203.0.113.7")

    row = Sessions.track_login(user, request, method: :sso, provider: "okta")

    assert row.persisted?
    assert_equal user, row.user
    assert_equal "sso", row.auth_method
    assert_equal "okta", row.auth_provider
    assert_equal "native_ios", row.device_type
    assert_equal 1, Sessions::Event.logins.count
  end

  test "track_login never raises (an invalid user yields nil + a warning)" do
    assert_nil Sessions.track_login(nil, fake_request)
  end

  test "record_failed_attempt is the manual failure seam" do
    event = Sessions.record_failed_attempt(fake_request(ua: UserAgents::CHROME_MAC),
                                           scope: :user,
                                           identity: "j@example.com",
                                           reason: :invalid_password,
                                           method: :passkey,
                                           detail: { error: "SignCountVerificationError" })

    assert_equal "failed_login", event.event
    assert_equal "passkey", event.auth_method
    assert_equal({ "error" => "SignCountVerificationError" }, event.auth_detail)
    assert_equal "invalid_password", event.failure_reason
  end

  test "record_failed_attempt respects track_failed_logins" do
    Sessions.config.track_failed_logins = false

    assert_nil Sessions.record_failed_attempt(fake_request, identity: "j@example.com")
    assert_equal 0, Sessions::Event.count
  end

  test "sweep! expires, prunes, and purges — each independently" do
    Sessions.config.idle_timeout = 1.hour
    Sessions.config.events_retention = 6.months

    user = create_user
    expired = create_session_for(user)
    expired.update_columns(created_at: 2.hours.ago)

    survivors = Array.new(3) { create_session_for(user) }
    survivors.each(&:touch_last_seen!)

    stale_event = Sessions::Event.record!(event: "login", occurred_at: 7.months.ago)
    fresh_event = Sessions::Event.record!(event: "login", occurred_at: 1.day.ago)

    # Lower the cap only now: at login time the cap is enforced eagerly
    # (tested in ModelTest), and we want the SWEEP to do the pruning here.
    Sessions.config.max_sessions_per_user = 2

    counts = Sessions.sweep!

    assert_equal 1, counts[:expired]
    assert_equal 1, counts[:pruned] # 4 rows - 1 expired = 3 > cap of 2
    assert_operator counts[:purged_events], :>=, 1
    assert_equal 2, user.sessions.live.count
    refute Sessions::Event.exists?(stale_event.id)
    assert Sessions::Event.exists?(fresh_event.id)
  end

  test "sweep! with no configuration only purges retention" do
    user = create_user
    ancient = create_session_for(user)
    ancient.update_columns(created_at: 10.years.ago)
    Sessions.config.max_sessions_per_user = nil

    counts = Sessions.sweep!

    assert_equal 0, counts[:expired]
    assert_equal 0, counts[:pruned]
    assert Session.exists?(ancient.id)
  end

  test "forget erases the user's sessions, trail, and typed identities" do
    user = create_user(email: "user@example.test")
    create_session_for(user)
    Sessions::Event.record_failure(fake_request, identity: "user@example.test", reason: :invalid)

    Sessions.forget(user)

    assert_equal 0, user.sessions.count
    assert_equal 0, Sessions::Event.where(authenticatable: user).count
    assert_equal 0, Sessions::Event.where(identity: "user@example.test").count
  end

  test "safely isolates errors and warns instead of raising" do
    result = Sessions.safely("test") { raise "boom" }

    assert_nil result
    assert_equal 42, Sessions.safely("test") { 42 }
  end

  test "token digests are SHA-256, deterministic, and never the raw token" do
    token = Sessions.generate_token

    assert_equal 64, token.length
    assert_equal Sessions.token_digest(token), Sessions.token_digest(token)
    refute_equal token, Sessions.token_digest(token)
    assert_equal 64, Sessions.token_digest(token).length
  end

  test "with_request restores the previous request even on raise" do
    outer = fake_request
    Sessions::Current.request = outer

    assert_raises(RuntimeError) do
      Sessions.with_request(fake_request) { raise "boom" }
    end

    assert_equal outer, Sessions::Current.request
  ensure
    Sessions::Current.reset
  end
end
