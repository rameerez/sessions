# frozen_string_literal: true

require "test_helper"

class ReauthenticationTest < ActiveSupport::TestCase
  KEY = "k" * 48

  setup do
    @user = User.create!(email_address: "reauth-#{SecureRandom.hex(4)}@example.test", password: "s3kr1t-pass")
    @session = Session.create!(user: @user)
    @previous_key = Sessions.config.reauthentication_key
    Sessions.config.reauthentication_key = KEY
  end

  teardown { Sessions.config.reauthentication_key = @previous_key }

  test "a session records a re-authentication and knows whether it is recent" do
    refute @session.reauthenticated_within?

    @session.reauthenticated!(method: :password)

    assert @session.reload.reauthenticated_within?
    assert_equal "password", @session.reauthentication_method
    refute @session.reauthenticated_within?(0.seconds)
  end

  test "an old re-authentication is not recent, and an ended session never is" do
    @session.reauthenticated!(at: 10.minutes.ago)
    refute @session.reauthenticated_within?(5.minutes)

    @session.reauthenticated!
    @session.end!(reason: :logout)
    refute @session.reload.reauthenticated_within?
    assert_raises(Sessions::Error) { @session.reauthenticated! }
  end

  test "an issued assertion verifies with the key, the audience, the subject and the purpose" do
    @session.reauthenticated!
    token = @session.reauthentication_assertion(audience: "billing", purpose: "refund:42")

    assertion = Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, subject: @user.id,
                                                         purpose: "refund:42")

    assert_equal [@user.id.to_s, @session.id.to_s, "password", "billing", "refund:42"],
                 [assertion.subject, assertion.session_id, assertion.method, assertion.audience, assertion.purpose]
    assert assertion.fresh?(within: 1.minute)
    assert_match(/\A\h{8}-/, assertion.jti)
  end

  test "an assertion is refused for another key, audience, subject or purpose, when tampered with, or when expired" do
    @session.reauthenticated!
    token = @session.reauthentication_assertion(audience: "billing", purpose: "refund:42")

    assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: "x" * 48)
    assert_nil Sessions::Reauthentication.verify(token, audience: "admin", key: KEY)
    assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, subject: "someone-else")
    assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, purpose: "refund:43")
    assert_nil Sessions::Reauthentication.verify("#{token}x", audience: "billing", key: KEY)
    assert_nil Sessions::Reauthentication.verify("", audience: "billing", key: KEY)
    travel(2.minutes) { assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: KEY) }
  end

  test "max_age refuses an assertion of an older re-authentication" do
    @session.reauthenticated!(at: 4.minutes.ago)
    token = @session.reauthentication_assertion(audience: "billing")

    assert Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, max_age: 5.minutes)
    assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, max_age: 1.minute)
  end

  test "no assertion without a recent re-authentication" do
    assert_raises(Sessions::Reauthentication::NotRecent) { @session.reauthentication_assertion(audience: "billing") }
  end

  test "the configuration refuses a short key and a non-positive window" do
    assert_raises(Sessions::ConfigurationError) { Sessions.config.reauthentication_key = "short" }
    assert_raises(Sessions::ConfigurationError) { Sessions.config.reauthentication_window = 0 }
    Sessions.config.reauthentication_key = -> { KEY }
    assert_equal KEY, Sessions.config.resolved_reauthentication_key
  end

  test "the verifier loads on its own, without the Rails parts of the gem" do
    script = <<~RUBY
      $LOAD_PATH.unshift(#{File.expand_path("../lib", __dir__).inspect})
      require "sessions/reauthentication"
      token = Sessions::Reauthentication.issue(subject: "u1", session_id: "s1", method: "password",
                                               authenticated_at: Time.now, audience: "a", key: "#{KEY}")
      print Sessions::Reauthentication.verify(token, audience: "a", key: "#{KEY}", subject: "u1").session_id
    RUBY
    output = IO.popen([RbConfig.ruby, "-e", script], err: %i[child out], &:read)

    assert_equal "s1", output
  end

  test "the controller helpers record and assert on the current session" do
    host = Class.new do
      include Sessions::ReauthenticationHelpers

      attr_reader :request

      def initialize(request) = @request = request
      public :record_sessions_reauthentication!, :sessions_reauthenticated?, :sessions_reauthentication_assertion
    end.new(:request)
    Sessions.stubs(:current).with(:request).returns(@session)

    assert_nil host.sessions_reauthentication_assertion(audience: "billing")
    refute host.sessions_reauthenticated?

    host.record_sessions_reauthentication!(method: :passkey)

    assert host.sessions_reauthenticated?
    token = host.sessions_reauthentication_assertion(audience: "billing")
    assert_equal "passkey", Sessions::Reauthentication.verify(token, audience: "billing", key: KEY).method
  end
end
