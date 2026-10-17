# frozen_string_literal: true

require "test_helper"

# An owner and a session model in one namespace that store short polymorphic
# type names (store_full_class_name = false), as Rails allows.
module ReauthNamespace
  class Member < ActiveRecord::Base
    self.table_name = "users"
    self.store_full_class_name = false
  end

  class Session < ::Session
    self.store_full_class_name = false
  end
end

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

    assertion = Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, subject: @user,
                                                         purpose: "refund:42")

    assert_equal ["User:#{@user.id}", @session.id.to_s, "password", "billing", "refund:42"],
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
      assertion = Sessions::Reauthentication.verify(token, audience: "a", key: "#{KEY}", subject: "u1",
                                                           max_age: 5.minutes)
      print assertion.session_id, " ", assertion.fresh?(within: 5.minutes)
    RUBY
    output = IO.popen([RbConfig.ruby, "-e", script], err: %i[child out], &:read)

    assert_equal "s1 true", output
  end

  test "a stored short polymorphic type gives the same subject as the owner record" do
    owner = ReauthNamespace::Member.find(@user.id)
    session = ReauthNamespace::Session.new(user_id: @user.id)
    session.define_singleton_method(:user_type) { "Member" } # store_full_class_name = false stores "Member"

    assert_equal "ReauthNamespace::Member:#{@user.id}", session.reauthentication_subject
    assert_equal Sessions::Reauthentication.subject_for(owner), session.reauthentication_subject

    session.define_singleton_method(:user_type) { "Ghost" } # a type that no longer resolves keeps its stored name
    assert_equal "Ghost:#{@user.id}", session.reauthentication_subject
  end

  test "the controller helpers record and assert on the current session" do
    host = Class.new do
      include Sessions::ReauthenticationHelpers

      attr_reader :request

      def initialize(request) = @request = request
      public :record_sessions_reauthentication!, :sessions_reauthenticated?, :sessions_reauthentication_assertion
    end.new(:request)
    Sessions.stubs(:current).with(:request, scope: nil).returns(@session)

    assert_nil host.sessions_reauthentication_assertion(@user, audience: "billing")
    refute host.sessions_reauthenticated?(@user)

    host.record_sessions_reauthentication!(@user, method: :passkey)

    assert host.sessions_reauthenticated?(@user)
    token = host.sessions_reauthentication_assertion(@user, audience: "billing")
    assert_equal "passkey", Sessions::Reauthentication.verify(token, audience: "billing", key: KEY).method
  end

  test "the helpers refuse to act on another owner's session" do
    other = User.create!(email_address: "other-#{SecureRandom.hex(4)}@example.test", password: "s3kr1t-pass")
    host = Class.new do
      include Sessions::ReauthenticationHelpers

      attr_reader :request

      def initialize(request) = @request = request
      public :record_sessions_reauthentication!, :sessions_reauthentication_assertion
    end.new(:request)
    Sessions.stubs(:current).with(:request, scope: nil).returns(@session)

    assert_nil host.record_sessions_reauthentication!(other)
    refute @session.reload.reauthenticated_within?
    assert_nil host.sessions_reauthentication_assertion(other, audience: "billing")
  end

  test "the subject carries the owner class, so ids of two classes never match" do
    @session.reauthenticated!
    token = @session.reauthentication_assertion(audience: "billing")

    assert Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, subject: @user)
    assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, subject: "Admin:#{@user.id}")
    assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: KEY, subject: @user.id.to_s)
  end

  test "a revocation seen through another instance stops recording and issuing" do
    @session.reauthenticated!
    stale = Session.find(@session.id)
    Session.find(@session.id).end!(reason: :admin_revoked)

    assert_raises(Sessions::Reauthentication::NotRecent) { stale.reauthentication_assertion(audience: "billing") }
    assert_raises(Sessions::Error) { Session.find(@session.id).tap { |s| s.instance_variable_set(:@ended_at, nil) }.reauthenticated! }
  end

  test "an expired session is never recent" do
    previous = Sessions.config.max_session_lifetime
    Sessions.config.max_session_lifetime = 1.minute
    @session.update_columns(created_at: 1.hour.ago)
    assert_raises(Sessions::Error) { @session.reauthenticated! }
  ensure
    Sessions.config.max_session_lifetime = previous
  end

  test "an assertion dated in the future is refused" do
    token = Sessions::Reauthentication.issue(subject: "User:1", session_id: "s", method: "password",
                                             authenticated_at: 1.hour.from_now, audience: "a", key: KEY)
    assert_nil Sessions::Reauthentication.verify(token, audience: "a", key: KEY)
  end

  test "an assertion carries its expiry for replay caches, and expires on the real clock" do
    @session.reauthenticated!
    previous = Sessions.config.reauthentication_assertion_ttl
    Sessions.config.reauthentication_assertion_ttl = 5.minutes
    token = @session.reauthentication_assertion(audience: "billing")

    assertion = Sessions::Reauthentication.verify(token, audience: "billing", key: KEY)
    assert_in_delta 5.minutes.from_now, assertion.expires_at, 5
    travel(4.minutes) { assert Sessions::Reauthentication.verify(token, audience: "billing", key: KEY) }
    travel(6.minutes) { assert_nil Sessions::Reauthentication.verify(token, audience: "billing", key: KEY) }
  ensure
    Sessions.config.reauthentication_assertion_ttl = previous
  end
end
