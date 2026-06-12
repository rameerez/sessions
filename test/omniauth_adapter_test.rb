# frozen_string_literal: true

require "test_helper"

class OmniauthAdapterTest < ActiveSupport::TestCase
  FakeStrategy = Struct.new(:name)

  # A stand-in for OmniAuth.config with the swappable on_failure endpoint —
  # the exact (and only) seam the adapter touches.
  class FakeOmniauthConfig
    attr_accessor :on_failure
  end

  def with_fake_omniauth(original_endpoint:)
    config = FakeOmniauthConfig.new
    config.on_failure = original_endpoint

    fake = Module.new
    fake.singleton_class.define_method(:config) { config }
    Object.const_set(:OmniAuth, fake)
    Sessions::Adapters::Omniauth.reset_installation!

    yield config
  ensure
    Object.send(:remove_const, :OmniAuth) if defined?(::OmniAuth)
    Sessions::Adapters::Omniauth.reset_installation!
  end

  def failure_env(type: :invalid_credentials, provider: "google_oauth2", origin: "/pricing")
    fake_request(method: "POST", path: "/auth/#{provider}/callback",
                 ua: UserAgents::CHROME_MAC).env.merge(
                   "omniauth.error" => RuntimeError.new("nope"),
                   "omniauth.error.type" => type,
                   "omniauth.error.strategy" => FakeStrategy.new(provider),
                   "omniauth.origin" => origin
                 )
  end

  test "install! compose-wraps on_failure: records, then delegates to the original" do
    original_calls = []
    original = lambda { |env|
      original_calls << env
      [302, { "Location" => "/auth/failure" }, []]
    }

    with_fake_omniauth(original_endpoint: original) do |config|
      Sessions::Adapters::Omniauth.install!
      refute_equal original, config.on_failure # wrapped

      status, = config.on_failure.call(failure_env)

      assert_equal 302, status # the original endpoint still answers
      assert_equal 1, original_calls.size

      event = Sessions::Event.failed_logins.sole
      assert_equal "oauth", event.auth_method
      assert_equal "google", event.auth_provider # normalized from google_oauth2
      assert_equal "invalid_credentials", event.failure_reason
      assert_equal "/pricing", event.auth_detail["origin"]
      assert_equal "Chrome", event.browser_name
    end
  end

  test "the user cancelling at the provider is recorded as access_denied" do
    with_fake_omniauth(original_endpoint: ->(_env) { [302, {}, []] }) do |config|
      Sessions::Adapters::Omniauth.install!
      config.on_failure.call(failure_env(type: :access_denied, provider: "apple"))

      event = Sessions::Event.failed_logins.sole
      assert_equal "access_denied", event.failure_reason
      assert_equal "apple", event.auth_provider
    end
  end

  test "a recording failure still reaches the original endpoint — OAuth UX is never broken" do
    Sessions::Event.stubs(:record_failure).raises(RuntimeError, "db down")

    with_fake_omniauth(original_endpoint: ->(_env) { [302, { "Location" => "/x" }, []] }) do |config|
      Sessions::Adapters::Omniauth.install!

      status, = config.on_failure.call(failure_env)

      assert_equal 302, status
    end
  end

  test "install! is idempotent — wrapping once, no matter how many boots" do
    with_fake_omniauth(original_endpoint: ->(_env) { [302, {}, []] }) do |config|
      Sessions::Adapters::Omniauth.install!
      wrapped = config.on_failure
      Sessions::Adapters::Omniauth.install!

      assert_equal wrapped, config.on_failure
    end
  end

  test "track_failed_logins = false silences OAuth failure capture too" do
    Sessions.config.track_failed_logins = false

    with_fake_omniauth(original_endpoint: ->(_env) { [302, {}, []] }) do |config|
      Sessions::Adapters::Omniauth.install!
      config.on_failure.call(failure_env)

      assert_equal 0, Sessions::Event.count
    end
  end

  test "OAuth SUCCESSES classify through the normal session pipeline (no adapter needed)" do
    auth = { "provider" => "github", "credentials" => { "scope" => "user:email" } }
    request = fake_request(env: { "omniauth.auth" => auth, "omniauth.origin" => "/repos" })

    row = with_request(request) { create_session_for(create_user) }

    assert_equal "oauth", row.auth_method
    assert_equal "github", row.auth_provider
    assert_equal "/repos", row.auth_detail["origin"]
    assert row.via_oauth?
  end
end
