# frozen_string_literal: true

require "test_helper"

class ConfigurationTest < ActiveSupport::TestCase
  test "delightful defaults work untouched" do
    config = Sessions::Configuration.new

    assert_equal 5.minutes, config.touch_every
    assert_equal 100, config.max_sessions_per_user
    assert_nil config.idle_timeout
    assert_nil config.max_session_lifetime
    assert config.revoke_on_password_change
    assert config.revoke_remember_me
    assert config.track_failed_logins
    assert_equal :browser, config.ua_parser
    refute config.request_client_hints
    assert_equal [], config.native_app_names
    assert_equal :full, config.ip_mode
    assert_equal :auto, config.geolocate
    assert_equal 2, config.geo_precision
    assert_equal 12.months, config.events_retention
    assert_equal "::ApplicationController", config.parent_controller
    assert_equal :current_user, config.current_user_method
    assert_equal :authenticate_user!, config.authenticate_method
    assert_nil config.require_reauthentication
    assert_equal "Session", config.session_class
    assert_equal({}, config.strategy_methods)
  end

  test "hooks default to no-ops that accept their kwargs" do
    config = Sessions::Configuration.new

    assert_nil config.on_new_device.call(user: nil, session: nil, event: nil)
    assert_nil config.on_session_revoked.call(session: nil, by: nil, reason: nil)
    assert_nil config.events.call(nil)
  end

  test "configure yields and validates" do
    Sessions.configure do |config|
      config.touch_every = 1.minute
    end

    assert_equal 1.minute, Sessions.config.touch_every
  end

  test "durations are validated with plain-English errors" do
    error = assert_raises(Sessions::ConfigurationError) { Sessions.config.touch_every = "soon" }
    assert_match(/must be a duration/, error.message)

    assert_raises(Sessions::ConfigurationError) { Sessions.config.idle_timeout = 42_000_000_000 }
    assert_raises(Sessions::ConfigurationError) { Sessions.config.events_retention = :forever }

    Sessions.config.touch_every = nil
    assert_nil Sessions.config.touch_every
  end

  test "max_sessions_per_user accepts positive integers or nil" do
    Sessions.config.max_sessions_per_user = 5
    assert_equal 5, Sessions.config.max_sessions_per_user

    Sessions.config.max_sessions_per_user = nil
    assert_nil Sessions.config.max_sessions_per_user

    assert_raises(Sessions::ConfigurationError) { Sessions.config.max_sessions_per_user = 0 }
    assert_raises(Sessions::ConfigurationError) { Sessions.config.max_sessions_per_user = "lots" }
  end

  test "timeout_preset sets the NIST pair in one line" do
    Sessions.config.timeout_preset = :nist_aal2

    assert_equal 1.hour, Sessions.config.idle_timeout
    assert_equal 24.hours, Sessions.config.max_session_lifetime

    assert_raises(Sessions::ConfigurationError) { Sessions.config.timeout_preset = :nope }
  end

  test "validate! rejects idle timeouts longer than the lifetime" do
    Sessions.config.idle_timeout = 2.days
    Sessions.config.max_session_lifetime = 1.day

    assert_raises(Sessions::ConfigurationError) { Sessions.config.validate! }
  end

  test "ua_parser accepts the known symbols or a lambda" do
    Sessions.config.ua_parser = :device_detector
    assert_equal :device_detector, Sessions.config.ua_parser

    custom = ->(_ua, _headers) { {} }
    Sessions.config.ua_parser = custom
    assert_equal custom, Sessions.config.ua_parser

    assert_raises(Sessions::ConfigurationError) { Sessions.config.ua_parser = :psychic }
  end

  test "ip_mode is validated" do
    Sessions.config.ip_mode = :truncated
    assert_equal :truncated, Sessions.config.ip_mode

    assert_raises(Sessions::ConfigurationError) { Sessions.config.ip_mode = :scrambled }
  end

  test "geolocate accepts auto, off, and false-as-off" do
    Sessions.config.geolocate = :off
    assert_equal :off, Sessions.config.geolocate

    Sessions.config.geolocate = false
    assert_equal :off, Sessions.config.geolocate

    assert_raises(Sessions::ConfigurationError) { Sessions.config.geolocate = :sometimes }
  end

  test "hooks must be callable" do
    assert_raises(Sessions::ConfigurationError) { Sessions.config.on_new_device = :send_email }
    assert_raises(Sessions::ConfigurationError) { Sessions.config.events = "AuditLog" }
    assert_raises(Sessions::ConfigurationError) { Sessions.config.ip_resolver = nil }
  end

  test "require_reauthentication accepts nil or a callable" do
    Sessions.config.require_reauthentication = ->(_controller) { true }
    assert_respond_to Sessions.config.require_reauthentication, :call

    Sessions.config.require_reauthentication = nil
    assert_nil Sessions.config.require_reauthentication

    assert_raises(Sessions::ConfigurationError) { Sessions.config.require_reauthentication = :sudo }
  end

  test "class names are stored as strings and resolved lazily" do
    Sessions.config.session_class = Session
    assert_equal "Session", Sessions.config.session_class
    assert_equal Session, Sessions.config.session_model

    assert_raises(Sessions::ConfigurationError) { Sessions.config.session_class = "  " }
    assert_raises(Sessions::ConfigurationError) { Sessions.config.parent_controller = "" }
  end

  test "strategy_methods normalizes keys and values" do
    Sessions.config.strategy_methods = { OtpAuthenticatable: "otp" }
    assert_equal({ "OtpAuthenticatable" => :otp }, Sessions.config.strategy_methods)

    assert_raises(Sessions::ConfigurationError) { Sessions.config.strategy_methods = 42 }
  end

  test "native_app_names cleans its input" do
    Sessions.config.native_app_names = ["MyApp", "", :OtherApp, "  "]
    assert_equal %w[MyApp OtherApp], Sessions.config.native_app_names
  end

  test "geo_precision must be a non-negative integer" do
    Sessions.config.geo_precision = 0
    assert_equal 0, Sessions.config.geo_precision

    assert_raises(Sessions::ConfigurationError) { Sessions.config.geo_precision = -1 }
    assert_raises(Sessions::ConfigurationError) { Sessions.config.geo_precision = 1.5 }
  end

  test "reset! restores a pristine configuration" do
    Sessions.config.touch_every = nil
    Sessions.reset!

    assert_equal 5.minutes, Sessions.config.touch_every
  end
end
