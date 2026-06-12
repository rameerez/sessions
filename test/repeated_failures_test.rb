# frozen_string_literal: true

require "test_helper"

class RepeatedFailuresTest < ActiveSupport::TestCase
  def fail_once(identity: "victim@example.com", ip: "203.0.113.7")
    Sessions::Event.record_failure(fake_request(ip: ip), identity: identity, reason: :invalid)
  end

  test "disabled by default — failures never fire the hook" do
    fired = false
    Sessions.config.on_repeated_failed_logins = ->(**) { fired = true }

    10.times { fail_once }

    refute fired
  end

  test "fires exactly once, at the threshold crossing, with the tripping event" do
    Sessions.config.repeated_failed_logins = { threshold: 3, within: 15.minutes }
    calls = []
    Sessions.config.on_repeated_failed_logins = lambda do |identity:, count:, event:|
      calls << [identity, count, event]
    end

    5.times { fail_once(identity: "Victim@Example.com") }

    assert_equal 1, calls.size, "the 4th and 5th failures must NOT re-fire (anti inbox-flooding)"
    identity, count, event = calls.first
    assert_equal "victim@example.com", identity # normalized
    assert_equal 3, count
    assert_equal "203.0.113.7", event.ip_address # the event carries IP/device/geo
  end

  test "failures outside the window don't count toward the threshold" do
    Sessions.config.repeated_failed_logins = { threshold: 3, within: 15.minutes }
    fired = false
    Sessions.config.on_repeated_failed_logins = ->(**) { fired = true }

    2.times { fail_once }
    Sessions::Event.failed_logins.update_all(occurred_at: 1.hour.ago)
    2.times { fail_once } # only 2 inside the window

    refute fired
  end

  test "different identities are tracked independently" do
    Sessions.config.repeated_failed_logins = { threshold: 2, within: 15.minutes }
    identities = []
    Sessions.config.on_repeated_failed_logins = ->(identity:, **) { identities << identity }

    2.times { fail_once(identity: "a@example.com") }
    2.times { fail_once(identity: "b@example.com") }

    assert_equal %w[a@example.com b@example.com], identities
  end

  test "failures without an identity never alert (nothing to notify about)" do
    Sessions.config.repeated_failed_logins = { threshold: 1, within: 15.minutes }
    fired = false
    Sessions.config.on_repeated_failed_logins = ->(**) { fired = true }

    3.times { Sessions::Event.record_failure(fake_request, reason: :invalid) }

    refute fired
  end

  test "a broken hook never breaks failure recording" do
    Sessions.config.repeated_failed_logins = { threshold: 1, within: 15.minutes }
    Sessions.config.on_repeated_failed_logins = ->(**) { raise "alerting pipeline down" }

    assert_nothing_raised { fail_once }
    assert_equal 1, Sessions::Event.failed_logins.count
  end

  test "the knob validates its shape" do
    Sessions.config.repeated_failed_logins = { threshold: 5, within: 15.minutes }
    assert_equal 5, Sessions.config.repeated_failed_logins[:threshold]

    Sessions.config.repeated_failed_logins = nil
    assert_nil Sessions.config.repeated_failed_logins

    assert_raises(Sessions::ConfigurationError) do
      Sessions.config.repeated_failed_logins = { threshold: "many" }
    end
    assert_raises(Sessions::ConfigurationError) do
      Sessions.config.repeated_failed_logins = { threshold: 0, within: 1.hour }
    end
  end
end
