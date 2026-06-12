# frozen_string_literal: true

require "test_helper"

class EventTest < ActiveSupport::TestCase
  test "record! stamps occurred_at, normalizes identity, and tees the hook" do
    seen = nil
    Sessions.config.events = ->(event) { seen = event }

    event = Sessions::Event.record!(event: "failed_login", identity: "  J@Example.COM ")

    assert event.persisted?
    assert_equal "j@example.com", event.identity
    assert_not_nil event.occurred_at
    assert_equal event, seen
  end

  test "record! tolerantly drops unknown attributes (hosts can prune columns)" do
    event = Sessions::Event.record!(event: "login", flux_capacitor: "1.21GW")

    assert event.persisted?
  end

  test "record! never raises — a failing write is a lost row, not a broken login" do
    assert_nil Sessions::Event.record!(event: "not_a_real_event")
    assert_nil Sessions::Event.record!({})
  end

  test "a broken events tee never blocks the write" do
    Sessions.config.events = ->(_event) { raise "boom" }

    event = Sessions::Event.record!(event: "login")

    assert event.persisted?
  end

  test "the event vocabulary is enforced" do
    assert_equal %w[login failed_login logout revoked expired], Sessions::Event::EVENTS
  end

  test "record_failure builds the full failure row from the request" do
    request = fake_request(method: "POST", path: "/session", ua: UserAgents::CHROME_MAC,
                           ip: "203.0.113.7", params: { email_address: "j@example.com", password: "x" })

    event = Sessions::Event.record_failure(request, scope: :user, identity: "J@example.com",
                                                    reason: :invalid_password)

    assert_equal "failed_login", event.event
    assert_equal "user", event.scope
    assert_equal "j@example.com", event.identity
    assert_equal "invalid_password", event.failure_reason
    assert_equal "203.0.113.7", event.ip_address
    assert_equal UserAgents::CHROME_MAC, event.user_agent
    assert_equal "Chrome", event.browser_name
    assert_equal "macOS", event.os_name
    assert_equal "password", event.auth_method
    assert event.failure?
    refute event.success?
    assert_nil event.authenticatable
  end

  test "record_failure never stores the password" do
    request = fake_request(method: "POST", path: "/session",
                           params: { email_address: "j@example.com", password: "hunter2" })

    event = Sessions::Event.record_failure(request, identity: "j@example.com", reason: :invalid)

    refute(event.attributes.values.grep(String).any? { |value| value.include?("hunter2") })
    refute event.metadata.to_s.include?("hunter2")
  end

  test "record_failure tolerates a nil request (console seams)" do
    event = Sessions::Event.record_failure(nil, identity: "j@example.com", reason: :invalid)

    assert event.persisted?
    assert_nil event.ip_address
  end

  test "scopes slice the trail" do
    user = create_user
    Sessions::Event.record!(event: "login", authenticatable: user, ip_address: "1.1.1.1",
                            country_code: "ES")
    Sessions::Event.record!(event: "failed_login", identity: "a@b.com", ip_address: "2.2.2.2")
    Sessions::Event.record!(event: "logout", authenticatable: user)
    Sessions::Event.record!(event: "revoked", authenticatable: user)
    Sessions::Event.record!(event: "expired", authenticatable: user)

    assert_equal 1, Sessions::Event.logins.count
    assert_equal 1, Sessions::Event.failed_logins.count
    assert_equal 1, Sessions::Event.logouts.count
    assert_equal 1, Sessions::Event.revocations.count
    assert_equal 1, Sessions::Event.expirations.count
    assert_equal 1, Sessions::Event.for_ip("2.2.2.2").count
    assert_equal 1, Sessions::Event.for_identity("A@B.com").count # normalized lookup
    assert_equal 1, Sessions::Event.by_country("es").count
    assert_equal 5, Sessions::Event.last_24_hours.count
    assert_equal 5, Sessions::Event.last_days(7).count
  end

  test "recent orders by occurrence" do
    older = Sessions::Event.record!(event: "login", occurred_at: 2.hours.ago)
    newer = Sessions::Event.record!(event: "login", occurred_at: 1.minute.ago)

    assert_equal [newer, older], Sessions::Event.recent.to_a
  end

  test "the admin one-liner: failed logins by IP in the last 24 hours" do
    3.times { Sessions::Event.record!(event: "failed_login", ip_address: "203.0.113.7") }
    Sessions::Event.record!(event: "failed_login", ip_address: "198.51.100.4")

    counts = Sessions::Event.failed_logins.last_24_hours.group(:ip_address).count

    assert_equal 3, counts["203.0.113.7"]
    assert_equal 1, counts["198.51.100.4"]
  end

  test "event.name reads better than event.event in host hooks" do
    event = Sessions::Event.record!(event: "login")

    assert_equal :login, event.name
  end

  test "session linkage survives the row's destruction" do
    user = create_user
    row = create_session_for(user)
    event = Sessions::Event.logins.find_by(session_id: row.id)

    assert_equal row, event.session

    row.destroy
    assert_nil event.reload.session # history outlives the registry row
    assert_equal row.id, event.session_id
  end

  test "location and country_flag render from geo columns" do
    event = Sessions::Event.record!(event: "login", city: "Madrid", country_name: "Spain",
                                    country_code: "ES")

    assert_equal "Madrid, Spain", event.location
    assert_equal "🇪🇸", event.country_flag
  end

  test "events carry device_name like registry rows do (admin lists, hooks)" do
    user = create_user
    create_session_for(user, ua: UserAgents::NATIVE_ANDROID)

    event = Sessions::Event.logins.sole
    assert_equal "MyApp 2.4.1 on Pixel 8 (Android 16)", event.device_name
    assert event.native_android?
  end

  test "source_line on events powers security emails and notification bodies" do
    event = Sessions::Event.record!(event: "failed_login", failure_reason: "invalid",
                                    ip_address: "203.0.113.99", city: "París",
                                    country_name: "France", country_code: "FR",
                                    browser_name: "Chrome", browser_version: "137",
                                    os_name: "Android", os_version: "14", device_type: "mobile")

    assert_equal "🇫🇷 París, France · IP 203.0.113.99 · Chrome 137 on Android 14", event.source_line
    assert_equal "🇫🇷 París, France · Chrome 137 on Android 14", event.source_line(ip: false)
  end

  test "reason resolves whichever reason applies; labels localize" do
    failed = Sessions::Event.record!(event: "failed_login", failure_reason: "invalid")
    revoked = Sessions::Event.record!(event: "revoked", revoked_reason: "password_change")
    login = Sessions::Event.record!(event: "login")

    assert_equal "invalid", failed.reason
    assert_equal "password_change", revoked.reason
    assert_nil login.reason

    assert_equal "Signed in", login.label
    assert_equal "Failed sign-in attempt", failed.label
    assert_equal "wrong credentials", failed.reason_label
    assert_equal "password was changed", revoked.reason_label
    assert_nil login.reason_label

    I18n.with_locale(:es) do
      assert_equal "Inicio de sesión", login.label
      assert_equal "credenciales incorrectas", failed.reason_label
    end
  end

  test "summary is the audit-shaped projection a config.events tee forwards" do
    user = create_user
    row = create_session_for(user, ua: UserAgents::CHROME_MAC, ip: "203.0.113.7")

    summary = Sessions::Event.logins.sole.summary

    assert_equal row.id, summary[:session_id]
    assert_equal "Chrome 137 on macOS", summary[:device]
    assert_equal "desktop", summary[:device_type]
    assert_equal "203.0.113.7", summary[:ip]
    refute summary.key?(:failure_reason) # compacted
    refute summary.key?(:user_agent)     # raw blobs never ride the tee
  end

  test "summary omits the device label when nothing was parseable" do
    event = Sessions::Event.record!(event: "failed_login", identity: "x@y.com")

    refute event.summary.key?(:device)
  end
end
