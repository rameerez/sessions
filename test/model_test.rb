# frozen_string_literal: true

require "test_helper"

class ModelTest < ActiveSupport::TestCase
  # --- Enrichment (before_create) ---------------------------------------------

  test "creating a session enriches device columns from the stored UA" do
    row = create_session_for(create_user, ua: UserAgents::CHROME_MAC)

    assert_equal "Chrome", row.browser_name
    assert_equal "137", row.browser_version
    assert_equal "macOS", row.os_name
    assert_equal "desktop", row.device_type
  end

  test "a native login is named like the PRD demo" do
    row = create_session_for(create_user, ua: UserAgents::NATIVE_ANDROID)

    assert_equal "native_android", row.device_type
    assert_equal "MyApp", row.app_name
    assert_equal "MyApp 2.4.1 on Pixel 8 (Android 16)", row.device_name
    assert row.hotwire_native?
    assert row.native_android?
    refute row.web?
  end

  test "nil ip and UA rows are tolerated (the sign_in_as test helper shape)" do
    row = create_user.sessions.create!

    assert row.persisted?
    assert_nil row.ip_address
    assert_equal "unknown", row.device_type
    assert_equal "Unknown device", row.device_name
  end

  test "enrichment classifies the auth method from the request context" do
    request = fake_request(method: "POST", path: "/session",
                           params: { email_address: "j@x.com", password: "x" })

    row = with_request(request) { create_session_for(create_user) }

    assert_equal "password", row.auth_method
    assert row.via_password?
  end

  test "garbage host-captured IPs are dropped, not persisted" do
    row = create_session_for(create_user, ip: "not-an-ip")

    assert_nil row.ip_address
  end

  test "ip_mode :truncated anonymizes before persistence" do
    Sessions.config.ip_mode = :truncated

    row = create_session_for(create_user, ip: "203.0.113.77")

    assert_equal "203.0.113.0", row.ip_address
  end

  test "client hints are captured raw for future re-parsing" do
    request = fake_request(env: { "HTTP_SEC_CH_UA_PLATFORM_VERSION" => '"15.5.0"' })

    row = with_request(request) { create_session_for(create_user, ua: UserAgents::CHROME_MAC) }

    assert_equal({ "Sec-CH-UA-Platform-Version" => '"15.5.0"' }, row.client_hints)
    assert_equal "15.5.0", row.os_version # and consumed for honesty upgrades
  end

  test "a raising enrichment never breaks the login write" do
    Sessions.config.ip_resolver = ->(_request) { raise "geo provider exploded" }
    Sessions::Classifier.stubs(:classify).raises(RuntimeError, "classifier exploded")

    row = nil
    assert_nothing_raised do
      row = with_request(fake_request) { create_session_for(create_user) }
    end
    assert row.persisted?
  end

  # --- The login event (after_create_commit) -----------------------------------

  test "every login writes a linked trail event copying the row's identity" do
    user = create_user
    row = create_session_for(user, ua: UserAgents::SAFARI_IPHONE, ip: "203.0.113.7")

    event = Sessions::Event.logins.sole
    assert_equal row.id, event.session_id
    assert_equal user, event.authenticatable
    assert_equal "Safari", event.browser_name
    assert_equal "iOS", event.os_name
    assert_equal "203.0.113.7", event.ip_address
  end

  test "a user's very first login is not a new device (no signup spam)" do
    fired = false
    Sessions.config.on_new_device = ->(user:, session:, event:) { fired = true }

    create_session_for(create_user)

    refute fired
    refute Sessions::Event.logins.sole.new_device?
  end

  test "a different device fires on_new_device with kwargs" do
    user = create_user
    create_session_for(user, ua: UserAgents::CHROME_MAC)

    captured = nil
    Sessions.config.on_new_device = ->(user:, session:, event:) { captured = [user, session, event] }

    row = create_session_for(user, ua: UserAgents::SAFARI_IPHONE)

    assert_equal user, captured[0]
    assert_equal row, captured[1]
    assert captured[2].new_device?
  end

  test "the same device again is NOT a new device" do
    user = create_user
    create_session_for(user, ua: UserAgents::CHROME_MAC)

    fired = false
    Sessions.config.on_new_device = ->(**) { fired = true }

    create_session_for(user, ua: UserAgents::CHROME_MAC)

    refute fired
  end

  test "a matching device remembered only in the trail (row revoked) still counts as known" do
    user = create_user
    create_session_for(user, ua: UserAgents::CHROME_MAC).revoke!

    fired = false
    Sessions.config.on_new_device = ->(**) { fired = true }
    create_session_for(user, ua: UserAgents::CHROME_MAC)

    refute fired
  end

  test "a broken on_new_device hook never breaks the login" do
    user = create_user
    create_session_for(user, ua: UserAgents::CHROME_MAC)
    Sessions.config.on_new_device = ->(**) { raise "mailer exploded" }

    assert_nothing_raised { create_session_for(user, ua: UserAgents::SAFARI_IPHONE) }
    assert_equal 2, user.sessions.count
  end

  # --- The per-user cap ----------------------------------------------------------

  test "logins beyond max_sessions_per_user evict the oldest with a pruned event" do
    Sessions.config.max_sessions_per_user = 2
    user = create_user

    oldest = create_session_for(user)
    oldest.update_columns(created_at: 3.days.ago)
    create_session_for(user)
    create_session_for(user)

    assert_equal 2, user.sessions.count
    refute user.sessions.exists?(oldest.id)
    assert_equal "pruned", Sessions::Event.revocations.sole.revoked_reason
  end

  test "the cap holds even for suppressed (adopted) writes" do
    Sessions.config.max_sessions_per_user = 2
    user = create_user

    3.times do
      row = user.sessions.new(ip_address: "203.0.113.7", user_agent: UserAgents::CHROME_MAC)
      row.sessions_suppress_login_event = true
      row.save!
    end

    assert_equal 2, user.sessions.count,
                 "adoption skips the trail and dedup — never the hard cap on live rows"
  end

  test "no cap when max_sessions_per_user is nil" do
    Sessions.config.max_sessions_per_user = nil
    user = create_user

    5.times { create_session_for(user) }

    assert_equal 5, user.sessions.count
  end

  # --- Revocation (the airtight part) ---------------------------------------------

  test "revoke! destroys the row and writes a revoked event with reason and actor" do
    user = create_user
    admin = create_user
    row = create_session_for(user)

    row.revoke!(reason: :admin_revoked, by: admin)

    refute Session.exists?(row.id)
    event = Sessions::Event.revocations.sole
    assert_equal "admin_revoked", event.revoked_reason
    assert_equal "User##{admin.id}", event.metadata["revoked_by"]
    assert_equal row.id, event.session_id
  end

  test "revoke! fires on_session_revoked with kwargs" do
    captured = nil
    Sessions.config.on_session_revoked = ->(session:, by:, reason:) { captured = [session, by, reason] }
    row = create_session_for(create_user)

    row.revoke!(reason: :user_revoked)

    assert_equal row, captured[0]
    assert_equal :user_revoked, captured[2]
  end

  test "revoke! rotates remember-me credentials when the user supports it" do
    user = create_user
    def user.forget_me!
      @forgotten = true
    end
    row = create_session_for(user)

    row.revoke!

    assert user.instance_variable_get(:@forgotten)
  end

  test "config.revoke_remember_me = false leaves remember-me alone" do
    Sessions.config.revoke_remember_me = false
    user = create_user
    def user.forget_me!
      @forgotten = true
    end

    create_session_for(user).revoke!

    refute user.instance_variable_get(:@forgotten)
  end

  test "an unmarked destroy records an honest revoked event with unknown reason" do
    row = create_session_for(create_user)

    row.destroy

    assert_equal "unknown", Sessions::Event.revocations.sole.revoked_reason
  end

  test "a logout-labeled destroy records a logout event" do
    row = create_session_for(create_user)
    row.revocation_reason = :logout

    row.destroy

    assert_equal 1, Sessions::Event.logouts.count
    assert_equal 0, Sessions::Event.revocations.count
  end

  test "destroying the user erases their sessions and trail (GDPR default)" do
    user = create_user
    create_session_for(user)
    assert_equal 1, Sessions::Event.count

    assert_nothing_raised { user.destroy! }

    assert_equal 0, Session.count
    # No zombie revoked-events for an erased owner, and the prior trail is gone.
    assert_equal 0, Sessions::Event.count
  end

  # --- Touch & expiry ---------------------------------------------------------------

  test "touch_last_seen! writes once per window — one conditional UPDATE" do
    row = create_session_for(create_user)

    assert row.touch_last_seen!
    first_seen = row.last_seen_at
    assert_not_nil first_seen

    refute row.touch_last_seen! # inside the window: no write
    assert_equal first_seen, row.last_seen_at
  end

  test "touch_last_seen! refreshes the roaming IP and moves updated_at" do
    row = create_session_for(create_user, ip: "203.0.113.7")
    original_updated_at = row.updated_at

    travel 10.minutes do
      row.touch_last_seen!(fake_request(ip: "198.51.100.4"))
    end

    row.reload
    assert_equal "198.51.100.4", row.last_seen_ip
    assert_equal "203.0.113.7", row.ip_address # the login-time IP is immutable
    assert_operator row.updated_at, :>, original_updated_at # the security guide's sweep works now
  end

  test "touch_last_seen! is disabled when touch_every is nil" do
    Sessions.config.touch_every = nil
    row = create_session_for(create_user)

    refute row.touch_last_seen!
    assert_nil row.last_seen_at
  end

  test "the touch races safely: a concurrent winner makes this instance back off" do
    row = create_session_for(create_user)
    Session.where(id: row.id).update_all(last_seen_at: Time.current) # another request won

    refute row.touch_last_seen!
  end

  test "sessions are never expired without opt-in timeouts" do
    row = create_session_for(create_user)
    row.update_columns(created_at: 10.years.ago)

    refute row.sessions_expired?
  end

  test "idle_timeout expires by last activity" do
    Sessions.config.idle_timeout = 1.hour
    row = create_session_for(create_user)

    refute row.sessions_expired?
    row.update_columns(created_at: 2.hours.ago)
    assert row.sessions_expired?

    row.update_columns(last_seen_at: 5.minutes.ago)
    refute row.sessions_expired?
  end

  test "max_session_lifetime expires by age regardless of activity" do
    Sessions.config.max_session_lifetime = 1.day
    row = create_session_for(create_user)
    row.update_columns(created_at: 2.days.ago, last_seen_at: 1.minute.ago)

    assert row.sessions_expired?
  end

  # --- Scopes & display ------------------------------------------------------------

  test "active/inactive group by last activity; by_recency sorts the devices page" do
    user = create_user
    stale = create_session_for(user)
    stale.update_columns(created_at: 45.days.ago)
    fresh = create_session_for(user)

    assert_equal [fresh], user.sessions.active.to_a
    assert_equal [stale], user.sessions.inactive.to_a
    assert_equal [fresh, stale], user.sessions.by_recency.to_a

    # A touch makes activity (not creation) drive the ordering.
    fresh.update_columns(created_at: 2.minutes.ago)
    stale.update_columns(last_seen_at: 1.minute.ago)
    assert_equal [stale, fresh], user.sessions.by_recency.to_a
  end

  test "device names read like the PRD examples" do
    assert_equal "Chrome 137 on macOS",
                 create_session_for(create_user, ua: UserAgents::CHROME_MAC).device_name
    assert_equal "Safari 19 on iOS 19.5",
                 create_session_for(create_user, ua: UserAgents::SAFARI_IPHONE).device_name
    assert_equal "MyApp 2.4.1 on iPhone15,2 (iOS 19.5)",
                 create_session_for(create_user, ua: UserAgents::NATIVE_IOS).device_name
    assert_equal "Pixel 7 (Android 14)",
                 create_session_for(create_user, ua: UserAgents::NATIVE_ANDROID_BARE).device_name
  end

  test "location and flag derive from geo columns; absent geo renders nothing" do
    row = create_session_for(create_user)
    assert_nil row.location
    assert_nil row.country_flag

    row.update_columns(city: "Madrid", country_name: "Spain", country_code: "ES")
    assert_equal "Madrid, Spain", row.location
    assert_equal "🇪🇸", row.country_flag
  end

  test "second_factor? reads the auth detail on rows and events alike" do
    request = fake_request(method: "POST", path: "/session", params: { email_address: "j@x.com", password: "x" })
    Sessions.tag(request, method: :password, detail: { second_factor: "webauthn" })

    row = with_request(request) { create_session_for(create_user) }

    assert row.second_factor?
    assert_equal "webauthn", row.second_factor
    assert Sessions::Event.logins.sole.second_factor?

    plain = create_session_for(create_user)
    refute plain.second_factor?
    assert_nil plain.second_factor
  end

  test "source_line leads with location, then IP, then device — parts drop out cleanly" do
    row = create_session_for(create_user)
    row.update_columns(browser_name: "Firefox", browser_version: "139", os_name: "Windows",
                       os_version: "10", device_type: "desktop", ip_address: "83.45.112.7",
                       city: "Madrid", country_name: "Spain", country_code: "ES")

    assert_equal "🇪🇸 Madrid, Spain · IP 83.45.112.7 · Firefox 139 on Windows 10", row.source_line
    assert_equal "🇪🇸 Madrid, Spain · Firefox 139 on Windows 10", row.source_line(ip: false)
    assert_equal "🇪🇸 Madrid, Spain — IP 83.45.112.7 — Firefox 139 on Windows 10",
                 row.source_line(separator: " — ")

    row.update_columns(city: nil, country_name: nil, country_code: nil)
    assert_equal "IP 83.45.112.7 · Firefox 139 on Windows 10", row.source_line, "no geo: location drops out"

    row.update_columns(ip_address: nil)
    assert_equal "Firefox 139 on Windows 10", row.source_line, "no IP either: device alone"
  end

  test "oversized strings clamp to their column limits (MySQL varchar(255) reality)" do
    # Rails 8's authentication generator creates user_agent as a plain
    # string — varchar(255) under MySQL's strict mode — and real native UAs
    # overflow it: without the clamp, the LOGIN itself raises
    # ActiveRecord::ValueTooLong. sqlite reports no limit, so simulate the
    # MySQL column here; the CI mysql leg proves it against the real thing.
    fake_column = Struct.new(:type, :limit).new(:string, 255)
    real_columns = Session.columns_hash
    Session.stubs(:columns_hash).returns(real_columns.merge("user_agent" => fake_column))

    row = Session.new(user_agent: "Mozilla/5.0 #{"x" * 300}")
    row.send(:sessions_clamp_oversized_strings)

    assert_equal 255, row.user_agent.length
    assert row.user_agent.start_with?("Mozilla/5.0 "), "clamping keeps the head, the parseable part"
  end

  test "second_factor! stamps a step-up factor onto a live session, preserving detail" do
    row = create_session_for(create_user)
    row.update!(auth_detail: { "adopted" => true })

    row.second_factor!(:totp)

    row.reload
    assert_equal "totp", row.second_factor
    assert row.second_factor?
    assert row.auth_detail["adopted"], "stamping the factor must not clobber existing detail"
  end

  test "auth_method_label humanizes the method or names the provider" do
    row = create_session_for(create_user)
    row.update_columns(auth_method: "password")
    assert_equal "password", row.auth_method_label

    row.update_columns(auth_method: "oauth", auth_provider: "google")
    assert_equal "Google", row.auth_method_label
    assert row.via_oauth?

    row.update_columns(auth_method: "unknown", auth_provider: nil)
    assert_nil row.auth_method_label
  end

  test "last_active_at coalesces touch and creation" do
    row = create_session_for(create_user)
    assert_equal row.created_at, row.last_active_at

    row.update_columns(last_seen_at: 1.minute.ago)
    assert_equal row.reload.last_seen_at, row.last_active_at
  end

  test "active_now? tracks the touch window (SSOT with config.touch_every)" do
    row = create_session_for(create_user)
    assert row.active_now? # just created

    row.update_columns(created_at: 10.minutes.ago)
    refute row.reload.active_now? # outside the default 5-minute window

    Sessions.config.touch_every = 30.minutes
    assert row.active_now? # the window follows the configured throttle
  end

  test "the icon-name helpers map devices and events for custom views" do
    helpers = ApplicationController.helpers
    row = create_session_for(create_user, ua: UserAgents::NATIVE_ANDROID)

    assert_equal "device-phone-mobile", helpers.sessions_device_icon_name(row)
    assert_equal "check-circle", helpers.sessions_event_icon_name(Sessions::Event.logins.sole)
    assert_equal "computer-desktop",
                 helpers.sessions_device_icon_name(create_session_for(create_user, ua: UserAgents::CHROME_MAC))
  end

  # --- Token plumbing (Devise mode) -------------------------------------------------

  test "token digests verify in constant time and never match blanks" do
    token = Sessions.generate_token
    row = create_session_for(create_user, token_digest: Sessions.token_digest(token))

    assert row.sessions_token_matches?(token)
    refute row.sessions_token_matches?("wrong")
    refute row.sessions_token_matches?(nil)
    refute row.sessions_token_matches?("")
  end

  test "omakase rows (no token) never match any token" do
    row = create_session_for(create_user)

    refute row.sessions_token_matches?(Sessions.generate_token)
  end

  test "the raw token never round-trips into the database" do
    token = Sessions.generate_token
    row = create_session_for(create_user, token_digest: Sessions.token_digest(token))

    refute(row.attributes.values.grep(String).any? { |value| value.include?(token) })
  end

  # --- Adoption ------------------------------------------------------------------

  test "suppressed rows (adopted sessions) write no login event" do
    user = create_user
    row = user.sessions.new(ip_address: "203.0.113.7", user_agent: UserAgents::CHROME_MAC)
    row.sessions_suppress_login_event = true
    row.save!

    assert_equal 0, Sessions::Event.logins.count
  end
end
