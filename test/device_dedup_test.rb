# frozen_string_literal: true

require "test_helper"

# Browser continuity: a signed device cookie minted at login lets a repeat
# login from the SAME browser supersede its old row instead of stacking
# duplicate devices — robust to browser updates (identity is the cookie,
# never the user agent), private windows and other people's browsers stay
# separate devices, and other USERS on the same browser are never touched.
class DeviceDedupTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email_address: "javi@example.com", password: "s3kr1t-pass")
  end

  teardown do
    Sessions.reset!
    Session.delete_all
    Sessions::Event.delete_all
    User.delete_all
  end

  test "logging in twice from the same browser keeps ONE device row" do
    sign_in_as @user
    first_row = @user.sessions.sole
    assert first_row.device_id.present?, "login mints the continuity id"

    delete "/session" # row destroyed on logout…
    sign_in_as @user  # …and a fresh zombie-less login reuses nothing weird

    sign_in_as @user # sign in AGAIN without logging out (abandoned session case)

    assert_equal 1, @user.sessions.count, "same browser must not stack duplicate devices"
  end

  test "an abandoned session (browser quit, cookie gone) is superseded on re-login" do
    sign_in_as @user
    zombie = @user.sessions.sole

    # The browser "quits": rack session cookie lost, but the device cookie
    # survives (it's long-lived). Simulate by keeping cookies and just
    # logging in again — the old row is still live server-side.
    sign_in_as @user

    refute Session.exists?(zombie.id), "the zombie row was superseded"
    assert_equal 1, @user.sessions.count
    assert_equal 0, Sessions::Event.revocations.where(revoked_reason: "superseded").count,
                 "superseded rows are internal dedup bookkeeping, not security events"
  end

  test "a browser update changing the UA still dedupes (identity is the cookie)" do
    sign_in_as @user, ua: UserAgents::FIREFOX_WINDOWS
    sign_in_as @user, ua: UserAgents::FIREFOX_WINDOWS.gsub("139.0", "151.0")

    assert_equal 1, @user.sessions.count
    assert_equal "151", @user.sessions.sole.browser_version
  end

  test "a different browser (no continuity cookie) is a separate device" do
    sign_in_as @user
    reset! # fresh cookie jar = different browser / private window

    sign_in_as @user

    assert_equal 2, @user.sessions.count
  end

  test "two users sharing one browser never supersede each other" do
    other = User.create!(email_address: "ana@example.com", password: "s3kr1t-pass")

    sign_in_as @user
    delete "/session"
    sign_in_as other # same browser, different account

    assert_equal 1, other.sessions.count
    assert_equal 0, Sessions::Event.revocations.where(revoked_reason: "superseded").count
  end

  test "superseding is quiet housekeeping: no revocation hook, no remember-me rotation" do
    fired = false
    Sessions.config.on_session_revoked = ->(**) { fired = true }
    def @user.forget_me!
      @forgotten = true
    end

    sign_in_as @user
    sign_in_as @user

    refute fired, "superseding must not fire on_session_revoked"
    refute @user.instance_variable_get(:@forgotten), "superseding must not rotate remember-me"
  end

  test "superseding never causes a false new-device alert (the trail remembers)" do
    sign_in_as @user
    fired = false
    Sessions.config.on_new_device = ->(**) { fired = true }

    sign_in_as @user # same device again — its row gets superseded

    refute fired, "the superseded row's login EVENT keeps the device known"
  end

  test "rows without a device id (pre-upgrade, bare rack) are left alone" do
    legacy = @user.sessions.create!(ip_address: "203.0.113.7", user_agent: UserAgents::CHROME_MAC)
    legacy.update_columns(device_id: nil)

    sign_in_as @user

    assert Session.exists?(legacy.id), "no device_id = no dedup, never collateral damage"
  end
end
