# frozen_string_literal: true

require "test_helper"

# The omakase-side two-factor flows, end to end against the dummy app:
# authentication-zero's two-phase challenge shape (the session is created
# ONLY at full auth, labeled by the README's tag recipe) and the DIY
# post-login step-up gate (`second_factor!`). The Devise/Warden shapes —
# devise-two-factor single-phase, devise-otp two-phase, passkey-first —
# live in warden_adapter_test.rb.
class TwoFactorFlowsTest < ActionDispatch::IntegrationTest
  setup do
    # The dummy's SessionsController challenges users flagged by the "2fa-"
    # email prefix (its stand-in for an otp_secret column).
    @user = User.create!(email_address: "2fa-user@example.test", password: "s3kr1t-pass")
  end

  teardown do
    Sessions.reset!
    Session.delete_all
    Sessions::Event.delete_all
    User.delete_all
  end

  test "the password phase creates NO session and NO trail event" do
    post "/session", params: { email_address: @user.email_address, password: "s3kr1t-pass" }

    assert_redirected_to "/two_factor_challenge/new"
    assert_equal 0, Session.count, "no session may exist before the second factor verifies"
    assert_equal 0, Sessions::Event.count
  end

  test "completing the challenge mints ONE session classified password + totp" do
    post "/session", params: { email_address: @user.email_address, password: "s3kr1t-pass" }
    post "/two_factor_challenge", params: { code: "123456" },
                                  headers: { "HTTP_USER_AGENT" => UserAgents::CHROME_MAC }

    row = @user.sessions.sole
    assert_equal "password", row.auth_method
    assert_equal "totp", row.second_factor
    event = Sessions::Event.logins.sole
    assert_equal "totp", event.second_factor
    assert_equal row.id, event.session_id
  end

  test "a wrong code records the failed second factor through the manual seam" do
    post "/session", params: { email_address: @user.email_address, password: "s3kr1t-pass" }
    post "/two_factor_challenge", params: { code: "000000" }

    assert_equal 0, Session.count
    failure = Sessions::Event.failed_logins.sole
    assert_equal "invalid_otp", failure.failure_reason
    assert_equal @user.email_address, failure.identity
    assert_equal "totp", failure.second_factor, "the factor that failed rides the detail for triage"
  end

  test "a post-login step-up stamps the live session via second_factor!" do
    plain = User.create!(email_address: "user@example.test", password: "s3kr1t-pass")
    post "/session", params: { email_address: plain.email_address, password: "s3kr1t-pass" }
    row = plain.sessions.sole
    refute row.second_factor?

    post "/step_up", params: { code: "123456" }

    assert_response :ok
    assert_equal "totp", row.reload.second_factor
  end

  test "a failed step-up changes nothing" do
    plain = User.create!(email_address: "user@example.test", password: "s3kr1t-pass")
    post "/session", params: { email_address: plain.email_address, password: "s3kr1t-pass" }

    post "/step_up", params: { code: "999999" }

    assert_response :unprocessable_entity
    refute plain.sessions.sole.second_factor?
  end
end
