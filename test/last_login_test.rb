# frozen_string_literal: true

require "test_helper"

# The "Last used" badge: `Sessions.last_login(request)` answers "how did
# this browser last sign in" ON THE LOGIN PAGE, signed out — the signed
# browser-continuity cookie survives logout by design, and login events
# carry the same device id. Device-scoped, not account-scoped.
class LastLoginTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email_address: "user@example.test", password: "s3kr1t-pass")
  end

  teardown do
    Sessions.reset!
    Session.delete_all
    Sessions::Event.delete_all
    User.delete_all
  end

  test "a browser that never signed in gets nil — and no badge" do
    get "/session/new"

    assert_response :success
    refute_includes response.body, "sessions-last-used-badge"
  end

  test "after sign-in and sign-out, the login page knows the last method" do
    sign_in_as @user
    delete "/session" # logout ends the row; the trail + cookie remain

    get "/session/new"

    assert_response :success
    assert_includes response.body, "sessions-last-used-badge",
                    "the badge renders from the trail event after logout"
  end

  test "last_login returns the freshest login event for this browser" do
    sign_in_as @user
    Sessions::Event.logins.sole.update_columns(occurred_at: 2.days.ago,
                                               auth_method: "oauth", auth_provider: "github")
    delete "/session"
    sign_in_as @user # a fresh password login, just now
    delete "/session"

    get "/session/new"
    event = Sessions.last_login(request)

    assert_equal "password", event.auth_method, "the newest login wins, not the github one"
    assert_operator event.occurred_at, :>, 1.minute.ago
  end

  test "a different browser (no cookie) knows nothing" do
    sign_in_as @user
    delete "/session"
    reset! # fresh cookie jar

    get "/session/new"

    refute_includes response.body, "sessions-last-used-badge"
  end

  test "a tampered cookie yields nil, never an error" do
    sign_in_as @user
    delete "/session"
    cookies[Sessions::DEVICE_COOKIE.to_s] = "forged-value"

    get "/session/new"

    assert_response :success
    refute_includes response.body, "sessions-last-used-badge"
  end

  test "device-scoped by design: it reflects whoever last signed in from this browser" do
    other = User.create!(email_address: "ana@example.com", password: "s3kr1t-pass")

    sign_in_as @user
    delete "/session"
    sign_in_as other
    delete "/session"

    # The cookie is the browser's identity; the latest login event from it
    # belongs to `other` — exactly what a signed-out login page can know.
    last = Sessions::Event.logins.order(occurred_at: :desc).first
    assert_equal other, last.authenticatable
  end
end
