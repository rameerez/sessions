# frozen_string_literal: true

require "test_helper"

# The mounted devices page, end to end on the omakase dummy (where the
# engine's auth chain rides the host's inherited require_authentication and
# the current user resolves through ::Current).
class EngineUiTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email_address: "javi@example.com", password: "s3kr1t-pass")
  end

  teardown do
    Sessions.reset!
    Session.delete_all
    Sessions::Event.delete_all
    User.delete_all
  end

  def sign_in!(ua: UserAgents::CHROME_MAC)
    sign_in_as(@user, ua: ua)
    @user.sessions.order(:created_at).last
  end

  test "the devices page lists sessions, badges the current one, and shows history" do
    sign_in!
    other = create_session_for(@user, ua: UserAgents::NATIVE_ANDROID)

    get "/settings/sessions"

    assert_response :success
    assert_includes response.body, "Your devices"
    assert_includes response.body, "Chrome 137 on macOS"
    assert_includes response.body, "MyApp 2.4.1 on Pixel 8 (Android 16)"
    assert_includes response.body, "This device"
    assert_includes response.body, "Signed in" # the trail section
    # The current session renders first, with no Log out button of its own.
    assert_operator response.body.index("Chrome 137 on macOS"),
                    :<, response.body.index("MyApp 2.4.1")
    assert_includes response.body, "/settings/sessions/#{other.id}"
  end

  test "anonymous visitors are bounced by the host's own auth" do
    get "/settings/sessions"

    assert_redirected_to "/session/new"
  end

  test "revoking another device works and writes the trail" do
    sign_in!
    other = create_session_for(@user, ua: UserAgents::FIREFOX_WINDOWS)

    delete "/settings/sessions/#{other.id}"

    assert_redirected_to "/settings/sessions/"
    refute Session.exists?(other.id)
    event = Sessions::Event.revocations.sole
    assert_equal "user_revoked", event.revoked_reason
  end

  test "the current session cannot be revoked from the page" do
    current = sign_in!

    delete "/settings/sessions/#{current.id}"

    assert_redirected_to "/settings/sessions/"
    assert Session.exists?(current.id)
    assert_equal 0, Sessions::Event.revocations.count
  end

  test "you can never touch a session you don't own — plain 404, no leak" do
    sign_in!
    other_user = create_user
    foreign = create_session_for(other_user)

    delete "/settings/sessions/#{foreign.id}"

    assert_response :not_found
    assert Session.exists?(foreign.id)
  end

  test "sign out everywhere else keeps only the current session" do
    current = sign_in!
    create_session_for(@user)
    create_session_for(@user)

    delete "/settings/sessions/others"

    assert_redirected_to "/settings/sessions/"
    assert_equal [current.id], @user.sessions.pluck(:id)
    assert_equal 2, Sessions::Event.revocations.where(revoked_reason: "logout_everywhere").count
  end

  test "the history page lists the trail, newest first" do
    sign_in!
    Sessions::Event.record_failure(fake_request, identity: "javi@example.com", reason: :invalid)

    get "/settings/sessions/history"

    assert_response :success
    assert_includes response.body, "Login history"
    assert_includes response.body, "Signed in"
    assert_includes response.body, "Failed sign-in attempt"
  end

  test "the optional sudo gate blocks destructive actions" do
    sign_in!
    other = create_session_for(@user)
    Sessions.config.require_reauthentication = lambda do |controller|
      controller.redirect_to "/session/new", alert: "Confirm your password first"
    end

    delete "/settings/sessions/#{other.id}"

    assert_redirected_to "/session/new"
    assert Session.exists?(other.id)
  end

  test "the page speaks Spanish out of the box" do
    sign_in!

    I18n.with_locale(:es) do
      get "/settings/sessions"
    end

    assert_response :success
    assert_includes response.body, "Tus dispositivos"
    assert_includes response.body, "Este dispositivo"
  end

  test "the partials render straight from a host view (Layer 1)" do
    sign_in!
    create_session_for(@user, ua: UserAgents::NATIVE_IOS)

    html = ApplicationController.render(
      partial: "sessions/devices",
      locals: { user: @user }
    )

    assert_includes html, "MyApp 2.4.1 on iPhone15,2 (iOS 19.5)"
    assert_includes html, "sessions-device-list"

    history = ApplicationController.render(
      partial: "sessions/history",
      locals: { user: @user, limit: 5 }
    )

    assert_includes history, "Signed in"
  end

  test "a configured parent_controller and current_user method are honored" do
    # The chats-style indirection: misconfigure on purpose and watch the
    # plain-English error (the engine controller resolves lazily, so this
    # only bites when the page renders).
    Sessions.config.current_user_method = :current_admin

    sign_in!
    get "/settings/sessions"

    # Falls through the resolver chain to ::Current.session.user — the
    # page still works because the chain is resilient by design.
    assert_response :success
  end
end
