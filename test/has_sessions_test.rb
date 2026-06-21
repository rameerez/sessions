# frozen_string_literal: true

require "test_helper"

class HasSessionsTest < ActiveSupport::TestCase
  test "revoke_other_sessions! keeps the given session, revokes the rest" do
    user = create_user
    keep = create_session_for(user)
    kill_one = create_session_for(user)
    kill_two = create_session_for(user)

    user.revoke_other_sessions!(current: keep)

    assert_equal [keep], user.sessions.live.to_a
    assert_equal 2, Sessions::Event.revocations.where(revoked_reason: "logout_everywhere").count
    assert_equal "logout_everywhere", kill_one.reload.ended_reason
    assert_equal "logout_everywhere", kill_two.reload.ended_reason
  end

  test "revoke_other_sessions! with no current session revokes everything" do
    user = create_user
    create_session_for(user)
    create_session_for(user)

    user.revoke_other_sessions!

    assert_equal 0, user.sessions.live.count
  end

  test "revoke_all_sessions! is the admin hammer with an attributed actor" do
    user = create_user
    admin = create_user
    2.times { create_session_for(user) }

    user.revoke_all_sessions!(by: admin)

    assert_equal 0, user.sessions.live.count
    events = Sessions::Event.revocations.where(revoked_reason: "admin_revoked")
    assert_equal 2, events.count
    assert(events.all? { |event| event.metadata["revoked_by"] == "User##{admin.id}" })
  end

  test "changing the password revokes every other session (ASVS 3.3.3)" do
    user = create_user
    create_session_for(user)
    create_session_for(user)

    user.update!(password: "an0ther-s3cret")

    assert_equal 0, user.sessions.live.count
    assert_equal 2, Sessions::Event.revocations.where(revoked_reason: "password_change").count
  end

  test "the session performing the password change survives" do
    user = create_user
    mine = create_session_for(user)
    other = create_session_for(user)

    fake_request
    Sessions.stubs(:current).returns(mine)
    user.update!(password: "an0ther-s3cret")

    assert_equal [mine], user.sessions.live.to_a
    assert_equal "password_change", other.reload.ended_reason
  end

  test "an admin's own session never counts as the user's current one" do
    admin = create_user
    admin_session = create_session_for(admin)
    user = create_user
    create_session_for(user)

    Sessions.stubs(:current).returns(admin_session)
    user.update!(password: "f0rced-r3set")

    assert_equal 0, user.sessions.live.count
    assert Session.exists?(admin_session.id)
  end

  test "config.revoke_on_password_change = false disables the auto-revocation" do
    Sessions.config.revoke_on_password_change = false
    user = create_user
    create_session_for(user)

    user.update!(password: "an0ther-s3cret")

    assert_equal 1, user.sessions.count
  end

  test "non-password updates revoke nothing" do
    user = create_user
    create_session_for(user)

    user.update!(email_address: "new@example.com")

    assert_equal 1, user.sessions.count
  end

  test "session_events is the user's slice of the trail" do
    user = create_user
    other = create_user
    create_session_for(user)
    create_session_for(other)

    assert_equal 1, user.session_events.count
    assert_equal 1, user.session_events.logins.count
  end
end
