# frozen_string_literal: true

require "test_helper"

# The cheapest, highest-value assertions: the engine booted inside a real
# omakase host, decorated the host's Session model, prepended the controller
# hooks, and wired the macro — all with zero app-code edits beyond
# `has_sessions`.
class BootTest < ActiveSupport::TestCase
  test "gem has a version" do
    assert_match(/\A\d+\.\d+\.\d+\z/, Sessions::VERSION)
  end

  test "the omakase adapter decorated the host Session model automatically" do
    assert_includes Session.ancestors, Sessions::Model
  end

  test "the controller hooks are prepended in front of the Authentication concern" do
    ancestors = ApplicationController.ancestors
    assert_operator ancestors.index(Sessions::Adapters::Omakase::ControllerHooks),
                    :<, ancestors.index(Authentication)
  end

  test "the failed-login hooks are prepended onto the sessions controller" do
    assert_includes SessionsController.ancestors, Sessions::Adapters::Omakase::FailedLoginHooks
  end

  test "has_sessions gave the user the events association and revocation verbs" do
    assert_includes User.ancestors, Sessions::HasSessions
    user = create_user
    assert_respond_to user, :session_events
    assert_respond_to user, :revoke_other_sessions!
    assert_respond_to user, :revoke_all_sessions!
  end

  test "warden hooks are installed (warden is loaded in the dummy)" do
    assert Sessions::Adapters::Warden.installed?
  end

  test "the middleware is in the host stack" do
    assert_includes Rails.application.middleware.middlewares, Sessions::Middleware
  end

  test "Sessions::Event is autoloadable and points at the right table" do
    assert_equal "sessions_events", Sessions::Event.table_name
    assert Sessions::Event.table_exists?
  end
end
