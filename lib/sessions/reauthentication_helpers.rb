# frozen_string_literal: true

module Sessions
  # Controller helpers for re-authentication assertions. Opt in where you
  # check a password again, and name whose password you checked:
  #
  #   class ReauthenticationsController < ApplicationController
  #     include Sessions::ReauthenticationHelpers
  #
  #     def create
  #       if current_user.valid_password?(params[:password])
  #         record_sessions_reauthentication!(current_user, method: :password)
  #         token = sessions_reauthentication_assertion(current_user, audience: "approvals")
  #       end
  #     end
  #   end
  #
  # Every helper takes the owner whose credential the controller checked and
  # acts only on a current session of that owner (in `scope:` when the app
  # signs in more than one Warden scope).
  module ReauthenticationHelpers
    private

    # Records the re-authentication on the owner's current session. Returns the session, or nil.
    def record_sessions_reauthentication!(owner, method: :password, scope: nil)
      sessions_reauthentication_session(owner, scope)&.tap { |session| session.reauthenticated!(method: method) }
    end

    # True when the owner's current session re-authenticated within the window.
    def sessions_reauthenticated?(owner, within: Sessions.config.reauthentication_window, scope: nil)
      sessions_reauthentication_session(owner, scope)&.reauthenticated_within?(within) || false
    end

    # An assertion of the owner's recent re-authentication, or nil.
    def sessions_reauthentication_assertion(owner, audience:, purpose: nil, scope: nil)
      sessions_reauthentication_session(owner, scope)&.reauthentication_assertion(audience: audience, purpose: purpose)
    rescue Sessions::Reauthentication::NotRecent
      nil
    end

    def sessions_reauthentication_session(owner, scope)
      session = Sessions.current(request, scope: scope)
      return nil unless session && owner
      return nil unless session.reauthentication_subject == Sessions::Reauthentication.subject_for(owner)

      session
    end
  end
end
