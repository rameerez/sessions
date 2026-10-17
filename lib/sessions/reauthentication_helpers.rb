# frozen_string_literal: true

module Sessions
  # Controller helpers for re-authentication assertions. Opt in where you
  # check a password again:
  #
  #   class ReauthenticationsController < ApplicationController
  #     include Sessions::ReauthenticationHelpers
  #
  #     def create
  #       if current_user.valid_password?(params[:password])
  #         record_sessions_reauthentication!(method: :password)
  #         redirect_to approvals_url(assertion: sessions_reauthentication_assertion(audience: "approvals"))
  #       end
  #     end
  #   end
  module ReauthenticationHelpers
    private

    # Records the re-authentication on the current session. Returns the session, or nil without one.
    def record_sessions_reauthentication!(method: :password)
      Sessions.current(request)&.tap { |session| session.reauthenticated!(method: method) }
    end

    # True when the current session re-authenticated within the window.
    def sessions_reauthenticated?(within: Sessions.config.reauthentication_window)
      Sessions.current(request)&.reauthenticated_within?(within) || false
    end

    # An assertion of the current session's recent re-authentication, or nil
    # when there is no session or no recent re-authentication.
    def sessions_reauthentication_assertion(audience:, purpose: nil)
      Sessions.current(request)&.reauthentication_assertion(audience: audience, purpose: purpose)
    rescue Sessions::Reauthentication::NotRecent
      nil
    end
  end
end
