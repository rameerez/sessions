# frozen_string_literal: true

module Madmin
  class SessionsController < Madmin::ResourceController
    # Admin remote logout. `revoke!` ends the row in place (the device is
    # kicked on its next matching request — the cookie session and, in Devise
    # mode, any remember-me revival), and writes the immutable `revoked`
    # trail event with `by:` attribution.
    def revoke
      session_row = <%= session_class %>.find(params[:id])
      device = session_row.device_name

      session_row.revoke!(reason: :admin_revoked, by: current_user)
      flash[:notice] = "Session revoked (#{device}). The device will be signed out on its next request."

      redirect_back fallback_location: main_app.madmin_sessions_path
    rescue ActiveRecord::RecordNotFound
      flash[:alert] = "That session no longer exists (probably already revoked)."
      redirect_back fallback_location: main_app.madmin_sessions_path
    end

    private

    # The index is a triage surface — always show who owns each row without
    # N+1ing the user column.
    def scoped_resources
      super.includes(:user)
    end
  end
end
