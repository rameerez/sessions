# frozen_string_literal: true

module Sessions
  # The "Your devices" page: list, revoke one, sign out everywhere else,
  # and the login history. Deliberately trivial — if you need custom
  # controller behavior, render the partials from your own controller
  # instead (the README's Layer 1).
  class DevicesController < ApplicationController
    # Current session always first (and never revocable from this page —
    # signing out the device you're on is the app's normal logout).
    def index
      @sessions = sessions_owner_sessions.by_recency.to_a
      if (current = @sessions.find { |session| session == sessions_current_session })
        @sessions.delete(current)
        @sessions.unshift(current)
      end
      @events = sessions_owner_events.recent.limit(10)
    end

    def history
      @events = sessions_owner_events.recent.limit(200)
    end

    def destroy
      return unless sessions_reauthenticate!

      session_row = sessions_owner_sessions.find(params[:id])

      if session_row.current?(request)
        redirect_to devices_path, alert: t("sessions.devices.cannot_revoke_current")
        return
      end

      session_row.revoke!(reason: :user_revoked, by: sessions_current_user)
      redirect_to devices_path, notice: t("sessions.devices.revoked"), status: :see_other
    end

    def others
      return unless sessions_reauthenticate!

      sessions_current_user.revoke_other_sessions!(
        current: sessions_current_session,
        by: sessions_current_user
      )
      redirect_to devices_path, notice: t("sessions.devices.revoked_others"), status: :see_other
    end
  end
end
