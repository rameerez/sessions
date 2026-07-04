# frozen_string_literal: true

module Sessions
  # Optional per-user Madmin panel actions. Include this in
  # Madmin::UsersController, then draw the routes printed by
  # `rails generate sessions:madmin --user-panel`.
  module MadminUserPanel
    extend ActiveSupport::Concern

    SESSION_EVENTS_PER_PAGE = 30

    def sessions
      @user = User.find(params[:id])
      @sessions = @user.sessions.live.by_recency.to_a
      events = @user.session_history.recent

      @failed_last_24h = events.failed_logins.last_24_hours.count
      if respond_to?(:pagy, true)
        @pagy, @events = pagy(events, limit: SESSION_EVENTS_PER_PAGE)
      else
        @events = events.limit(SESSION_EVENTS_PER_PAGE)
      end
    rescue StandardError => e
      raise unless defined?(::Pagy::OptionError) && e.is_a?(::Pagy::OptionError)

      @pagy, @events = pagy(events, page: 1, limit: SESSION_EVENTS_PER_PAGE)
    end

    # Account-takeover response: revoke every live row with admin attribution.
    # Each row writes its own `revoked` event and, in Devise mode, rotates
    # remember-me credentials so a long-lived cookie cannot revive the device.
    def revoke_all_sessions
      user = User.find(params[:id])
      count = user.sessions.live.count

      user.revoke_all_sessions!(by: current_user)
      flash[:notice] = "#{count} #{"session".pluralize(count)} revoked. " \
                       "Every device will be signed out on its next request."

      redirect_to main_app.sessions_madmin_user_path(user)
    end
  end
end
