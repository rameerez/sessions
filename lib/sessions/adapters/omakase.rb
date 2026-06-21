# frozen_string_literal: true

module Sessions
  module Adapters
    # The Rails 8 omakase auth adapter — zero app-code changes.
    #
    # Installed from `config.to_prepare` (so it re-applies to freshly
    # reloaded constants in development) and entirely capability-detected:
    # nothing happens unless the app actually has the generated
    # authentication code. Three attachment points, each name-stable since
    # Rails 8.0 (the Authentication concern is byte-identical from 8.0.5
    # through 8.1.3 to main — → docs/research/03-rails-core.md):
    #
    #   1. The Session MODEL gets Sessions::Model included. Its callbacks
    #      observe `start_new_session_for` (create!) for logins. Normal
    #      logout is intercepted by ControllerHooks and ends the row in
    #      place; host-side destroy_all (Rails password reset/account erasure)
    #      is still tolerated by the model's destroy compatibility hook.
    #
    #   2. ApplicationController gets ControllerHooks PREPENDED — the
    #      prepend sits in front of the included Authentication concern in
    #      the ancestor chain, so `super`-wrapping `resume_session`
    #      (throttled touch + opt-in expiry) and `terminate_session`
    #      (labeling the lifecycle end as a logout) is clean.
    #
    #   3. The generated SessionsController#create gets FailedLoginHooks
    #      prepended: `authenticate_by` is deliberately silent on failure
    #      (no hook, no notification), so we observe the controller seam —
    #      after `super`, no session + a credentials POST = a failed login.
    #      Rails 8.1's `rate_limit.action_controller` notification adds the
    #      brute-force-threshold signal for free.
    module Omakase
      module_function

      def install!
        Sessions.safely("omakase.install") do
          decorate_session_model!
          prepend_controller_hooks!
          prepend_failed_login_hooks!
        end
      end

      # `Session.include Sessions::Model` when the host has a Rails-8-shaped
      # session model (the Devise-mode shell model includes it explicitly;
      # this is a no-op there).
      def decorate_session_model!
        klass = session_class
        return unless klass
        return if klass.include?(Sessions::Model)

        klass.include(Sessions::Model)
      end

      def prepend_controller_hooks!
        return unless omakase_controller?

        ::ApplicationController.prepend(ControllerHooks)
      end

      def prepend_failed_login_hooks!
        return unless omakase_controller?
        return unless defined?(::SessionsController)
        return unless ::SessionsController.method_defined?(:create)

        ::SessionsController.prepend(FailedLoginHooks)
      end

      # The duck test: the generated Authentication concern defines these
      # private methods on ApplicationController. Capability-based, so a
      # host that renamed or removed its auth code simply isn't touched.
      def omakase_controller?
        defined?(::ApplicationController) &&
          ::ApplicationController.private_method_defined?(:start_new_session_for) &&
          ::ApplicationController.private_method_defined?(:resume_session)
      end

      def session_class
        klass = Sessions.config.session_class.safe_constantize
        return nil unless klass.is_a?(Class)
        return nil unless defined?(::ActiveRecord::Base) && klass < ::ActiveRecord::Base
        # The Rails 8 base columns prove the shape; last_seen_at proves the
        # install migration ran (decorating a half-migrated table would give
        # candy methods nothing to stand on).
        return nil unless klass.table_exists? &&
                          (%w[ip_address user_agent last_seen_at] - klass.column_names).empty?

        klass
      rescue StandardError
        nil
      end

      # Rails 8.1+ instruments rate-limit hits with a payload carrying the
      # request — a free brute-force signal. Subscribed once per process
      # (from the engine initializer, not to_prepare); on Rails ≤ 8.0 the
      # notification never fires and this is inert.
      def subscribe_rate_limit_notifications!
        return if @rate_limit_subscribed

        @rate_limit_subscribed = true
        ActiveSupport::Notifications.subscribe("rate_limit.action_controller") do |*_args, payload|
          record_rate_limited(payload)
        end
      end

      def record_rate_limited(payload)
        Sessions.safely("omakase.rate_limit") do
          next unless Sessions.config.track_failed_logins

          request = payload[:request]
          next unless request

          # Only the sessions controller: a rate-limited LOGIN burst is
          # failed-login activity; throttles elsewhere (password resets,
          # API endpoints) are not — recording them here would put
          # non-logins in the failed_login vocabulary.
          controller = request.path_parameters[:controller].to_s.split("/").last
          next unless controller == "sessions"

          Sessions::Event.record_failure(
            request,
            reason: :rate_limited,
            metadata: { count: payload[:count], limit: payload[:to] }.compact
          )
        end
      end

      # Prepended in front of the generated Authentication concern.
      module ControllerHooks
        private

        # After the host resolves the session row, refuse ended lifecycle rows,
        # enforce opt-in expiry and apply the throttled last_seen_at touch.
        # In Rails 8 auth this row is the session of record, so an ended row
        # must be treated as unauthenticated even though it still exists for
        # audit/history.
        def resume_session
          session = super
          return session unless session.respond_to?(:sessions_expired?)

          if session.ended?
            Sessions.safely("omakase.ended") { sessions_clear_omakase_session_cookie }
            ::Current.session = nil if defined?(::Current) && ::Current.respond_to?(:session=)
            nil
          elsif session.sessions_expired?
            # The lifecycle row is the server-side liveness source of truth.
            # If the end transition rolls back (for example, the audit event
            # cannot be written), do not clear the Rails auth cookie: that
            # would log the user out while leaving a stale `.live` row behind.
            # Source: Warden's session_limitable pattern also kicks only after
            # a durable server-side state change:
            # https://github.com/devise-security/devise-security/blob/v0.18.0/lib/devise-security/hooks/session_limitable.rb
            if sessions_end_omakase_session(session, reason: :expired, context: "omakase.expire")
              Sessions.safely("omakase.expire.cookie") { sessions_clear_omakase_session_cookie }
              ::Current.session = nil if defined?(::Current) && ::Current.respond_to?(:session=)
              nil
            else
              session
            end
          else
            Sessions.safely("omakase.touch") { session.touch_last_seen!(request) }
            session
          end
        end

        # Rails' generated auth calls `Current.session.destroy` here:
        # https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/authentication/templates/app/controllers/concerns/authentication.rb.tt
        # v0.2 preserves the row and marks it ended instead, because the row is
        # now the lifecycle source of truth. We still delete the signed cookie
        # exactly like the generated method.
        def terminate_session
          session = defined?(::Current) ? ::Current.try(:session) : nil
          if session.respond_to?(:end!)
            sessions_end_omakase_session!(session, reason: :logout, context: "omakase.terminate")
            ::Current.session = nil if defined?(::Current) && ::Current.respond_to?(:session=)
            sessions_clear_omakase_session_cookie
          else
            super
          end
        end

        def sessions_clear_omakase_session_cookie
          cookies.delete(:session_id)
        end

        def sessions_end_omakase_session(session, reason:, context:)
          session.end!(reason: reason)
          true
        rescue StandardError => e
          Sessions.warn("#{context} failed open: #{e.class}: #{e.message}")
          false
        end

        def sessions_end_omakase_session!(session, reason:, context:)
          session.end!(reason: reason)
          true
        rescue StandardError => e
          # Explicit logout must either persist its lifecycle transition or
          # abort before deleting the cookie. Otherwise the tracking layer
          # silently changes auth state while the row still says "live".
          Sessions.warn("#{context} aborted auth teardown: #{e.class}: #{e.message}")
          raise
        end
      end

      # Prepended onto the generated SessionsController.
      module FailedLoginHooks
        # The generated create either calls start_new_session_for (success —
        # Current.session is set) or redirects with an alert (failure —
        # nothing recorded anywhere). We add the missing failure record.
        def create
          super
          Sessions.safely("omakase.failed_login") do
            next unless Sessions.config.track_failed_logins
            next if defined?(::Current) && ::Current.try(:session)
            next unless request.post?
            # Two-phase 2FA controllers redirect to their challenge with the
            # password VALIDATED and no session yet — `Sessions.skip!` is
            # their one-line way to say "not a failure" (see lib/sessions.rb).
            next if request.env[Sessions::SKIP_ENV_KEY]

            identity = sessions_attempted_identity
            next unless identity || params[:password].present?

            Sessions::Event.record_failure(request, identity: identity, reason: :invalid_credentials)
          end
        end

        private

        # The generated form posts `email_address`; common hand-rolled
        # variants are accepted too. The password itself is NEVER read
        # beyond presence.
        def sessions_attempted_identity
          %i[email_address email username login].lazy.map { |key| params[key] }.find(&:present?)
        end
      end
    end
  end
end
