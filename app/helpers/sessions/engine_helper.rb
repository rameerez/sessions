# frozen_string_literal: true

module Sessions
  # View helpers for the devices page (and for the host-renderable
  # partials).
  module EngineHelper
    DEVICE_ICONS = {
      "desktop" => "🖥",
      "smartphone" => "📱",
      "tablet" => "📱",
      "native_ios" => "📱",
      "native_android" => "📱",
      "bot" => "🤖"
    }.freeze

    # Semantic icon names (Heroicons vocabulary — map them onto whatever
    # icon helper your app uses) so custom views don't re-derive the
    # device_type → icon mapping the gem already knows.
    DEVICE_ICON_NAMES = {
      "desktop" => "computer-desktop",
      "smartphone" => "device-phone-mobile",
      "tablet" => "device-tablet",
      "native_ios" => "device-phone-mobile",
      "native_android" => "device-phone-mobile",
      "bot" => "bug-ant"
    }.freeze

    EVENT_ICON_NAMES = {
      "login" => "check-circle",
      "failed_login" => "x-circle",
      "logout" => "arrow-right-on-rectangle",
      "revoked" => "no-symbol",
      "expired" => "clock"
    }.freeze

    def sessions_device_icon(session)
      DEVICE_ICONS.fetch(session.device_type.to_s, "🌐")
    end

    def sessions_device_icon_name(session)
      DEVICE_ICON_NAMES.fetch(session.device_type.to_s, "globe-alt")
    end

    def sessions_event_icon_name(event)
      EVENT_ICON_NAMES.fetch(event.event.to_s, "information-circle")
    end

    # "Active now" within the touch window, else "Active 3 minutes ago".
    def sessions_last_active_in_words(session)
      # active_now? owns the window (config.touch_every) — the badge can't
      # honestly claim more freshness than the throttle records.
      return t("sessions.devices.active_now") if session.respond_to?(:active_now?) && session.active_now?

      time = session.last_active_at
      return nil unless time

      t("sessions.devices.active_ago", time: time_ago_in_words(time))
    end

    # The engine's route proxy when it's mounted, nil otherwise — partials
    # rendered inside a host that didn't mount the engine simply omit the
    # revoke buttons. The proxy method is named after the mount (`sessions`
    # by default, or whatever `as:` was given), so it's DISCOVERED from the
    # host's named routes rather than assumed.
    def sessions_engine_routes
      name = Sessions::EngineHelper.engine_mount_name
      name && respond_to?(name) ? public_send(name) : nil
    end

    # The name of the route that mounts Sessions::Engine in the host app
    # ("sessions" for a plain mount, the `as:` value otherwise). Memoized
    # per-process; in development a changed mount name reloads routes and
    # to_prepare re-touches this helper file, clearing the memo.
    def self.engine_mount_name
      return @engine_mount_name if defined?(@engine_mount_name)

      @engine_mount_name = begin
        route = Rails.application.routes.routes.find do |candidate|
          # The mount sits behind a Constraints wrapper; unwrap a bounded
          # number of times, checking BEFORE each unwrap — Rails::Engine
          # itself responds to #app (its middleware stack), so an unguarded
          # `while app.respond_to?(:app)` would walk straight past it.
          app = candidate.app
          matched = false
          3.times do
            matched = (app == Sessions::Engine)
            break if matched || !app.respond_to?(:app)

            app = app.app
          end
          matched
        end
        route&.name
      rescue StandardError
        nil
      end
    end

    def self.reset_engine_mount_name!
      remove_instance_variable(:@engine_mount_name) if defined?(@engine_mount_name)
    end

    # "Signed in May 2, 2026" — localized when the host bundles date
    # formats (rails-i18n or its own locale files), with a safe fallback so
    # a bare host never 500s over a missing `date.formats.long`. nil-safe:
    # without the guard, I18n.l(nil) raises I18n::ArgumentError and the
    # rescue would then call nil.strftime — a trap for custom views passing
    # a nullable column.
    def sessions_format_date(date)
      return nil unless date

      I18n.l(date, format: :long)
    rescue I18n::MissingTranslationData, I18n::ArgumentError
      date.strftime("%Y-%m-%d")
    end

    def sessions_format_time(time)
      return nil unless time

      I18n.l(time, format: :short)
    rescue I18n::MissingTranslationData, I18n::ArgumentError
      time.strftime("%Y-%m-%d %H:%M")
    end
  end
end

# Expose the helpers to the HOST's views too, so the Layer-1 partials
# (`render "sessions/devices"`) work outside the engine. Registered at the
# bottom of this file (not from an engine initializer) so the hook is
# self-resolving on hosts where ActionView loads early — the engine's
# to_prepare touches this constant to guarantee the file loads every boot
# (the moderate/chats-proven pattern).
ActiveSupport.on_load(:action_view) { include Sessions::EngineHelper }
