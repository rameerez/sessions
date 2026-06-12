# frozen_string_literal: true

module Sessions
  # Human, honest device presentation — shared by the registry rows
  # (Sessions::Model) and the trail (Sessions::Event), which carry the same
  # parsed device columns:
  #
  #   "Chrome 137 on macOS"
  #   "MyApp 2.4.1 on Pixel 8 (Android 16)"
  #   "iPhone (iOS 19.5)"
  #
  # Frozen-UA tokens are never rendered as facts — versions appear only
  # where they're real (see Sessions::Device).
  module DeviceDisplay
    extend ActiveSupport::Concern

    def device_name
      return sessions_t("bot", default: "Bot (%{name})", name: try(:browser_name) || "unknown") if bot?
      return sessions_native_device_name if hotwire_native?

      client = [try(:browser_name), try(:browser_version)].compact.join(" ").presence
      platform = sessions_os_label

      if client && platform
        sessions_t("composite", default: "%{client} on %{platform}", client: client, platform: platform)
      else
        client || platform || sessions_t("unknown", default: "Unknown device")
      end
    end

    # "Madrid, Spain" — or nil when geolocation is unavailable (the UI
    # omits location cleanly).
    def location
      [try(:city), try(:country_name)].compact_blank.join(", ").presence
    end

    # "🇪🇸" — derived from country_code at render time; no column needed.
    def country_flag
      code = try(:country_code).to_s
      return nil unless code.match?(/\A[A-Za-z]{2}\z/)

      code.upcase.each_codepoint.map { |codepoint| (codepoint + 0x1F1A5).chr(Encoding::UTF_8) }.join
    end

    # "🇪🇸 Madrid, Spain · IP 83.45.112.7 · Firefox 139 on Windows" — the
    # one-line WHERE-then-WHAT of a login, ready for security emails,
    # notification bodies, and admin lists. Location leads (people
    # recognize places; browser version numbers mean nothing to them), the
    # IP is the verifiable fact, the device closes. Each part drops out
    # cleanly when the record lacks it (no geo in dev, no UA on odd
    # clients). `ip: false` for compact UI like notification feed rows;
    # `separator:` for plain-text contexts.
    def source_line(ip: true, separator: " · ")
      located = [country_flag, location].compact.join(" ").presence
      address = ip ? (try(:ip_address) || try(:last_seen_ip)).presence : nil

      [located, address && "IP #{address}", device_name].compact.join(separator).presence
    end

    def hotwire_native?
      try(:device_type).to_s.start_with?("native_")
    end

    def native_ios?
      try(:device_type) == "native_ios"
    end

    def native_android?
      try(:device_type) == "native_android"
    end

    def bot?
      try(:device_type) == "bot"
    end

    def web?
      !hotwire_native? && !bot?
    end

    def via_oauth?
      try(:auth_method) == "oauth"
    end

    def via_password?
      try(:auth_method) == "password"
    end

    # The second factor that protected this login, when one did: "totp"
    # (authenticator apps via devise-two-factor — detected automatically),
    # "backup_code", or whatever the host tagged ("webauthn" for security
    # keys / Touch ID as a second factor — see the README's two-factor
    # recipes). nil for single-factor logins.
    def second_factor
      detail = try(:auth_detail)
      detail.is_a?(Hash) ? detail["second_factor"].presence : nil
    end

    def second_factor?
      second_factor.present?
    end

    # "Google", "GitHub", "password", "passkey"… for "Signed in via %{method}"
    # copy. nil when the method is unknown (the UI omits the clause).
    def auth_method_label
      method = try(:auth_method)
      return nil if method.blank? || method == "unknown"
      return try(:auth_provider).to_s.titleize if via_oauth? && try(:auth_provider).present?

      I18n.t("sessions.auth_methods.#{method}", default: method.humanize.downcase)
    end

    private

    def sessions_native_device_name
      hardware = [try(:device_model).presence, sessions_os_label && "(#{sessions_os_label})"].compact.join(" ")
      hardware = sessions_os_label if hardware.blank?

      if try(:app_name).present?
        client = [try(:app_name), try(:app_version)].compact_blank.join(" ")
        sessions_t("composite", default: "%{client} on %{platform}", client: client, platform: hardware)
      else
        hardware || sessions_t("unknown", default: "Unknown device")
      end
    end

    def sessions_os_label
      [try(:os_name), try(:os_version)].compact_blank.join(" ").presence
    end

    def sessions_t(key, **options)
      I18n.t("sessions.device_name.#{key}", **options)
    end
  end
end
