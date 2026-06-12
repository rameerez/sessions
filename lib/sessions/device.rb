# frozen_string_literal: true

require "browser"

module Sessions
  # Turns a raw user agent (+ optional client-hint / X-Client-* headers) into
  # the parsed device columns a "your devices" page renders. This is a
  # PROJECTION: the raw UA is always persisted alongside, so parsing can be
  # re-run as parsers and conventions improve.
  #
  # Three layers, in order (→ docs/research/07-device-detection.md):
  #
  #   1. Native matcher — Hotwire Native UAs (`/(Turbo|Hotwire) Native/`, the
  #      same contract as turbo-rails' `hotwire_native_app?`), the documented
  #      `AppName/1.2.3 (model; OS version; build N);` prefix convention,
  #      legacy shapes like "MyApp Android 1.0.5 (build 6; Android 14; sdk
  #      34; Pixel 7)", and validated X-Client-* headers. No third-party
  #      parser understands any of this; it's the layer that names a session
  #      "MyApp 2.4.1 on Pixel 8 (Android 16)".
  #   2. Web parser — the `browser` gem by default (MIT, zero-dep, what
  #      Mastodon uses), auto-upgrading to `device_detector` when the host
  #      bundles it, or any `->(user_agent, headers) { ... }` lambda.
  #   3. Honesty filter — 2026 web UAs are frozen husks ("Windows NT 10.0",
  #      "Intel Mac OS X 10_15_7", "Android 10; K"); we never present a
  #      frozen token as a fact. OS versions are kept only where they're
  #      real: iOS UAs, Android WebViews (exempt from UA reduction), and
  #      Chromium client hints. Everything else renders version-less
  #      ("Chrome on macOS") — accurate beats impressive.
  class Device
    # Hard input bound (GitLab's SafeDeviceDetector precedent): parse at most
    # this many characters. The FULL raw UA is still stored by the caller.
    UA_PARSE_LIMIT = 1024

    # Same contract as turbo-rails (app/controllers/turbo/native/navigation.rb).
    NATIVE_MARKER = /(?:Turbo|Hotwire) Native (iOS|Android)/i

    # The README's recommended prefix convention:
    #   MyApp/2.4.1 (iPhone15,2; iOS 19.5; build 241);
    # Product tokens that are part of every browser UA must never match as
    # app names.
    BROWSER_PRODUCT_TOKENS = %w[
      Mozilla AppleWebKit Chrome CriOS Safari Version Firefox FxiOS Gecko
      KHTML Mobile OPR Edg\w* SamsungBrowser
    ].freeze
    CONVENTION_DENYLIST = /\A(?:#{BROWSER_PRODUCT_TOKENS.join("|")})\z/i
    CONVENTION = %r{(?<app>[A-Za-z][\w .-]*?)/(?<version>\d[\w.]*)\s*\((?<fields>[^)]*)\)}

    # The legacy native-HTTP-client shape (apps declare the name via
    # config.native_app_names):
    #   MyApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)
    LEGACY = /(?<app>[A-Za-z][\w .-]*?) (?<platform>iOS|Android) (?<version>\d[\w.]*)\s*\((?<fields>[^)]*)\)/

    # The Android WebView segment of a Hotwire Native UA — exempt from
    # Chrome's UA reduction, so model + OS version here are REAL.
    ANDROID_WEBVIEW = %r{\(Linux; Android (?<os_version>[\d.]+); (?<model>[^;)]+?)(?: Build/[^;)]*)?[;)]}

    # Real iOS version from the WebKit UA ("CPU iPhone OS 19_5 like Mac OS X").
    IOS_OS_VERSION = /CPU (?:iPhone )?OS (?<version>\d+(?:_\d+)*)/

    DEVICE_TYPES = %w[desktop smartphone tablet native_ios native_android bot unknown].freeze

    ATTRIBUTES = %i[
      browser_name browser_version os_name os_version
      device_type device_model app_name app_version app_build
    ].freeze

    attr_reader(*ATTRIBUTES)

    # Parse a raw user agent string (and optional canonical headers hash from
    # `Device.headers_from`). Never raises: a hostile or unparseable UA
    # degrades to device_type "unknown" — tracking must never break login.
    def self.parse(user_agent, headers: {})
      new(user_agent, headers: headers)
    rescue StandardError => e
      Sessions.warn("device parsing failed: #{e.class}: #{e.message}")
      allocate.tap { |device| device.send(:initialize_blank) }
    end

    # The interesting request headers, normalized to their canonical names —
    # used both as parser input and as the raw `client_hints` column value
    # (so a future `sessions:reparse` can re-run parsing offline).
    CAPTURED_HEADERS = {
      "HTTP_SEC_CH_UA" => "Sec-CH-UA",
      "HTTP_SEC_CH_UA_MOBILE" => "Sec-CH-UA-Mobile",
      "HTTP_SEC_CH_UA_PLATFORM" => "Sec-CH-UA-Platform",
      "HTTP_SEC_CH_UA_PLATFORM_VERSION" => "Sec-CH-UA-Platform-Version",
      "HTTP_SEC_CH_UA_MODEL" => "Sec-CH-UA-Model",
      "HTTP_SEC_CH_UA_FULL_VERSION_LIST" => "Sec-CH-UA-Full-Version-List",
      "HTTP_X_CLIENT_PLATFORM" => "X-Client-Platform",
      "HTTP_X_CLIENT_VERSION" => "X-Client-Version",
      "HTTP_X_CLIENT_BUILD" => "X-Client-Build",
      "HTTP_X_CLIENT_OS" => "X-Client-OS"
    }.freeze

    def self.headers_from(request)
      return {} unless request

      CAPTURED_HEADERS.each_with_object({}) do |(env_key, name), hints|
        value = request.get_header(env_key)
        hints[name] = value if value.respond_to?(:to_str) && !value.to_str.empty?
      end
    rescue StandardError
      {}
    end

    def initialize(user_agent, headers: {})
      initialize_blank
      # Strip BEFORE the emptiness check: the browser gem's bot list treats
      # whitespace-only UAs as bots, but for a devices page they're just
      # unknown.
      @user_agent = user_agent.to_s.strip[0, UA_PARSE_LIMIT]
      @headers = headers || {}

      if native_platform
        parse_native
      elsif @user_agent.empty?
        @device_type = "unknown"
      else
        parse_web
      end

      freeze
    end

    def native?
      device_type&.start_with?("native_")
    end

    def bot?
      device_type == "bot"
    end

    # Only the attributes that map 1:1 onto session/event columns.
    def to_h
      ATTRIBUTES.index_with { |attribute| public_send(attribute) }.compact
    end

    private

    def initialize_blank
      ATTRIBUTES.each { |attribute| instance_variable_set(:"@#{attribute}", nil) }
      @device_type = "unknown"
      @user_agent = ""
      @headers = {}
    end

    # --- Layer 1: native ------------------------------------------------------

    # ios/android/nil — the union of the three native signals.
    def native_platform
      @native_platform ||=
        if (marker = @user_agent.match(NATIVE_MARKER))
          marker[1].downcase == "ios" ? "ios" : "android"
        elsif %w[ios android].include?(header("X-Client-Platform").to_s.downcase)
          header("X-Client-Platform").downcase
        elsif (legacy = legacy_match) && known_native_app?(legacy[:app])
          legacy[:platform].downcase == "ios" ? "ios" : "android"
        end
    end

    def parse_native
      @device_type = "native_#{native_platform}"

      apply_native_fallbacks   # weakest signals first…
      apply_ua_prefix
      apply_client_headers     # …explicit headers win
    end

    # Platform defaults available even when the app sets no UA prefix at all:
    # Android WebView UAs carry real model + OS; iOS UAs carry real OS.
    def apply_native_fallbacks
      if native_platform == "android"
        @os_name = "Android"
        if (webview = @user_agent.match(ANDROID_WEBVIEW))
          @os_version = webview[:os_version]
          @device_model = clean_token(webview[:model])
        end
      else
        @os_name = "iOS"
        if (ios = @user_agent.match(IOS_OS_VERSION))
          @os_version = ios[:version].tr("_", ".")
        end
        # WKWebView UAs carry the device FAMILY (real, unlike desktop
        # Safari) — never the hardware model; the prefix convention adds
        # that and overwrites this via apply_prefix_fields.
        @device_model = "iPad" if @user_agent.include?("iPad")
        @device_model = "iPhone" if @user_agent.include?("iPhone")
      end
    end

    def apply_ua_prefix
      if (convention = convention_match)
        @app_name = clean_token(convention[:app])
        @app_version = convention[:version]
        apply_prefix_fields(convention[:fields])
      elsif (legacy = legacy_match)
        @app_name = clean_token(legacy[:app])
        @app_version = legacy[:version]
        apply_prefix_fields(legacy[:fields])
      end
    end

    # Semicolon-separated, order-insensitive fields from the parenthesized
    # part of the prefix: "iPhone15,2; iOS 19.5; build 241". The first
    # unrecognized field is the device model — more specific than any
    # platform fallback (the iOS family, the Android WebView model), so it
    # overwrites.
    def apply_prefix_fields(fields)
      model = nil
      fields.to_s.split(";").map(&:strip).each do |field|
        case field
        when /\Abuild (\w+)\z/i then @app_build = Regexp.last_match(1)
        when /\A(?:iOS|iPadOS) ([\d.]+)\z/i then @os_name = "iOS"
                                                 @os_version = Regexp.last_match(1)
        when /\AAndroid ([\d.]+)\z/i then @os_name = "Android"
                                          @os_version = Regexp.last_match(1)
        when /\Asdk \d+\z/i then nil # Android API level — implied by the OS version
        when "" then nil
        else
          model ||= field
        end
      end
      @device_model = model if model
    end

    # Validated headers, production-proven (spoofable, diagnostics-only —
    # never authorization). Bounds mirror ClientVersionInfo: semver-ish
    # versions, OS strings capped at 64 chars.
    def apply_client_headers
      if (version = header("X-Client-Version")) && version.match?(/\A\d+(\.\d+){0,3}\z/)
        @app_version = version
      end
      if (build = header("X-Client-Build")) && build.match?(/\A\w{1,32}\z/)
        @app_build = build
      end
      if (os = header("X-Client-OS")) && (os = os[0, 64].strip) &&
         (parsed = os.match(/\A(?<name>iOS|iPadOS|Android)\s+(?<version>[\d.]+)\z/i))
        @os_name = parsed[:name].casecmp("android").zero? ? "Android" : "iOS"
        @os_version = parsed[:version]
      end
    end

    def convention_match
      @user_agent.to_enum(:scan, CONVENTION).map { Regexp.last_match }.find do |match|
        !match[:app].match?(CONVENTION_DENYLIST) && match[:fields].include?(";")
      end
    end

    def legacy_match
      @user_agent.match(LEGACY)
    end

    def known_native_app?(app_name)
      Sessions.config.native_app_names.any? { |known| app_name.strip.casecmp?(known) }
    end

    # --- Layer 2: web ---------------------------------------------------------

    def parse_web
      parser = Sessions.config.ua_parser

      if parser.respond_to?(:call)
        apply_custom(parser.call(@user_agent, @headers))
      elsif parser == :device_detector && defined?(::DeviceDetector)
        parse_with_device_detector
      else
        parse_with_browser
      end

      apply_client_hints
      enforce_honest_os_version
    end

    def parse_with_browser
      browser = ::Browser.new(@user_agent)

      if browser.bot?
        @device_type = "bot"
        @browser_name = browser.bot.name
        return
      end

      @browser_name = presence(browser.name) unless browser.name == "Unknown Browser"
      @browser_version = presence(browser.version) unless browser.version.to_s == "0"
      @os_name = browser_platform_name(browser)
      @os_version = presence(browser.platform.version)
      @device_type = if browser.device.tablet? then "tablet"
                     elsif browser.device.mobile? then "smartphone"
                     elsif @os_name then "desktop"
                     else "unknown"
                     end
    end

    def browser_platform_name(browser)
      case browser.platform.id
      when :mac then "macOS"
      when :windows then "Windows"
      when :linux then "Linux"
      when :ios then "iOS"
      when :android then "Android"
      when :chrome_os then "ChromeOS"
      when :unknown_platform, nil then nil
      else presence(browser.platform.name)
      end
    end

    def parse_with_device_detector
      detector = ::DeviceDetector.new(@user_agent, device_detector_headers)

      if detector.bot?
        @device_type = "bot"
        @browser_name = detector.bot_name
        return
      end

      @browser_name = presence(detector.name) unless detector.name == "UNK"
      @browser_version = presence(detector.full_version.to_s.split(".").first)
      @os_name = presence(detector.os_name) unless detector.os_name == "UNK"
      @os_name = "macOS" if @os_name == "Mac"
      @os_version = presence(detector.os_full_version)
      @device_model = presence(detector.device_name)
      @device_type = case detector.device_type
                     when "smartphone", "phablet" then "smartphone"
                     when "tablet" then "tablet"
                     when "desktop" then "desktop"
                     when nil then @os_name ? "desktop" : "unknown"
                     else "unknown"
                     end
    end

    # device_detector expects literal header names, not Rack env keys — our
    # canonical hash already uses them.
    def device_detector_headers
      @headers.slice(*CAPTURED_HEADERS.values.grep(/\ASec-CH/))
    end

    def apply_custom(result)
      return unless result.respond_to?(:to_h)

      result.to_h.symbolize_keys.slice(*ATTRIBUTES).each do |attribute, value|
        instance_variable_set(:"@#{attribute}", presence(value&.to_s))
      end
      @device_type = "unknown" unless DEVICE_TYPES.include?(@device_type)
    end

    # High-entropy Chromium client hints recover what the frozen UA dropped:
    # real platform versions and Android device models.
    def apply_client_hints
      if (model = header("Sec-CH-UA-Model")) && !(model = unquote(model)).empty?
        @device_model = model
      end

      if (platform_version = header("Sec-CH-UA-Platform-Version"))
        version = unquote(platform_version)
        @os_version = hinted_os_version(version) unless version.empty?
      end

      case header("Sec-CH-UA-Mobile")
      when "?1" then @device_type = "smartphone" if @device_type == "desktop"
      when "?0" then @device_type = "desktop" if @device_type == "smartphone"
      end
    end

    # Windows is the one platform whose hinted version needs decoding: the
    # platform version is the internal build line, where 13+ means Windows 11
    # (learn.microsoft.com/microsoft-edge/web-platform/how-to-detect-win11).
    def hinted_os_version(version)
      return version unless @os_name == "Windows"

      major = version.split(".").first.to_i
      if major >= 13 then "11"
      elsif major.positive? then "10"
      end
    end

    # Frozen-UA honesty: a 2026 web UA carries REAL OS versions only on iOS.
    # macOS is frozen at 10.15.7, Windows at NT 10.0, Chrome-on-Android at
    # "Android 10; K" — rendering those as facts would be lying to users on
    # their own security page. Client hints (handled above) overwrite with
    # real values when present.
    def enforce_honest_os_version
      return if @os_version.nil?
      return if @os_name == "iOS"
      return if hinted?("Sec-CH-UA-Platform-Version")

      @os_version = nil
    end

    # --- Helpers ----------------------------------------------------------------

    def header(name)
      presence(@headers[name])
    end

    def hinted?(name)
      !header(name).nil?
    end

    def unquote(value)
      value.to_s.delete('"').strip
    end

    def clean_token(value)
      presence(value.to_s.strip.delete_suffix(";"))
    end

    def presence(value)
      value.nil? || value.to_s.empty? ? nil : value
    end
  end
end
