# frozen_string_literal: true

module Sessions
  # All of the gem's knobs, with delightful defaults: a fresh `Configuration`
  # is fully working out of the box on both Rails 8 omakase auth and a
  # classic Devise + `User` app — without touching a single setting.
  #
  # Three design rules, shared across the gem ecosystem (chats, moderate,
  # api_keys, …):
  #
  #   1. Class names are stored as STRINGS and constantized lazily, so the
  #      initializer can reference app classes before they're loaded and
  #      everything survives Zeitwerk reloads.
  #   2. Hooks are PROCS with no-op defaults and are error-isolated at the
  #      call site — the gem runs standalone and lights up when the host
  #      wires goodmail / noticed / its own AuditLog in. A broken hook can
  #      never break a login.
  #   3. Validating setters fail at boot with a plain-English message, not
  #      at 3am with a NoMethodError.
  class Configuration
    IP_MODES = %i[full truncated].freeze
    UA_PARSERS = %i[browser device_detector].freeze
    GEOLOCATE_MODES = %i[auto off].freeze

    # NIST SP 800-63B-4 reauthentication ceilings, exposed as one-line
    # presets (§2.2.3: AAL2 ≤ 24h absolute / ≤ 1h inactivity; §2.3.3: AAL3
    # ≤ 12h / ≤ 15min). `timeout_preset = :nist_aal2` is sugar for setting
    # idle_timeout + max_session_lifetime to the matching pair.
    TIMEOUT_PRESETS = {
      nist_aal2: { idle: 1.hour, lifetime: 24.hours },
      nist_aal3: { idle: 15.minutes, lifetime: 12.hours }
    }.freeze

    # --- Behavior -------------------------------------------------------------

    # How often `last_seen_at` may be written, per session. The touch is ONE
    # conditional UPDATE (hot-row-safe, callback-free) and at most one write
    # per session per window — authie's touch-every-request and
    # devise-security's per-request update_column are the documented
    # anti-patterns this throttle exists to avoid. `nil` disables touching
    # entirely (your devices page then shows sign-in-time data only).
    attr_reader :touch_every

    # Per-user live-session cap with oldest-eviction (GitLab keeps 100,
    # Discourse 60). Evicted rows get a `revoked` event with reason
    # `:pruned`. `nil` = unlimited.
    attr_reader :max_sessions_per_user

    # Opt-in session expiry. BOTH default to nil — a tracking gem must never
    # silently shorten anyone's sessions. When set, expiry is enforced
    # inline at session resume (both adapters) and by the generated
    # SessionsSweepJob. `timeout_preset = :nist_aal2` sets both in one line.
    attr_reader :idle_timeout
    attr_reader :max_session_lifetime

    # Terminate other sessions when the user's password changes (ASVS 3.3.3
    # / 7.4.3; Laravel's logoutOtherDevices and Phoenix's token nuke are the
    # cross-framework precedent; Rails 8.1's generated password reset uses
    # `destroy_all`, which our direct-delete compatibility hook still labels
    # honestly). Wired by `has_sessions` via an after_update on the password
    # digest column, so it works on both auth stacks.
    attr_accessor :revoke_on_password_change

    # Devise mode only: revoking a session also rotates the user's
    # remember-me credentials (`forget_me!`), closing the
    # stolen-remember-cookie revival hole (GitLab semantics: other devices
    # keep their live sessions but cannot auto-revive after those end).
    attr_accessor :revoke_remember_me

    # Record failed login attempts (the `failed_login` trail). On by
    # default; flip off if you only want the live device registry.
    attr_accessor :track_failed_logins

    # Burst detection for failed logins: when set to
    # `{ threshold: 5, within: 15.minutes }`, the on_repeated_failed_logins
    # hook fires ONCE when an identity crosses `threshold` failed attempts
    # inside the window — never per attempt (per-attempt alerts are both
    # notification fatigue and an abuse vector: an attacker could spam a
    # victim's inbox by hammering the form). nil (the default) disables
    # detection entirely.
    attr_reader :repeated_failed_logins

    # --- Device intelligence --------------------------------------------------

    # Which web UA parser projects raw user agents into device columns:
    #   :browser          — the bundled default (MIT, zero-dep, tiny)
    #   :device_detector  — auto-upgrade if your app bundles the
    #                       device_detector gem (better Android device
    #                       names, Client-Hints-native — but LGPL and 1.5 MB
    #                       of data, which is why it's not the default)
    #   a lambda          — ->(user_agent, headers) { { browser_name: …, … } }
    attr_reader :ua_parser

    # Set `Accept-CH` on responses so Chromium browsers send high-entropy
    # client hints (real platform versions, Android device models) on
    # subsequent requests — login POSTs are rarely first-navigations, so
    # hints are reliably present exactly when sessions get created.
    # Safari/Firefox don't implement client hints; they stay UA-only.
    attr_accessor :request_client_hints

    # Extra app-name prefixes to recognize in native user agents, for apps
    # using a legacy convention like
    # "MyApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)".
    # The documented `AppName/1.2.3 (model; OS version; build N);` prefix
    # convention is always recognized without configuration.
    attr_reader :native_app_names

    # --- IP & geo ---------------------------------------------------------------

    # How to extract the client IP from a request. The default
    # (`request.remote_ip`) honors Rails' trusted_proxies middleware; apps
    # behind Cloudflare without cloudflare-rails can point this at
    # CF-Connecting-IP (see the README's "Behind Cloudflare" section).
    attr_reader :ip_resolver

    # :full stores the address as-is; :truncated zeroes the last IPv4 octet
    # / the last 80 IPv6 bits BEFORE persistence (the Google Analytics
    # anonymization precedent) — nothing un-truncated ever touches disk.
    attr_reader :ip_mode

    # :auto geolocates through the trackdown gem when it's installed
    # (Cloudflare headers synchronously — free; MaxMind asynchronously in
    # Sessions::GeolocateJob); :off disables geolocation entirely. Without
    # trackdown, geo columns simply stay nil and the UI omits location.
    attr_reader :geolocate

    # Decimal places kept on event latitude/longitude (2 ≈ 1km — privacy
    # now, impossible-travel math later).
    attr_reader :geo_precision

    # --- Retention --------------------------------------------------------------

    # How long `sessions_events` rows are kept before the sweep job purges
    # them. CNIL recommends 6–12 months for security logs; default 12.
    # `nil` keeps events forever (you own the purge).
    attr_reader :events_retention

    # --- Hooks (kwargs, no-op defaults, error-isolated — never break login) ----

    # ->(user:, session:, event:) — fired when a login doesn't match any
    # device this user has signed in from before. Wire your "Was this you?"
    # email here (goodmail / noticed recipes in the README). Not fired on a
    # user's very first session (nobody wants a new-device alert on signup).
    attr_reader :on_new_device

    # ->(session:, by:, reason:) — fired after a session is revoked.
    attr_reader :on_session_revoked

    # ->(identity:, count:, event:) — fired when an identity crosses the
    # repeated_failed_logins threshold (see above). The identity is the
    # email AS TYPED (it may match no account — resolve it yourself if you
    # want to notify the owner); `event` is the failed_login that tripped
    # the threshold, carrying IP, location and device.
    attr_reader :on_repeated_failed_logins

    # ->(event) — catch-all tee receiving every Sessions::Event after it's
    # recorded: logins, failures, logouts, revocations. One line wires your
    # AuditLog / Telegrama / analytics.
    attr_reader :events

    # --- Integration ------------------------------------------------------------

    # The controller the engine's devices page inherits from. Pointing this
    # at your ApplicationController (the default) gives the page your
    # layout, helpers, auth filters and locale for free — the same pattern
    # Devise, api_keys and chats use.
    attr_reader :parent_controller

    # How the engine finds the signed-in user. The resolver chain tries, in
    # order: this method → :current_user → ::Current.session&.user — so
    # Devise AND Rails 8 omakase auth work with zero configuration.
    attr_accessor :current_user_method

    # The before_action that requires authentication (:authenticate_user!
    # works with Devise out of the box; omakase hosts already enforce
    # `require_authentication` through the inherited concern, so the engine
    # detects that and needs nothing).
    attr_accessor :authenticate_method

    # Optional explicit layout for the devices page. nil (default) inherits
    # whatever layout the parent controller resolves — usually the host's
    # `application` layout. Set it when your signed-in surfaces render with
    # a different one (e.g. "app").
    attr_accessor :layout

    # ->(controller) — optional sudo gate run before destructive actions on
    # the devices page (ASVS 3.3.4's "having re-entered login credentials").
    # nil (default) means no extra gate; wire your password-confirm flow
    # here. The action runs only when the gate returns TRUTHY without
    # rendering: render/redirect to take over the response, or return
    # false/nil to block (a bare falsy gets a 403 — the gate fails closed,
    # never through to the destructive action).
    attr_reader :require_reauthentication

    # The host's session-of-record model, as a string. "Session" matches
    # both the Rails 8 generator and the model our install generator writes
    # in Devise mode. Escape hatch for apps with a conflicting legacy
    # Session class (e.g. activerecord-session_store).
    attr_reader :session_class

    # Maps Warden strategy classes to auth methods for classification, on
    # top of the built-ins (DatabaseAuthenticatable → :password,
    # Rememberable → :password, MagicLinkAuthenticatable → :magic_link).
    # Keys are class-name substrings, values are method symbols:
    #   config.strategy_methods = { "OtpAuthenticatable" => :otp }
    attr_reader :strategy_methods

    def initialize
      @touch_every = 5.minutes
      @max_sessions_per_user = 100
      @idle_timeout = nil
      @max_session_lifetime = nil
      @revoke_on_password_change = true
      @revoke_remember_me = true
      @track_failed_logins = true
      @repeated_failed_logins = nil

      @ua_parser = :browser
      @request_client_hints = false
      @native_app_names = []

      # remote_ip (ActionDispatch — honors trusted_proxies) with a fallback
      # to Rack's #ip for plain-Warden stacks where the request isn't an
      # ActionDispatch::Request.
      @ip_resolver = ->(request) { request.respond_to?(:remote_ip) ? request.remote_ip : request.ip }
      @ip_mode = :full
      @geolocate = :auto
      @geo_precision = 2

      @events_retention = 12.months

      @on_new_device = ->(user:, session:, event:) {}
      @on_session_revoked = ->(session:, by:, reason:) {}
      @on_repeated_failed_logins = ->(identity:, count:, event:) {}
      @events = ->(_event) {}

      @parent_controller = "::ApplicationController"
      @current_user_method = :current_user
      @authenticate_method = :authenticate_user!
      @layout = nil
      @require_reauthentication = nil
      @session_class = "Session"
      @strategy_methods = {}
    end

    # --- Validating setters ---------------------------------------------------

    def touch_every=(value)
      @touch_every = ensure_duration_or_nil(value, "touch_every")
    end

    def max_sessions_per_user=(value)
      if value.nil?
        @max_sessions_per_user = nil
        return
      end

      unless value.is_a?(Integer) && value.positive?
        raise ConfigurationError, "max_sessions_per_user must be a positive Integer or nil, got #{value.inspect}"
      end

      @max_sessions_per_user = value
    end

    def idle_timeout=(value)
      @idle_timeout = ensure_duration_or_nil(value, "idle_timeout")
    end

    def max_session_lifetime=(value)
      @max_session_lifetime = ensure_duration_or_nil(value, "max_session_lifetime")
    end

    # Sugar: `config.timeout_preset = :nist_aal2` sets both timeouts to the
    # named NIST pair in one line.
    def timeout_preset=(name)
      preset = TIMEOUT_PRESETS[name&.to_sym]
      unless preset
        raise ConfigurationError,
              "timeout_preset must be one of #{TIMEOUT_PRESETS.keys.inspect}, got #{name.inspect}"
      end

      @idle_timeout = preset[:idle]
      @max_session_lifetime = preset[:lifetime]
    end

    def ua_parser=(value)
      if value.respond_to?(:call)
        @ua_parser = value
        return
      end

      normalized = value&.to_sym
      unless UA_PARSERS.include?(normalized)
        raise ConfigurationError,
              "ua_parser must be one of #{UA_PARSERS.inspect} or a lambda, got #{value.inspect}"
      end

      @ua_parser = normalized
    end

    def native_app_names=(value)
      names = Array(value).map(&:to_s).reject { |name| name.strip.empty? }
      @native_app_names = names
    end

    def ip_resolver=(value)
      @ip_resolver = ensure_callable(value, "ip_resolver")
    end

    def ip_mode=(value)
      normalized = value&.to_sym
      unless IP_MODES.include?(normalized)
        raise ConfigurationError, "ip_mode must be one of #{IP_MODES.inspect}, got #{value.inspect}"
      end

      @ip_mode = normalized
    end

    def geolocate=(value)
      normalized = value == false ? :off : value&.to_sym
      unless GEOLOCATE_MODES.include?(normalized)
        raise ConfigurationError, "geolocate must be :auto or :off, got #{value.inspect}"
      end

      @geolocate = normalized
    end

    def geo_precision=(value)
      unless value.is_a?(Integer) && value >= 0
        raise ConfigurationError, "geo_precision must be a non-negative Integer, got #{value.inspect}"
      end

      @geo_precision = value
    end

    def events_retention=(value)
      @events_retention = ensure_duration_or_nil(value, "events_retention")
    end

    def on_new_device=(value)
      @on_new_device = ensure_callable(value, "on_new_device")
    end

    def on_session_revoked=(value)
      @on_session_revoked = ensure_callable(value, "on_session_revoked")
    end

    def on_repeated_failed_logins=(value)
      @on_repeated_failed_logins = ensure_callable(value, "on_repeated_failed_logins")
    end

    def repeated_failed_logins=(value)
      if value.nil?
        @repeated_failed_logins = nil
        return
      end

      hash = value.to_h.symbolize_keys
      unless hash[:threshold].is_a?(Integer) && hash[:threshold].positive? &&
             hash[:within].respond_to?(:ago)
        raise ConfigurationError,
              "repeated_failed_logins must be nil or { threshold: Integer, within: duration }, " \
              "got #{value.inspect}"
      end

      @repeated_failed_logins = hash
    end

    def events=(value)
      @events = ensure_callable(value, "events")
    end

    def parent_controller=(value)
      name = value.is_a?(Class) ? value.name : value.to_s
      raise ConfigurationError, "parent_controller can't be blank" if name.strip.empty?

      @parent_controller = name
    end

    def require_reauthentication=(value)
      if value.nil?
        @require_reauthentication = nil
        return
      end

      @require_reauthentication = ensure_callable(value, "require_reauthentication")
    end

    def session_class=(value)
      name = value.is_a?(Class) ? value.name : value.to_s
      raise ConfigurationError, "session_class can't be blank" if name.strip.empty?

      @session_class = name
    end

    def strategy_methods=(value)
      unless value.respond_to?(:to_h)
        raise ConfigurationError, "strategy_methods must be a Hash of { 'StrategyClassName' => :method }"
      end

      @strategy_methods = value.to_h.transform_keys(&:to_s).transform_values(&:to_sym)
    end

    # Cross-field validation, run at the end of `Sessions.configure`.
    def validate!
      if idle_timeout && max_session_lifetime && idle_timeout > max_session_lifetime
        raise ConfigurationError,
              "idle_timeout (#{idle_timeout.inspect}) can't exceed max_session_lifetime " \
              "(#{max_session_lifetime.inspect})"
      end

      true
    end

    # The constantized session-of-record class (resolved lazily — see class
    # comment).
    def session_model
      session_class.constantize
    end

    private

    def ensure_duration_or_nil(value, name)
      return nil if value.nil?

      unless value.respond_to?(:from_now) && value.respond_to?(:ago)
        raise ConfigurationError,
              "#{name} must be a duration (like 5.minutes) or nil, got #{value.inspect}"
      end

      value
    end

    def ensure_callable(value, name)
      unless value.respond_to?(:call)
        raise ConfigurationError, "#{name} must respond to #call (a proc/lambda), got #{value.inspect}"
      end

      value
    end
  end
end
