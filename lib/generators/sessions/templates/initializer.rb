# frozen_string_literal: true

Sessions.configure do |config|
  # ==========================================================================
  # BEHAVIOR
  # ==========================================================================
  #
  # How often `last_seen_at` may be written per session — ONE conditional
  # UPDATE, at most once per window (hot-row safe; this is what powers
  # "Active 3 minutes ago" and the staleness sweep). nil disables touching.
  #
  # config.touch_every = 5.minutes
  #
  # Per-user live-session cap with oldest-eviction (GitLab keeps 100,
  # Discourse 60). Evicted sessions land in the trail as revoked (:pruned).
  # nil = unlimited.
  #
  # config.max_sessions_per_user = 100
  #
  # Opt-in session expiry — both default to nil because a tracking gem must
  # never silently shorten anyone's sessions. When set, expiry is enforced
  # at session resume AND by the SessionsSweepJob. Heads-up for Rails 8 auth
  # apps: the generated cookie lives 20 years, so this sweep is the only
  # real expiry your sessions will ever have.
  #
  # config.idle_timeout = nil                # e.g. 1.hour
  # config.max_session_lifetime = nil        # e.g. 24.hours
  # config.timeout_preset = :nist_aal2       # sugar: sets both (24h / 1h, NIST 800-63B)
  #
  # Changing a password revokes the user's other sessions (ASVS 3.3.3 —
  # Laravel, Phoenix, and Rails 8.1's own password reset all do this).
  #
  # config.revoke_on_password_change = true
  #
  # Devise mode: revoking a session also rotates the user's remember-me
  # credentials, so a stolen long-lived remember cookie can't quietly revive
  # a revoked device (GitLab semantics; user-wide — other live sessions stay
  # alive but can't auto-revive after they end).
  #
  # config.revoke_remember_me = true
  #
  # Record failed login attempts (with the typed identity, never the
  # password) in the trail.
  #
  # config.track_failed_logins = true
  #
  # Burst detection: fire on_repeated_failed_logins (see HOOKS below) ONCE
  # when an identity crosses the threshold inside the window — never per
  # attempt (that would be notification fatigue and an inbox-flooding
  # vector). Complements :lockable / rate limiting: they stop the attacker,
  # this tells the user. nil disables.
  #
  # config.repeated_failed_logins = { threshold: 5, within: 15.minutes }

  # ==========================================================================
  # DEVICE INTELLIGENCE
  # ==========================================================================
  #
  # The web UA parser. :browser (bundled, MIT, tiny) covers "Chrome on
  # macOS"-grade names; :device_detector auto-upgrades device naming if your
  # app bundles that gem; or bring your own lambda.
  #
  # config.ua_parser = :browser              # :device_detector | ->(ua, headers) { {...} }
  #
  # Advertise Accept-CH so Chromium browsers send high-entropy client hints
  # (real platform versions, Android device models) — Safari/Firefox don't
  # implement client hints and stay UA-only either way.
  #
  # config.request_client_hints = false
  #
  # Hotwire Native apps are detected automatically; if your native shells
  # use a legacy UA prefix (like "MyApp Android 1.0.5 (build 6; …)") on
  # raw HTTP clients, declare the app name so those parse too. (The
  # documented `AppName/1.2.3 (model; OS ver; build N);` convention from the
  # README always parses without configuration.)
  #
  # config.native_app_names = ["MyApp"]

  # ==========================================================================
  # IP & GEOLOCATION
  # ==========================================================================
  #
  # How to read the client IP. The default honors Rails' trusted_proxies
  # (`request.remote_ip`). Behind Cloudflare, prefer the cloudflare-rails
  # gem (remote_ip just works); reading CF-Connecting-IP directly is only
  # safe when your origin is unreachable except through Cloudflare:
  #
  # config.ip_resolver = ->(request) { request.headers["CF-Connecting-IP"] || request.remote_ip }
  #
  # Privacy hardening: :truncated zeroes the last IPv4 octet / 80 IPv6 bits
  # BEFORE persistence (the Google Analytics precedent) — nothing
  # un-truncated ever touches disk.
  #
  # config.ip_mode = :full                   # | :truncated
  #
  # Geolocation through the trackdown gem when it's installed (Cloudflare
  # headers resolve synchronously for free; MaxMind lookups run async in
  # Sessions::GeolocateJob). Without trackdown, locations simply stay blank.
  #
  # config.geolocate = :auto                 # | :off
  #
  # Decimals kept on event coordinates (2 ≈ 1km).
  #
  # config.geo_precision = 2

  # ==========================================================================
  # RETENTION (the trail is personal data — keep it bounded)
  # ==========================================================================
  #
  # How long sessions_events rows live before SessionsSweepJob purges them.
  # CNIL recommends 6–12 months for security logs. nil keeps them forever
  # (you own the purge).
  #
  # config.events_retention = 12.months

  # ==========================================================================
  # HOOKS — kwargs, no-op defaults, error-isolated (a broken hook can never
  # break a login)
  # ==========================================================================
  #
  # A login from a device this user has never used before — wire your
  # "Was this you?" email here. Not fired on a user's very first login.
  #
  # PASS THE EVENT to your mailer, not the session: the event is a
  # persisted, GlobalID-able record that survives revocation (the session
  # row may be destroyed before an async job runs) and already carries
  # everything the email needs — event.user, event.device_name,
  # event.location, event.country_flag, event.occurred_at.
  #
  # config.on_new_device = ->(user:, session:, event:) do
  #   SecurityMailer.with(event: event).new_device.deliver_later
  # end
  #
  # config.on_session_revoked = ->(session:, by:, reason:) do
  #   Rails.logger.info("session revoked (#{reason}) by #{by.inspect}")
  # end
  #
  # Someone crossed the repeated_failed_logins threshold (see BEHAVIOR
  # above). The identity is the email AS TYPED — it may match no account,
  # so resolve it yourself before notifying:
  #
  # config.on_repeated_failed_logins = ->(identity:, count:, event:) do
  #   user = User.find_by(email: identity) or next
  #   SecurityMailer.with(user: user, event: event).repeated_failed_logins.deliver_later
  # end
  #
  # The catch-all tee: EVERY trail event (logins, failures, logouts,
  # revocations) right after it's recorded. `event.summary` is the
  # audit-shaped projection (device, identity, reasons, ip, country —
  # compacted, no raw blobs), so wiring an audit ledger is one line:
  #
  # config.events = ->(event) do
  #   AuditLog.log(event_type: "session.#{event.name}", user: event.user,
  #                request: event.request, data: event.summary)
  # end

  # ==========================================================================
  # INTEGRATION
  # ==========================================================================
  #
  # The controller the devices page inherits from — your layout, helpers,
  # auth filters and locale apply automatically (the Devise/api_keys/chats
  # pattern).
  #
  # config.parent_controller = "::ApplicationController"
  #
  # How the page finds the signed-in user. The resolver chain tries: this
  # method → :current_user → ::Current.session&.user — so Devise AND Rails 8
  # auth work with zero configuration. Override for custom stacks:
  #
  # config.current_user_method = :current_user
  # config.authenticate_method = :authenticate_user!
  #
  # Render the devices page with a specific layout (nil inherits whatever
  # your parent controller uses — set this if your signed-in surfaces use a
  # different layout, e.g. "app"):
  #
  # config.layout = nil
  #
  # Optional sudo gate before destructive actions on the devices page (ASVS
  # 3.3.4's "having re-entered login credentials"). The action runs only
  # when the gate returns TRUTHY without rendering — render/redirect to
  # take over with your password-confirm flow, or return false/nil to
  # block (a bare falsy answers 403; the gate fails closed):
  #
  # config.require_reauthentication = ->(controller) do
  #   controller.session[:sudo_until]&.future? ||
  #     controller.redirect_to(controller.main_app.confirm_password_path)
  # end
  #
  # The session-of-record model (escape hatch for apps that installed with
  # --model because a legacy Session class was in the way):
  #
  # config.session_class = "Session"
  #
  # Classify custom Warden strategies (substring of the strategy class name
  # → auth method). DatabaseAuthenticatable/Rememberable/
  # MagicLinkAuthenticatable are built in.
  #
  # config.strategy_methods = { "OtpAuthenticatable" => :otp }
end
