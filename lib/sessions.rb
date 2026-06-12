# frozen_string_literal: true

require "openssl"
require "securerandom"

require "active_support"
require "active_support/core_ext/integer/time"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/object/try"
require "active_support/core_ext/enumerable"
require "active_support/security_utils"

require_relative "sessions/version"
require_relative "sessions/errors"
require_relative "sessions/configuration"
require_relative "sessions/current"
require_relative "sessions/ip_address"
require_relative "sessions/device"
require_relative "sessions/classifier"
require_relative "sessions/geolocation"
require_relative "sessions/middleware"
require_relative "sessions/macros"
require_relative "sessions/adapters/omakase"
require_relative "sessions/adapters/warden"
require_relative "sessions/adapters/omniauth"

require_relative "sessions/engine" if defined?(::Rails::Engine)

# == Sessions
#
# Every session, every device, every login — tracked, revocable, visible.
# The missing session layer for Rails.
#
# The public surface is intentionally tiny:
#
#   Sessions.configure { |config| ... }       # one block, in an initializer
#   has_sessions                              # on your auth model
#
#   current_user.sessions.active              # live devices
#   session.device_name                       # => "Chrome on macOS"
#   session.revoke!                           # remote logout, effective next request
#   current_user.revoke_other_sessions!       # GitHub's "sign out everywhere else"
#   current_user.session_events.failed_logins # the trail
#
# Plus a handful of request-side seams for flows that can't self-identify:
#
#   Sessions.tag(request, method: :passkey)   # label the upcoming login
#   Sessions.skip!(request)                   # "neither a login nor a failure" (2FA handoffs)
#   Sessions.current(request)                 # this request's session row
#   Sessions.last_login(request)              # how this browser last signed in ("Last used" badge)
#   Sessions.record_failed_attempt(request, identity: params[:email], reason: :invalid_password)
#   Sessions.track_login(user, request, method: :sso)
#
# Everything else (adapters, the devices page, the sweep) ships with the
# engine and stays out of your way. One rule above all: tracking NEVER
# breaks authentication — every recording path in this gem is
# error-isolated (see Sessions.safely).
module Sessions
  # The signed browser-continuity cookie (see Sessions::Model — minted at
  # login, identifies the browser install so repeat logins replace their
  # old device row instead of stacking duplicates).
  DEVICE_COOKIE = :sessions_device_id

  # The rack env flag `Sessions.skip!` sets — every recording seam checks
  # it before writing anything for the request.
  SKIP_ENV_KEY = "sessions.skip"

  class << self
    # --- Configuration --------------------------------------------------------

    def config
      @config ||= Configuration.new
    end

    alias configuration config

    def configure
      yield config if block_given?
      config.validate!
      config
    end

    # Reset all global state. Used by the test suite to keep examples
    # isolated; also handy in a console when experimenting.
    def reset!
      @config = Configuration.new
      self
    end

    # The host's session-of-record model (`Session` on both supported
    # stacks; `config.session_class` is the escape hatch).
    def session_model
      config.session_model
    end

    # --- Request-side API -----------------------------------------------------

    # Label the login that's about to happen on this request — for flows
    # that can't self-identify at the session-row level (Google One Tap,
    # passkeys, magic links, custom SSO). Call it BEFORE signing the user
    # in; the classification pipeline gives explicit tags top priority.
    #
    #   Sessions.tag(request, method: :google_one_tap, detail: { select_by: params[:select_by] })
    #   Sessions.tag(request, method: :passkey, detail: { user_verified: true })
    def tag(request, method:, provider: nil, detail: {})
      return unless request

      request.env[Classifier::TAG_ENV_KEY] = { method: method, provider: provider, detail: detail }
      request
    end

    # Silence tracking for THIS request — the escape hatch for flows that
    # intentionally end with neither a session nor a failure. The canonical
    # case is the password phase of a two-phase 2FA challenge
    # (authentication-zero's --two-factor, hand-rolled TOTP gates): the
    # password was RIGHT, the controller redirects to the challenge, and
    # recording a failed_login there would be a lie:
    #
    #   if user.otp_required_for_sign_in?
    #     Sessions.skip!(request)
    #     session[:challenge_token] = user.signed_id(...)
    #     redirect_to new_two_factor_authentication_challenge_totp_path
    #   end
    #
    # Honored by every recording seam (both adapters, the failed-login
    # heuristics). One request only — the challenge completion records
    # normally.
    def skip!(request)
      return unless request

      request.env[SKIP_ENV_KEY] = true
      request
    end

    # The registry row for this request — works on both adapters:
    # omakase (Current.session / the signed session cookie) and
    # Devise/Warden (the per-scope token stashed in the warden session).
    # Returns nil when the request carries no live tracked session.
    def current(request = Sessions::Current.request)
      return nil unless request

      safely("current") do
        omakase_current(request) || warden_current(request) || cookie_current(request)
      end
    end

    # The most recent login EVENT from THIS BROWSER — works on the login
    # page, signed out, because the browser-continuity cookie (the same one
    # that deduplicates devices) survives logout by design. This is the
    # one-lookup answer behind the "Last used" badge next to your sign-in
    # buttons:
    #
    #   <% if (last = Sessions.last_login(request))&.auth_provider == "google" %>
    #     <span class="badge">Last used</span>
    #   <% end %>
    #
    # The event carries auth_method / auth_provider / auth_method_label /
    # occurred_at ("last used 2 days ago"). Device-scoped, not
    # account-scoped: it reflects whoever last signed in from this browser
    # — exactly what a login page can honestly know. Returns nil for
    # browsers that never signed in, cleared cookies, or tampered values
    # (the cookie is signed). Read-only: never mints the cookie.
    def last_login(request)
      return nil unless request.respond_to?(:cookie_jar)

      safely("last_login") do
        device_id = request.cookie_jar.signed[DEVICE_COOKIE]
        next nil if device_id.blank?

        Sessions::Event.logins.where(device_id: device_id.to_s[0, 36])
                       .order(occurred_at: :desc).first
      end
    end

    # Record a failed login attempt from a custom controller — the manual
    # seam for flows outside Warden's failure app and the omakase
    # SessionsController (a native-app sign-in branch, passkey
    # verification rescues, One Tap token errors…).
    #
    #   Sessions.record_failed_attempt(request, scope: :user,
    #                                  identity: params[:email],
    #                                  reason: :invalid_password)
    #
    # Never raises; returns the Sessions::Event or nil.
    def record_failed_attempt(request, scope: nil, identity: nil, reason: nil,
                              method: nil, provider: nil, detail: {}, metadata: {})
      return nil unless config.track_failed_logins

      safely("record_failed_attempt") do
        tag(request, method: method, provider: provider, detail: detail) if method

        Sessions::Event.record_failure(
          request,
          scope: scope,
          identity: identity,
          reason: reason,
          metadata: metadata
        )
      end
    end

    # Fully manual integration: create (and classify, parse, geolocate) a
    # registry row + login event for +user+ outside any adapter. The host
    # owns linking the returned row to its own session mechanism and
    # enforcing revocation. Never raises; returns the session row or nil.
    def track_login(user, request, method: nil, provider: nil, detail: {})
      safely("track_login") do
        tag(request, method: method, provider: provider, detail: detail) if method

        with_request(request) do
          session_model.create!(
            user: user,
            ip_address: IpAddress.resolve(request),
            user_agent: request&.user_agent
          )
        end
      end
    end

    # --- Lifecycle ------------------------------------------------------------

    # The maintenance pass the generated SessionsSweepJob runs on a
    # schedule: expire idle/over-age sessions (only when timeouts are
    # configured), evict per-user overflow beyond the session cap, and
    # purge trail rows past retention. Each part is independently
    # error-isolated. Returns a Hash of counts.
    def sweep!
      {
        expired: safely("sweep.expired") { sweep_expired_sessions! } || 0,
        pruned: safely("sweep.pruned") { sweep_session_overflow! } || 0,
        purged_events: safely("sweep.events") { sweep_stale_events! } || 0
      }
    end

    # Right-to-erasure helper: destroy every live session, delete the trail,
    # and null the typed identity on any retained failure rows that match
    # +user+'s email — so honoring a GDPR deletion request is one call.
    def forget(user, identity: nil)
      safely("forget") do
        session_model.where(user: user).destroy_all if session_model_table?
        Sessions::Event.where(authenticatable: user).delete_all

        typed = identity || user.try(:email_address) || user.try(:email)
        Sessions::Event.where(identity: Sessions::Event.normalize_identity(typed)).update_all(identity: nil) if typed

        true
      end
    end

    # --- Internals (used by the adapters; stable but undocumented) -------------

    # The error-isolation chokepoint: this gem sits on the authentication
    # hot path, where a tracking bug may lose a log row but must NEVER 500 a
    # sign-in (authtrail's `safely` pattern, ecosystem rule). Everything the
    # adapters and model callbacks do goes through here.
    def safely(context = nil)
      yield
    rescue StandardError => e
      warn("#{context}: #{e.class}: #{e.message}")
      nil
    end

    def warn(message)
      logger&.warn("[sessions] #{message}")
      nil
    end

    def logger
      defined?(::Rails) && ::Rails.respond_to?(:logger) ? ::Rails.logger : nil
    end

    # SHA-256 of a session token. High-entropy random input ⇒ a plain
    # digest suffices (no pepper KDF theater); the raw token only ever
    # lives in the user's own Rack session (OWASP: never persist raw
    # session identifiers).
    def token_digest(token)
      OpenSSL::Digest::SHA256.hexdigest(token.to_s)
    end

    def generate_token
      SecureRandom.hex(32)
    end

    # Run a block with Sessions::Current.request temporarily set — lets
    # explicit APIs reuse the same model-callback pipeline the adapters use.
    def with_request(request)
      previous = Sessions::Current.request
      Sessions::Current.request = request
      yield
    ensure
      Sessions::Current.request = previous
    end

    # The catch-all `config.events` tee, error-isolated.
    def notify_event(event)
      safely("events hook") { config.events.call(event) }
    end

    private

    def omakase_current(_request)
      return nil unless defined?(::Current) && ::Current.respond_to?(:session)

      session = ::Current.session
      session if session.is_a?(session_model)
    rescue StandardError
      nil
    end

    def warden_current(request)
      return nil unless request.env["warden"]

      request.session.to_hash.each do |key, value|
        next unless key.to_s.match?(/\Awarden\.user\..+\.session\z/) && value.is_a?(Hash)

        id, token = value[Adapters::Warden::SESSION_KEY]
        next unless id && token

        row = session_model.find_by(id: id)
        return row if row.respond_to?(:sessions_token_matches?) && row&.sessions_token_matches?(token)
      end
      nil
    rescue StandardError
      nil
    end

    def cookie_current(request)
      return nil unless request.respond_to?(:cookie_jar)

      id = request.cookie_jar.signed[:session_id]
      session_model.find_by(id: id) if id
    rescue StandardError
      nil
    end

    def session_model_table?
      session_model.table_exists?
    rescue StandardError
      false
    end

    # --- Sweep internals --------------------------------------------------------

    def sweep_expired_sessions!
      return 0 unless config.idle_timeout || config.max_session_lifetime
      return 0 unless session_model_table?

      count = 0
      expired_sessions_scope.find_each do |session|
        session.revoke!(reason: :expired)
        count += 1
      end
      count
    end

    def expired_sessions_scope
      scopes = []

      if (idle = config.idle_timeout)
        threshold = idle.ago
        # A session's last activity is its throttled touch when present,
        # else its creation.
        scopes << session_model.where(last_seen_at: ...threshold)
        scopes << session_model.where(last_seen_at: nil).where(created_at: ...threshold)
      end

      if (lifetime = config.max_session_lifetime)
        scopes << session_model.where(created_at: ...lifetime.ago)
      end

      # NOTE: reduce(:or), never `none.or(...)` — a NullRelation stays null
      # through #or and would silently sweep nothing.
      scopes.empty? ? session_model.none : scopes.reduce(:or)
    end

    def sweep_session_overflow!
      cap = config.max_sessions_per_user
      return 0 unless cap
      return 0 unless session_model_table?

      count = 0
      session_model.group(:user_id).count.each do |user_id, sessions_count|
        next if sessions_count <= cap

        session_model.where(user_id: user_id)
                     .order(created_at: :asc)
                     .limit(sessions_count - cap)
                     .each do |session|
          session.revoke!(reason: :pruned)
          count += 1
        end
      end
      count
    end

    def sweep_stale_events!
      retention = config.events_retention
      return 0 unless retention
      return 0 unless Sessions::Event.table_exists?

      Sessions::Event.where(occurred_at: ...retention.ago).delete_all
    end
  end
end
