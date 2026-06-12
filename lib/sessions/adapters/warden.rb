# frozen_string_literal: true

module Sessions
  module Adapters
    # The Devise/Warden adapter — four class-level Warden hooks, registered
    # from the engine ONLY when `::Warden::Manager` is already loaded
    # (Bundler.require precedes initializers, so the check is decisive; the
    # gem never `require`s warden itself and stays inert in non-Warden apps).
    #
    # The revocation mechanism generalizes devise-security's proven
    # `session_limitable` (a complete 55-line template whose only structural
    # flaw is one-token-per-user): the token moves from a users-table column
    # to a sessions-table ROW, turning "exactly one session" into "N devices,
    # each individually revocable" (→ docs/research/04-devise-warden.md §5).
    #
    #   login  — mint a random token, store [row_id, raw_token] in the
    #            per-scope warden session (it survives Warden's :renew SID
    #            rotation and is deleted by Warden itself on logout; we
    #            never key on the Rack SID), persist only the SHA-256
    #            digest on the row.
    #   fetch  — per-request liveness check: row exists + digest matches
    #            (constant-time) → throttled touch; row gone (revoked!) →
    #            the proven session_limitable kick: clear, logout, throw.
    #   failure — record the failed attempt with the typed identity.
    #   logout — destroy the row, labeled as a logout.
    module Warden
      # Key inside `warden.session(scope)` holding [row_id, raw_token].
      SESSION_KEY = "sessions"

      # Sticky per-scope flag: a login recorded with `sessions_skip: true`
      # must not be kicked by the fetch validation later (session_limitable's
      # third skip layer).
      SKIP_SESSION_KEY = "sessions.skip"

      # Request-wide skip: `request.env["sessions.skip"] = true`.
      SKIP_ENV_KEY = "sessions.skip" # = Sessions::SKIP_ENV_KEY (set by Sessions.skip!)

      # The `throw :warden` message on revoked sessions — Devise's failure
      # app surfaces it like :timeout/:session_limited (add a
      # `devise.failure.session_revoked` translation for custom copy).
      THROW_MESSAGE = :session_revoked

      module_function

      def install!
        return if @installed

        @installed = true

        ::Warden::Manager.after_set_user(except: :fetch) do |record, warden, opts|
          Sessions::Adapters::Warden.record_login(record, warden, opts)
        end

        ::Warden::Manager.after_set_user(only: :fetch) do |record, warden, opts|
          Sessions::Adapters::Warden.validate_session(record, warden, opts)
        end

        ::Warden::Manager.before_failure do |env, opts|
          Sessions::Adapters::Warden.record_failure(env, opts)
        end

        ::Warden::Manager.before_logout do |record, warden, opts|
          Sessions::Adapters::Warden.record_logout(record, warden, opts)
        end
      end

      # Test seam.
      def installed?
        !!@installed
      end

      def reset_installation!
        @installed = false
      end

      # --- Hook 1: any fresh login (form, remember-me, OmniAuth, sign-up
      # auto-login, post-password-reset) ----------------------------------------

      def record_login(record, warden, opts)
        Sessions.safely("warden.login") do
          scope = opts[:scope]
          # Guard set lifted from Devise's own hooks. The `store: false`
          # check is CRITICAL: token/HTTP-Basic strategies fire this hook on
          # EVERY request with store: false — without it we'd mint a session
          # row per API call.
          next unless warden.authenticated?(scope)
          next if opts[:store] == false
          next if warden.request.env[SKIP_ENV_KEY]
          next if record.respond_to?(:sessions_skip?) && record.sessions_skip?
          # Reauthentication (sudo-style confirms) re-runs sign_in
          # MID-SESSION — devise-passkeys' `reauthenticate` calls
          # `sign_in(..., event: :passkey_reauthentication)` (see its
          # controllers/reauthentication_controller_concern.rb), which fires
          # after_set_user like any login. That's the same person proving
          # presence on an already-tracked session, not a new device:
          # minting a row here would orphan the live one mid-request.
          next if opts[:event].to_s.match?(/reauth/i)

          if opts[:sessions_skip]
            warden.session(scope)[SKIP_SESSION_KEY] = true
            next
          end

          next unless row_accepts?(record)

          create_row_for(record, warden, scope)
        end
      end

      def create_row_for(record, warden, scope, suppress_login_event: false)
        token = Sessions.generate_token
        request = warden.request

        row = Sessions.session_model.new(
          user: record,
          scope: scope.to_s,
          ip_address: Sessions::IpAddress.resolve(request),
          user_agent: request.user_agent,
          token_digest: Sessions.token_digest(token)
        )
        row.sessions_suppress_login_event = suppress_login_event
        Sessions.with_request(request) { row.save! }

        warden.session(scope)[SESSION_KEY] = [row.id, token]
        row
      end

      # --- Hook 2: per-request resume — validate, expire, touch ---------------

      def validate_session(record, warden, opts)
        scope = opts[:scope]
        return if opts[:store] == false
        return if warden.request.env[SKIP_ENV_KEY]
        return if record.respond_to?(:sessions_skip?) && record.sessions_skip?

        data = Sessions.safely("warden.fetch") do
          session_data = warden.session(scope)
          next :skip if session_data[SKIP_SESSION_KEY]

          session_data[SESSION_KEY]
        end
        return if data == :skip

        if data.nil?
          adopt_preexisting_session(record, warden, scope)
          return
        end

        row = Sessions.safely("warden.fetch") do
          id, token = data
          found = Sessions.session_model.find_by(id: id)
          found if found&.sessions_token_matches?(token)
        end

        if row.nil?
          # Revoked (the row is gone) or tampered (digest mismatch): the
          # proven session_limitable sequence — clear everything, log the
          # scope out, and hand control to the failure app. NOT wrapped in
          # `safely`: the throw is control flow, not an error.
          kick!(warden, scope)
        elsif row.sessions_expired?
          Sessions.safely("warden.expire") { row.revoke!(reason: :expired) }
          kick!(warden, scope)
        else
          Sessions.safely("warden.touch") { row.touch_last_seen!(warden.request) }
        end
      end

      # A session that predates the gem (no token in the warden session):
      # adopt it so existing logged-in users appear on their devices page
      # right after deploy — a row is minted with `auth_method: "unknown"`
      # and NO login event (adoption isn't a login; the trail stays honest).
      # Never kicks anyone: adoption failures degrade to "untracked".
      def adopt_preexisting_session(record, warden, scope)
        Sessions.safely("warden.adopt") do
          next unless row_accepts?(record)

          row = create_row_for(record, warden, scope, suppress_login_event: true)
          row&.update_columns(auth_detail: { "adopted" => true })
        end
      end

      def kick!(warden, scope)
        warden.raw_session.clear
        warden.logout(scope)
        throw :warden, scope: scope, message: THROW_MESSAGE
      end

      # --- Hook 3: failed logins ------------------------------------------------

      def record_failure(env, opts)
        Sessions.safely("warden.failure") do
          next unless Sessions.config.track_failed_logins
          next if env[SKIP_ENV_KEY]

          request = ActionDispatch::Request.new(env)
          # `before_failure` fires for EVERY warden failure, including plain
          # unauthenticated page-hits and timeouts. A real credential
          # failure is a POST carrying the scope's credentials hash
          # (→ research/04 §3). The password key is never read.
          next unless request.post?

          # Devise passes scope: explicitly in auth_options; a bare
          # `warden.authenticate!` throws opts WITHOUT it — fall back to the
          # stack's default scope, like Warden itself does.
          scope = opts[:scope] || warden_default_scope(env)
          credentials = request.params[scope.to_s]
          next unless credentials.is_a?(Hash)

          identity = credentials.values_at("email", "login", "username", "phone").compact.first

          Sessions::Event.record_failure(
            request,
            scope: scope,
            identity: identity,
            # Devise's message symbol, verbatim — under paranoid mode this
            # stays :invalid; we never infer (or leak) account existence.
            reason: opts[:message],
            metadata: { attempted_path: opts[:attempted_path] }.compact
          )
        end
      end

      # --- Hook 4: logout ---------------------------------------------------------

      # Fires once per scope (including forced logouts: timeout, lockout,
      # our own revocation kick). If the row is already gone — revoked from
      # another device — there's nothing to do; the `revoked` event was
      # written by whoever destroyed it.
      #
      # CRITICAL: read the RAW session here, never `warden.session(scope)`.
      # Warden's logout deletes `@users[scope]` BEFORE running before_logout
      # callbacks (proxy.rb#logout), so Proxy#session's authenticated? check
      # would re-deserialize the user → re-fire after_set_user → and when the
      # logout came from a hook that logs out and throws (Devise's
      # activatable on unconfirmed/locked accounts, timeoutable) that loops:
      # activatable → logout → us → re-auth → activatable → … SystemStackError.
      def record_logout(_record, warden, opts)
        Sessions.safely("warden.logout") do
          scope = opts[:scope]
          data = warden.raw_session["warden.user.#{scope}.session"]&.dig(SESSION_KEY)
          next unless data

          id, token = data
          row = Sessions.session_model.find_by(id: id)
          next unless row&.sessions_token_matches?(token)

          row.revocation_reason ||= :logout
          row.destroy
        end
      end

      def warden_default_scope(env)
        warden = env["warden"]
        warden.respond_to?(:config) ? warden.config.default_scope : nil
      rescue StandardError
        nil
      end

      # Multi-scope safety: with a plain (non-polymorphic) `user`
      # association, rows can only hold the matching class — a second Devise
      # scope on another model stays silently untracked (re-run the install
      # generator with --polymorphic to track every scope).
      def row_accepts?(record)
        reflection = Sessions.session_model.reflect_on_association(:user)
        return false unless reflection
        return true if reflection.polymorphic?

        record.is_a?(reflection.klass)
      rescue StandardError
        false
      end
    end
  end
end
