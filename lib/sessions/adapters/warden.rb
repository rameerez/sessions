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

      # Rememberable can restore a user on background/native JSON requests
      # before the browser/WebView has actually navigated. Defer the row
      # until a document request can name the user-visible device.
      PENDING_LOGIN_KEY = "sessions.pending_login"

      # Sticky per-scope flag: a login recorded with `sessions_skip: true`
      # must not be kicked by the fetch validation later (session_limitable's
      # third skip layer).
      SKIP_SESSION_KEY = "sessions.skip"

      # Request-wide skip: `request.env["sessions.skip"] = true`.
      SKIP_ENV_KEY = "sessions.skip" # = Sessions::SKIP_ENV_KEY (set by Sessions.skip!)

      # The `throw :warden` message on revoked sessions — Devise's failure
      # app surfaces it like :timeout/:session_limited. The gem SHIPS the
      # `devise.failure.session_revoked` copy (en + es, config/locales/);
      # hosts override that key for custom wording.
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

          auth = Sessions::Classifier.classify(warden.request)
          if deferred_login_request?(warden.request, auth)
            stash_pending_login(warden, scope, auth)
            next
          end

          if (row = remembered_existing_row(record, warden, scope, auth))
            attach_existing_row(row, warden, scope)
            next
          end

          warden.session(scope).delete(PENDING_LOGIN_KEY)
          create_row_for(record, warden, scope)
        end
      end

      def create_row_for(record, warden, scope, suppress_login_event: false, skip_supersede: false, attributes: {})
        token = Sessions.generate_token
        request = warden.request
        model = Sessions.session_model

        row = model.new(
          user: record,
          scope: scope.to_s,
          ip_address: Sessions::IpAddress.resolve(request),
          user_agent: request.user_agent,
          token_digest: Sessions.token_digest(token)
        ).tap do |session|
          attributes.each do |column, value|
            session[column] = value if model.column_names.include?(column.to_s)
          end
        end
        row.sessions_suppress_login_event = suppress_login_event
        row.sessions_skip_supersede = skip_supersede
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

          {
            login: session_data[SESSION_KEY],
            pending_login: session_data[PENDING_LOGIN_KEY]
          }
        end
        return if data == :skip

        session_token = data && data[:login]
        if session_token.nil?
          if data && data[:pending_login]
            activate_pending_login(record, warden, scope, data[:pending_login])
          else
            adopt_preexisting_session(record, warden, scope)
          end
          return
        end

        # The lookup is NOT wrapped in `safely`: an ERRORED lookup and a
        # MISSING row must be distinguishable from a raised lookup, but a
        # missing/mismatched tracking row is still not automatically auth
        # state. Only an explicit revoked/expired tombstone event may kick.
        # A raised lookup — the sessions table unreachable, a timeout, a
        # migration mid-deploy — means the TRACKING layer is down, and
        # tracking must never break authentication: fail OPEN, let the request
        # through untracked, try again next request.
        begin
          id, token = session_token
          found = Sessions.session_model.find_by(id: id)
          if token.blank?
            # v0.1.3 intentionally reattached remember-me restores to an
            # existing device row without writing another login event, storing
            # [row_id, nil] in Warden. That is fine as a tracking hint, but it
            # must never become an auth/liveness check. Touch when the signed
            # browser-continuity cookie still agrees; otherwise clear only the
            # gem's tracking key and let Devise/Rails keep owning auth.
            # Source: https://github.com/rameerez/sessions/blob/v0.1.3/CHANGELOG.md
            if existing_row_session?(found, record, scope, warden.request)
              Sessions.safely("warden.remembered_existing.touch") { found.touch_last_seen!(warden.request) }
            else
              clear_tracking_key(warden, scope)
            end
            return
          end

          row = found if found&.sessions_token_matches?(token)
        rescue StandardError => e
          Sessions.warn("warden.fetch failed open: #{e.class}: #{e.message}")
          return
        end

        if row.nil?
          if explicitly_ended_session?(id)
            # Explicit remote revocation/expiry is the one intentional place
            # where the tracking registry is allowed to end a Devise session.
            # Quiet housekeeping such as same-device supersede writes no
            # revoked/expired event, so a stale token for such a row fails open.
            kick!(warden, scope)
          else
            clear_tracking_key(warden, scope)
          end
        elsif Sessions.safely("warden.expired?") { row.sessions_expired? }
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
          next unless document_request?(warden.request)

          # IDEMPOTENT, because a client that can't persist cookies re-enters
          # adoption on EVERY request: the SESSION_KEY we write rides a
          # Set-Cookie the client drops, so the next request adopts again.
          #
          # Adoption is intentionally coarse: it is a low-fidelity marker for
          # "this owner already had an authenticated session when the gem
          # arrived", not a real login. One owner+scope marker is enough. Do
          # not key it on UA (Hotwire Native devices legitimately use WebView
          # and native-client UAs) or time (cookie-dropping clients would mint
          # one per day forever). When the adoption_key column is present, the
          # unique index makes the first concurrent burst atomic.
          adoption_key = adoption_key_for(record, scope)
          if (row = adopted_row(record, scope, adoption_key: adoption_key))
            Sessions.safely("warden.adopt.touch") { row.touch_last_seen!(warden.request) }
            next
          end

          create_adopted_row(record, warden, scope, adoption_key: adoption_key)
        end
      end

      def activate_pending_login(record, warden, scope, pending_login)
        Sessions.safely("warden.pending_login") do
          next unless row_accepts?(record)
          next unless document_request?(warden.request)

          if (row = pending_existing_row(record, warden, scope, pending_login))
            attach_existing_row(row, warden, scope)
            warden.session(scope).delete(PENDING_LOGIN_KEY)
            next row
          end

          row = create_row_for(record, warden, scope, attributes: pending_login_attributes(pending_login))
          warden.session(scope).delete(PENDING_LOGIN_KEY)
          row
        end
      end

      def deferred_login_request?(request, auth)
        remembered_login?(auth) && !document_request?(request)
      end

      def remembered_login?(auth)
        detail = auth[:detail].to_h
        detail["remembered"] || detail[:remembered]
      rescue StandardError
        false
      end

      def stash_pending_login(warden, scope, auth)
        warden.session(scope)[PENDING_LOGIN_KEY] = login_auth_attributes(auth).transform_keys(&:to_s)
      end

      def login_auth_attributes(auth)
        {
          auth_method: auth[:method],
          auth_provider: auth[:provider],
          auth_detail: auth[:detail].presence
        }.compact
      end

      def pending_login_attributes(attributes)
        attributes.to_h.slice("auth_method", "auth_provider", "auth_detail")
      rescue StandardError
        {}
      end

      def pending_existing_row(record, warden, scope, pending_login)
        auth = { detail: pending_login.to_h["auth_detail"] || {} }
        remembered_existing_row(record, warden, scope, auth)
      end

      def remembered_existing_row(record, warden, scope, auth)
        return unless remembered_login?(auth)

        device_id = device_id_from_request(warden.request)
        return if device_id.blank?

        rows = Sessions.session_model.where(user: record, device_id: device_id)
        rows = rows.where(scope: scope.to_s) if Sessions.session_model.column_names.include?("scope")
        rows.order(created_at: :desc).first
      rescue StandardError
        nil
      end

      def attach_existing_row(row, warden, scope)
        warden.session(scope)[SESSION_KEY] = [row.id, nil]
        Sessions.safely("warden.remembered_existing.touch") { row.touch_last_seen!(warden.request) }
        row
      end

      def existing_row_session?(row, record, scope, request)
        return false unless row

        device_id = device_id_from_request(request)
        return false if device_id.blank?
        return false unless row.try(:device_id) == device_id
        return false unless row.user == record
        return false if row.respond_to?(:scope) && row.scope.present? && row.scope != scope.to_s

        true
      rescue StandardError
        false
      end

      def device_id_from_request(request)
        return unless request.respond_to?(:cookie_jar)

        request.cookie_jar.signed[Sessions::DEVICE_COOKIE].presence
      rescue StandardError
        nil
      end

      def document_request?(request)
        return true unless request
        return false if non_document_path?(request)

        accept = request_header(request, "HTTP_ACCEPT").to_s
        return true if accept.empty? || accept == "*/*"
        return true if accept.match?(%r{\btext/html\b|\bapplication/xhtml\+xml\b|\btext/vnd\.turbo-stream\.html\b})
        return false if accept.match?(%r{\b(?:application|text)/(?:[\w.+-]+\+)?json\b})
        return false if request_header(request, "HTTP_X_REQUESTED_WITH").to_s.casecmp("XMLHttpRequest").zero?

        if request.respond_to?(:format)
          format = request.format
          return true if format.respond_to?(:html?) && format.html?
          return false if format.respond_to?(:json?) && format.json?
        end

        true
      rescue StandardError
        true
      end

      def non_document_path?(request)
        path = if request.respond_to?(:path)
                 request.path
               elsif request.respond_to?(:path_info)
                 request.path_info
               end
        File.extname(path.to_s).delete(".").casecmp("json").zero?
      end

      def request_header(request, key)
        if request.respond_to?(:get_header)
          request.get_header(key)
        elsif request.respond_to?(:env)
          request.env[key]
        end
      end

      def create_adopted_row(record, warden, scope, adoption_key:)
        attributes = { auth_detail: { "adopted" => true } }
        attributes[:adoption_key] = adoption_key if adoption_key_column?

        create_row_for(record, warden, scope, suppress_login_event: true, skip_supersede: true, attributes: attributes)
      rescue ActiveRecord::RecordNotUnique
        adopted_row(record, scope, adoption_key: adoption_key)&.tap do |row|
          Sessions.safely("warden.adopt.touch") { row.touch_last_seen!(warden.request) }
        end
      end

      def adopted_row(record, scope, adoption_key:)
        model = Sessions.session_model
        rows = model.where(user: record)
        rows = rows.where(scope: scope.to_s) if model.column_names.include?("scope")

        row = model.find_by(adoption_key: adoption_key) if adoption_key_column?(model) && adoption_key.present?
        row = nil unless adopted_row?(row)
        row ||= rows.order(created_at: :desc).detect { |candidate| adopted_row?(candidate) }

        claim_adoption_key(row, adoption_key)
      end

      def adopted_row?(row)
        row && row.try(:auth_detail).to_h["adopted"]
      end

      def claim_adoption_key(row, adoption_key)
        return row unless row
        return row unless adoption_key_column?(row.class)
        return row if adoption_key.blank? || row.try(:adoption_key).present?

        row.update_columns(adoption_key: adoption_key)
        row.adoption_key = adoption_key
        row
      rescue ActiveRecord::RecordNotUnique
        row.class.find_by(adoption_key: adoption_key) || row
      end

      def adoption_key_for(record, scope)
        owner_id = record.respond_to?(:to_key) ? Array(record.to_key).join("/") : record.try(:id)
        return if owner_id.blank?

        owner_type = if record.class.respond_to?(:polymorphic_name)
                       record.class.polymorphic_name
                     else
                       record.class.name
                     end

        "adopt:#{Sessions.token_digest([owner_type, owner_id, scope.to_s].join("\0"))}"
      end

      def adoption_key_column?(model = Sessions.session_model)
        model.column_names.include?("adoption_key")
      end

      def clear_tracking_key(warden, scope)
        warden.session(scope).delete(SESSION_KEY)
      rescue StandardError
        nil
      end

      def explicitly_ended_session?(id)
        return false if id.blank?

        events = Sessions::Event.where(session_id: id)
        events.expirations.exists? ||
          events.revocations.where.not(revoked_reason: "superseded").exists?
      rescue StandardError => e
        Sessions.warn("warden.fetch end-event lookup failed open: #{e.class}: #{e.message}")
        false
      end

      # SCOPE-PRECISE teardown: only this scope's warden entries go (the
      # serialized user key and our token stash) — an admin scope riding
      # the same rack session, and unrelated host session data (carts,
      # locale, return-to paths), survive a user-scope kick. Deleting the
      # keys BEFORE logout matters: our before_logout hook then finds no
      # token and records nothing (a kick is not a logout — the revocation
      # event was already written by whoever destroyed the row).
      def kick!(warden, scope)
        warden.raw_session.delete("warden.user.#{scope}.key")
        warden.raw_session.delete("warden.user.#{scope}.session")
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

          # `email_address` included: it's the omakase-era key, and Devise
          # apps configure `authentication_keys = [:email_address]` too.
          identity = credentials.values_at("email", "email_address", "login", "username", "phone").compact.first

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
      def record_logout(record, warden, opts)
        Sessions.safely("warden.logout") do
          scope = opts[:scope]
          data = warden.raw_session["warden.user.#{scope}.session"]&.dig(SESSION_KEY)
          next unless data

          id, token = data
          row = Sessions.session_model.find_by(id: id)
          next unless row

          token_backed = row.sessions_token_matches?(token)
          tokenless_known_device = token.blank? && existing_row_session?(row, record, scope, warden.request)
          next unless token_backed || tokenless_known_device

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
