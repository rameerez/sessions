# frozen_string_literal: true

module Sessions
  # The registry concern — included into the host's session-of-record model
  # (`Session`). On Rails 8 omakase apps the adapter includes it
  # automatically at boot (the generated 2-line model stays untouched); in
  # Devise mode the install generator writes a 3-line shell that includes it
  # explicitly. Either way, ALL gem logic lives here, so the host's model
  # file never goes stale.
  #
  # One mental model: **rows = active sessions; events = history.** A row is
  # destroyed on logout/revocation/expiry (instant remote revocation — the
  # same omakase semantics as Rails 8.1's own password-reset destroy_all),
  # and its tombstone lives in the `sessions_events` trail.
  #
  # The three lifecycle callbacks observe 100% of both adapters' flows:
  #
  #   before_create        — enrich the row: normalize the IP, parse the
  #                          device, capture client hints, classify the auth
  #                          method, geolocate (when free).
  #   after_create_commit  — write the `login` event, detect new devices,
  #                          enforce the per-user cap, enqueue async geo.
  #   after_destroy_commit — write the `logout`/`revoked`/`expired` event.
  #
  # Every callback body is error-isolated: a parsing/geo/event failure may
  # lose a log row; it may NEVER break a sign-in.
  module Model
    extend ActiveSupport::Concern

    # device_name / location / country_flag / native predicates /
    # auth_method_label — shared with Sessions::Event, which carries the
    # same parsed device columns.
    include Sessions::DeviceDisplay

    # How long without activity before a session is grouped as "inactive"
    # on the devices page (UI grouping only — never enforcement; expiry is
    # the opt-in idle_timeout/max_session_lifetime pair).
    INACTIVE_AFTER = 30.days

    included do
      # The Devise-mode shell model needs the association declared; the
      # omakase host model already has `belongs_to :user` and is left
      # untouched. Polymorphic when the table was generated with
      # --polymorphic (detected by the user_type column).
      unless reflect_on_association(:user)
        if Sessions::Model.polymorphic_table?(self)
          belongs_to :user, polymorphic: true
        else
          belongs_to :user
        end
      end

      # Transient revocation context: set by `revoke!` (and the adapters'
      # logout labeling) before the row is destroyed, read by the
      # after_destroy_commit event writer.
      attr_accessor :revocation_reason, :revoked_by

      # Set on adopted rows (sessions that predate the gem) so adoption
      # doesn't fabricate a `login` event in the trail.
      attr_accessor :sessions_suppress_login_event

      before_create :sessions_enrich
      after_create_commit :sessions_record_login
      after_destroy_commit :sessions_record_end

      scope :by_recency, lambda {
        # COALESCE keeps never-touched sessions ordered by creation time,
        # portably across sqlite/postgres/mysql.
        order(Arel.sql("COALESCE(#{table_name}.last_seen_at, #{table_name}.created_at) DESC"))
      }
      scope :active, lambda {
        where("COALESCE(#{table_name}.last_seen_at, #{table_name}.created_at) >= ?", INACTIVE_AFTER.ago)
      }
      scope :inactive, lambda {
        where("COALESCE(#{table_name}.last_seen_at, #{table_name}.created_at) < ?", INACTIVE_AFTER.ago)
      }
    end

    class_methods do
      # The user-facing trail rows linked to this registry (`session_id` is
      # a plain column, no FK — history must survive row destruction).
      def sessions_events_for(session_id)
        Sessions::Event.where(session_id: session_id)
      end
    end

    def self.polymorphic_table?(klass)
      klass.table_exists? && klass.column_names.include?("user_type")
    rescue StandardError
      false
    end

    # --- The candy ---------------------------------------------------------------
    #
    # device_name / location / country_flag / hotwire_native? / web? /
    # via_oauth? / auth_method_label … live in Sessions::DeviceDisplay.

    # The moment of last activity: the throttled touch when present, else
    # sign-in time.
    def last_active_at
      try(:last_seen_at) || created_at
    end

    # "Active now" — activity within the touch window. The window IS
    # config.touch_every (last_seen_at lags by up to one throttle window by
    # design), so the devices-page badge stays truthful whatever the host
    # configured.
    def active_now?(window = Sessions.config.touch_every || 5.minutes)
      activity = last_active_at
      activity.present? && activity > window.ago
    end

    # Whether this row is the one serving +request+ — powers the
    # "This device" badge (which is also the row the devices page refuses
    # to revoke).
    def current?(request = Sessions::Current.request)
      return false unless request

      Sessions.current(request) == self
    end

    # Stamp the second factor onto an ALREADY-LIVE session — the affordance
    # for step-up flows where the row exists before the challenge completes
    # (a post-login TOTP gate, a WebAuthn step-up before sensitive areas):
    #
    #   Sessions.current(request)&.second_factor!("totp")
    #
    # Flows that verify the second factor BEFORE the session exists
    # (devise-two-factor, authentication-zero's challenge controllers,
    # devise-otp) don't need this — they classify at login via the strategy
    # map or a `Sessions.tag` call (see the README's two-factor recipes).
    # Reading happens through `second_factor` / `second_factor?`.
    def second_factor!(kind)
      detail = (try(:auth_detail) || {}).to_h
      update!(auth_detail: detail.merge("second_factor" => kind.to_s))
    end

    # --- Revocation -----------------------------------------------------------

    # Destroy this session — remote logout, effective on that device's very
    # next request (both adapters validate liveness per request). Writes a
    # `revoked` (or `expired`) event with the reason and actor, rotates the
    # user's remember-me credentials in Devise mode (config.revoke_remember_me),
    # and fires the on_session_revoked hook.
    def revoke!(reason: :user_revoked, by: nil)
      self.revocation_reason = reason
      self.revoked_by = by
      destroy!

      Sessions.safely("revoke_remember_me") { sessions_forget_remember_me! } if Sessions.config.revoke_remember_me
      Sessions.safely("on_session_revoked hook") do
        Sessions.config.on_session_revoked.call(session: self, by: by, reason: reason)
      end

      self
    end

    # --- Lifecycle plumbing (used by the adapters) -------------------------------

    # Opt-in expiry — false unless the host configured timeouts.
    def sessions_expired?(now = Time.current)
      config = Sessions.config
      activity = last_active_at
      return true if config.idle_timeout && activity && activity < now - config.idle_timeout
      return true if config.max_session_lifetime && created_at && created_at < now - config.max_session_lifetime

      false
    end

    # The throttled last-seen touch: at most one write per
    # config.touch_every per session, issued as a single conditional UPDATE
    # (hot-row-safe under concurrent requests, callback-free, and it also
    # moves updated_at — which finally makes the Rails security guide's own
    # `Session.sweep` recommendation implementable).
    def touch_last_seen!(request = nil)
      every = Sessions.config.touch_every
      return false unless every
      return false unless sessions_column?("last_seen_at")

      now = Time.current
      threshold = now - every
      return false if last_seen_at && last_seen_at > threshold

      updates = { last_seen_at: now, updated_at: now }
      if sessions_column?("last_seen_ip") && request && (ip = Sessions::IpAddress.resolve(request))
        updates[:last_seen_ip] = ip
      end

      updated = self.class.where(id: id)
                    .where("last_seen_at IS NULL OR last_seen_at <= ?", threshold)
                    .update_all(updates)

      if updated.positive?
        updates.each { |column, value| self[column] = value }
        clear_attribute_changes(updates.keys)
        true
      else
        # Another request won the race — refresh our throttle window so this
        # instance doesn't retry.
        self[:last_seen_at] = now
        clear_attribute_changes([:last_seen_at])
        false
      end
    end

    # Constant-time token check (Devise mode). Omakase rows store no token
    # (the signed cookie is the credential) and never match.
    def sessions_token_matches?(token)
      digest = try(:token_digest)
      return false if digest.blank? || token.blank?

      ActiveSupport::SecurityUtils.secure_compare(digest, Sessions.token_digest(token))
    end

    private

    # --- before_create: enrichment ------------------------------------------------

    def sessions_enrich
      Sessions.safely("enrich") do
        request = Sessions::Current.request

        sessions_enrich_ip(request)
        sessions_enrich_device(request)
        sessions_enrich_device_id(request)
        sessions_enrich_auth(request)
        sessions_enrich_geo(request)
        sessions_clamp_oversized_strings
      end

      true # never halt the host's save chain
    end

    # Rails 8's authentication generator creates `user_agent` as a plain
    # string — VARCHAR(255) on MySQL — and real native UAs (app prefix +
    # WebView UA + Hotwire markers) routinely overflow it, turning a login
    # into ActiveRecord::ValueTooLong under MySQL's strict mode. The gem's
    # own tables use text, but on ADOPTED tables we clamp every string
    # column to its limit AFTER parsing (the parsers saw the full value;
    # only storage is bounded). Tracking never breaks login — and here,
    # login itself would have broken without us.
    def sessions_clamp_oversized_strings
      self.class.columns_hash.each do |name, column|
        next unless column.type == :string && column.limit
        next unless (value = self[name]).is_a?(String) && value.length > column.limit

        self[name] = value[0, column.limit]
      end
    end

    def sessions_enrich_ip(request)
      return unless sessions_column?("ip_address")

      # Normalize (and truncate, per config.ip_mode) whatever the host
      # captured; resolve from the request when nothing was set (Devise
      # mode sets it explicitly; omakase's start_new_session_for already
      # did). Garbage that doesn't parse as an IP is dropped.
      self.ip_address = Sessions::IpAddress.normalize(ip_address) if ip_address.present?
      self.ip_address ||= Sessions::IpAddress.resolve(request) if request
    end

    def sessions_enrich_device(request)
      ua = (user_agent.presence if sessions_column?("user_agent")) || request&.user_agent
      headers = Sessions::Device.headers_from(request)

      device = Sessions::Device.parse(ua, headers: headers)
      sessions_assign(device.to_h)
      sessions_assign(client_hints: headers) if headers.any?
    end

    # Browser continuity: a signed, long-lived, random cookie identifying
    # the BROWSER INSTALL (never the user — it carries no identity and is
    # worthless as a credential; it only lets two logins from the same
    # browser collapse into one device row). Minted ONLY at login — no
    # pre-login tracking cookie ever. Cookie unavailable (bare rack stacks,
    # tests without key material)? The row simply has no device_id and
    # nothing dedupes — degraded, never broken.
    def sessions_enrich_device_id(request)
      return unless sessions_column?("device_id")
      return if device_id.present?
      return unless request.respond_to?(:cookie_jar)

      jar = request.cookie_jar.signed
      continuity = jar[Sessions::DEVICE_COOKIE]
      if continuity.blank?
        continuity = SecureRandom.uuid
        jar[Sessions::DEVICE_COOKIE] = {
          value: continuity,
          expires: 5.years,
          httponly: true,
          same_site: :lax
        }
      end

      self.device_id = continuity.to_s[0, 36]
    rescue StandardError => e
      Sessions.warn("device continuity cookie unavailable: #{e.class}: #{e.message}")
    end

    def sessions_enrich_auth(request)
      auth = Sessions::Classifier.classify(request)
      sessions_assign(auth_method: auth[:method], auth_provider: auth[:provider])
      sessions_assign(auth_detail: auth[:detail]) if auth[:detail].present?
    end

    def sessions_enrich_geo(request)
      return unless sessions_column?("country_code")
      return if country_code.present? || ip_address.blank?
      # Synchronous only when it's free (Cloudflare already answered in
      # request headers); otherwise the GeolocateJob enriches after commit.
      return unless Sessions::Geolocation.cloudflare_headers?(request)

      sessions_assign(Sessions::Geolocation.locate(ip_address, request: request))
    end

    # Tolerant assignment: only columns that exist, never overwriting
    # host-set values — hosts can drop columns without gem releases.
    def sessions_assign(attributes)
      attributes.each do |column, value|
        name = column.to_s
        next unless sessions_column?(name)
        next if self[name].present?

        self[name] = value
      end
    end

    def sessions_column?(name)
      self.class.column_names.include?(name.to_s)
    rescue StandardError
      false
    end

    # --- after_create_commit: the login event ------------------------------------

    def sessions_record_login
      Sessions.safely("record_login") do
        next if sessions_suppress_login_event

        # Same browser signing in again (abandoned session, expired
        # remember-me, browser update — anything) replaces its old row
        # instead of stacking a duplicate device. Runs BEFORE new-device
        # detection on purpose: the trail (which survives the superseded
        # row) is what remembers known devices, so dedup never causes
        # false "new device" alerts.
        Sessions.safely("supersede") { sessions_supersede_previous_rows! }

        new_device = Sessions.safely("new_device") { sessions_new_device? } || false

        event = Sessions::Event.record!(
          sessions_event_identity_attributes.merge(
            event: "login",
            auth_method: try(:auth_method),
            auth_provider: try(:auth_provider),
            auth_detail: try(:auth_detail).presence,
            # The browser-continuity id rides the trail too: it's what lets
            # Sessions.last_login answer "how did this browser last sign
            # in" AFTER logout destroys the row (the "Last used" badge).
            device_id: try(:device_id).presence,
            metadata: new_device ? { "new_device" => true } : nil
          )
        )

        Sessions::Geolocation.enqueue(self) if try(:country_code).blank?
        sessions_enforce_cap!

        if new_device && event
          Sessions.safely("on_new_device hook") do
            Sessions.config.on_new_device.call(user: user, session: self, event: event)
          end
        end
      end
    end

    # A login is a NEW DEVICE when no prior session or login event for this
    # user matches on (device_type, os_name, browser/app identity) —
    # deliberately coarse, server-observed-only matching; never
    # fingerprinting. A user's very first login is NOT a new device (nobody
    # wants a "was this you?" email on signup).
    def sessions_new_device?
      return false unless user
      return false if try(:device_type).blank? || try(:device_type) == "unknown"

      match = { device_type: try(:device_type), os_name: try(:os_name),
                browser_name: try(:browser_name), app_name: try(:app_name) }

      prior_sessions = self.class.where(user: user).where.not(id: id)
      prior_events = Sessions::Event.logins.where(authenticatable: user)
      return false unless prior_sessions.exists? || prior_events.exists?

      !prior_sessions.where(match).exists? && !prior_events.where(match).exists?
    end

    # The dedup half of browser continuity: prior live rows for the SAME
    # user on the SAME browser install are superseded by this login. A
    # quiet destroy on purpose — no on_session_revoked hook, no
    # remember-me rotation (this is housekeeping, not a security event;
    # the trail records it as revoked/:superseded). Scoped to the user:
    # a shared computer with two accounts keeps both rows.
    def sessions_supersede_previous_rows!
      return if try(:device_id).blank?

      self.class.where(user: user, device_id: device_id).where.not(id: id).each do |row|
        row.revocation_reason = :superseded
        row.destroy
      end
    end

    # GitLab-style per-user cap: evict the OLDEST sessions beyond
    # config.max_sessions_per_user (the freshly created row is the newest,
    # so it always survives).
    def sessions_enforce_cap!
      cap = Sessions.config.max_sessions_per_user
      return unless cap

      siblings = self.class.where(user: user)
      overflow = siblings.count - cap
      return unless overflow.positive?

      siblings.where.not(id: id).order(created_at: :asc).limit(overflow).each do |session|
        session.revoke!(reason: :pruned)
      end
    end

    # --- after_destroy_commit: the end-of-session event ---------------------------

    def sessions_record_end
      Sessions.safely("record_end") do
        # Account deletion: dependent-destroyed rows of a destroyed owner
        # write no events (their trail is erased with them — GDPR default).
        next if user.nil? || user.destroyed?

        reason = revocation_reason&.to_sym
        event_name = case reason
                     when :logout then "logout"
                     when :expired then "expired"
                     else "revoked"
                     end

        Sessions::Event.record!(
          sessions_event_identity_attributes.merge(
            event: event_name,
            revoked_reason: (event_name == "revoked" ? (reason || :unknown) : nil),
            metadata: sessions_revoked_by_metadata
          )
        )
      end
    end

    def sessions_revoked_by_metadata
      return nil unless revoked_by

      label = if revoked_by.respond_to?(:id) && revoked_by.class.respond_to?(:name)
                "#{revoked_by.class.name}##{revoked_by.id}"
              else
                revoked_by.to_s
              end
      { "revoked_by" => label }
    end

    # The row's identity, copied onto every event it produces — the trail
    # must describe the device even after the row is gone.
    def sessions_event_identity_attributes
      {
        session_id: id,
        authenticatable: user,
        scope: try(:scope),
        ip_address: (ip_address if sessions_column?("ip_address")),
        user_agent: (user_agent if sessions_column?("user_agent")),
        client_hints: try(:client_hints).presence,
        browser_name: try(:browser_name),
        browser_version: try(:browser_version),
        os_name: try(:os_name),
        os_version: try(:os_version),
        device_type: try(:device_type),
        device_model: try(:device_model),
        app_name: try(:app_name),
        app_version: try(:app_version),
        country_code: try(:country_code),
        country_name: try(:country_name),
        city: try(:city),
        region: try(:region),
        request_id: sessions_request_id,
        context: sessions_request_context
      }
    end

    # Plain-Warden stacks hand us a Rack::Request (Devise upgrades it to
    # ActionDispatch); neither request_id nor path_parameters can be assumed.
    def sessions_request_id
      request = Sessions::Current.request
      request.request_id if request.respond_to?(:request_id)
    rescue StandardError
      nil
    end

    def sessions_request_context
      request = Sessions::Current.request
      return nil unless request.respond_to?(:path_parameters)

      params = request.path_parameters
      return nil unless params && params[:controller]

      "#{params[:controller]}##{params[:action]}"
    rescue StandardError
      nil
    end

    def sessions_forget_remember_me!
      user.forget_me! if user.respond_to?(:forget_me!)
    end
  end
end
