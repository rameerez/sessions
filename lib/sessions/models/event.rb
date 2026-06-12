# frozen_string_literal: true

module Sessions
  # The append-only login-activity trail: every successful AND failed login,
  # logout, revocation and expiry — with attempted identity, device, geo,
  # and the linkage no prior art has: `session_id` points at the live
  # registry row the event created (or ended), so a suspicious login in the
  # trail is one click away from revoking the session it started.
  #
  # `session_id` is a plain column with NO foreign key on purpose: registry
  # rows get destroyed on revoke/logout (rows = active sessions); history
  # must survive them.
  #
  # Rows are written through one tolerant pipeline (`.record!`): unknown
  # attributes are dropped instead of raising, so hosts can add or remove
  # columns without waiting for a gem release (authtrail's proven pattern).
  #
  # Scopes are the admin product (BYOUI):
  #
  #   Sessions::Event.failed_logins.last_24_hours.group(:ip_address).count
  #   Sessions::Event.for_identity("j@example.com")     # ATO investigation
  #   Sessions::Event.failed_logins.for_ip("203.0.113.7")
  #   Sessions::Event.by_country("RU").logins
  class Event < ::ActiveRecord::Base
    self.table_name = "sessions_events"

    # device_name / location / country_flag / native predicates /
    # auth_method_label — shared with the registry rows; events carry the
    # same parsed device columns (handy for admin lists and host hooks).
    include Sessions::DeviceDisplay

    EVENTS = %w[login failed_login logout revoked expired].freeze

    # Nullable: failed attempts against unknown identities have no one to
    # point at — that's exactly why the typed `identity` column exists.
    belongs_to :authenticatable, polymorphic: true, optional: true

    validates :event, presence: true, inclusion: { in: EVENTS }

    # APPEND-ONLY at the model-contract level: normal AR mutations raise;
    # history is evidence, and evidence you can casually rewrite is
    # worthless. Every legitimate internal mutation already goes through
    # callback-bypassing APIs — the geolocate job backfills geo via
    # update_columns/update_all, `Sessions.forget` nulls identities via
    # update_all (GDPR), the sweep and `dependent: :delete_all` purge via
    # delete_all — so the callback paths can refuse everything else loudly.
    # (Those bypass APIs remain public Active Record; this is a guardrail,
    # not a database constraint.)
    before_update { raise ActiveRecord::ReadOnlyRecord, "sessions_events are append-only history" }
    before_destroy { raise ActiveRecord::ReadOnlyRecord, "sessions_events are append-only history (retention purges go through delete_all)" }

    scope :logins, -> { where(event: "login") }
    scope :failed_logins, -> { where(event: "failed_login") }
    scope :logouts, -> { where(event: "logout") }
    scope :revocations, -> { where(event: "revoked") }
    scope :expirations, -> { where(event: "expired") }

    scope :recent, -> { order(occurred_at: :desc) }
    scope :last_24_hours, -> { where(occurred_at: 24.hours.ago..) }
    scope :last_days, ->(days) { where(occurred_at: days.days.ago..) }
    scope :between, ->(from, to) { where(occurred_at: from..to) }

    scope :for_ip, ->(ip) { where(ip_address: ip.to_s) }
    scope :for_identity, ->(identity) { where(identity: normalize_identity(identity)) }
    scope :by_country, ->(code) { where(country_code: code.to_s.upcase) }
    scope :with_method, ->(method) { where(auth_method: method.to_s) }
    scope :new_devices, lambda {
      # Portable substring match on a json/jsonb column: each adapter casts
      # differently (PG can't LIKE jsonb directly; CHAR(1) truncates there;
      # SQLite/MySQL accept their own casts). /postg/ also covers PostGIS.
      column = case connection.adapter_name
               when /postg/i then "metadata::text"
               when /mysql/i then "CAST(metadata AS CHAR)"
               else "CAST(metadata AS TEXT)"
               end
      logins.where("#{column} LIKE ?", "%new_device%")
    }

    before_validation { self.occurred_at ||= Time.current }

    class << self
      # The single, error-isolated write path. Tolerant-assigns every
      # attribute (unknown columns are skipped via `try`), normalizes the
      # typed identity for correlation, stamps occurred_at, persists, and
      # tees the event into `config.events`. Returns the Event or nil —
      # never raises into a login.
      def record!(attributes)
        Sessions.safely("event") do
          event = new
          attributes.each do |name, value|
            next if value.nil?

            event.try(:"#{name}=", value)
          end
          event.identity = normalize_identity(event.try(:identity))
          clamp_string_columns!(event)
          event.save!

          Sessions.notify_event(event)
          event
        end
      end

      # Clamp string columns to their limits BEFORE the insert: the
      # identity is attacker-typed (a 10KB "email" must not turn into
      # MySQL's ValueTooLong and silently cost us the failure row — that
      # row IS the attack trail), and hosts may have pruned the text
      # columns down to strings.
      def clamp_string_columns!(event)
        columns_hash.each do |name, column|
          next unless column.type == :string && column.limit
          next unless (value = event[name]).is_a?(String) && value.length > column.limit

          event[name] = value[0, column.limit]
        end
      end

      # Build a `failed_login` event straight from a request — the shared
      # engine behind Warden's before_failure, the OmniAuth failure
      # composer, the omakase controller hook, and the public
      # Sessions.record_failed_attempt seam.
      def record_failure(request, scope: nil, identity: nil, reason: nil, metadata: {})
        headers = Sessions::Device.headers_from(request)
        user_agent = request&.user_agent
        device = Sessions::Device.parse(user_agent, headers: headers)
        auth = Sessions::Classifier.classify(request)
        ip = Sessions::IpAddress.resolve(request)

        geo = {}
        if ip && Sessions::Geolocation.cloudflare_headers?(request)
          geo = Sessions::Geolocation.locate(ip, request: request, coordinates: true)
        end

        event = record!(
          device.to_h.merge(geo).merge(
            event: "failed_login",
            scope: scope&.to_s,
            identity: identity,
            failure_reason: reason&.to_s,
            auth_method: auth[:method],
            auth_provider: auth[:provider],
            auth_detail: auth[:detail].presence,
            ip_address: ip,
            user_agent: user_agent,
            client_hints: headers.presence,
            request_id: (request.request_id if request.respond_to?(:request_id)),
            context: context_for(request),
            metadata: metadata.presence
          )
        )

        Sessions::Geolocation.enqueue(event) if event && event.try(:country_code).blank?
        maybe_alert_repeated_failures(event) if event
        event
      end

      # Burst detection (config.repeated_failed_logins): fires the hook
      # exactly when the identity CROSSES the threshold inside the window —
      # count == threshold, so the 6th, 7th… attempt doesn't re-fire and an
      # attacker can't turn the alert into an inbox-flooding primitive.
      # (Two simultaneous commits can race past the crossing — the alert is
      # then skipped rather than doubled; for a notification, missing one
      # beats spamming two.)
      def maybe_alert_repeated_failures(event)
        config = Sessions.config.repeated_failed_logins
        return unless config
        return if event.identity.blank?

        count = failed_logins
                .for_identity(event.identity)
                .where(occurred_at: config[:within].ago..)
                .count
        return unless count == config[:threshold]

        Sessions.safely("on_repeated_failed_logins hook") do
          Sessions.config.on_repeated_failed_logins.call(
            identity: event.identity,
            count: count,
            event: event
          )
        end
      end

      # Emails-as-typed are normalized (strip + downcase) so failed attempts
      # correlate across casing — but stored even for identities that match
      # no account (the data authtrail proved valuable and Rodauth can't
      # capture).
      def normalize_identity(identity)
        return nil if identity.nil?

        normalized = identity.to_s.strip.downcase
        normalized.empty? ? nil : normalized
      end

      def context_for(request)
        params = request.respond_to?(:path_parameters) ? request.path_parameters : nil
        return nil unless params && params[:controller]

        "#{params[:controller]}##{params[:action]}"
      rescue StandardError
        nil
      end
    end

    # --- Candy ------------------------------------------------------------------

    # `event.name` reads better than `event.event` in host hooks:
    #   config.events = ->(event) { AuditLog.log(event_type: "session.#{event.name}", …) }
    def name
      event&.to_sym
    end

    def user
      authenticatable
    end

    # The live registry row this event points at — nil once it's been
    # revoked/logged out (that's the point of the trail).
    def session
      return nil if session_id.nil?

      Sessions.session_model.find_by(id: session_id)
    rescue StandardError
      nil
    end

    # The request being served when the event was recorded (only available
    # in the same request cycle — handy inside `config.events` hooks).
    def request
      Sessions::Current.request
    end

    def success?
      event == "login"
    end

    def failure?
      event == "failed_login"
    end

    def new_device?
      !!(metadata.is_a?(Hash) && metadata["new_device"])
    end

    # The reason that applies to THIS event: the failure reason on failed
    # logins, the revocation reason on revocations — so views and hooks
    # never branch on the event type to find it.
    def reason
      failure_reason.presence || revoked_reason.presence
    end

    # Human, localized labels (the gem ships en + es; hosts override the
    # i18n keys like any Rails app):
    #   event.label        # => "Signed in" / "Inicio de sesión"
    #   event.reason_label # => "wrong credentials" / "credenciales incorrectas"
    def label
      I18n.t("sessions.history.events.#{event}", default: event.to_s.humanize)
    end

    def reason_label
      return nil unless reason

      I18n.t("sessions.history.reasons.#{reason}", default: reason.humanize.downcase)
    end

    # The audit-friendly compact projection — exactly what a
    # `config.events` tee wants to forward to an audit ledger or analytics
    # pipe, without hand-picking columns:
    #
    #   config.events = ->(event) do
    #     AuditLog.log(event_type: "session.#{event.name}", user: event.user,
    #                  request: event.request, data: event.summary)
    #   end
    def summary
      {
        session_id: session_id,
        identity: identity,
        device: (device_name if try(:device_type).present? && device_type != "unknown"),
        device_type: device_type,
        auth_method: auth_method,
        auth_provider: auth_provider,
        failure_reason: failure_reason,
        revoked_reason: revoked_reason,
        ip: ip_address,
        country: country_code
      }.compact
    end

    def to_h
      attributes.symbolize_keys
    end
  end
end
