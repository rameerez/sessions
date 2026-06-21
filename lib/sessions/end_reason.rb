# frozen_string_literal: true

module Sessions
  # Canonical lifecycle vocabulary for registry rows.
  #
  # v0.1.x used "row missing + event tombstone" as the revocation signal. That
  # made Warden infer security intent from absence, which is exactly how quiet
  # housekeeping ended up looking too much like a real logout. v0.2 moves the
  # source of truth onto the session row itself: events are audit trail, not
  # liveness state.
  #
  # External precedents:
  # - Rails 8 generated auth resolves a Session row on every request:
  #   https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/authentication/templates/app/controllers/concerns/authentication.rb.tt
  # - Rodauth's active_sessions feature keeps explicit active-session state
  #   separate from audit logging:
  #   https://github.com/jeremyevans/rodauth/blob/master/lib/rodauth/features/active_sessions.rb
  module EndReason
    LOGOUT = "logout"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"

    REVOKED = %w[
      user_revoked
      admin_revoked
      password_change
      logout_everywhere
      pruned
      unknown
    ].freeze

    INTERNAL = [SUPERSEDED].freeze
    EVENTS = {
      LOGOUT => "logout",
      EXPIRED => "expired"
    }.freeze

    KICKING = ([LOGOUT, EXPIRED] + REVOKED).freeze

    module_function

    def normalize(reason)
      value = reason.to_s.presence || "unknown"
      value == "revoked" ? "user_revoked" : value
    end

    def internal?(reason)
      INTERNAL.include?(normalize(reason))
    end

    def kicks_on_resume?(reason)
      KICKING.include?(normalize(reason))
    end

    def event_for(reason)
      normalized = normalize(reason)
      return nil if internal?(normalized)

      EVENTS.fetch(normalized, "revoked")
    end

    def revoked_reason_for(reason)
      normalized = normalize(reason)
      event_for(normalized) == "revoked" ? normalized : nil
    end
  end
end
