# frozen_string_literal: true

module Sessions
  # What `has_sessions` includes into the auth model. On Rails 8 omakase
  # apps the generated `has_many :sessions, dependent: :destroy` already
  # exists and is left alone; on Devise apps the association is declared
  # here. Either way the model gains the events trail and the revocation
  # verbs:
  #
  #   current_user.sessions.live
  #   current_user.session_events.failed_logins.last_24_hours
  #   current_user.revoke_other_sessions!     # "sign out everywhere else"
  #   current_user.revoke_all_sessions!       # the account-takeover hammer
  #
  # Plus the ASVS 3.3.3 default: changing the password revokes every other
  # session (`config.revoke_on_password_change`), detected on whichever
  # digest column the auth stack uses (password_digest / encrypted_password).
  module HasSessions
    extend ActiveSupport::Concern

    PASSWORD_COLUMNS = %w[password_digest encrypted_password].freeze

    included do
      unless reflect_on_association(:sessions)
        if Sessions::HasSessions.polymorphic_sessions?
          has_many :sessions, class_name: Sessions.config.session_class, as: :user, dependent: :destroy
        else
          has_many :sessions,
                   class_name: Sessions.config.session_class,
                   foreign_key: :user_id,
                   inverse_of: :user,
                   dependent: :destroy
        end
      end

      # delete_all (not destroy) — the trail is append-only data with no
      # callbacks worth running, and erasing it with the account is the
      # GDPR-correct default. `Sessions.forget(user)` does the full
      # right-to-erasure pass including typed identities.
      has_many :session_events,
               class_name: "Sessions::Event",
               as: :authenticatable,
               dependent: :delete_all

      after_update :sessions_revoke_others_on_password_change, if: :sessions_password_changed?
    end

    def self.polymorphic_sessions?
      Sessions.session_model.column_names.include?("user_type")
    rescue StandardError
      false
    end

    # The user's COMPLETE trail slice — owned events PLUS the failed
    # attempts typed against their email. Failures deliberately never link
    # to accounts (`session_events` alone can't see them — recording a
    # failure must not confirm an account exists); matching the resolved
    # user's own identity here is the safe read side. This is what the
    # engine's history page renders:
    #
    #   user.session_history.recent          # everything, newest first
    #   user.session_history.failed_logins  # including identity-matched ones
    def session_history
      scope = Sessions::Event.where(authenticatable: self)

      identity = Sessions::Event.normalize_identity(try(:email_address) || try(:email))
      scope = scope.or(Sessions::Event.where(identity: identity)) if identity

      scope
    end

    # GitHub's "sign out everywhere else": revoke every session except
    # +current+ (defaulting to the one serving this request, so a controller
    # can call it bare). Each revocation writes its event and fires hooks.
    def revoke_other_sessions!(current: nil, by: nil, reason: :logout_everywhere)
      current = Sessions.current if current.nil?

      scope = sessions.live
      scope = scope.where.not(id: current.id) if current.respond_to?(:id)
      scope.each { |session| session.revoke!(reason: reason, by: by || self) }
      true
    end

    # The admin hammer — the account-takeover response. Revokes EVERYTHING,
    # including the session serving this request if it belongs to this user.
    def revoke_all_sessions!(by: nil, reason: :admin_revoked)
      sessions.live.each { |session| session.revoke!(reason: reason, by: by) }
      true
    end

    private

    def sessions_password_changed?
      return false unless Sessions.config.revoke_on_password_change

      PASSWORD_COLUMNS.any? do |column|
        respond_to?(:"saved_change_to_#{column}?") && public_send(:"saved_change_to_#{column}?")
      end
    end

    # ASVS 3.3.3 / 7.4.3: terminate other sessions on password change. The
    # session performing the change survives — but only when it belongs to
    # THIS user (an admin resetting someone's password keeps their own
    # session, and the target loses all of theirs; a password reset by an
    # anonymous visitor revokes everything — exactly Rails 8.1's own
    # behavior, with events).
    def sessions_revoke_others_on_password_change
      Sessions.safely("revoke_on_password_change") do
        current = Sessions.current
        current = nil unless current && current.try(:user) == self

        revoke_other_sessions!(current: current, by: self, reason: :password_change)
      end
    end
  end
end
