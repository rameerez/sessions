# frozen_string_literal: true

require "json"
require "securerandom"
require "time"
require "active_support"
require "active_support/message_verifier"
require "active_support/core_ext/time/calculations"
require "active_support/security_utils"
require_relative "errors"

module Sessions
  # Short-lived, signed proof that a person re-entered their password (or
  # passed another re-authentication) on a given session a moment ago.
  #
  # The host records the re-authentication on the session row and issues an
  # assertion for one audience; another service that holds the shared key
  # verifies it without a database, without a session cookie, and without
  # this app's models:
  #
  #   # The host, right after it checked the password:
  #   session = Sessions.current(request)
  #   session.reauthenticated!(method: :password)
  #   token = session.reauthentication_assertion(audience: "billing", purpose: "refund:42")
  #
  #   # The other service (only `require "sessions/reauthentication"` is needed):
  #   assertion = Sessions::Reauthentication.verify(token, audience: "billing", key: ENV["REAUTH_KEY"],
  #                                                 subject: user_id, purpose: "refund:42")
  #   assertion&.fresh?(within: 5.minutes)  # => true
  #
  # An assertion is a signed statement, not a session: it expires quickly
  # (`reauthentication_assertion_ttl`), names its audience and purpose, and
  # carries a unique `jti` so a verifier that must refuse replays can keep a
  # short list of the ones it accepted.
  module Reauthentication
    # The claims of a verified assertion.
    Assertion = Data.define(:subject, :session_id, :method, :authenticated_at, :audience, :purpose, :jti, :issued_at) do
      # True when the re-authentication happened within the duration.
      def fresh?(within:, now: Time.now) = authenticated_at > now - within
    end

    DIGEST = "SHA256"

    # The session has no re-authentication recent enough to assert.
    class NotRecent < Sessions::Error; end

    module_function

    # A signed assertion. `key` is the shared secret (at least 32 bytes).
    def issue(subject:, session_id:, method:, authenticated_at:, audience:, key:, purpose: nil, expires_in: 60,
              now: Time.now)
      claims = { "sub" => subject.to_s, "sid" => session_id.to_s, "method" => method.to_s,
                 "auth_at" => authenticated_at.utc.iso8601(6), "aud" => audience.to_s, "purpose" => purpose&.to_s,
                 "jti" => SecureRandom.uuid, "iat" => now.utc.iso8601(6) }
      verifier(key).generate(claims, expires_in: expires_in, purpose: signing_purpose(audience))
    end

    # The Assertion of a token, or nil when the token is forged, expired, for
    # another audience, purpose or subject, or older than `max_age`.
    def verify(token, audience:, key:, subject: nil, purpose: nil, max_age: nil, now: Time.now)
      return nil if token.to_s.empty?

      claims = verifier(key).verified(token.to_s, purpose: signing_purpose(audience))
      return nil unless claims.is_a?(Hash) && claims["aud"] == audience.to_s
      return nil if subject && !secure_equal?(claims["sub"], subject.to_s)
      return nil if purpose && !secure_equal?(claims["purpose"].to_s, purpose.to_s)

      assertion = Assertion.new(subject: claims["sub"], session_id: claims["sid"], method: claims["method"],
                                authenticated_at: Time.iso8601(claims["auth_at"]), audience: claims["aud"],
                                purpose: claims["purpose"], jti: claims["jti"], issued_at: Time.iso8601(claims["iat"]))
      return nil if max_age && !assertion.fresh?(within: max_age, now: now)

      assertion
    rescue ArgumentError, TypeError, KeyError
      nil
    end

    def verifier(key)
      raise Sessions::ConfigurationError, "a reauthentication key needs at least 32 bytes" if key.to_s.bytesize < 32

      ActiveSupport::MessageVerifier.new(key.to_s, digest: DIGEST, serializer: JSON)
    end

    def signing_purpose(audience) = "sessions/reauthentication/#{audience}"

    def secure_equal?(left, right)
      left.to_s.bytesize == right.to_s.bytesize && ActiveSupport::SecurityUtils.secure_compare(left.to_s, right.to_s)
    end
  end
end
