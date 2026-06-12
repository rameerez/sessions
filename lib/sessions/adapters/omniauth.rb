# frozen_string_literal: true

module Sessions
  module Adapters
    # OmniAuth integration.
    #
    # Successes need NO hook here: the OAuth callback always lands in an
    # app-side controller that creates the session through whichever adapter
    # is active, and the classifier sniffs `env["omniauth.auth"]` at that
    # moment (→ docs/research/05-oauth.md §1.2).
    #
    # Failures are the part nobody records: every strategy failure funnels
    # through the swappable `OmniAuth.config.on_failure` rack endpoint. We
    # COMPOSE-wrap it (record, then call the original — Devise's dispatcher
    # or OmniAuth's FailureEndpoint both keep working) from
    # `config.after_initialize`, so it wraps whatever the app's own
    # initializers installed. Captured: the error type symbol
    # (:invalid_credentials, :access_denied = the user hit Cancel,
    # :authenticity_error = CSRF), the provider, the originating page, and
    # IP/UA. Not capturable (documented): which local user, and
    # abandonments at the provider.
    module Omniauth
      module_function

      def install!
        return if @installed
        return unless defined?(::OmniAuth) && ::OmniAuth.respond_to?(:config)

        @installed = true
        original = ::OmniAuth.config.on_failure
        ::OmniAuth.config.on_failure = lambda do |env|
          Sessions::Adapters::Omniauth.record_failure(env)
          original.call(env)
        end
      end

      def installed?
        !!@installed
      end

      def reset_installation!
        @installed = false
      end

      def record_failure(env)
        Sessions.safely("omniauth.failure") do
          next unless Sessions.config.track_failed_logins

          request = ActionDispatch::Request.new(env)
          strategy = env["omniauth.error.strategy"]
          provider = strategy.respond_to?(:name) ? strategy.name.to_s : nil

          Sessions.record_failed_attempt(
            request,
            reason: env["omniauth.error.type"],
            method: :oauth,
            provider: Sessions::Classifier.normalize_provider(provider),
            detail: { origin: env["omniauth.origin"] }.compact
          )
        end
      end
    end
  end
end
