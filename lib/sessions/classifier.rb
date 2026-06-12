# frozen_string_literal: true

module Sessions
  # Classifies HOW a session was started — password, OAuth (which provider),
  # passkey, magic link… — from whatever signals the request carries at
  # session-creation time. First match wins (→ docs/research/05-oauth.md):
  #
  #   1. An explicit `Sessions.tag(request, …)` (the universal escape hatch —
  #      One Tap, passkeys, custom SSO flows can't self-identify).
  #   2. `env["omniauth.auth"]` — any OmniAuth callback, on either auth stack.
  #   3. The winning Warden strategy class (Devise password and remember-me
  #      logins, devise-passwordless magic links, custom strategies via
  #      `config.strategy_methods`).
  #   4. `flash[:google_sign_in]` — Basecamp's google_sign_in gem hands the
  #      id_token to the app through the flash.
  #   5. A credentials POST (the omakase SessionsController#create shape and
  #      any custom password form: a password param was just exchanged for a
  #      session).
  #   6. :unknown — never guess.
  #
  # Output: { method:, provider:, detail: } matching the auth_method /
  # auth_provider / auth_detail columns. Methods are reserved for
  # transport-distinct flows (Sign in with Apple is `oauth` + provider
  # "apple", NOT its own method) so the taxonomy stays stable.
  module Classifier
    METHODS = %w[password oauth google_one_tap passkey magic_link otp sso token unknown].freeze

    # The rack env key `Sessions.tag` writes.
    TAG_ENV_KEY = "sessions.auth"

    # Built-in Warden strategy → method mapping. Keys are matched as
    # substrings of the strategy class name, so Devise's
    # `Devise::Strategies::DatabaseAuthenticatable` and a host's custom
    # subclass both classify. `config.strategy_methods` entries are
    # consulted first and may override these.
    #
    # devise-two-factor is SINGLE-PHASE (password + OTP validated together
    # in one strategy — its TwoFactorAuthenticatable SUBCLASSES Devise's
    # DatabaseAuthenticatable and consumes params[scope]["otp_attempt"]
    # before deferring to password validation, see devise-two-factor
    # lib/devise_two_factor/strategies/two_factor_authenticatable.rb — so
    # warden signs in once, at full auth). Its method is therefore
    # :password — the second factor rides auth_detail (see from_warden).
    #
    # Passkey first-factor strategies classify as :passkey out of the box:
    # devise-passkeys registers Devise::Strategies::PasskeyAuthenticatable
    # (lib/devise/passkeys/strategy.rb) and its PasskeyReauthentication
    # subclass; bare warden-webauthn registers Warden::WebAuthn::Strategy
    # (lib/warden/webauthn/strategy.rb) — both names match by substring.
    STRATEGY_METHODS = {
      "DatabaseAuthenticatable" => :password,
      "Rememberable" => :password,
      "MagicLinkAuthenticatable" => :magic_link,
      "TwoFactorAuthenticatable" => :password,
      "TwoFactorBackupable" => :password,
      "Passkey" => :passkey,
      "WebAuthn" => :passkey
    }.freeze

    # OmniAuth strategy names normalized to recognizable providers
    # ("google_oauth2" → "google"). Unlisted strategies pass through as-is.
    PROVIDER_ALIASES = {
      "google_oauth2" => "google",
      "google_oauth2_hd" => "google",
      "azure_activedirectory_v2" => "microsoft",
      "microsoft_graph" => "microsoft"
    }.freeze

    module_function

    # Never raises — classification is best-effort decoration on the login
    # hot path; an exotic env degrades to :unknown.
    def classify(request)
      return blank if request.nil?

      from_tag(request) ||
        from_omniauth(request) ||
        from_warden(request) ||
        from_google_sign_in(request) ||
        from_password_post(request) ||
        blank
    rescue StandardError => e
      Sessions.warn("auth classification failed: #{e.class}: #{e.message}")
      blank
    end

    def blank
      { method: "unknown", provider: nil, detail: {} }
    end

    def from_tag(request)
      tag = request.env[TAG_ENV_KEY]
      return unless tag.is_a?(Hash)

      {
        method: normalize_method(tag[:method]),
        provider: tag[:provider]&.to_s,
        detail: (tag[:detail] || {}).to_h
      }
    end

    def from_omniauth(request)
      auth = request.env["omniauth.auth"]
      return unless auth

      detail = {}
      detail["origin"] = request.env["omniauth.origin"] if request.env["omniauth.origin"]
      # AuthHash is a Hashie::Mash; plain hashes from tests work too.
      credentials = auth["credentials"] if auth.respond_to?(:[])
      detail["scopes"] = credentials["scope"] if credentials.respond_to?(:[]) && credentials["scope"]
      info = auth["info"] if auth.respond_to?(:[])
      detail["email_verified"] = info["email_verified"] if info.respond_to?(:[]) && !info["email_verified"].nil?
      extra = auth["extra"] if auth.respond_to?(:[])
      id_info = extra["id_info"] if extra.respond_to?(:[])
      detail["hd"] = id_info["hd"] if id_info.respond_to?(:[]) && id_info["hd"]

      { method: "oauth", provider: normalize_provider(auth["provider"]), detail: detail }
    end

    def from_warden(request)
      warden = request.env["warden"]
      return unless warden.respond_to?(:winning_strategy)

      strategy = warden.winning_strategy
      return unless strategy

      strategy_name = strategy.class.name.to_s
      method = method_for_strategy(strategy_name)
      return unless method

      detail = {}
      detail["remembered"] = true if strategy_name.include?("Rememberable")

      # devise-two-factor: a backup-code win IS a second factor; the main
      # strategy also serves users without 2FA, so the OTP only counts when
      # an otp_attempt actually rode the request.
      if strategy_name.include?("TwoFactorBackupable")
        detail["second_factor"] = "backup_code"
      elsif strategy_name.include?("TwoFactorAuthenticatable") && otp_attempted?(request)
        detail["second_factor"] = "totp"
      end

      { method: method.to_s, provider: nil, detail: detail }
    end

    def otp_attempted?(request)
      params = request.params
      return true if params["otp_attempt"].present?

      params.each_value.any? { |value| value.is_a?(Hash) && value["otp_attempt"].present? }
    rescue StandardError
      false
    end

    def method_for_strategy(strategy_name)
      Sessions.config.strategy_methods.merge(STRATEGY_METHODS).each do |substring, method|
        return method if strategy_name.include?(substring)
      end
      nil
    end

    def from_google_sign_in(request)
      flash = request.respond_to?(:flash) ? request.flash : nil
      return unless flash && flash["google_sign_in"].present?

      { method: "oauth", provider: "google", detail: {} }
    rescue StandardError
      # Requests outside the Flash middleware (rack tests, API stacks) raise
      # when the flash hash is unavailable — there's just no signal here.
      nil
    end

    # A POST that exchanged a password for a session IS a password login —
    # covers the omakase SessionsController and hand-rolled password forms.
    def from_password_post(request)
      return unless request.respond_to?(:post?) && request.post?

      params = request.params
      return unless params.is_a?(Hash) || params.respond_to?(:[])
      return unless password_param?(params)

      { method: "password", provider: nil, detail: {} }
    rescue StandardError
      nil
    end

    def password_param?(params)
      return true if params["password"].present?

      # Devise nests credentials under the scope: user[password]
      params.each_value.any? { |value| value.is_a?(Hash) && value["password"].present? }
    rescue StandardError
      false
    end

    def normalize_method(method)
      name = method.to_s
      METHODS.include?(name) ? name : name.presence || "unknown"
    end

    def normalize_provider(provider)
      return nil if provider.nil?

      name = provider.to_s
      PROVIDER_ALIASES.fetch(name, name)
    end
  end
end
