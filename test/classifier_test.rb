# frozen_string_literal: true

require "test_helper"

class ClassifierTest < ActiveSupport::TestCase
  # Named so `strategy.class.name` carries the Devise-style suffixes the
  # classifier matches on.
  class DatabaseAuthenticatableStub; end
  class RememberableStub; end
  class MagicLinkAuthenticatableStub; end
  class OtpAuthenticatableStub; end
  class TwoFactorAuthenticatableStub; end
  class TwoFactorBackupableStub; end
  # Name shapes from the passkey ecosystem: devise-passkeys registers
  # Devise::Strategies::PasskeyAuthenticatable; bare warden-webauthn
  # registers Warden::WebAuthn::Strategy. Substring matching covers both.
  class PasskeyAuthenticatableStub; end
  class WebAuthnStrategyStub; end

  FakeWarden = Struct.new(:winning_strategy)

  test "an explicit Sessions.tag wins over everything" do
    request = fake_request(env: { "omniauth.auth" => { "provider" => "github" } })
    Sessions.tag(request, method: :passkey, detail: { user_verified: true })

    result = Sessions::Classifier.classify(request)

    assert_equal "passkey", result[:method]
    assert_nil result[:provider]
    assert_equal({ user_verified: true }, result[:detail])
  end

  test "omniauth env classifies as oauth with a normalized provider" do
    auth = {
      "provider" => "google_oauth2",
      "credentials" => { "scope" => "email profile" },
      "info" => { "email_verified" => true },
      "extra" => { "id_info" => { "hd" => "rameerez.com" } }
    }
    request = fake_request(env: { "omniauth.auth" => auth, "omniauth.origin" => "/pricing" })

    result = Sessions::Classifier.classify(request)

    assert_equal "oauth", result[:method]
    assert_equal "google", result[:provider]
    assert_equal "/pricing", result[:detail]["origin"]
    assert_equal "email profile", result[:detail]["scopes"]
    assert_equal true, result[:detail]["email_verified"]
    assert_equal "rameerez.com", result[:detail]["hd"]
  end

  test "unknown omniauth providers pass through as-is" do
    request = fake_request(env: { "omniauth.auth" => { "provider" => "apple" } })
    assert_equal "apple", Sessions::Classifier.classify(request)[:provider]
  end

  test "the winning warden strategy maps to a method" do
    request = fake_request(env: { "warden" => FakeWarden.new(DatabaseAuthenticatableStub.new) })

    result = Sessions::Classifier.classify(request)

    assert_equal "password", result[:method]
    assert_empty result[:detail]
  end

  test "remember-me cookie re-auths classify as password with the remembered flag" do
    request = fake_request(env: { "warden" => FakeWarden.new(RememberableStub.new) })

    result = Sessions::Classifier.classify(request)

    assert_equal "password", result[:method]
    assert_equal true, result[:detail]["remembered"]
  end

  test "devise-passwordless magic links classify automatically" do
    request = fake_request(env: { "warden" => FakeWarden.new(MagicLinkAuthenticatableStub.new) })

    assert_equal "magic_link", Sessions::Classifier.classify(request)[:method]
  end

  test "devise-two-factor with an OTP attempt classifies as password + totp second factor" do
    request = fake_request(method: "POST", path: "/users/sign_in",
                           params: { user: { email: "j@x.com", password: "x", otp_attempt: "123456" } },
                           env: { "warden" => FakeWarden.new(TwoFactorAuthenticatableStub.new) })

    result = Sessions::Classifier.classify(request)

    assert_equal "password", result[:method]
    assert_equal "totp", result[:detail]["second_factor"]
  end

  test "devise-passkeys' first-factor strategy classifies as passkey" do
    request = fake_request(method: "POST", path: "/users/sign_in",
                           env: { "warden" => FakeWarden.new(PasskeyAuthenticatableStub.new) })

    assert_equal "passkey", Sessions::Classifier.classify(request)[:method]
  end

  test "bare warden-webauthn classifies as passkey" do
    request = fake_request(method: "POST", path: "/session",
                           env: { "warden" => FakeWarden.new(WebAuthnStrategyStub.new) })

    assert_equal "passkey", Sessions::Classifier.classify(request)[:method]
  end

  test "devise-two-factor WITHOUT an OTP attempt (2FA off for this user) stays plain password" do
    request = fake_request(method: "POST", path: "/users/sign_in",
                           params: { user: { email: "j@x.com", password: "x" } },
                           env: { "warden" => FakeWarden.new(TwoFactorAuthenticatableStub.new) })

    result = Sessions::Classifier.classify(request)

    assert_equal "password", result[:method]
    refute result[:detail].key?("second_factor")
  end

  test "a backup-code win is a second factor in its own right" do
    request = fake_request(env: { "warden" => FakeWarden.new(TwoFactorBackupableStub.new) })

    result = Sessions::Classifier.classify(request)

    assert_equal "password", result[:method]
    assert_equal "backup_code", result[:detail]["second_factor"]
  end

  test "config.strategy_methods extends the warden mapping" do
    Sessions.config.strategy_methods = { "OtpAuthenticatable" => :otp }
    request = fake_request(env: { "warden" => FakeWarden.new(OtpAuthenticatableStub.new) })

    assert_equal "otp", Sessions::Classifier.classify(request)[:method]
  end

  test "a warden proxy with no winning strategy falls through" do
    request = fake_request(method: "GET", env: { "warden" => FakeWarden.new(nil) })

    assert_equal "unknown", Sessions::Classifier.classify(request)[:method]
  end

  test "the google_sign_in flash handoff classifies as oauth/google" do
    flash = ActionDispatch::Flash::FlashHash.new
    flash["google_sign_in"] = { "id_token" => "jwt" }
    request = fake_request(env: { ActionDispatch::Flash::KEY => flash })

    result = Sessions::Classifier.classify(request)

    assert_equal "oauth", result[:method]
    assert_equal "google", result[:provider]
  end

  test "a credentials POST classifies as password (omakase + custom forms)" do
    request = fake_request(method: "POST", path: "/session",
                           params: { email_address: "j@example.com", password: "secret" })

    assert_equal "password", Sessions::Classifier.classify(request)[:method]
  end

  test "devise-style nested credentials POSTs classify as password" do
    request = fake_request(method: "POST", path: "/users/sign_in",
                           params: { user: { email: "j@example.com", password: "secret" } })

    assert_equal "password", Sessions::Classifier.classify(request)[:method]
  end

  test "a plain GET classifies as unknown — never guess" do
    assert_equal "unknown", Sessions::Classifier.classify(fake_request)[:method]
  end

  test "a nil request classifies as unknown" do
    result = Sessions::Classifier.classify(nil)

    assert_equal "unknown", result[:method]
    assert_nil result[:provider]
  end

  test "classification never raises on hostile envs" do
    request = fake_request(env: { "omniauth.auth" => Object.new, "warden" => Object.new })

    assert_equal "unknown", Sessions::Classifier.classify(request)[:method]
  end
end
