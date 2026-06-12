# frozen_string_literal: true

module Sessions
  # Base class for every error this gem raises, so hosts can
  # `rescue Sessions::Error` to catch anything sessions-specific.
  #
  # Deliberately tiny: the gem sits on the authentication hot path, where its
  # contract is to OBSERVE and never to interrupt — tracking code rescues its
  # own failures (see Sessions.safely) instead of raising into a sign-in.
  # Errors here are reserved for things that SHOULD stop you: invalid
  # configuration at boot, and generator-time misdetection.
  class Error < StandardError; end

  # Raised by `Sessions.configure` / setters when the configuration is
  # invalid (unknown ip_mode, non-callable hook, blank class name, …).
  # Fails at boot with a plain-English message, not at 3am with a
  # NoMethodError.
  class ConfigurationError < Error; end

  # Raised at generator time when `rails generate sessions:install` can't
  # tell which auth system the app uses (no Rails 8 authentication, no
  # Devise) — the gem decorates a session of record; it never creates one.
  class UnknownAuthSystemError < Error; end
end
