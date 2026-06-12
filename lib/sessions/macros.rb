# frozen_string_literal: true

module Sessions
  # The host-facing macro. The engine extends `ActiveRecord::Base` with this
  # module (via `ActiveSupport.on_load(:active_record)`), so the auth model
  # can declare:
  #
  #   class User < ApplicationRecord
  #     has_sessions
  #   end
  #
  # On a Rails 8 omakase app this ENRICHES the `has_many :sessions` the
  # authentication generator already wrote (revocation verbs, the events
  # association, password-change auto-revocation); on a Devise app it also
  # declares the association itself. Same grammar as the rest of the
  # ecosystem: `has_credits`, `has_api_keys`, `has_wallets`.
  #
  # The macro is a thin forwarder — all behavior lives in
  # Sessions::HasSessions so it's discoverable, testable, and `include`-able
  # directly when a host prefers that style.
  module Macros
    def has_sessions
      include Sessions::HasSessions
    end
  end
end
