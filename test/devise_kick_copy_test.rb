# frozen_string_literal: true

require "test_helper"

# When the Warden adapter kicks a revoked session, Devise's failure app turns
# the thrown message into user-facing flash copy. The gem must SHIP that copy:
# without `devise.failure.session_revoked`, the very first thing a user sees
# after the flagship remote-revocation feature fires is literally
# "Translation missing: en.devise.failure.user.session_revoked".
#
# These tests don't need Devise in the bundle — they pin the EXACT lookup
# Devise performs, mirrored from Devise::FailureApp#i18n_message
# (devise/lib/devise/failure_app.rb):
#
#   I18n.t(:"#{scope}.#{message}", scope: "devise.failure", default: [message])
#
# i.e. `devise.failure.<scope>.session_revoked` falling back to
# `devise.failure.session_revoked` — the key the gem's locale files provide.
class DeviseKickCopyTest < ActiveSupport::TestCase
  THROW_MESSAGE = Sessions::Adapters::Warden::THROW_MESSAGE

  test "the kick message resolves through Devise's exact i18n lookup in every shipped locale" do
    %i[en es].each do |locale|
      copy = I18n.with_locale(locale) do
        I18n.t(:"user.#{THROW_MESSAGE}", scope: "devise.failure", default: [THROW_MESSAGE])
      end

      assert_kind_of String, copy
      refute_match(/translation missing/i, copy, "#{locale}: the gem must ship devise.failure.#{THROW_MESSAGE}")
      assert_operator copy.length, :>, 10, "#{locale}: the copy should be a real sentence"
    end
  end

  test "a host override of the key wins over the gem's copy" do
    I18n.backend.store_translations(:en, devise: { failure: { THROW_MESSAGE => "Custom kick copy." } })

    copy = I18n.t(:"user.#{THROW_MESSAGE}", scope: "devise.failure", default: [THROW_MESSAGE])

    assert_equal "Custom kick copy.", copy
  ensure
    I18n.reload!
  end
end
