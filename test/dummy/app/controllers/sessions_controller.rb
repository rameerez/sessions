# frozen_string_literal: true

# Vendored from the Rails 8.1.3 authentication generator
# (templates/app/controllers/sessions_controller.rb.tt), with TWO deviations:
#
#   1. `rate_limit` is a Rails 8.0+ API, and this dummy also boots on the
#      7.1/7.2 appraisal lanes — so it's feature-guarded the same way real
#      pre-8 hosts simply wouldn't have it.
#   2. A two-factor branch in authentication-zero's exact shape (its
#      sessions_controller.rb.tt: stash a signed challenge token, create
#      NOTHING, redirect to the challenge) — the dummy flags 2FA users by
#      email prefix instead of an otp_secret column.
class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[new create]
  if respond_to?(:rate_limit)
    rate_limit to: 10, within: 3.minutes, only: :create,
               with: -> { redirect_to new_session_path, alert: "Try again later." }
  end

  def new
  end

  def create
    if (user = User.authenticate_by(params.permit(:email_address, :password)))
      if user.email_address.start_with?("2fa-")
        # The password was RIGHT — this is a challenge handoff, not a
        # failure, and not a login yet either.
        Sessions.skip!(request)
        session[:challenge_token] = user.signed_id(purpose: :authentication_challenge,
                                                   expires_in: 20.minutes)
        redirect_to new_two_factor_challenge_path
      else
        start_new_session_for user
        redirect_to after_authentication_url
      end
    else
      redirect_to new_session_path, alert: "Try another email address or password."
    end
  end

  def destroy
    terminate_session
    redirect_to new_session_path, status: :see_other
  end
end
