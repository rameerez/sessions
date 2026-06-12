# frozen_string_literal: true

# authentication-zero's challenge shape (its challenge/totps_controller.rb.tt)
# wearing the README's tag recipe: the session starts ONLY at full auth, and
# one `Sessions.tag` line before `start_new_session_for` labels it. The code
# check stands in for `ROTP::TOTP#verify`.
class TwoFactorChallengesController < ApplicationController
  allow_unauthenticated_access

  def new
    render plain: "enter your code"
  end

  def create
    user = User.find_signed!(session[:challenge_token], purpose: :authentication_challenge)

    if params[:code] == "123456"
      Sessions.tag(request, method: :password, detail: { second_factor: "totp" })
      start_new_session_for user
      redirect_to after_authentication_url
    else
      # Failed second factors ride the same manual seam as any custom
      # failure path — with the factor in the detail for triage.
      Sessions.record_failed_attempt(request, scope: :user, identity: user.email_address,
                                              reason: :invalid_otp, method: :password,
                                              detail: { second_factor: "totp" })
      redirect_to new_two_factor_challenge_path, alert: "That code didn't work"
    end
  end
end
