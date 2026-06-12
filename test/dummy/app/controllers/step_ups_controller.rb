# frozen_string_literal: true

# A post-login step-up gate (the DIY rotp/active_model_otp shape): the
# session already exists; verifying the second factor mid-session stamps it
# via the README's `second_factor!` recipe.
class StepUpsController < ApplicationController
  def create
    if params[:code] == "123456"
      Sessions.current(request)&.second_factor!("totp")
      head :ok
    else
      head :unprocessable_entity
    end
  end
end
