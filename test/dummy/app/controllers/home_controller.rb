# frozen_string_literal: true

# A protected page — every GET / exercises the full per-request resume path
# (cookie lookup → expiry check → throttled touch) through the vendored
# Authentication concern with the gem's ControllerHooks prepended in front.
class HomeController < ApplicationController
  def show
    render plain: "signed in as #{Current.user.email_address}"
  end
end
