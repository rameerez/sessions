# frozen_string_literal: true

Rails.application.routes.draw do
  # The exact route the Rails 8 authentication generator adds.
  resource :session

  # The two-phase challenge (authentication-zero shape) and a post-login
  # step-up gate — the dummy's 2FA surfaces for the flow tests.
  resource :two_factor_challenge, only: %i[new create]
  resource :step_up, only: :create

  # A protected page behind the vendored `require_authentication` —
  # exercises per-request resume, the throttled touch, and revocation kicks.
  root "home#show"

  # The engine, mounted the README way.
  mount Sessions::Engine => "/settings/sessions"
end
