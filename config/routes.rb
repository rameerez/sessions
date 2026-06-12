# frozen_string_literal: true

Sessions::Engine.routes.draw do
  # `path: ""` keeps URLs short under the host's mount point: with
  # `mount Sessions::Engine => "/settings/sessions"` the devices page is
  # /settings/sessions, revoking one is DELETE /settings/sessions/:id,
  # "sign out everywhere else" is DELETE /settings/sessions/others, and the
  # full login history is /settings/sessions/history.
  resources :devices, path: "", only: %i[index destroy] do
    collection do
      delete :others
      get :history
    end
  end

  root to: "devices#index"
end
