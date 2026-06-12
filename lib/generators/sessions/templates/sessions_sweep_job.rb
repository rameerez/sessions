# frozen_string_literal: true

# The sessions maintenance pass — schedule it daily (see config/recurring.yml
# below if you're on Solid Queue). It purges trail rows past
# `config.events_retention`, evicts per-user overflow beyond
# `config.max_sessions_per_user`, and (only if you opted into timeouts)
# expires idle/over-age sessions.
#
#   # config/recurring.yml
#   production:
#     sessions_sweep:
#       class: SessionsSweepJob
#       schedule: every day at 4am
class SessionsSweepJob < ApplicationJob
  queue_as :default

  def perform
    Sessions.sweep!
  end
end
