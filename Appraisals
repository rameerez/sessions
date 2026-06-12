# frozen_string_literal: true

# Test the minimum supported Rails version (matches the gemspec floor).
# There's no omakase auth generator on 7.1 — this lane proves the Devise/
# Warden side and the engine still work (the omakase adapter simply stays
# duck-detected off… except the dummy vendors the generated code, which runs
# fine on 7.1 because the concern only uses 7.1-era APIs).
appraise "rails-7.1" do
  gem "rails", "~> 7.1.0"
end

appraise "rails-7.2" do
  gem "rails", "~> 7.2.0"
end

# The version that shipped `rails generate authentication` — the substrate
# this gem decorates.
appraise "rails-8.0" do
  gem "rails", "~> 8.0.0"
end

# The latest Rails — also adds the rate_limit.action_controller notification
# the failed-login pipeline subscribes to.
appraise "rails-8.1" do
  gem "rails", "~> 8.1.0"
end
