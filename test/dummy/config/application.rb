# frozen_string_literal: true

require_relative "boot"

# Pull in ONLY the Rails frameworks the gem's test suite actually exercises,
# rather than `require "rails/all"`. A leaner boot is faster and makes the
# dependency surface explicit:
#   - active_record     : the host Session/User models + Sessions::Event
#   - action_controller : the vendored omakase auth + the engine's devices page
#   - action_view       : renders the engine views/partials
#   - active_job        : Sessions::GeolocateJob + the sweep-job pattern
#   - action_mailer     : hosts commonly email from the on_new_device hook;
#                         booting it keeps that integration path honest
require "rails"
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"
require "action_mailer/railtie"

# Propshaft is the default Rails 8 asset pipeline — loading it exercises the
# engine's asset-path wiring exactly like a real host would.
require "propshaft"

# Warden is in the test bundle so the Devise/Warden adapter's hook
# registration runs at boot exactly as it would in a real Devise app
# (Bundler.require precedes initializers there; an explicit require here
# keeps the dummy honest about that ordering). The hooks are exercised by
# the rack-level warden harness in test/warden_adapter_test.rb.
require "warden"

# Load the gem under test. `Bundler.require` would also work, but requiring
# the entry point explicitly keeps the dummy honest about what it depends on
# and means the engine is loaded the same way a real host loads it.
require "sessions"

module Dummy
  # The minimal HOST application the engine integrates into: a Rails 8
  # omakase-auth app whose auth files are vendored VERBATIM from
  # `rails generate authentication` (see app/controllers/concerns/
  # authentication.rb) — so the adapter's duck-detection, prepends and model
  # decoration are tested against the real generated shapes, and upstream
  # template drift breaks CI here instead of production there.
  class Application < Rails::Application
    # PIN THE APP ROOT EXPLICITLY to this dummy directory (test/dummy), not
    # whatever Rails guesses. Rails infers an application's root by walking
    # up for markers like a Gemfile/Rakefile/config.ru; from `rake test`
    # (run at the GEM root) it would otherwise guess the gem root, so
    # `config/database.yml` would resolve to `<gem>/config/database.yml`
    # (which doesn't exist) instead of `test/dummy/config/database.yml`.
    config.root = File.expand_path("..", __dir__)

    # Pin the framework defaults to the gemspec floor (Rails 7.1). The dummy
    # must boot identically on every Rails in the matrix, so we anchor to
    # the LOWEST supported version's defaults — newer Rails happily loads
    # older defaults.
    config.load_defaults 7.1

    # Eager load in test so the whole gem (every model, adapter, controller,
    # helper) is loaded up front: it surfaces autoload/NameError problems as
    # a boot failure instead of a mysterious mid-test error.
    config.eager_load = true

    # Quiet, deterministic test output.
    config.consider_all_requests_local = true
    config.action_controller.perform_caching = false
    config.active_support.deprecation = :stderr

    # Don't dump schema.rb after migrating. CI drives the test DB with
    # migrations (not schema.rb) because a dumped schema.rb carries
    # SQLite-specific JSON/default quirks that fail to load on
    # PostgreSQL/MySQL. The migrations stay the single source of truth.
    config.active_record.dump_schema_after_migration = false

    # :test adapters everywhere so the suite can assert on enqueued jobs
    # (GeolocateJob) and deliveries without external services.
    config.active_job.queue_adapter = :test
    config.action_mailer.delivery_method = :test

    # A real cache store (not :null_store) so Rails 8's controller
    # rate_limit (vendored in the omakase SessionsController) can count.
    config.cache_store = :memory_store

    # What config/environments/test.rb sets in a generated app (the dummy
    # has no environment files): without it, every integration-test POST
    # trips CSRF protection and 422s.
    config.action_controller.allow_forgery_protection = false

    config.action_mailer.default_url_options = { host: "example.com" }

    # Secret base for the signed session cookie (the omakase credential).
    # A fixed value keeps signed cookies stable within a run.
    config.secret_key_base = "sessions_dummy_secret_key_base_for_tests_only"
  end
end
