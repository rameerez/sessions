# frozen_string_literal: true

require "rails/engine"

module Sessions
  # The mountable engine: wires autoloading, migrations, locales, the
  # `has_sessions` macro, the request-capture middleware, and all three
  # adapters into the host app — every adapter strictly capability-detected,
  # so the gem is inert wherever its target isn't present.
  class Engine < ::Rails::Engine
    isolate_namespace Sessions

    # -------------------------------------------------------------------------
    # Zeitwerk: the gem keeps its ActiveRecord models and jobs under
    # lib/sessions/{models,jobs} (same layout as the moderate and chats gems)
    # so the whole domain ships in lib/ and the engine's app/ tree only holds
    # the web layer (controllers, helpers, views). For that to autoload
    # correctly we manage the loader by hand:
    #
    #   - `push_dir(lib/sessions, namespace: Sessions)` makes
    #     lib/sessions/models/... autoloadable *under the Sessions namespace*.
    #   - `collapse(models)` + `collapse(models/concerns)` + `collapse(jobs)`
    #     mean those files define Sessions::Event / Sessions::Model /
    #     Sessions::GeolocateJob — not Sessions::Models::Event.
    #   - The SPINE files (version/errors/configuration/adapters/…) are
    #     required explicitly by lib/sessions.rb at boot, so they must be
    #     *ignored* by the loader or Zeitwerk would complain about double
    #     definitions / unmanaged constants.
    # -------------------------------------------------------------------------
    LIB_ROOT = File.expand_path("..", __dir__)
    SESSIONS_LIB = File.expand_path("sessions", LIB_ROOT)

    ZEITWERK_IGNORED = %w[
      version.rb errors.rb configuration.rb current.rb ip_address.rb
      device.rb classifier.rb geolocation.rb middleware.rb macros.rb
      adapters engine.rb
    ].freeze

    initializer "sessions.autoload", before: :set_autoload_paths do
      loader = Rails.autoloaders.main

      ZEITWERK_IGNORED.each do |entry|
        path = File.join(SESSIONS_LIB, entry)
        loader.ignore(path) if File.exist?(path)
      end

      %w[models models/concerns jobs].each do |dir|
        path = File.join(SESSIONS_LIB, dir)
        loader.collapse(path) if File.directory?(path)
      end

      loader.push_dir(SESSIONS_LIB, namespace: Sessions)
    end

    config.eager_load_paths << SESSIONS_LIB

    # Request capture for model-callback context (and the opt-in Accept-CH
    # advertisement). Inserted after the Executor so CurrentAttributes'
    # executor-driven reset cleans our state after every request.
    initializer "sessions.middleware" do |app|
      app.middleware.insert_after ActionDispatch::Executor, Sessions::Middleware
    rescue StandardError
      app.middleware.use Sessions::Middleware
    end

    # Expose `has_sessions` on every AR model.
    initializer "sessions.active_record" do
      ActiveSupport.on_load(:active_record) do
        extend Sessions::Macros
      end
    end

    # Ship the gem's locale files (en, es). Host locale files with the same
    # keys override these automatically (I18n's load order puts the app last).
    initializer "sessions.locales" do |app|
      app.config.i18n.load_path += Dir[root.join("config", "locales", "**", "*.{rb,yml}").to_s]
    end

    # Serve the engine's stylesheet through the host's asset pipeline
    # (propshaft or sprockets — both honor config.assets.paths).
    initializer "sessions.assets" do |app|
      app.config.assets.paths << root.join("app/assets/stylesheets") if app.config.respond_to?(:assets)
    end

    # The Devise/Warden adapter. Bundler.require has already loaded every
    # gem in the Gemfile by the time initializers run, so `defined?` is
    # decisive regardless of Gemfile order; Warden hooks live on the Manager
    # CLASS and are read live per request, so registering here (before the
    # first request) is all that's needed (→ research/04 §8).
    initializer "sessions.warden" do
      Sessions::Adapters::Warden.install! if defined?(::Warden::Manager)
    end

    # Rails 8.1's rate_limit notification — a free brute-force-threshold
    # signal on the generated sessions/passwords controllers. Subscribed
    # once per process; inert on earlier Rails.
    initializer "sessions.rate_limit" do
      Sessions::Adapters::Omakase.subscribe_rate_limit_notifications!
    end

    # The OmniAuth failure composer must wrap LAST — after Devise replaced
    # the failure endpoint (at require time) and after the app's own
    # initializers possibly customized it. after_initialize runs once, after
    # everything.
    config.after_initialize do
      Sessions::Adapters::Omniauth.install! if defined?(::OmniAuth)
    end

    # The omakase adapter touches autoloaded app constants (Session,
    # ApplicationController), so it must re-apply on every code reload.
    config.to_prepare do
      # Touch the helper so its bottom-of-file on_load(:action_view) hook
      # registers even if no engine code was referenced yet — and clear its
      # mount-name memo, since a development reload may have redrawn routes.
      Sessions::EngineHelper.reset_engine_mount_name!

      Sessions::Adapters::Omakase.install!
    end
  end
end
