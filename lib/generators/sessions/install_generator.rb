# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module Sessions
  module Generators
    # `rails generate sessions:install` — detects the app's auth stack and
    # writes the right pieces:
    #
    #   Rails 8 omakase auth → ONE migration extending the existing
    #     `sessions` table (the Devise-extends-`users` precedent) + the
    #     events table. The generated Session model stays untouched.
    #
    #   Devise → the Rails-8-shaped `sessions` table (plus our columns,
    #     with token_digest populated by the Warden adapter) + the events
    #     table + a 3-line app-owned Session shell model. The app converges
    #     on the omakase shape: a future Devise→Rails-auth migration finds
    #     its table already waiting.
    #
    #   Neither → aborts with guidance. The gem decorates a session of
    #     record; it never creates one.
    #
    # Plus, in every mode: the annotated initializer, the SessionsSweepJob
    # (host-scheduled — the trackdown/nondisposable pattern), and the
    # post-install steps.
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      desc "Install sessions: adaptive migrations, initializer, and sweep job"

      class_option :polymorphic, type: :boolean, default: false,
                                 desc: "Track multiple Devise scopes/models (polymorphic session owner)"
      class_option :model, type: :string, default: "Session",
                           desc: "Session model name (escape hatch for apps with a conflicting Session class)"

      def self.next_migration_number(dir)
        ActiveRecord::Generators::Base.next_migration_number(dir)
      end

      def detect_auth_stack!
        # Detection is MEMOIZED here, before anything is generated:
        # create_session_model writes app/models/session.rb a few steps
        # below, which would otherwise flip omakase_detected? mid-run and
        # make the post-install message claim the wrong stack.
        adopt_existing_table?
        detected_stack

        return if omakase_detected? || devise_detected?

        raise Thor::Error, <<~MSG
          ❌ sessions couldn't detect an authentication system to decorate.

          The gem tracks the session of record your app already has — it never
          creates one. Set one up first:

            • Rails 8+ omakase auth:  bin/rails generate authentication
            • or Devise:              https://github.com/heartcombo/devise

          …then run `rails generate sessions:install` again.
        MSG
      end

      def check_for_conflicting_sessions_table!
        return unless conflicting_sessions_table?

        raise Thor::Error, <<~MSG
          ❌ A `#{table_name}` table exists but doesn't look like the Rails 8 auth
          shape (no user reference + ip_address + user_agent columns) — most
          likely a legacy table (activerecord-session_store?).

          Two ways forward:

            1. Re-run with a different model: rails g sessions:install --model=SessionRecord
               (and set `config.session_class = "SessionRecord"` in the initializer)
            2. Migrate/rename the legacy table first, then re-run.
        MSG
      end

      def create_migration_files
        if adopt_existing_table?
          migration_template "add_sessions_columns.rb.erb",
                             File.join(db_migrate_path, "add_sessions_columns_to_#{table_name}.rb")
        else
          migration_template "create_sessions.rb.erb",
                             File.join(db_migrate_path, "create_#{table_name}.rb")
        end

        migration_template "create_sessions_events.rb.erb",
                           File.join(db_migrate_path, "create_sessions_events.rb")
      end

      # Devise mode only: the app-owned 3-line shell. All gem logic lives in
      # the Sessions::Model concern, so this file never goes stale.
      def create_session_model
        return if adopt_existing_table? || session_model_file?

        template "session.rb.erb", "app/models/#{model_name.underscore}.rb"
      end

      def create_initializer
        template "initializer.rb", "config/initializers/sessions.rb"
      end

      def create_sweep_job
        template "sessions_sweep_job.rb", "app/jobs/sessions_sweep_job.rb"
      end

      def display_post_install_message
        say "\n🔐 The `sessions` gem has been installed#{" (#{detected_stack} detected)" if detected_stack}.",
            :green
        say "\nTo complete the setup:"

        migrate_verb = adopt_existing_table? ? "enrich your sessions table" : "create the sessions tables"
        say "  1. Run 'rails db:migrate' to #{migrate_verb}."
        say "     ⚠️  You must run migrations before starting your app!", :yellow

        say "  2. Add the macro to your auth model:"
        say "       class User < ApplicationRecord"
        say "         has_sessions"
        say "       end"

        say "  3. Mount the \"Your devices\" page wherever you want it to live:"
        say "       # config/routes.rb"
        if devise_detected? && !omakase_detected?
          say "       authenticate :user do"
          say "         mount Sessions::Engine => \"/settings/sessions\""
          say "       end"
        else
          say "       mount Sessions::Engine => \"/settings/sessions\""
        end

        say "  4. Schedule the sweep (retention purge + cap + opt-in expiry):"
        say "       # config/recurring.yml (Solid Queue)"
        say "       production:"
        say "         sessions_sweep:"
        say "           class: SessionsSweepJob"
        say "           schedule: every day at 4am"

        say "\nEvery login now lands on the devices page and in the trail:"
        say "  current_user.sessions.active     # live devices, revocable"
        say "  current_user.session_history     # the trail — logins, failures, revocations"
        say "\nEvery session, every device, every login — tracked. 🔐✨\n", :green
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end

      def model_name
        options[:model].presence || "Session"
      end

      def table_name
        model_name.underscore.pluralize.tr("/", "_")
      end

      def polymorphic?
        options[:polymorphic]
      end

      # --- Detection (each predicate is a test seam) ---------------------------

      def detected_stack
        @detected_stack ||= if adopt_existing_table? then "Rails authentication"
                            elsif devise_detected? then "Devise"
                            end
      end

      # The Rails-8-shaped table, or the generated Authentication concern's
      # methods on ApplicationController (the same duck test the runtime
      # adapter uses — generators run with the app booted). Deliberately NOT
      # "a session.rb model file exists": in Devise mode this generator
      # writes that file itself, and a leftover copy must not flip a re-run
      # into adopt mode against a table that isn't there.
      def omakase_detected?
        rails8_shaped_table? || omakase_controller_shape?
      end

      def omakase_controller_shape?
        defined?(::ApplicationController) &&
          ::ApplicationController.private_method_defined?(:start_new_session_for)
      rescue StandardError
        false
      end

      def devise_detected?
        defined?(::Devise) ? true : false
      end

      def adopt_existing_table?
        return @adopt_existing_table if defined?(@adopt_existing_table)

        # Adoption means "enrich the table that's already there", so it
        # requires that table. An omakase-shaped app installing with
        # `--model SessionRecord` (because a legacy Session class is in the
        # way) has NO session_records table yet — that's the create-table
        # path, not an add-columns migration against nothing.
        @adopt_existing_table = omakase_detected? && sessions_table_exists?
      end

      def session_model_file?
        File.exist?(File.expand_path("app/models/#{model_name.underscore}.rb", destination_root)) ||
          (defined?(Rails.root) && Rails.root && File.exist?(Rails.root.join("app/models/#{model_name.underscore}.rb")))
      end

      def sessions_table_exists?
        ActiveRecord::Base.connection.table_exists?(table_name)
      rescue StandardError
        false
      end

      def rails8_shaped_table?
        return false unless sessions_table_exists?

        columns = ActiveRecord::Base.connection.columns(table_name).map(&:name)
        (%w[ip_address user_agent] - columns).empty? && columns.any? { |name| name.end_with?("user_id") }
      rescue StandardError
        false
      end

      def conflicting_sessions_table?
        sessions_table_exists? && !rails8_shaped_table?
      end
    end
  end
end
