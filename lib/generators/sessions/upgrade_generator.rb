# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module Sessions
  module Generators
    # `rails generate sessions:upgrade` — copies version-to-version
    # migrations for apps that installed a prior release. The install
    # generator remains the source for fresh apps; this generator gives
    # existing hosts an explicit, reviewable upgrade path.
    class UpgradeGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)
      desc "Install sessions upgrade migrations"

      class_option :model, type: :string, default: "Session",
                           desc: "Session model name (escape hatch for apps with a custom session class)"

      def self.next_migration_number(dir)
        ActiveRecord::Generators::Base.next_migration_number(dir)
      end

      def create_upgrade_migrations
        migration_template "add_adoption_key_to_sessions.rb.erb",
                           File.join(db_migrate_path, "add_sessions_adoption_key_to_#{table_name}.rb")
        migration_template "add_app_build_to_sessions_events.rb.erb",
                           File.join(db_migrate_path, "add_sessions_app_build_to_sessions_events.rb")
      end

      def display_post_upgrade_message
        say "\n🔐 sessions upgrade migrations have been installed.", :green
        say "\nTo complete the upgrade:"
        say "  1. Review the generated migration."
        say "  2. Run 'rails db:migrate'."
        say "     ⚠️  Deploy the migrations before relying on adoption hardening or app-build event columns.", :yellow
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
    end
  end
end
