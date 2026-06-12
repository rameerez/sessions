# frozen_string_literal: true

require "rails/generators/base"

module Sessions
  module Generators
    # `rails generate sessions:madmin` — drop-in admin surfaces for
    # https://github.com/excid3/madmin: the live session registry (with a
    # per-row Revoke action) and the login trail with its triage scopes.
    #
    # The generated files use only STOCK Madmin APIs, so they work on any
    # Madmin install and are yours to restyle (swap in your custom fields,
    # add member actions). Two Madmin footguns are pre-solved in the
    # generated code: the trail's namespaced model needs an explicit
    # `resource_class_name` on its flat controller, and the events routes
    # must be drawn BEFORE `resources :sessions` (or /sessions/events gets
    # captured as a session id).
    class MadminGenerator < Rails::Generators::Base
      source_root File.expand_path("templates/madmin", __dir__)

      desc "Generate Madmin resources + controllers for sessions and the login trail"

      def check_for_madmin!
        return if madmin_available?

        raise Thor::Error, <<~MSG
          ❌ Madmin isn't loaded in this app (gem "madmin").

          This generator produces Madmin resources for the session registry and
          the login trail. For other admin frameworks, build on the same
          primitives it uses: Session.active / session.revoke! /
          Sessions::Event scopes (failed_logins, last_24_hours, …).
        MSG
      end

      def create_resources
        template "session_resource.rb", "app/madmin/resources/session_resource.rb"
        template "event_resource.rb", "app/madmin/resources/sessions/event_resource.rb"
      end

      def create_controllers
        template "sessions_controller.rb", "app/controllers/madmin/sessions_controller.rb"
        template "session_events_controller.rb", "app/controllers/madmin/session_events_controller.rb"
      end

      def display_post_install_message
        say "\n🔐 Madmin resources for sessions installed.", :green
        say "\nTo complete the setup:"

        say "  1. Add the routes where you draw your Madmin routes"
        say "     (config/routes/madmin.rb in most apps):"
        say ""
        say "       # Login trail — drawn BEFORE `resources :sessions`, or"
        say "       # /sessions/events would match as a session id."
        say "       namespace :sessions do"
        say "         resources :events, only: [ :index, :show ], controller: \"/madmin/session_events\""
        say "       end"
        say ""
        say "       resources :sessions, only: [ :index, :show ] do"
        say "         member do"
        say "           post :revoke"
        say "         end"
        say "       end"

        say "\n  2. (Optional) Group them in the sidebar — both resources declare"
        say "     `parent: \"Security\"`; pre-seed its position in an initializer:"
        say ""
        say "       Madmin.menu.before_render do"
        say "         add label: \"Security\", position: 91"
        say "       end"

        say "\n  3. (Optional) For a per-user panel (devices + trail on the user's"
        say "     show page), add a member action to your users controller that"
        say "     loads `user.sessions.by_recency` and `user.session_history.recent`"
        say "     — the README's Admin section has the full recipe."

        say "\nRevoking from the index destroys the row: that device is signed out"
        say "on its very next request, and the revocation lands in the trail with"
        say "admin attribution. 🔐\n", :green
      end

      private

      def madmin_available?
        defined?(::Madmin) ? true : false
      end

      def session_class
        Sessions.config.session_class
      rescue StandardError
        "Session"
      end
    end
  end
end
