# frozen_string_literal: true

require "rails/generators/base"

module Sessions
  module Generators
    # `rails generate sessions:views` — eject the engine's overridable
    # templates into the HOST app so they can be restyled. This is the
    # Devise move (`rails g devise:views`), and it works for the same boring
    # Rails reason: the host app's `app/views` sits AHEAD of any engine's
    # view paths in the lookup chain, so a file copied to e.g.
    # `app/views/sessions/_device.html.erb` SHADOWS the gem's bundled
    # default automatically — no config, no registration. Delete your copy
    # and the gem's default comes back. Upgrade the gem and your ejected
    # copies are untouched (re-run only if you WANT the new defaults).
    class ViewsGenerator < Rails::Generators::Base
      source_root File.expand_path("../../../app/views/sessions", __dir__)

      desc "Copy sessions' overridable views into your app so you can restyle them."

      def copy_views
        directory ".", "app/views/sessions"
      end

      def show_styling_tip
        say "\n🎨 Views copied to app/views/sessions/. They render with the gem's"
        say "   bundled sessions.css by default; restyle freely — if your app uses"
        say "   Tailwind, classes you add here are picked up by your build"
        say "   automatically (the files now live in app/views)."
      end
    end
  end
end
