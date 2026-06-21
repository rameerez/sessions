# frozen_string_literal: true

source "https://rubygems.org"

# Runtime dependencies are specified in sessions.gemspec
gemspec

# Build & release tools
gem "rake", "~> 13.0"

group :development do
  gem "appraisal"

  # Code quality
  gem "rubocop", "~> 1.0", require: false
  gem "rubocop-minitest", "~> 0.35", require: false
  gem "rubocop-performance", "~> 1.0", require: false
end

group :test do
  gem "minitest", "~> 6.0"
  # Minitest 6 extracted minitest/mock into its own gem.
  gem "minitest-mock"
  gem "mocha", "~> 2.0"
  gem "simplecov", require: false

  # Rails frameworks the dummy app boots that are NOT runtime dependencies of
  # the gem itself. The gemspec only depends on what sessions actually needs
  # at runtime (actionpack/activerecord/activesupport/railties + browser);
  # ActiveJob (the geolocation enrichment job + the generated sweep job) and
  # ActionMailer (hosts typically email from the `on_new_device` hook; the
  # dummy boots it so that integration stays honest) are pieces the HOST app
  # provides — so they belong in the test bundle, not the gemspec.
  gem "actionmailer"
  gem "activejob"

  # The dummy app vendors the exact code `rails generate authentication`
  # emits (User with has_secure_password + the Authentication concern), so it
  # needs bcrypt just like a real omakase host would.
  gem "bcrypt"

  # The Devise adapter attaches to Warden's class-level hooks — warden itself
  # is tiny (rack middleware) and lets us exercise the full hook ABI
  # (after_set_user/before_failure/before_logout) without dragging all of
  # Devise into the default test bundle. Devise-specific behavior is
  # duck-typed and covered with stubs; HostApp/LicenseSeat are the real-Devise
  # incubation apps.
  gem "warden"

  # Soft-dependency lane: the device_detector adapter upgrade is
  # feature-detected at runtime; bundling it here exercises that path.
  gem "device_detector"

  # Database adapters (for multi-database testing)
  gem "mysql2"
  gem "pg"
  gem "sqlite3"

  # Dummy Rails app
  gem "bootsnap", require: false
  gem "propshaft"
  gem "puma"

  # Fix RDoc version conflict (Ruby 3.4+ ships with 7.0.3)
  gem "rdoc", ">= 7.0"
end
