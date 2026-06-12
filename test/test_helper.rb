# frozen_string_literal: true

# SimpleCov must be loaded before any application code
# (configuration is auto-loaded from the .simplecov file).
require "simplecov"

# Configure Rails Environment
ENV["RAILS_ENV"] = "test"

require File.expand_path("dummy/config/environment.rb", __dir__)
ActiveRecord::Migrator.migrations_paths = [
  File.expand_path("dummy/db/migrate", __dir__)
]

# Auto-migrate so a plain `bundle exec rake test` works on a fresh checkout
# (CI also runs db:migrate explicitly; this is idempotent either way).
ActiveRecord::MigrationContext.new(ActiveRecord::Migrator.migrations_paths).migrate

# In a real app, migrations run before boot — here the dummy boots first and
# migrates after, so re-apply the (idempotent) omakase install now that the
# tables actually exist, exactly what the next boot would do in production.
Session.reset_column_information
Sessions::Adapters::Omakase.install!

require "rails/test_help"
require "minitest/mock"
require "mocha/minitest"

# Filter out Minitest backtrace while allowing backtrace from other libraries
# to be shown.
Minitest.backtrace_filter = Minitest::BacktraceFilter.new

# A canned user agent per device family, shared across the suite.
module UserAgents
  CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " \
               "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
  SAFARI_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_5 like Mac OS X) AppleWebKit/605.1.15 " \
                  "(KHTML, like Gecko) Version/19.5 Mobile/15E148 Safari/604.1"
  FIREFOX_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0"
  NATIVE_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_5 like Mac OS X) AppleWebKit/605.1.15 " \
               "(KHTML, like Gecko) MyApp/2.4.1 (iPhone15,2; iOS 19.5; build 241); " \
               "Hotwire Native iOS; Turbo Native iOS; bridge-components: [form menu]"
  NATIVE_ANDROID = "MyApp/2.4.1 (Pixel 8; Android 16; build 241); Hotwire Native Android; " \
                   "Turbo Native Android; bridge-components: [form menu]; " \
                   "Mozilla/5.0 (Linux; Android 16; Pixel 8 Build/BP2A.250605.031; wv) " \
                   "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.0.0 Mobile Safari/537.36"
  NATIVE_ANDROID_BARE = "Hotwire Native Android; Turbo Native Android; bridge-components: []; " \
                        "Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/UQ1A.240105.004; wv) " \
                        "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.0.0 Mobile Safari/537.36"
  GOOGLEBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; " \
              "Googlebot/2.1; +http://www.google.com/bot.html) Chrome/137.0.0.0 Safari/537.36"
end

module ActiveSupport
  class TestCase
    include ActiveJob::TestHelper

    setup do
      # Start every test from a known configuration so hooks/flags never
      # leak between tests.
      Sessions.reset!
      # The vendored SessionsController's rate_limit counts in Rails.cache —
      # a previous test's sign-in attempts must never 429 this one's.
      Rails.cache.clear
    end

    teardown do
      Sessions.reset!
      Sessions::Current.reset
      Session.delete_all if Session.table_exists?
      Sessions::Event.delete_all if Sessions::Event.table_exists?
      User.delete_all if User.table_exists?
    end

    # --- Data helpers -----------------------------------------------------------

    def create_user(email: "user#{SecureRandom.hex(3)}@example.com", password: "s3kr1t-pass", **attributes)
      User.create!(email_address: email, password: password, **attributes)
    end

    # A registry row created the omakase way (the host's own model API).
    def create_session_for(user, ip: "203.0.113.7", ua: UserAgents::CHROME_MAC, **attributes)
      user.sessions.create!(ip_address: ip, user_agent: ua, **attributes)
    end

    # A fabricated request carrying the given UA/IP/headers — the unit-test
    # stand-in for a real inbound request.
    def fake_request(ua: UserAgents::CHROME_MAC, ip: "203.0.113.7", method: "GET", path: "/",
                     params: {}, env: {})
      base = {
        "REQUEST_METHOD" => method,
        "PATH_INFO" => path,
        "REMOTE_ADDR" => ip,
        "HTTP_USER_AGENT" => ua,
        "rack.input" => StringIO.new(Rack::Utils.build_nested_query(params))
      }
      base["CONTENT_TYPE"] = "application/x-www-form-urlencoded" if method == "POST"
      ActionDispatch::Request.new(Rack::MockRequest.env_for(path, base.merge(env)))
    end

    # Run a block with Sessions::Current.request set, the way the
    # middleware does in a real request cycle.
    def with_request(request, &block)
      Sessions.with_request(request, &block)
    end
  end
end

module ActionDispatch
  class IntegrationTest
    DEFAULT_UA = UserAgents::CHROME_MAC

    # Sign in through the real (vendored) omakase SessionsController.
    def sign_in_as(user, password: "s3kr1t-pass", ua: DEFAULT_UA)
      post "/session", params: { email_address: user.email_address, password: password },
                       headers: { "HTTP_USER_AGENT" => ua }
    end
  end
end
