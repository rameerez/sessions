# frozen_string_literal: true

# SimpleCov configuration file (auto-loaded before test suite)
# This keeps test_helper.rb clean and follows best practices.
# Coherent with the rest of the gem ecosystem (chats, moderate, usage_credits, pricing_plans, …).

SimpleCov.start do
  # Use SimpleFormatter for terminal-only output (no HTML generation)
  formatter SimpleCov::Formatter::SimpleFormatter

  # Don't count the test suite itself toward coverage
  add_filter "/test/"

  # Don't count code that ISN'T unit-testable by this suite and would only
  # distort the numbers:
  #   - Generators + their templates: these run via `rails generate
  #     sessions:install` / `sessions:views` in a real host. The generator
  #     classes ARE exercised by Rails::Generators::TestCase, but the
  #     migration .erb itself is never loaded as Ruby here (the dummy
  #     migrates a copy of it instead).
  #   - version.rb: a single constant; nothing to cover.
  add_filter "/lib/generators/"
  add_filter "/lib/sessions/version.rb"

  # Track Ruby files in the lib directory (gem source code)
  track_files "lib/**/*.rb"

  # Enable branch coverage for more detailed metrics
  enable_coverage :branch

  # Minimum coverage thresholds to prevent coverage REGRESSION. The
  # primitives (models, parsing, classification, configuration, the facade)
  # are thoroughly covered by the unit suite; the adapters and engine
  # controllers are driven by the integration tests against the dummy app.
  # The thresholds sit just under the current floor so the gate catches a
  # real regression without failing on the existing baseline; raise them as
  # coverage grows.
  minimum_coverage line: 80, branch: 60

  # Disambiguate parallel test runs
  command_name "Job #{ENV["TEST_ENV_NUMBER"]}" if ENV["TEST_ENV_NUMBER"]
end

# Print coverage summary to terminal after tests complete
SimpleCov.at_exit do
  SimpleCov.result.format!
  puts "\n#{"=" * 60}"
  puts "COVERAGE SUMMARY"
  puts "=" * 60
  puts "Line Coverage:   #{SimpleCov.result.covered_percent.round(2)}%"
  branch_coverage = SimpleCov.result.coverage_statistics[:branch]&.percent&.round(2) || "N/A"
  puts "Branch Coverage: #{branch_coverage}%"
  puts "=" * 60
end
