# frozen_string_literal: true

require_relative "lib/sessions/version"

Gem::Specification.new do |spec|
  spec.name = "sessions"
  spec.version = Sessions::VERSION
  spec.authors = ["rameerez"]
  spec.email = ["rubygems@rameerez.com"]

  spec.summary = "Session & login-activity tracking, device management, and remote revocation for Rails"
  spec.description = "sessions gives any Rails 8+ app a GitHub-style \"your devices\" page (list every active session, log out of one device, sign out everywhere else) plus an admin-grade, append-only trail of every login attempt — successful and failed — with parsed device intelligence (\"Chrome on macOS\", \"CarHey 2.4.1 on Pixel 8 (Android 16)\"), IP geolocation (via the trackdown gem, soft dependency), and the auth method that started each session (password, OAuth provider, passkey, magic link…). It decorates the session storage your app already has instead of replacing it: on Rails 8 omakase auth (`rails generate authentication`) it enriches the generated sessions table with zero app-code changes, and on Devise it generalizes the proven session_limitable mechanism into true per-device remote revocation via Warden hooks. It detects Hotwire Native apps (platform, OS version, app version, device model), never breaks login (every tracking path is error-isolated), ships privacy-first defaults (bounded retention with a sweep job, optional IP truncation, no client-side fingerprinting ever), and includes a mountable, i18n'd devices page you can restyle or eject view-by-view like Devise."
  spec.homepage = "https://github.com/rameerez/sessions"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime dependencies — kept minimal and host-agnostic on purpose.
  # `browser` is the one non-negotiable extra: a drop-in devices page needs
  # human device names ("Chrome on macOS") working with zero setup, and
  # browser is MIT, zero-dependency and ~15 KB of data (it's also what
  # Mastodon uses for exactly this feature). Everything else — trackdown
  # (geolocation), device_detector (parser upgrade), Devise/Warden, OmniAuth —
  # is an optional host-side integration detected at runtime, never a forced
  # dependency.
  spec.add_dependency "actionpack", ">= 7.1.0", "< 9.0"
  spec.add_dependency "activerecord", ">= 7.1.0", "< 9.0"
  spec.add_dependency "activesupport", ">= 7.1.0", "< 9.0"
  spec.add_dependency "browser", ">= 6.0"
  spec.add_dependency "railties", ">= 7.1.0", "< 9.0"
end
