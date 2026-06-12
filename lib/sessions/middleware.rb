# frozen_string_literal: true

module Sessions
  # A tiny rack middleware with two jobs:
  #
  #   1. Stash the current request in Sessions::Current so MODEL-level
  #      callbacks (the omakase adapter's whole login pipeline) can see
  #      request context. The engine inserts this after
  #      ActionDispatch::Executor, so the executor's CurrentAttributes
  #      reset cleans up after every request — no leaks across requests or
  #      between jobs and web.
  #
  #   2. When `config.request_client_hints` is on, advertise `Accept-CH` so
  #      Chromium browsers attach high-entropy client hints (real platform
  #      versions, Android device models) to subsequent requests — login
  #      POSTs are rarely first-navigations, so the hints are reliably
  #      there exactly when sessions get created.
  class Middleware
    # The high-entropy hints the device pipeline consumes (low-entropy ones
    # are sent by default on every secure request).
    ACCEPT_CH = "Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List"

    def initialize(app)
      @app = app
    end

    def call(env)
      Sessions::Current.request = ActionDispatch::Request.new(env)

      status, headers, body = @app.call(env)

      if Sessions.config.request_client_hints && !(headers["accept-ch"] || headers["Accept-CH"])
        # Lowercase per the Rack 3 spec; Rack 2 hashes pass it through
        # verbatim and HTTP header names are case-insensitive on the wire.
        headers["accept-ch"] = ACCEPT_CH
      end

      [status, headers, body]
    end
  end
end
