# frozen_string_literal: true

require "active_support/current_attributes"

module Sessions
  # Per-request state, set by Sessions::Middleware and reset automatically by
  # the Rails executor (the middleware sits after ActionDispatch::Executor in
  # the stack, so CurrentAttributes' executor-driven clear_all covers it).
  #
  # Why it exists: the omakase adapter records logins from MODEL callbacks
  # (Session#after_create_commit — the only seam that captures 100% of the
  # generated login lifecycle), and model callbacks have no request. This
  # carries the request reference across that gap. Background jobs and
  # console code simply see nil and the pipeline degrades gracefully (rows
  # parse from their own stored columns).
  class Current < ActiveSupport::CurrentAttributes
    # The ActionDispatch::Request being served, if any.
    attribute :request
  end
end
