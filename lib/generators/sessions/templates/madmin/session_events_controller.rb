# frozen_string_literal: true

module Madmin
  # The login trail — read-only by design (append-only history; the
  # destructive verbs live on live sessions, not on their records).
  class SessionEventsController < Madmin::ResourceController
    private

    # Stock Madmin derives the resource from the controller path
    # ("madmin/session_events" → ::SessionEventResource); ours is namespaced
    # under Sessions::. Overriding resource_name keeps this self-contained
    # on stock Madmin — no host patches required.
    def resource_name
      "Sessions::EventResource"
    end

    def scoped_resources
      super.includes(:authenticatable)
    end
  end
end
