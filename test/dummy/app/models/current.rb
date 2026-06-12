# frozen_string_literal: true

# Vendored from the Rails 8.1.3 authentication generator (current.rb.tt).
class Current < ActiveSupport::CurrentAttributes
  attribute :session
  delegate :user, to: :session, allow_nil: true
end
