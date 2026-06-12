# frozen_string_literal: true

# The model `rails g authentication` generates, plus the gem's one-line
# macro — exactly what the README tells users to do.
class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy

  normalizes :email_address, with: ->(e) { e.strip.downcase }

  has_sessions
end
