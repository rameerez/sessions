# frozen_string_literal: true

# The ENTIRE model `rails g authentication` generates — deliberately
# untouched: the gem's omakase adapter must decorate it automatically
# (Sessions::Model is included at to_prepare), proving the zero-app-edits
# story.
class Session < ApplicationRecord
  belongs_to :user
end
