# frozen_string_literal: true

class ApplicationController < ActionController::Base
  include Authentication # the line `rails g authentication` injects
end
