# frozen_string_literal: true

require "test_helper"

# An API-only host (parent = ActionController::API) may bundle the gem purely
# for the model/trail APIs (`Sessions.track_login`, the scopes) without ever
# mounting the devices page — and production EAGER LOADS the engine's
# controllers anyway. The engine controller's class body must therefore
# survive a parent that lacks the view-layer DSL (`helper`, `helper_method`,
# `layout`); rendering the HTML page still requires a Base-derived parent,
# which is the default.
class ApiOnlyHostTest < ActiveSupport::TestCase
  CONTROLLER_PATH = Sessions::Engine.root.join("app/controllers/sessions/application_controller.rb").to_s

  test "the engine controller class body survives an ActionController::API parent" do
    Sessions::ApplicationController.name # force the autoload before remove_const
    Object.const_set(:SessionsApiParentForTest, Class.new(ActionController::API))
    Sessions.config.parent_controller = "SessionsApiParentForTest"
    Sessions.send(:remove_const, :ApplicationController)

    load CONTROLLER_PATH

    assert_operator Sessions::ApplicationController, :<, SessionsApiParentForTest,
                    "the class body must evaluate cleanly on an API parent (boot safety)"
  ensure
    # Restore the real engine controller for the rest of the suite: default
    # config FIRST (so the superclass resolves back to the host's
    # ApplicationController), then re-evaluate the file. Already-loaded
    # subclasses (DevicesController) keep their original superclass object —
    # functionally identical — and ones loaded later subclass the restored
    # constant.
    Sessions.reset!
    Sessions.send(:remove_const, :ApplicationController) if Sessions.const_defined?(:ApplicationController, false)
    load CONTROLLER_PATH
    Object.send(:remove_const, :SessionsApiParentForTest)
  end
end
