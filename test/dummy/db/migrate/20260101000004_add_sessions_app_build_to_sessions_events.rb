# frozen_string_literal: true

# A copy of the v0.1.3 upgrade migration. Fresh dummy databases already get
# app_build from the install-template migration; existing local test
# databases exercise the same idempotent upgrade path as host apps.
class AddSessionsAppBuildToSessionsEvents < ActiveRecord::Migration[7.1]
  def change
    add_column :sessions_events, :app_build, :string unless column_exists?(:sessions_events, :app_build)
  end
end
