# frozen_string_literal: true

# A copy of the v0.1.2 upgrade migration. Fresh dummy databases already get
# adoption_key from the install-template migration; existing local test
# databases run this idempotent migration to catch up.
class AddSessionsAdoptionKeyToSessions < ActiveRecord::Migration[7.1]
  def change
    add_column :sessions, :adoption_key, :string unless column_exists?(:sessions, :adoption_key)
    add_index :sessions, :adoption_key, unique: true unless index_exists?(:sessions, :adoption_key)
  end
end
