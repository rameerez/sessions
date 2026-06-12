# frozen_string_literal: true

# A copy of what `rails generate sessions:install` writes on a Rails 8
# omakase app (lib/generators/sessions/templates/add_sessions_columns.rb.erb,
# ERB resolved for the default model). The runtime helpers (json_column_type)
# are kept VERBATIM so every CI database leg (sqlite/postgres/mysql) executes
# the template's real logic. The drift test in generators_test.rb keeps this
# file honest against the template.
class AddSessionsColumnsToSessions < ActiveRecord::Migration[7.1]
  def change
    change_table :sessions, bulk: true do |t|
      t.string :token_digest
      t.string :scope

      t.string :auth_method
      t.string :auth_provider
      t.send(json_column_type, :auth_detail)

      t.string :browser_name
      t.string :browser_version
      t.string :os_name
      t.string :os_version
      t.string :device_type
      t.string :device_model
      t.string :app_name
      t.string :app_version
      t.string :app_build
      t.send(json_column_type, :client_hints)

      t.string :country_code, limit: 2
      t.string :country_name
      t.string :city
      t.string :region

      t.string :device_id, limit: 36

      t.datetime :last_seen_at
      t.string :last_seen_ip, limit: 45
    end

    add_index :sessions, :device_id
    add_index :sessions, :token_digest, unique: true
    add_index :sessions, :auth_method
    add_index :sessions, :auth_provider
    add_index :sessions, :country_code
    add_index :sessions, :last_seen_at
  end

  private

  # match? (not equality): PostGIS apps report adapter_name "PostGIS" and
  # are PostgreSQL too.
  def json_column_type
    return :jsonb if connection.adapter_name.match?(/postg/i)

    :json
  end
end
