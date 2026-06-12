# frozen_string_literal: true

# A copy of what `rails generate sessions:install` writes for the trail
# (lib/generators/sessions/templates/create_sessions_events.rb.erb, ERB
# resolved). The runtime helpers are kept VERBATIM so every CI database leg
# executes the template's real logic; the drift test in generators_test.rb
# keeps this file honest against the template.
class CreateSessionsEvents < ActiveRecord::Migration[7.1]
  def change
    primary_key_type, foreign_key_type = primary_and_foreign_key_types

    create_table :sessions_events, id: primary_key_type do |t|
      t.string :event, null: false
      t.references :authenticatable, polymorphic: true, type: foreign_key_type, index: false
      t.string :scope

      # The trail ↔ registry linkage. A plain column, NO foreign key: the
      # registry row it points at gets destroyed on revoke; history must
      # survive.
      t.send(session_id_column_type, :session_id)

      t.string :identity
      t.string :device_id, limit: 36
      t.string :auth_method
      t.string :auth_provider
      t.send(json_column_type, :auth_detail)
      t.string :failure_reason
      t.string :revoked_reason

      t.string :ip_address, limit: 45
      t.text :user_agent
      t.send(json_column_type, :client_hints)
      t.string :browser_name
      t.string :browser_version
      t.string :os_name
      t.string :os_version
      t.string :device_type
      t.string :device_model
      t.string :app_name
      t.string :app_version

      t.string :country_code, limit: 2
      t.string :country_name
      t.string :city
      t.string :region
      t.decimal :latitude, precision: 10, scale: 7
      t.decimal :longitude, precision: 10, scale: 7

      t.string :request_id
      t.string :context
      t.send(json_column_type, :metadata)

      t.datetime :occurred_at, null: false # append-only: no updated_at
    end

    add_index :sessions_events, %i[authenticatable_type authenticatable_id occurred_at],
              name: "index_sessions_events_on_authenticatable_and_occurred_at"
    add_index :sessions_events, %i[event occurred_at]
    add_index :sessions_events, %i[device_id occurred_at]
    add_index :sessions_events, :identity
    add_index :sessions_events, :ip_address
    add_index :sessions_events, :session_id
    add_index :sessions_events, :occurred_at
  end

  private

  def primary_and_foreign_key_types
    config = Rails.configuration.generators
    setting = config.options[config.orm][:primary_key_type]
    primary_key_type = setting || :primary_key
    foreign_key_type = setting || :bigint
    [ primary_key_type, foreign_key_type ]
  end

  def session_id_column_type
    config = Rails.configuration.generators
    setting = config.options[config.orm][:primary_key_type]
    setting == :uuid ? :uuid : :bigint
  end

  # match? (not equality): PostGIS apps report adapter_name "PostGIS" and
  # are PostgreSQL too.
  def json_column_type
    return :jsonb if connection.adapter_name.match?(/postg/i)

    :json
  end
end
