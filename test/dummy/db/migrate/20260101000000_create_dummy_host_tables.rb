# frozen_string_literal: true

# The host tables `rails g authentication` generates: users + the Rails-8
# `sessions` table (user:references ip_address:string user_agent:string).
class CreateDummyHostTables < ActiveRecord::Migration[7.1]
  def change
    create_table :users do |t|
      t.string :email_address, null: false
      t.string :password_digest, null: false
      t.timestamps
    end
    add_index :users, :email_address, unique: true

    create_table :sessions do |t|
      t.references :user, null: false, foreign_key: true
      t.string :ip_address
      t.string :user_agent
      t.timestamps
    end
  end
end
