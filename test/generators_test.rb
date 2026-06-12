# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/sessions/install_generator"
require "generators/sessions/views_generator"
require "generators/sessions/madmin_generator"

class InstallGeneratorTest < Rails::Generators::TestCase
  tests Sessions::Generators::InstallGenerator
  destination File.expand_path("../tmp/generators", __dir__)
  setup :prepare_destination

  teardown do
    FileUtils.rm_rf(destination_root)
  end

  # The dummy app this suite runs inside IS an omakase host (session model +
  # Rails-8-shaped table), so the unstubbed path exercises adoption.
  test "on an omakase app: extends the existing table, never replaces the model" do
    run_generator

    assert_migration "db/migrate/add_sessions_columns_to_sessions.rb" do |migration|
      assert_match(/change_table :sessions/, migration)
      assert_match(/t\.string :token_digest/, migration)
      # Column types resolve at MIGRATION RUN time (jsonb on pg, json
      # elsewhere) so one migration file works across the dev/prod DB split.
      assert_match(/t\.send\(json_column_type, :auth_detail\)/, migration)
      assert_match(/add_index :sessions, :token_digest, unique: true/, migration)
    end
    assert_migration "db/migrate/create_sessions_events.rb" do |migration|
      assert_match(/create_table :sessions_events/, migration)
      assert_match(/t\.references :authenticatable, polymorphic: true/, migration)
      assert_match(/NO foreign key/, migration)
      assert_match(/t\.send\(session_id_column_type, :session_id\)/, migration)
    end
    assert_no_file "app/models/session.rb" # the host's own model stays the host's
    assert_file "config/initializers/sessions.rb", /Sessions\.configure/
    assert_file "app/jobs/sessions_sweep_job.rb", /Sessions\.sweep!/
  end

  test "on a Devise app: creates the Rails-8-shaped table and the shell model" do
    stub_devise_mode!

    run_generator

    assert_migration "db/migrate/create_sessions.rb" do |migration|
      assert_match(/create_table :sessions, id: primary_key_type/, migration)
      assert_match(/t\.references :user, null: false, foreign_key: true, type: foreign_key_type/, migration)
      assert_match(/t\.text :user_agent/, migration)
      assert_match(/primary_and_foreign_key_types/, migration) # uuid/bigint adaptivity
    end
    assert_file "app/models/session.rb" do |model|
      assert_match(/class Session < ApplicationRecord/, model)
      assert_match(/include Sessions::Model/, model)
    end
  end

  test "--polymorphic tracks every Devise scope" do
    stub_devise_mode!

    run_generator %w[--polymorphic]

    assert_migration "db/migrate/create_sessions.rb",
                     /t\.references :user, polymorphic: true, null: false/
  end

  test "--model is the escape hatch for conflicting Session classes" do
    stub_devise_mode!

    run_generator %w[--model=SessionRecord]

    assert_migration "db/migrate/create_session_records.rb", /create_table :session_records/
    assert_file "app/models/session_record.rb" do |model|
      assert_match(/class SessionRecord < ApplicationRecord/, model)
      assert_match(/include Sessions::Model/, model)
    end
  end

  test "aborts with guidance when no auth system is detected" do
    Sessions::Generators::InstallGenerator.any_instance.stubs(:omakase_detected?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:devise_detected?).returns(false)

    stderr = capture(:stderr) { run_generator }

    assert_match(/couldn't detect an authentication system/, stderr)
    assert_match(/generate authentication/, stderr)
    assert_no_file "config/initializers/sessions.rb" # the run truly aborted
    assert_no_migration "db/migrate/create_sessions_events.rb"
  end

  test "aborts with guidance on a conflicting legacy sessions table" do
    Sessions::Generators::InstallGenerator.any_instance.stubs(:omakase_detected?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:devise_detected?).returns(true)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:sessions_table_exists?).returns(true)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:rails8_shaped_table?).returns(false)

    stderr = capture(:stderr) { run_generator }

    assert_match(/--model=SessionRecord/, stderr)
    assert_no_file "config/initializers/sessions.rb"
    assert_no_migration "db/migrate/create_sessions_events.rb"
  end

  test "--model on an omakase app takes the create-table path (adoption needs a table)" do
    # The escape hatch for omakase apps with a conflicting legacy Session
    # class: the controller shape says "omakase", but session_records does
    # NOT exist — an add-columns migration against nothing would be
    # unrunnable. Adoption requires the table.
    Sessions::Generators::InstallGenerator.any_instance.stubs(:rails8_shaped_table?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:omakase_controller_shape?).returns(true)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:sessions_table_exists?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:devise_detected?).returns(false)

    run_generator %w[--model=SessionRecord]

    assert_migration "db/migrate/create_session_records.rb" do |migration|
      assert_match(/create_table :session_records, id: primary_key_type/, migration)
    end
    assert_no_migration "db/migrate/add_sessions_columns_to_session_records.rb"
    assert_file "app/models/session_record.rb"
  end

  # --- Drift checks (footprinted's CI-drift rule) -----------------------------
  #
  # The dummy app migrates RESOLVED COPIES of these templates on every CI
  # database leg — these tests fail the build the moment template and copy
  # disagree on columns, so "the migrations the dummy proved" and "the
  # migrations users get" can never drift apart silently.

  TEMPLATES = File.expand_path("../lib/generators/sessions/templates", __dir__)
  DUMMY_MIGRATIONS = File.expand_path("dummy/db/migrate", __dir__)

  test "the dummy's add-columns migration matches the template" do
    assert_equal column_names_in(File.join(TEMPLATES, "add_sessions_columns.rb.erb")),
                 column_names_in(File.join(DUMMY_MIGRATIONS, "20260101000001_add_sessions_columns_to_sessions.rb"))
  end

  test "the dummy's events migration matches the template" do
    assert_equal column_names_in(File.join(TEMPLATES, "create_sessions_events.rb.erb")),
                 column_names_in(File.join(DUMMY_MIGRATIONS, "20260101000002_create_sessions_events.rb"))
  end

  test "both created tables mirror the host's primary-key type" do
    # uuid hosts embed sessions/events into uuid polymorphic associations
    # (Noticed records, audit ledgers); a bigint id assigned to a uuid
    # column type-casts to NULL silently — the PK type must follow the app.
    assert_includes File.read(File.join(TEMPLATES, "create_sessions_events.rb.erb")),
                    "create_table :sessions_events, id: primary_key_type"
    assert_includes File.read(File.join(TEMPLATES, "create_sessions.rb.erb")),
                    "create_table :<%= table_name %>, id: primary_key_type"
  end

  test "the Devise-mode table is the omakase base plus the add-columns set" do
    base = %w[user ip_address user_agent]
    add_columns = column_names_in(File.join(TEMPLATES, "add_sessions_columns.rb.erb"))

    assert_equal (base + add_columns).sort,
                 column_names_in(File.join(TEMPLATES, "create_sessions.rb.erb")).sort
  end

  private

  # Set semantics (uniq): templates carry BOTH branches of ERB conditionals
  # (e.g. the polymorphic-vs-plain user reference), of which exactly one
  # survives generation.
  def column_names_in(path)
    source = File.read(path)
    plain = source.scan(/^\s*t\.(?:string|text|datetime|decimal|bigint|uuid|integer|json|jsonb|references) :(\w+)/)
    sent = source.scan(/^\s*t\.send\(\w+, :(\w+)\)/)
    (plain + sent).flatten.uniq
  end

  def stub_devise_mode!
    Sessions::Generators::InstallGenerator.any_instance.stubs(:session_model_file?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:rails8_shaped_table?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:omakase_controller_shape?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:sessions_table_exists?).returns(false)
    Sessions::Generators::InstallGenerator.any_instance.stubs(:devise_detected?).returns(true)
  end
end

class MadminGeneratorTest < Rails::Generators::TestCase
  tests Sessions::Generators::MadminGenerator
  destination File.expand_path("../tmp/generators", __dir__)
  setup :prepare_destination

  teardown do
    FileUtils.rm_rf(destination_root)
  end

  test "generates the resources and controllers with the footguns pre-solved" do
    Sessions::Generators::MadminGenerator.any_instance.stubs(:madmin_available?).returns(true)

    output = run_generator

    assert_file "app/madmin/resources/session_resource.rb" do |resource|
      assert_match(/model Session$/, resource)
      assert_match(/attribute :device_name, :string/, resource)
      assert_match(/attribute :token_digest, show: false/, resource) # never rendered
      assert_match(/scope :active/, resource)
    end
    assert_file "app/madmin/resources/sessions/event_resource.rb" do |resource|
      assert_match(/class Sessions::EventResource < Madmin::Resource/, resource)
      assert_match(/scope :failed_logins/, resource)
    end
    assert_file "app/controllers/madmin/sessions_controller.rb", /def revoke/
    # The namespaced-resource pointer must be the stock-Madmin-portable
    # resource_name override, NOT a resource_class_name class attribute
    # (that's a host-app patch some dashboards carry, not Madmin API).
    assert_file "app/controllers/madmin/session_events_controller.rb",
                /def resource_name\s+"Sessions::EventResource"/

    # The route-ordering footgun is spelled out in the instructions.
    assert_match(/BEFORE `resources :sessions`/, output)
    assert_match(/namespace :sessions do/, output)
  end

  test "aborts with guidance when madmin isn't in the bundle" do
    Sessions::Generators::MadminGenerator.any_instance.stubs(:madmin_available?).returns(false)

    stderr = capture(:stderr) { run_generator }

    assert_match(/Madmin isn't loaded/, stderr)
    assert_no_file "app/madmin/resources/session_resource.rb"
  end
end

class ViewsGeneratorTest < Rails::Generators::TestCase
  tests Sessions::Generators::ViewsGenerator
  destination File.expand_path("../tmp/generators", __dir__)
  setup :prepare_destination

  teardown do
    FileUtils.rm_rf(destination_root)
  end

  test "ejects every overridable view into the host" do
    run_generator

    assert_file "app/views/sessions/_devices.html.erb"
    assert_file "app/views/sessions/_device.html.erb"
    assert_file "app/views/sessions/_history.html.erb"
    assert_file "app/views/sessions/_event.html.erb"
    assert_file "app/views/sessions/devices/index.html.erb"
    assert_file "app/views/sessions/devices/history.html.erb"
  end
end
