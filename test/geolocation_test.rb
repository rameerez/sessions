# frozen_string_literal: true

require "test_helper"

class GeolocationTest < ActiveSupport::TestCase
  # A stand-in for trackdown's LocationResult.
  FakeResult = Struct.new(:country_code, :country_name, :city, :region, :latitude, :longitude,
                          keyword_init: true)
  LegacyResult = Struct.new(:country_code, :country_name, :city, keyword_init: true)

  MADRID = FakeResult.new(country_code: "ES", country_name: "Spain", city: "Madrid",
                          region: "Madrid", latitude: 40.4167754, longitude: -3.7037902)

  # Define a ::Trackdown stand-in for the duration of a block — the gem only
  # ever talks to it through `defined?(::Trackdown)` + duck typing, so this
  # exercises the exact soft-dependency seam.
  def with_fake_trackdown(result: MADRID, database: false, raises: nil)
    fake = Module.new do
      singleton_class.define_method(:locate) do |_ip, request: nil|
        raise raises if raises

        result
      end
      singleton_class.define_method(:database_exists?) { database }
    end
    Object.const_set(:Trackdown, fake)
    yield
  ensure
    Object.send(:remove_const, :Trackdown) if defined?(::Trackdown)
  end

  test "without trackdown, geolocation is silently disabled" do
    refute Sessions::Geolocation.enabled?
    assert_equal({}, Sessions::Geolocation.locate("8.8.8.8"))
    refute Sessions::Geolocation.async_capable?
  end

  test "locate maps the trackdown result onto the geo columns" do
    with_fake_trackdown do
      columns = Sessions::Geolocation.locate("8.8.8.8")

      assert_equal "ES", columns[:country_code]
      assert_equal "Spain", columns[:country_name]
      assert_equal "Madrid", columns[:city]
      refute columns.key?(:latitude)
    end
  end

  test "locate tolerates older trackdown results without optional region fields" do
    result = LegacyResult.new(country_code: "ES", country_name: "Spain", city: "Madrid")

    with_fake_trackdown(result: result) do
      columns = Sessions::Geolocation.locate("8.8.8.8")

      assert_equal "ES", columns[:country_code]
      assert_equal "Spain", columns[:country_name]
      assert_equal "Madrid", columns[:city]
      refute columns.key?(:region)
    end
  end

  test "coordinates are precision-reduced per config.geo_precision" do
    with_fake_trackdown do
      columns = Sessions::Geolocation.locate("8.8.8.8", coordinates: true)

      assert_in_delta 40.42, columns[:latitude]
      assert_in_delta(-3.70, columns[:longitude])
    end
  end

  test "a raising trackdown (private IPs in dev!) never breaks the caller" do
    with_fake_trackdown(raises: RuntimeError.new("private IP")) do
      assert_equal({}, Sessions::Geolocation.locate("127.0.0.1"))
    end
  end

  test "an Unknown result yields no columns" do
    unknown = FakeResult.new(country_code: nil, country_name: "Unknown", city: "Unknown")
    with_fake_trackdown(result: unknown) do
      assert_equal({}, Sessions::Geolocation.locate("8.8.8.8"))
    end
  end

  test "geolocate :off disables everything even with trackdown present" do
    with_fake_trackdown do
      Sessions.config.geolocate = :off

      refute Sessions::Geolocation.enabled?
      assert_equal({}, Sessions::Geolocation.locate("8.8.8.8"))
    end
  end

  test "cloudflare_headers? detects a usable CF answer" do
    refute Sessions::Geolocation.cloudflare_headers?(nil)
    refute Sessions::Geolocation.cloudflare_headers?(fake_request)
    refute Sessions::Geolocation.cloudflare_headers?(fake_request(env: { "HTTP_CF_IPCOUNTRY" => "XX" }))
    assert Sessions::Geolocation.cloudflare_headers?(fake_request(env: { "HTTP_CF_IPCOUNTRY" => "ES" }))
  end

  test "async is only capable with trackdown AND a database" do
    with_fake_trackdown(database: false) { refute Sessions::Geolocation.async_capable? }
    with_fake_trackdown(database: true) { assert Sessions::Geolocation.async_capable? }
  end

  test "enqueue hands persisted records to the GeolocateJob" do
    user = create_user

    with_fake_trackdown(database: true) do
      row = create_session_for(user)

      assert_enqueued_with(job: Sessions::GeolocateJob) do
        assert Sessions::Geolocation.enqueue(row)
      end
    end
  end

  test "the GeolocateJob enriches the row and mirrors onto its login event" do
    user = create_user

    with_fake_trackdown(database: true) do
      row = create_session_for(user)
      assert_nil row.country_code

      Sessions::GeolocateJob.perform_now(row.class.name, row.id)

      assert_equal "ES", row.reload.country_code
      assert_equal "Madrid", row.city

      event = Sessions::Event.logins.find_by(session_id: row.id)
      assert_equal "ES", event.country_code
    end
  end

  test "the GeolocateJob skips rows that already have geo" do
    user = create_user

    with_fake_trackdown(database: true) do
      row = create_session_for(user)
      row.update_columns(country_code: "FR", country_name: "France")

      Sessions::GeolocateJob.perform_now(row.class.name, row.id)

      assert_equal "FR", row.reload.country_code
    end
  end

  test "the GeolocateJob enriches failed-login events with coordinates" do
    with_fake_trackdown(database: true) do
      event = Sessions::Event.record_failure(fake_request, identity: "j@example.com", reason: :invalid)

      Sessions::GeolocateJob.perform_now("Sessions::Event", event.id)

      event.reload
      assert_equal "ES", event.country_code
      assert_in_delta 40.42, event.latitude.to_f
    end
  end

  test "a vanished record is a no-op, not an error" do
    with_fake_trackdown(database: true) do
      assert_nothing_raised { Sessions::GeolocateJob.perform_now("Sessions::Event", 999_999) }
    end
  end
end
