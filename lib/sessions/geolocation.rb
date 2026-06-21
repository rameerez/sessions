# frozen_string_literal: true

module Sessions
  # IP geolocation through the `trackdown` gem — a SOFT dependency, never
  # required: every call site is `defined?(::Trackdown)`-guarded and
  # rescue-everything (trackdown raises on private/loopback IPs in
  # development, and a geo hiccup must never block a login write). The
  # integration contract is lifted verbatim from footprinted's proven one
  # (→ docs/research/02-ecosystem.md §2):
  #
  #   - always pass `request:` through so Cloudflare headers win when present
  #     (zero config, free, synchronous header read);
  #   - go async only when sync would mean a database lookup (the MaxMind
  #     mode) — Sessions::GeolocateJob enriches the row after commit;
  #   - skip lookups when country_code is already present.
  #
  # Without trackdown, geo columns simply stay nil and the devices page
  # omits location cleanly.
  module Geolocation
    COLUMNS = %i[country_code country_name city region].freeze

    module_function

    def enabled?
      Sessions.config.geolocate == :auto && defined?(::Trackdown)
    end

    # Synchronous geolocation — called inline at session-creation time ONLY
    # when it's free (Cloudflare already did the lookup and put the answer
    # in request headers). Returns a column hash or {}. `coordinates: true`
    # adds precision-reduced lat/lng (event rows only).
    def locate(ip, request: nil, coordinates: false)
      return {} unless enabled?
      return {} if ip.to_s.empty?

      result = ::Trackdown.locate(ip.to_s, request: request)
      columns = columns_from(result)
      columns = columns.merge(coordinates_from(result)) if coordinates && columns.any?
      columns
    rescue StandardError => e
      Sessions.warn("geolocation failed for #{ip}: #{e.class}: #{e.message}")
      {}
    end

    # Hand a record to the async MaxMind path (no-op without ActiveJob or a
    # trackdown database — see async_capable?).
    def enqueue(record)
      return false unless record&.persisted?
      return false unless async_capable?

      Sessions::GeolocateJob.perform_later(record.class.name, record.id)
      true
    rescue StandardError => e
      Sessions.warn("geolocation enqueue failed: #{e.class}: #{e.message}")
      false
    end

    # Whether this request already carries a Cloudflare geo answer — the
    # header read is free, so we resolve synchronously.
    def cloudflare_headers?(request)
      return false unless request

      country = request.get_header("HTTP_CF_IPCOUNTRY")
      !country.nil? && !country.empty? && country != "XX"
    rescue StandardError
      false
    end

    # Whether an async MaxMind lookup could possibly succeed — used to avoid
    # enqueueing a no-op job per login on hosts without a MaxMind database.
    def async_capable?
      enabled? &&
        defined?(::ActiveJob) &&
        ::Trackdown.respond_to?(:database_exists?) &&
        ::Trackdown.database_exists?
    rescue StandardError
      false
    end

    def columns_from(result)
      return {} unless result

      country_code = location_value(result, :country_code)
      return {} if country_code.to_s.empty?

      {
        country_code: country_code,
        country_name: presence(location_value(result, :country_name)),
        city: presence(location_value(result, :city)),
        region: presence(location_value(result, :region))
      }.compact
    end

    # Latitude/longitude for EVENT rows only, precision-reduced per
    # config.geo_precision (2 decimals ≈ 1km — privacy now,
    # impossible-travel math later).
    def coordinates_from(result)
      latitude = location_value(result, :latitude)
      longitude = location_value(result, :longitude)
      return {} if latitude.nil? || longitude.nil?

      precision = Sessions.config.geo_precision
      {
        latitude: latitude.to_f.round(precision),
        longitude: longitude.to_f.round(precision)
      }
    rescue StandardError
      {}
    end

    def location_value(result, attribute)
      result.public_send(attribute) if result.respond_to?(attribute)
    rescue StandardError
      nil
    end

    def presence(value)
      value.nil? || value.to_s.empty? || value.to_s == "Unknown" ? nil : value
    end
  end
end
