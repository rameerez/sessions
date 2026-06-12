# frozen_string_literal: true

module Sessions
  # Async geo enrichment for the MaxMind path (the Cloudflare path is a free
  # synchronous header read at request time and never gets here). Enqueued
  # after commit — only when trackdown is present AND has a database (see
  # Sessions::Geolocation.async_capable?), so hosts without MaxMind never
  # see a no-op job.
  #
  # The conditional superclass keeps the constant loadable (Zeitwerk eager
  # loads this file) in the rare host that runs without ActiveJob — where
  # enqueueing is already guarded off.
  class GeolocateJob < (defined?(::ActiveJob::Base) ? ::ActiveJob::Base : Object)
    if defined?(::ActiveJob::Base)
      discard_on ActiveRecord::RecordNotFound if defined?(::ActiveRecord::RecordNotFound)

      def perform(class_name, id)
        record = class_name.constantize.find_by(id: id)
        return unless record.respond_to?(:country_code)
        return if record.country_code.present?

        ip = record.try(:ip_address)
        return if ip.blank?
        return unless defined?(::Trackdown)

        result = ::Trackdown.locate(ip.to_s)
        updates = Sessions::Geolocation.columns_from(result)
        return if updates.empty?

        # Events also store precision-reduced coordinates (privacy now,
        # impossible-travel math later); registry rows don't have the
        # columns and the filter drops them.
        updates.merge!(Sessions::Geolocation.coordinates_from(result))
        updates.select! { |column, _| record.class.column_names.include?(column.to_s) }

        record.update_columns(updates) if updates.any?

        mirror_to_login_event(record, updates)
      rescue StandardError => e
        Sessions.warn("geolocate job failed: #{e.class}: #{e.message}")
      end

      private

      # When the enriched record is a registry row, its login event was
      # written before geo resolved — keep the trail consistent.
      def mirror_to_login_event(record, updates)
        return unless record.respond_to?(:sessions_token_matches?) # a registry row
        return unless Sessions::Event.table_exists?

        event_updates = updates.select { |column, _| Sessions::Event.column_names.include?(column.to_s) }
        return if event_updates.empty?

        Sessions::Event.logins.where(session_id: record.id, country_code: nil).update_all(event_updates)
      end
    end
  end
end
