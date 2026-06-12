# frozen_string_literal: true

# The login trail (sessions gem): append-only record of every login attempt
# — successful AND failed, with the identity AS TYPED even when no such
# account exists — plus logouts, revocations and expiries. This is the
# brute-force / credential-stuffing / account-takeover triage surface:
#
#   filter "Failed logins" + sort by occurred_at  → tonight's attack
#   search an email                               → everything typed against it
#   search an IP                                  → everything from that address
#
# Events are immutable history; there are no destructive actions here. The
# kill switch lives on the live session (SessionResource).
class Sessions::EventResource < Madmin::Resource
  model Sessions::Event

  attribute :id, index: false, form: false
  attribute :event, index: true, form: false, label: "Event"
  attribute :identity, index: true, form: false, label: "Identity (as typed)"
  # Virtual: Event#user is the resolved account (nil for unknown-identity
  # failures — that's the point of the identity column above).
  attribute :user, :string, index: true, form: false, label: "User"
  # Virtual (gem-computed): "Chrome 137 on macOS".
  attribute :device_name, :string, index: true, form: false, label: "Device"
  attribute :failure_reason, index: true, form: false
  attribute :revoked_reason, index: false, form: false
  attribute :auth_method, index: false, form: false
  attribute :auth_provider, index: false, form: false
  attribute :ip_address, index: true, form: false, label: "IP"
  attribute :country_code, index: true, form: false, label: "Country"
  attribute :city, index: false, form: false
  attribute :region, index: false, form: false
  attribute :scope, index: false, form: false
  attribute :session_id, index: false, form: false, label: "Session"
  attribute :user_agent, index: false, form: false
  attribute :browser_name, index: false, form: false
  attribute :os_name, index: false, form: false
  attribute :device_type, index: false, form: false
  attribute :device_model, index: false, form: false
  attribute :app_name, index: false, form: false
  attribute :app_version, index: false, form: false
  attribute :request_id, index: false, form: false
  attribute :context, index: false, form: false
  attribute :metadata, index: false, form: false
  attribute :occurred_at, index: true, form: false, label: "When"

  # Hidden: raw blobs / geo internals that only add noise next to the
  # parsed columns.
  attribute :auth_detail, show: false, form: false
  attribute :client_hints, show: false, form: false
  attribute :latitude, show: false, form: false
  attribute :longitude, show: false, form: false
  attribute :country_name, show: false, form: false
  attribute :browser_version, show: false, form: false
  attribute :os_version, show: false, form: false
  attribute :app_build, show: false, form: false
  attribute :authenticatable_type, show: false, form: false
  attribute :authenticatable_id, show: false, form: false

  # Gem scopes — the triage filters.
  scope :logins
  scope :failed_logins
  scope :logouts
  scope :revocations
  scope :expirations
  scope :new_devices
  scope :last_24_hours

  menu label: "Login activity", parent: "Security"

  def self.display_name(record)
    "#{record.event} · #{record.identity || record.user.try(:email) || "unknown"}"
  end

  def self.default_sort_column = "occurred_at"
  def self.default_sort_direction = "desc"
end
