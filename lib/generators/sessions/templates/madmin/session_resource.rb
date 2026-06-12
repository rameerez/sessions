# frozen_string_literal: true

# Live device registry (sessions gem): one row = one signed-in device,
# destroyed on logout/revocation — so this index IS the set of sessions that
# can act on your app right now. The append-only history lives in
# Sessions::Event (see Sessions::EventResource).
class SessionResource < Madmin::Resource
  model <%= session_class %>

  attribute :id, index: true, form: false, label: "ID"
  attribute :user, index: true, form: false, label: "User"
  # Virtual (gem-computed): "Chrome 137 on macOS",
  # "MyApp 2.4.1 on Pixel 8 (Android 16)".
  attribute :device_name, :string, index: true, form: false, label: "Device"
  attribute :auth_method, index: true, form: false, label: "Via"
  attribute :auth_provider, index: false, form: false
  attribute :ip_address, index: true, form: false, label: "IP (login)"
  attribute :last_seen_ip, index: false, form: false, label: "IP (last seen)"
  attribute :country_code, index: true, form: false, label: "Country"
  attribute :city, index: false, form: false
  attribute :scope, index: false, form: false
  attribute :device_type, index: false, form: false
  attribute :browser_name, index: false, form: false
  attribute :browser_version, index: false, form: false
  attribute :os_name, index: false, form: false
  attribute :os_version, index: false, form: false
  attribute :device_model, index: false, form: false
  attribute :app_name, index: false, form: false
  attribute :app_version, index: false, form: false
  attribute :app_build, index: false, form: false
  attribute :user_agent, index: false, form: false
  attribute :last_seen_at, index: true, form: false, label: "Last seen"
  attribute :created_at, index: true, form: false, label: "Signed in"
  attribute :updated_at, show: false, form: false

  # NEVER rendered: the token digest is a credential hash, and the raw
  # header blobs are noise next to the parsed columns above.
  attribute :token_digest, show: false, form: false
  attribute :auth_detail, show: false, form: false
  attribute :client_hints, show: false, form: false

  # Gem scopes: active = last activity within 30 days.
  scope :active
  scope :inactive

  menu label: "Sessions", parent: "Security"

  def self.display_name(record)
    "#{record.device_name} — #{record.user.try(:email) || record.user_id}"
  end

  def self.default_sort_column = "created_at"
  def self.default_sort_direction = "desc"

  # Remote logout: destroys the row (the device is signed out on its next
  # request), writes the `revoked` trail event attributed to the admin, and
  # rotates the user's remember-me credentials in Devise mode.
  member_action do
    button_to "Revoke session",
      main_app.revoke_madmin_session_path(@record),
      method: :post,
      class: "rounded-md bg-white px-3 py-2 text-sm font-semibold text-red-700 shadow-sm ring-1 ring-inset ring-red-300 hover:bg-red-50",
      data: { turbo_confirm: "Revoke this session? The device will be signed out on its next request." }
  end
end
