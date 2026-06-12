# frozen_string_literal: true

require "test_helper"

class DeviceTest < ActiveSupport::TestCase
  # --- Web user agents (the browser-gem layer + the honesty filter) ----------

  test "Chrome on macOS: name + major version, OS family, NO frozen version" do
    device = Sessions::Device.parse(UserAgents::CHROME_MAC)

    assert_equal "Chrome", device.browser_name
    assert_equal "137", device.browser_version
    assert_equal "macOS", device.os_name
    assert_nil device.os_version # 10_15_7 is a frozen lie — never rendered as fact
    assert_equal "desktop", device.device_type
    refute device.native?
  end

  test "Safari on iPhone: real iOS version is kept" do
    device = Sessions::Device.parse(UserAgents::SAFARI_IPHONE)

    assert_equal "Safari", device.browser_name
    assert_equal "iOS", device.os_name
    assert_equal "19.5", device.os_version # iOS versions are real in 2026 UAs
    assert_equal "smartphone", device.device_type
  end

  test "Firefox on Windows: frozen NT 10.0 is not presented as a version" do
    device = Sessions::Device.parse(UserAgents::FIREFOX_WINDOWS)

    assert_equal "Firefox", device.browser_name
    assert_equal "139", device.browser_version
    assert_equal "Windows", device.os_name
    assert_nil device.os_version
  end

  test "bots are flagged, never rendered as devices" do
    device = Sessions::Device.parse(UserAgents::GOOGLEBOT)

    assert_equal "bot", device.device_type
    assert device.bot?
  end

  # --- Client hints (the only way back to real versions on the web) ----------

  test "Sec-CH-UA-Platform-Version recovers the real macOS version" do
    device = Sessions::Device.parse(UserAgents::CHROME_MAC,
                                    headers: { "Sec-CH-UA-Platform-Version" => '"15.5.0"' })

    assert_equal "15.5.0", device.os_version
  end

  test "Windows platform-version 13+ decodes to Windows 11" do
    device = Sessions::Device.parse(UserAgents::FIREFOX_WINDOWS,
                                    headers: { "Sec-CH-UA-Platform-Version" => '"15.0.0"' })
    assert_equal "11", device.os_version

    device = Sessions::Device.parse(UserAgents::FIREFOX_WINDOWS,
                                    headers: { "Sec-CH-UA-Platform-Version" => '"10.0.0"' })
    assert_equal "10", device.os_version
  end

  test "Sec-CH-UA-Model recovers the real Android device model" do
    android_web = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) " \
                  "Chrome/137.0.0.0 Mobile Safari/537.36"
    device = Sessions::Device.parse(android_web, headers: { "Sec-CH-UA-Model" => '"Pixel 8"' })

    assert_equal "Pixel 8", device.device_model
    assert_equal "smartphone", device.device_type
  end

  test "the frozen Android 10 / model K husk is never trusted without hints" do
    android_web = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) " \
                  "Chrome/137.0.0.0 Mobile Safari/537.36"
    device = Sessions::Device.parse(android_web)

    assert_equal "Android", device.os_name
    assert_nil device.os_version
    assert_nil device.device_model
  end

  # --- Hotwire Native (the moat) ----------------------------------------------

  test "native iOS with the README prefix convention" do
    device = Sessions::Device.parse(UserAgents::NATIVE_IOS)

    assert_equal "native_ios", device.device_type
    assert device.native?
    assert_equal "MyApp", device.app_name
    assert_equal "2.4.1", device.app_version
    assert_equal "241", device.app_build
    assert_equal "iPhone15,2", device.device_model
    assert_equal "iOS", device.os_name
    assert_equal "19.5", device.os_version
  end

  test "native Android with the README prefix convention" do
    device = Sessions::Device.parse(UserAgents::NATIVE_ANDROID)

    assert_equal "native_android", device.device_type
    assert_equal "MyApp", device.app_name
    assert_equal "2.4.1", device.app_version
    assert_equal "241", device.app_build
    assert_equal "Pixel 8", device.device_model
    assert_equal "Android", device.os_name
    assert_equal "16", device.os_version
  end

  test "bare Hotwire Native Android still yields model + OS from the WebView UA" do
    device = Sessions::Device.parse(UserAgents::NATIVE_ANDROID_BARE)

    assert_equal "native_android", device.device_type
    assert_nil device.app_name
    assert_equal "Pixel 7", device.device_model
    assert_equal "14", device.os_version
  end

  test "bare Hotwire Native iOS yields the real OS version and the device family" do
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_5 like Mac OS X) AppleWebKit/605.1.15 " \
         "(KHTML, like Gecko) Hotwire Native iOS; Turbo Native iOS; bridge-components: [form]"
    device = Sessions::Device.parse(ua)

    assert_equal "native_ios", device.device_type
    assert_equal "iOS", device.os_name
    assert_equal "19.5", device.os_version
    assert_equal "iPhone", device.device_model # family is real; exact model isn't in iOS UAs
  end

  test "MyApp's legacy native-HTTP-client shape parses when the app is declared" do
    Sessions.config.native_app_names = ["MyApp"]
    ua = "MyApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)"
    device = Sessions::Device.parse(ua)

    assert_equal "native_android", device.device_type
    assert_equal "MyApp", device.app_name
    assert_equal "1.0.5", device.app_version
    assert_equal "6", device.app_build
    assert_equal "Pixel 7", device.device_model
    assert_equal "Android", device.os_name
    assert_equal "14", device.os_version
  end

  test "the legacy shape is NOT native without the marker, headers, or declaration" do
    ua = "MyApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)"
    device = Sessions::Device.parse(ua)

    refute device.native?
  end

  test "validated X-Client-* headers win over UA-derived values" do
    headers = {
      "X-Client-Platform" => "ios",
      "X-Client-Version" => "3.0.0",
      "X-Client-Build" => "300",
      "X-Client-OS" => "iOS 19.6"
    }
    device = Sessions::Device.parse(UserAgents::NATIVE_IOS, headers: headers)

    assert_equal "native_ios", device.device_type
    assert_equal "3.0.0", device.app_version
    assert_equal "300", device.app_build
    assert_equal "19.6", device.os_version
  end

  test "X-Client-Platform alone classifies a native request (no UA marker needed)" do
    device = Sessions::Device.parse("SomeCustomClient", headers: { "X-Client-Platform" => "android" })

    assert_equal "native_android", device.device_type
  end

  test "malformed X-Client headers are rejected, not trusted" do
    headers = {
      "X-Client-Platform" => "ios",
      "X-Client-Version" => "not-a-version<script>",
      "X-Client-Build" => "x" * 60,
      "X-Client-OS" => "Windows 95"
    }
    device = Sessions::Device.parse(UserAgents::NATIVE_IOS, headers: headers)

    assert_equal "2.4.1", device.app_version # UA convention value kept
    assert_equal "241", device.app_build
    assert_equal "19.5", device.os_version
  end

  # --- Edge cases (each from a research-memo finding) --------------------------

  test "nil and empty UAs degrade to unknown" do
    [nil, "", "   "].each do |ua|
      device = Sessions::Device.parse(ua)
      assert_equal "unknown", device.device_type
      assert_nil device.browser_name
    end
  end

  test "a 2000-char native UA parses (only the first 1024 chars are read)" do
    ua = UserAgents::NATIVE_ANDROID + ("x" * 2000)
    device = Sessions::Device.parse(ua)

    assert_equal "native_android", device.device_type
    assert_equal "MyApp", device.app_name
  end

  test "a hostile UA never raises" do
    hostile = "\x00\xFF(((((;;;;#{"(" * 500}Hotwire Native iOS"
    device = Sessions::Device.parse(hostile)

    assert_kind_of Sessions::Device, device
  end

  test "to_h only carries column attributes, compacted" do
    device = Sessions::Device.parse(UserAgents::CHROME_MAC)

    assert_equal "Chrome", device.to_h[:browser_name]
    refute device.to_h.key?(:os_version)
  end

  # --- Pluggable parsers ----------------------------------------------------------

  test "a lambda ua_parser takes over web parsing" do
    Sessions.config.ua_parser = lambda do |_ua, _headers|
      { browser_name: "Lynx", device_type: "desktop" }
    end
    device = Sessions::Device.parse(UserAgents::CHROME_MAC)

    assert_equal "Lynx", device.browser_name
    assert_equal "desktop", device.device_type
  end

  test "a lambda returning garbage degrades to unknown device_type" do
    Sessions.config.ua_parser = ->(_ua, _headers) { { device_type: "quantum" } }
    device = Sessions::Device.parse(UserAgents::CHROME_MAC)

    assert_equal "unknown", device.device_type
  end

  test "native parsing always runs first, regardless of the configured web parser" do
    Sessions.config.ua_parser = ->(_ua, _headers) { raise "web parser must not run for native UAs" }
    device = Sessions::Device.parse(UserAgents::NATIVE_IOS)

    assert_equal "native_ios", device.device_type
  end

  test "the device_detector upgrade parses when bundled" do
    Sessions.config.ua_parser = :device_detector
    device = Sessions::Device.parse(UserAgents::CHROME_MAC)

    assert_equal "Chrome", device.browser_name
    assert_equal "macOS", device.os_name
    assert_nil device.os_version # same honesty filter applies
    assert_equal "desktop", device.device_type
  end

  # --- Header extraction -----------------------------------------------------------

  test "headers_from picks the interesting headers under canonical names" do
    request = fake_request(env: {
                             "HTTP_SEC_CH_UA_PLATFORM" => '"macOS"',
                             "HTTP_SEC_CH_UA_MODEL" => '""',
                             "HTTP_X_CLIENT_PLATFORM" => "ios",
                             "HTTP_ACCEPT" => "text/html" # not interesting
                           })
    headers = Sessions::Device.headers_from(request)

    assert_equal '"macOS"', headers["Sec-CH-UA-Platform"]
    assert_equal "ios", headers["X-Client-Platform"]
    refute headers.key?("Accept")
  end

  test "headers_from tolerates nil requests" do
    assert_equal({}, Sessions::Device.headers_from(nil))
  end
end
