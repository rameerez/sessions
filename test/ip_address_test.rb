# frozen_string_literal: true

require "test_helper"

class IpAddressTest < ActiveSupport::TestCase
  test "resolves through the configured resolver and normalizes" do
    request = fake_request(ip: "203.0.113.7")
    assert_equal "203.0.113.7", Sessions::IpAddress.resolve(request)
  end

  test "a custom ip_resolver wins (the CF-Connecting-IP escape hatch)" do
    Sessions.config.ip_resolver = ->(request) { request.get_header("HTTP_CF_CONNECTING_IP") }
    request = fake_request(ip: "10.0.0.1", env: { "HTTP_CF_CONNECTING_IP" => "198.51.100.4" })

    assert_equal "198.51.100.4", Sessions::IpAddress.resolve(request)
  end

  test "garbage input never raises, never persists" do
    assert_nil Sessions::IpAddress.normalize("not-an-ip")
    assert_nil Sessions::IpAddress.normalize("")
    assert_nil Sessions::IpAddress.normalize(nil)
    assert_nil Sessions::IpAddress.normalize("999.999.999.999")
    assert_nil Sessions::IpAddress.normalize("<script>alert(1)</script>")
  end

  test "a raising resolver degrades to nil — never breaks a login" do
    Sessions.config.ip_resolver = ->(_request) { raise "boom" }
    assert_nil Sessions::IpAddress.resolve(fake_request)
  end

  test "ipv6 addresses are canonicalized" do
    assert_equal "2001:db8::1", Sessions::IpAddress.normalize("2001:0DB8:0000:0000:0000:0000:0000:0001")
  end

  test "truncated mode zeroes the last IPv4 octet before persistence" do
    Sessions.config.ip_mode = :truncated
    assert_equal "203.0.113.0", Sessions::IpAddress.normalize("203.0.113.77")
  end

  test "truncated mode zeroes the last 80 IPv6 bits" do
    Sessions.config.ip_mode = :truncated
    assert_equal "2001:db8:abcd::", Sessions::IpAddress.normalize("2001:db8:abcd:1234:5678:9abc:def0:1234")
  end

  test "full mode stores the address as-is" do
    assert_equal "203.0.113.77", Sessions::IpAddress.normalize("203.0.113.77")
  end

  test "absurdly long input is bounded before parsing" do
    assert_nil Sessions::IpAddress.normalize("1" * 10_000)
  end
end
