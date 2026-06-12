# frozen_string_literal: true

require "ipaddr"

module Sessions
  # IP capture, normalization and (optional) anonymization.
  #
  # Capture goes through `config.ip_resolver` (default `request.remote_ip`,
  # which honors Rails' trusted_proxies — see the README's "Behind
  # Cloudflare" section for CDN setups). Every address is IPAddr-normalized
  # before persistence (canonical form, garbage rejected) and, when
  # `config.ip_mode = :truncated`, anonymized BEFORE it ever touches disk:
  # the last IPv4 octet / the last 80 IPv6 bits are zeroed — the Google
  # Analytics precedent, and the reason the column can be shown to a GDPR
  # auditor with a straight face.
  module IpAddress
    # 45 chars covers the maximum IPv6 textual form including IPv4-mapped
    # addresses ("::ffff:255.255.255.255") — the portable column size used
    # across sqlite/mysql/postgres.
    MAX_LENGTH = 45

    # Anonymization prefix lengths (bits kept): IPv4 /24 zeroes the last
    # octet; IPv6 /48 zeroes the last 80 bits.
    IPV4_PREFIX = 24
    IPV6_PREFIX = 48

    module_function

    # The client IP for this request, resolved + normalized + anonymized per
    # configuration. Returns nil for unresolvable/garbage input — a nil IP
    # must never block a login write.
    def resolve(request)
      return nil unless request

      raw = Sessions.config.ip_resolver.call(request)
      normalize(raw)
    rescue StandardError => e
      Sessions.warn("ip resolution failed: #{e.class}: #{e.message}")
      nil
    end

    def normalize(raw)
      return nil if raw.to_s.strip.empty?

      address = IPAddr.new(raw.to_s.strip[0, MAX_LENGTH])
      address = truncate(address) if Sessions.config.ip_mode == :truncated
      address.to_s
    rescue ArgumentError # IPAddr::Error included — it subclasses ArgumentError
      nil
    end

    def truncate(address)
      address.mask(address.ipv4? ? IPV4_PREFIX : IPV6_PREFIX)
    end
  end
end
