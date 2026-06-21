# Device intelligence: UA parsing, Hotwire Native, client hints, IP capture

Researched 2026-06-11. Code citations are from read-only clones under `/tmp/sessions-research/` (browser, device_detector, hotwire-native-ios, hotwire-native-android, turbo-rails, rails-stable @ v8.1.3) and the local apps under `/path/to/repos/`. Web citations carry URL + fetch date.

## Top findings

- **Both Ruby UA parsers are zero-dependency, but neither is fully alive.** `browser` (MIT): last release 6.2.0 on 2024-12-04, last commit 2025-06-10. `device_detector` (LGPL-3.0): last commit/release 1.1.3 on **2024-07-03** — its vendored Matomo data is frozen at June 2024 (zero `iPhone17,x` identifiers, barely knows Pixel 9). Staleness matters less than it sounds because reduced web UAs carry no device models anyway — but it kills device_detector's main selling point.
- **device_detector's cache is not an LRU.** It's a Mutex-guarded bounded Hash (default 5,000 keys) that evicts the first-inserted third when full (`lib/device_detector/memory_cache.rb:5-60`).
- **Every prior-art gem stores the raw UA and parses nothing** (authie even truncates to 255 chars — a footgun: Hotwire Native UAs with bridge-components easily exceed 255). Store raw `text`, parse into derived columns, keep re-parseability.
- **Hotwire Native UA construction is fully deterministic and documented in source**: iOS appends `"[prefix] Hotwire Native iOS; Turbo Native iOS; bridge-components: [...]"` via `applicationNameForUserAgent`; Android *prepends* `"[prefix] Hotwire Native Android; Turbo Native Android; bridge-components: [...];"` to the WebView's default Chromium UA. Neither embeds app version, SDK version, or (on iOS) device model.
- **Android WebView is explicitly excluded from Chrome's UA reduction** ("We don't have current plans for User-Agent Reduction on iOS and Android WebView" — chromium.org/updates/ua-reduction, fetched 2026-06-10). So Hotwire Native **Android** UAs still carry real device model + real Android version. Hotwire Native **iOS** UAs carry real iOS version but never the hardware model.
- **Web Chrome UAs are husks since 2023**: frozen `Windows NT 10.0`, `Intel Mac OS X 10_15_7`, `Linux; Android 10; K`, minor versions `0.0.0`. Real data moved to UA Client Hints — which **only Chromium ships; Safari and Firefox still refuse as of June 2026**.
- **iPadOS masquerades as macOS by default** since iPadOS 13 — server-side, an iPad on Safari is byte-identical to a Mac. No fix without JS.
- **Our four local apps customize the UA prefix today but none embeds app version or (iOS) device model** — the gem should ship a recommended prefix convention; HostApp's native HTTP client already proves the pattern (`"HostApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)"`).
- **`request.remote_ip` behind Cloudflare returns a Cloudflare edge IP** unless CF ranges are added to `trusted_proxies` (which *replaces* the private-range defaults) — document `cloudflare-rails` or an `ip_resolver` hook. Portable IP column: `string limit: 45`; `inet` is Postgres-only.

## A. Ruby UA parsers: `browser` vs `device_detector`

### Side-by-side

| | `browser` (fnando) | `device_detector` (podigee) |
|---|---|---|
| Approach | Hand-rolled matcher classes, ordered list (`lib/browser/browser.rb:70-104`); first match wins (`:107-113`) | Ruby port of Matomo's device-detector; regex DB in YAML |
| Data size | ~15 KB YAML (bots.yml 327 lines, samsung.yml, languages.yml) | **1.5 MB** `regexes/` — mobiles.yml 1.1 MB, bots.yml 108 KB, client/browsers.yml 70 KB, mobile_apps.yml 60 KB |
| Browser name/version | `name`, `full_version`, `version` (major) | `name`, `full_version` |
| OS name/version | `platform.name`, `platform.version`, `ios?/android?/mac?/windows?` predicates | `os_name`, `os_full_version`, `os_family` |
| Device type | Predicates only: `device.mobile?/tablet?/console?` | `device_type` → smartphone/tablet/desktop/tv/wearable/console/feature phone/… (`lib/device_detector.rb:94-189`) |
| Device model | Named devices only (iPhone/iPad/PS/Xbox/Switch/Kindle/Surface) + Samsung via samsung.yml; **no generic Android model** | `device_name` + `device_brand` from mobiles.yml (full Matomo model DB) |
| Bot detection | `bot?`, `bot.name`, `bot.why?`, `search_engine?` — 327-line list | `bot?`, `bot_name` — 108 KB list incl. AI crawlers (as of 2024-06) |
| Client Hints | None | Yes: `DeviceDetector.new(ua, headers)` reads `Sec-CH-UA*` (`lib/device_detector/client_hint.rb:176-230`) |
| Caching | None global; per-instance memoization; UA length capped at 2048 (`lib/browser/browser.rb:62-66`) | Global `MemoryCache`: bounded Hash, 5,000 keys default, Mutex, evicts oldest ⅓ — **not LRU** (`memory_cache.rb:5-60`); configurable `max_cache_keys` |
| Runtime deps | **Zero** | **Zero** |
| License | **MIT** | **LGPL-3.0** (fine as a dependency, but some corp policies flag it) |
| Ruby | ≥ 3.2 | ≥ 2.7.5 |
| Last release | v6.2.0, 2024-12-04 (git tag) | v1.1.3, 2024-07-03 (git tag) |
| Last commit | 2025-06-10 (`git log`, clone) | **2024-07-03** (`git log`, `develop` = HEAD) |
| Rails sugar | `Browser::ActionController` helper, middleware, meta tags | None |

### Notable internals

- `browser` detection is code, not data: e.g. Safari requires the literal `"Safari"` token and ~16 negative checks (`lib/browser/safari.rb:21-38`); iOS version comes from `OS (\d+)_(\d+)` (`lib/browser/platform/ios.rb:7-8`) and `platform.name` returns `"iOS (iPhone)"` (`ios.rb:26-28`). Webview heuristics ship built-in: `ios_app?` = iOS && no `"Safari"` token, `android_app?` = `/\bwv\b/` (`lib/browser/platform.rb:127-141`).
- `device_detector` is Client-Hints-native to a surprising degree: it **reconstructs reduced UAs**, substituting the frozen `"Android 10; K"` with the hinted model + `Sec-CH-UA-Platform-Version` before parsing (`lib/device_detector.rb:30-39`), reads `Sec-CH-UA`/`Sec-CH-UA-Full-Version-List` for browser identity (`client_hint.rb:176-210`) and `x-requested-with` for Android app names (`client_hint.rb:140-146`). Caveat: it expects literal header keys (`'Sec-CH-UA'`), not Rack-env `HTTP_SEC_CH_UA` — the caller must normalize.
- Data staleness check (clone, 2026-06-11): `grep -c "iPhone17\|iPhone16" regexes/device/mobiles.yml` → **0**; `grep -c "Pixel 9"` → 2. Two years of hardware missing. (Matomo upstream is alive; the Ruby port simply hasn't synced since 2024-07.)
- On a Hotwire Native iOS UA (no `Safari` token): `browser` yields Unknown browser + `platform.ios?` true + `ios_app?` true — platform usable, name useless. device_detector does no better; **neither understands `bridge-components:` or app prefixes**. Native parsing must be ours.

### What other auth/session gems do (clones at /tmp/sessions-research/)

- **authie**: raw UA, truncated — `self.user_agent = user_agent[0, 255]` (`lib/authie/session_model.rb:119`).
- **authtrail**: raw `request.user_agent` (`lib/authtrail.rb:41`); geolocation via optional `geocoder` gem in a background job (README.md:112-131).
- **authentication-zero**: generates `t.string :user_agent` columns + `Current.user_agent = request.user_agent`; renders the raw string in views.
- **devise / warden / rodauth**: store nothing UA-related.
- Conclusion: nobody in the ecosystem turns a UA into "Chrome 137 on macOS" — that's the gap, and it validates **storing the raw UA always** (everyone does) while differentiating on parsed presentation.

### Recommendation

1. **Always persist the raw UA in a `text` column** (no 255 limit) plus the relevant raw Client-Hint headers when present. Parsing is a *projection* that can be re-run as parsers/conventions improve. Validated by uniform prior art.
2. **Hard dependency on `browser`** as the default web parser: MIT, zero-dep, tiny, Rails-aware, good enough for "Chrome 137 on macOS" + bot flagging. A drop-in gem needs device intel working with zero setup; an adapter-only design would gut the first-run experience.
3. **Optional `device_detector` adapter** (auto-upgrade if the host app bundles it): better device names on legacy/Android UAs, native Client-Hints handling, much bigger bot DB. Don't hard-depend: LGPL, 1.5 MB data, 2-years-stale releases.
4. **Built-in native-app UA parser that runs first** (before any web parser): recognizes `Hotwire Native iOS|Android`, `Turbo Native`, the recommended prefix convention below, and HostApp's existing shapes. This is the gem's actual moat; no third-party parser does it.
5. Expose `config.ua_parser = :browser | :device_detector | ->(ua, headers) { DeviceInfo.new(...) }` for escape hatches, and stamp rows with parser identity/version if cheap (optional).

## B. Hotwire Native user agents

### iOS construction (hotwire-native-ios, HEAD 2025-11-06, latest tag 1.3.0-beta)

`Source/Bridge/UserAgent.swift:3-15` — the literal composition:

```swift
enum UserAgent {
    static func build(applicationPrefix: String?, componentTypes: [BridgeComponent.Type]) -> String {
        let components = componentTypes.map { $0.name }.joined(separator: " ")
        let componentsSubstring = "bridge-components: [\(components)]"
        return [applicationPrefix, "Hotwire Native iOS;", "Turbo Native iOS;", componentsSubstring]
            .compactMap { $0 }.joined(separator: " ")
    }
}
```

Applied as the WebKit *application name*, not the whole UA: `configuration.applicationNameForUserAgent = userAgent` (`Source/HotwireConfig.swift:133`; `userAgent` property at `:47-55`; customization point `applicationUserAgentPrefix` at `:17`). WebKit then composes the final UA, replacing the default trailing `Mobile/15E148` segment. Official docs example for an iPhone on iOS 18.2 (https://native.hotwired.dev/ios/configuration, fetched 2026-06-10):

```text
Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) My Application; Hotwire Native iOS; Turbo Native iOS; bridge-components: [form menu]
```

Present by default: device *family* (`iPhone`/`iPad` — WKWebView does **not** masquerade like desktop-mode Safari), **real iOS version** (`18_2`), framework markers, bridge component names. Absent: hardware model (`iPhone15,2`), app name/version (unless prefix set), SDK version. Note: no `Safari` token, no `Version/x` token → generic web parsers see "unknown browser on iOS".

### Android construction (hotwire-native-android, HEAD 2026-05-14, latest tag 1.2.8)

`core/src/main/kotlin/dev/hotwire/core/config/HotwireConfig.kt:83-94`:

```kotlin
val userAgent: String get() {
    val components = registeredBridgeComponentFactories.joinToString(" ") { it.name }
    return listOf(
        applicationUserAgentPrefix,
        "Hotwire Native Android; Turbo Native Android;",
        "bridge-components: [$components];"
    ).filterNotNull().joinToString(" ")
}
```

…and `userAgentWithWebViewDefault` (`HotwireConfig.kt:100-102`) = `"$userAgent ${Hotwire.webViewInfo(context).defaultUserAgent}"`, i.e. the Hotwire segment comes **before** the stock Chromium UA (`WebSettings.getDefaultUserAgent`, `WebViewInfo.kt:42`), set on every WebView at `HotwireWebView.kt:42`. Customization: `applicationUserAgentPrefix` (`HotwireConfig.kt:74`). Docs: https://native.hotwired.dev/android/configuration (fetched 2026-06-10). Resulting shape:

```text
MyApp; Hotwire Native Android; Turbo Native Android; bridge-components: [form menu]; Mozilla/5.0 (Linux; Android 16; Pixel 8 Build/BP2A…; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.0.0 Mobile Safari/537.36
```

Present by default: **real Android version, real device model, Build id** (WebView is exempt from UA reduction — see §C), Chrome major version, `wv` webview token, framework markers. Absent: app name/version, SDK version.

### turbo-rails detection helper (turbo-rails, HEAD 2026-01-29, v2.0.23)

`app/controllers/turbo/native/navigation.rb:13-19`:

```ruby
# Hotwire Native applications are identified by having the string "Hotwire Native" as part of their user agent.
def hotwire_native_app?
  request.user_agent.to_s.match?(/(Turbo|Hotwire) Native/)
end
alias_method :turbo_native_app?, :hotwire_native_app?
```

Substring contract: `"Turbo Native"` or `"Hotwire Native"` anywhere in the UA. The SDKs append these automatically after any prefix, so prefixes can't break it. The sessions gem should match the same regex for platform classification, then refine `iOS` vs `Android` from the following token.

### What our local apps send today (greps 2026-06-11)

| App | Prefix set | Where | Effective UA shape |
|---|---|---|---|
| hostapp-ios | `"HostApp iOS; RailsFast Native iOS;"` (`{App}` from `CFBundleDisplayName`) | `RailsFast/Core/AppConfiguration.swift:10-12`, applied `RailsFast/App/AppDelegate.swift:103` | `Mozilla/5.0 (iPhone; CPU iPhone OS x_y like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) HostApp iOS; RailsFast Native iOS; Hotwire Native iOS; Turbo Native iOS; bridge-components: […]` |
| railsfast-ios | `"RailsFast iOS; RailsFast Native iOS;"` | `RailsFast/Core/AppConfiguration.swift:10-12`, `RailsFast/App/AppDelegate.swift:93-99` | same shape, `RailsFast` tokens |
| hostapp-android | `"HostApp Android;"` | `app/src/main/java/com/hostapp/android/HostAppApplication.kt:169` | `HostApp Android; Hotwire Native Android; Turbo Native Android; bridge-components: […]; Mozilla/5.0 (Linux; Android NN; <Model> Build/…; wv) … Chrome/NNN.0.0.0 Mobile Safari/537.36` |
| railsfast-android | `"${BuildConfig.APPLICATION_NAME} Android; RailsFast Native Android;"` | `app/src/main/java/com/railsfast/android/RailsFastApplication.kt:45-46` | same shape with two leading brand segments |

So today: **no webview UA carries the app version anywhere, and iOS UAs carry no device model.** Android model/OS arrive free via the WebView default UA.

However, HostApp's *native* (URLSession/OkHttp) calls already use a richer convention the gem should accept as prior art:

- iOS: `"\(applicationName) iOS \(version) (build \(build); iOS \(osVersion); \(resolvedModel))"` → e.g. `HostApp iOS 1.0.5 (build 6; iOS 19.5; iPhone15,2)` (`hostapp-ios/RailsFast/Core/NativeHttpClient.swift:61-71`), plus headers `X-Client-Platform/-Version/-Build/-OS` (`NativeHttpClient.swift:13-17`).
- Android: `"HostApp Android $versionName (build $versionCode; Android $osRelease; sdk $sdkInt; $device)"` → e.g. `HostApp Android 1.0.5 (build 6; Android 14; sdk 34; Pixel 7)` (`hostapp-android/app/src/main/java/com/hostapp/android/ClientHeaders.kt:66-76`; header names `:25-29`).

### Recommended UA convention for the gem's README

Use an RFC 9110-style product token as the `applicationUserAgentPrefix`, ending with `;` so it reads cleanly before the SDK-appended segments:

```text
<AppName>/<version> (<model>; <os> <os_version>; build <build>);
e.g.  HostApp/2.4.1 (iPhone15,2; iOS 19.5; build 241);
e.g.  HostApp/2.4.1 (Pixel 8; Android 16; build 241);
```

Parse rule (gem-side, tolerant): `%r{(?<app>[\w .-]+)/(?<version>\d[\w.]*) \((?<fields>[^)]*)\)}` with semicolon-split, order-insensitive fields; also accept HostApp's space-separated legacy `"HostApp iOS 1.0.5 (build 6; …)"`. Everything else (Hotwire markers, WebView UA) stays intact, so `hotwire_native_app?` and bridge components keep working.

README client snippets:

**iOS (AppDelegate, before creating the Navigator):**

```swift
var u = utsname(); uname(&u)
let model = withUnsafeBytes(of: &u.machine) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
Hotwire.config.applicationUserAgentPrefix = "HostApp/\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0") (\(model); iOS \(UIDevice.current.systemVersion));"
```

(`model` is `"iPhone15,2"` on device, `"arm64"` on Simulator — fine for production traffic.)

**Android (Application.onCreate, before any HotwireActivity):**

```kotlin
Hotwire.config.applicationUserAgentPrefix =
    "HostApp/${BuildConfig.VERSION_NAME} " +
    "(${Build.MODEL}; Android ${Build.VERSION.RELEASE}; build ${BuildConfig.VERSION_CODE});"
```

Even without these snippets the gem still detects platform + (Android) model + (iOS) OS version from the defaults; the snippets add app version everywhere and hardware model on iOS.

## C. Web platform realities, June 2026

### Chrome UA reduction — long finished, fully frozen

Complete since Chrome 110-113 (2023). Final templates (https://www.chromium.org/updates/ua-reduction/, fetched 2026-06-10):

- Desktop: `Mozilla/5.0 (<unifiedPlatform>) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<major>.0.0.0 Safari/537.36`
- Mobile/tablet: `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<major>.0.0.0 [Mobile ]Safari/537.36`

Frozen literals: `Windows NT 10.0; Win64; x64` (Win10 vs Win11 indistinguishable), `Macintosh; Intel Mac OS X 10_15_7` (even Apple Silicon), `Android 10`, model `K`, minor version `0.0.0`. Variable: Chrome major + `Mobile` token. **WebView exempt**: "We don't have current plans for User-Agent Reduction on iOS and Android WebView at this time" (same page) — the load-bearing fact for Hotwire Native Android.

Safari freezes macOS at `10_15_7` too but reports **real iOS versions** on iPhone (`iPhone; CPU iPhone OS 26_0 like Mac OS X` style; see https://nielsleenheer.com/articles/2025/the-user-agent-string-of-safari-on-ios-26-and-macos-26/, 2025, found 2026-06-11). Firefox likewise caps macOS at `10.15` but otherwise sends real versions. Practical: from a 2026 web UA you can trust browser name + major version, OS *family*, mobile-vs-not — and almost nothing else.

### UA Client Hints — the only way back to detail, Chromium-only

Mechanics (https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Client_hints, fetched 2026-06-11):

- **Low-entropy, sent by default on every secure request**: `Sec-CH-UA` (brand list + major), `Sec-CH-UA-Mobile` (`?1`/`?0`), `Sec-CH-UA-Platform` (`"Windows"`, `"macOS"`, `"Android"`, …), plus `Save-Data`.
- **High-entropy, server opt-in**: respond with `Accept-CH: Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List` (also available: `-Arch`, `-Bitness`, `-Form-Factors`). The browser attaches them to **subsequent** requests only (second-request problem); `Critical-CH` triggers a transparent retry; add `Vary` on hint headers for cacheable responses.
- Yields: real macOS/Windows platform versions (`Sec-CH-UA-Platform-Version` ≥ `13.0.0` on Windows = Win11), Android **device model** (`Sec-CH-UA-Model`, empty on desktop), exact browser build (`Sec-CH-UA-Full-Version-List`).
- **Support matrix (June 2026): Chromium only** — Chrome/Edge/Opera/Brave/etc. **Safari: no. Firefox: no** (Mozilla position negative; https://caniuse.com/wf-ua-client-hints and https://github.com/mozilla/standards-positions/issues/552, checked 2026-06-10; corroborated by https://www.corbado.com/blog/client-hints-user-agent-chrome-safari-firefox).
- Lucky break for a *sessions* gem: login POSTs are never the first request of a browsing session, so if the app has been emitting `Accept-CH`, high-entropy hints are reliably present exactly when sessions get created.

### iPadOS masquerades as macOS

Since iPadOS 13, Safari defaults to "Request Desktop Website" and sends the literal macOS UA `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 …` — no `iPad` token, no client hints, **no server-side tell** (https://developer.apple.com/forums/thread/119186 and nielsleenheer.com article above, checked 2026-06-11). Only JS (`navigator.maxTouchPoints > 1` on "MacIntel") can distinguish. PRD expectation: iPads will display as "Safari on macOS"; offer an optional JS beacon later if it matters.

### Honest "device name" precision per platform (what the PRD should promise)

| Source | Can say | Cannot say |
|---|---|---|
| Chrome/Edge desktop | "Chrome 137 on Windows / macOS / Linux"; +Win11/real macOS version *with Accept-CH* | OS version from UA alone (frozen tokens — never render "macOS 10.15" or "Windows 10" as fact) |
| Chrome Android | "Chrome 137 on Android (phone/tablet)"; +model ("Pixel 8") and real Android version *with Accept-CH* | model/version from UA alone (`Android 10; K` is a lie) |
| Safari iPhone | "Safari on iOS 19.5, iPhone" (real OS version) | hardware model (never present) |
| Safari iPad/Mac | "Safari on macOS" | iPad vs Mac; any real macOS version |
| Firefox | "Firefox 1xx on <OS family>" | real macOS version; any hints |
| Hotwire Native iOS | app name + platform + real iOS version (+ model, app version *with our prefix convention*) | model without the convention |
| Hotwire Native Android | app name + real Android version + real model + Chrome version (+ app version *with convention*) | — |

## D. IP capture correctness

### `ActionDispatch::RemoteIp` semantics (rails-stable v8.1.3)

- Algorithm (`actionpack/lib/action_dispatch/middleware/remote_ip.rb:129-169`): collect `Client-Ip` + `X-Forwarded-For` (reversed, i.e. nearest-first), validate each entry (`sanitize_ips` rejects netmasks/garbage, `:185-196`), spoof-check (`IpSpoofAttackError` if `Client-Ip` and XFF disagree, `:150-153`), then `filter_proxies(ips + [remote_addr]).first || ips.last || remote_addr` (`:169`) — i.e. **the closest-to-client address that is not a trusted proxy**.
- Default `TRUSTED_PROXIES` (`remote_ip.rb:40-49`): loopback, RFC 1918 ranges, link-local, `fc00::/7`.
- `config.action_dispatch.trusted_proxies` **replaces** the default list ("will be used *instead of* `TRUSTED_PROXIES`", `:61-62`; `@proxies = custom_proxies || TRUSTED_PROXIES`, `:70-74`) — when adding CDN ranges you must re-include the private ranges if an LB/private hop also sets XFF. Single values raise `ArgumentError` (`:75-80`).
- Use `request.remote_ip` (this middleware), never `request.ip` (Rack's looser logic) and never raw `X-Forwarded-For`.

### Cloudflare (RailsFast deploys behind it)

- Cloudflare *appends* to inbound `X-Forwarded-For` and recommends origins read **`CF-Connecting-IP`** ("CF-Connecting-IP provides the client IP address connecting to Cloudflare to the origin web server"; "Cloudflare recommends that your logs or applications look at CF-Connecting-IP or True-Client-IP instead of X-Forwarded-For" — https://developers.cloudflare.com/fundamentals/reference/http-headers/, fetched 2026-06-11). `True-Client-IP` is Enterprise-only and identical in content.
- Problem: Cloudflare edge IPs are **public**, so with default trusted proxies `remote_ip` returns the CF edge address, not the visitor. Fixes, best-first:
  1. `cloudflare-rails` gem — fetches CF's published IP ranges on boot and folds them into the trusted-proxy logic so `request.remote_ip` just works.
  2. Manual: `config.action_dispatch.trusted_proxies = ActionDispatch::RemoteIp::TRUSTED_PROXIES + CF_IPV4_RANGES + CF_IPV6_RANGES` (remember: replacement semantics).
  3. Read `CF-Connecting-IP` directly **only** if the origin is unreachable except via Cloudflare (otherwise trivially spoofable by direct-to-origin requests).
- Gem stance: default to `request.remote_ip`; expose `config.ip_resolver = ->(request) { ... }` for CF-Connecting-IP setups; ship a "Behind Cloudflare" README section with the three options above. Never parse XFF ourselves.

### Storage column across sqlite/mysql/pg

- `inet` is Postgres-only: registered at `activerecord/lib/active_record/connection_adapters/postgresql_adapter.rb:158` and `:1200` (`OID::Inet`, returns `IPAddr` objects); no `inet` mapping exists in the mysql or sqlite3 adapters.
- Portable choice for a gem: **`t.string :ip_address, limit: 45`** — 45 chars covers max IPv6 textual form including IPv4-mapped (`::ffff:255.255.255.255`). Normalize with `IPAddr.new(raw).to_s` before save (downcases, canonicalizes, rejects garbage). Optionally use `:inet` when `adapter_name == "PostgreSQL"` in the install generator for index/CIDR-query friendliness; keep model code `IPAddr`-agnostic since PG returns `IPAddr` and others return `String`.
- Privacy note for the README: IPs are personal data (GDPR); consider an opt-in anonymization mode (zero the last octet / last 80 bits) and document retention.

## Implications for the sessions gem

**Parser strategy.** Three-layer pipeline, raw-first:
1. Persist raw `user_agent` (text) and, when present, the interesting headers (`Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Platform-Version`, `Sec-CH-UA-Model`, `Sec-CH-UA-Full-Version-List`, `X-Client-*`) into a `client_hints` json/jsonb column. Re-parse is always possible; ship `sessions:reparse` task.
2. Built-in **native matcher first**: `/(Turbo|Hotwire) Native (iOS|Android)/` (same contract as turbo-rails `navigation.rb:15-17`) → platform; then the prefix convention regex → app name/version/build/model/OS version; on Android fall back to the embedded WebView UA for model/OS.
3. Web UAs → **`browser` gem as hard dependency** (MIT, zero-dep, ~15 KB data) for name/version/platform/bot; **`device_detector` as auto-detected optional adapter** (better device names, CH-aware, 108 KB bot list — but LGPL, 1.5 MB, data frozen 2024-07); `config.ua_parser` accepts a lambda for BYO.

**Schema (device fields on `sessions` / `login_activities`):** `user_agent :text`, `client_hints :json`, `browser_name :string`, `browser_version :string`, `os_name :string`, `os_version :string`, `device_type :string` (desktop/smartphone/tablet/native_ios/native_android/bot/unknown), `device_model :string`, `app_name :string`, `app_version :string`, `ip_address :string, limit: 45` (`:inet` on PG). Display name composes defensively: never render frozen tokens ("macOS 10.15", "Android 10", model "K") as facts.

**Client hints.** Optional `config.request_client_hints = true` → set `Accept-CH: Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List` (HTTPS responses only; document `Vary` if responses cache). Works only on Chromium — Safari/Firefox sessions stay UA-only; the login request is rarely a first navigation, so hints are usually present when sessions are created.

**Native convention.** Ship the iOS/Android snippets from §B in the README; parse both the convention and Hotwire defaults so unconfigured apps still get platform + OS (+ Android model) for free.

**IP.** Default `request.remote_ip`; `config.ip_resolver` hook; "Behind Cloudflare" docs (cloudflare-rails / trusted_proxies-with-defaults / CF-Connecting-IP-if-locked); normalize via `IPAddr`; optional anonymization.
