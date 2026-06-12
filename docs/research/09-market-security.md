# Market validation & security/privacy requirements

Research memo for the `sessions` gem PRD — drop-in session & login-activity tracking + device management
for Rails 8+ (omakase auth, Devise, OAuth): demand validation via cross-framework and in-the-wild
precedent, the UX bar, competitive scan, and security/privacy/compliance norms as hard requirements.
All sources verified via live web fetch on **2026-06-10/11**; non-verifiable items marked **UNVERIFIED**.

## Top findings

1. **Every comparable framework ships this; Rails doesn't.** Laravel's default app is born with a
   `sessions` table (`user_id`, `ip_address`, `user_agent`, `last_activity`) and Jetstream ships a
   "Browser Sessions" page with "logout other browser sessions"; Phoenix's `mix phx.gen.auth` tracks
   every session token in a DB table and deletes them all on password change; Django's answer is
   `django-user-sessions` (Jazzband) — adopted but aging. Rails 8's own auth generator creates the
   *table* (`CreateSessions user:references ip_address:string user_agent:string`) but ships **zero UI:
   no listing, no per-session revocation, no alerts, no audit trail**. The gap is the product.
2. **Every serious Rails app hand-rolls it**: GitLab (`ActiveSession`, Redis + device_detector),
   Mastodon (`SessionActivation`, Postgres + `browser` gem), Discourse (`UserAuthToken`, rotating
   SHA-1-hashed tokens + `UserAuthTokenLog` audit table). Three independent, expensive reimplementations
   of the same feature = textbook gem opportunity.
3. **"View and revoke your sessions" is a literal compliance requirement**: OWASP ASVS v4.0.3 **3.3.4**
   (L2): "users are able to view and (having re-entered login credentials) log out of any or all
   currently active sessions and devices" — carried into ASVS 5.0 as **7.5.2**. Kill-all-sessions on
   password change is ASVS 3.3.3 / 7.4.3.
4. **The gem name `sessions` is unregistered on RubyGems** (API 404, 2026-06-10) and no living Ruby
   library owns the space: `authtrail` (4.1M downloads) only logs login *events*; `devise-security`
   (20.8M) only *limits* to one session; `session_tracker` died in 2021; `active_sessions`,
   `user_sessions`, `login_activity` and `sessionable` are all unregistered.
5. **IPs are personal data** (CJEU *Breyer* C-582/14; GDPR Recital 30), but security logging has an
   explicit lawful basis (Recital 49 → Art. 6(1)(f)). CNIL recommends **6–12 month** log retention. So
   the gem must ship configurable retention + a purge job, optional IP truncation (Google Analytics
   last-octet precedent), and must **never log raw session IDs** (OWASP: log a salted hash — Discourse
   already does exactly this).
6. **Fingerprinting is a legal trap**: Article 29 WP Opinion 9/2014 (WP224) makes device fingerprinting
   consent-gated under ePrivacy Art. 5(3). UA + IP parsing (the GitLab/Mastodon/Discourse scope) is the
   safe industry standard; "impossible/atypical travel" (Microsoft Entra) is the established next-step
   fraud signal, computable later from the data this gem stores on day one.

---

## Cross-framework precedent

### Laravel (PHP) — the strongest precedent

- **Database session driver is the default**: "By default, Laravel is configured to use the `database`
  session driver." — https://laravel.com/docs/12.x/session (accessed 2026-06-10).
- **The schema ships in the default migration** (`0001_01_01_000000_create_users_table.php`): `id`
  (string PK), `user_id` (`foreignId`, nullable, indexed), `ip_address` (string 45, nullable),
  `user_agent` (text, nullable), `payload` (longText), `last_activity` (integer, indexed) —
  https://github.com/laravel/laravel/blob/12.x/database/migrations/0001_01_01_000000_create_users_table.php
  (accessed 2026-06-10). Implication: **every new Laravel app is born with user-attributed,
  IP/UA-stamped session rows.**
- **Jetstream "Browser Sessions"** (official feature docs): users "may view the browser sessions
  associated with their account" and "logout browser sessions other than the one being used by the
  device they are currently using"; built on `Illuminate\Session\Middleware\AuthenticateSession`;
  requires `SESSION_DRIVER=database` — https://jetstream.laravel.com/features/browser-sessions.html
  (accessed 2026-06-10).
- **Framework-level API** — "Invalidating Sessions on Other Devices": `Auth::logoutOtherDevices($password)`
  plus the `auth.session` middleware alias; "invalidating and 'logging out' a user's sessions that are
  active on other devices without invalidating the session on their current device… typically utilized
  when a user is changing or updating their password" —
  https://laravel.com/docs/12.x/authentication#invalidating-sessions-on-other-devices (accessed 2026-06-10).
- Positioning note: Laravel treats this as a *starter-kit default*, not an enterprise add-on. That is the
  bar Rails is being compared against.

### Django (Python)

- **django-user-sessions** (Jazzband): "Extend Django sessions with a foreign key back to the user,
  allowing enumerating all user's sessions."
  - Features: per-user session queryset, remote logout (`user.session_set.all().delete()`), **IP +
    user-agent stored per session**, Django admin integration, bundled session-list template.
  - Adoption/maintenance: 712 stars, 127 forks; **last release 1.7.1 (Jan 2020)**; Django 3.2/4.2 —
    https://github.com/jazzband/django-user-sessions (accessed 2026-06-10). Read: enough demand for
    Jazzband adoption; its staleness is the maintenance gap a fresh, Rails-8-native gem avoids.
- Django core stores sessions server-side by default but does **not** bind them to users or expose any
  device UI — which is exactly why the package exists.

### Phoenix / Elixir

- `mix phx.gen.auth` generates a `UserToken` schema backed by a `users_tokens` table: "All sessions and
  tokens are tracked in a separate table. This allows you to track how many sessions are active for each
  account. You could even expose this information to users if desired." On password change: "all tokens
  are deleted, and the user has to log in again on all devices." —
  https://hexdocs.pm/phoenix/mix_phx_gen_auth.html (accessed 2026-06-10).
- The *official generator* bakes in revocable, enumerable, server-side sessions — the same architecture
  this gem brings to Rails.

### JS ecosystem (NextAuth/Auth.js)

- No built-in "your devices" UI; session invalidation is a recurring community ask: "How to
  invalidate/delete sessions for CredentialsProvider" —
  https://github.com/nextauthjs/next-auth/discussions/4687 (accessed 2026-06-10). Database-session
  strategy makes listing *possible* but UI, revocation and alerts are DIY. Commercial auth (Clerk,
  Auth0) sells device/session management as a hosted feature (**UNVERIFIED**: tier placement not re-checked).

### Rails — framing the gap

- Rails 8's authentication generator creates exactly the right table and nothing else:
  `generate "migration", "CreateSessions", "user:references ip_address:string user_agent:string"`; routes
  `resource :session, only: [:new, :create, :destroy]` (current-session lifecycle only) —
  https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/authentication/authentication_generator.rb
  (accessed 2026-06-11).
- Devise persists nothing per-session (cookie-only by default); `activerecord-session_store` (the legacy
  extraction) persists sessions without `user_id`/IP/UA or any management UI —
  https://github.com/rails/activerecord-session_store (accessed 2026-06-10; **UNVERIFIED** beyond README).
- **Rails ships the schema; nobody ships the product.** A gem named `sessions` that upgrades the exact
  table Rails 8 already generates is a natural, omakase-aligned extension.

---

## Rails apps that hand-rolled it

### GitLab — `ActiveSession` (Redis)

- **User docs** (https://docs.gitlab.com/user/profile/active_sessions/, accessed 2026-06-10): Profile →
  Access → Active sessions; each row shows "IP: {ip_address}, Browser: {browser}, Last active:
  {updated_at}" with a per-session **Revoke** button; "GitLab allows users to have up to 100 active
  sessions at once. If the number of active sessions exceeds 100, the oldest ones are deleted." The
  current session cannot be revoked; revoking a session also revokes all "Remember me" tokens.
- **Model** (https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/models/active_session.rb, accessed
  2026-06-10): Redis-backed (per-user lookup set + per-session keys); attributes `ip_address, browser,
  os, device_name, device_type, is_impersonated, session_id, session_private_id, admin_mode,
  step_up_authenticated` (+ `created_at`, `updated_at`); `ALLOWED_NUMBER_OF_ACTIVE_SESSIONS = 100`;
  `destroy_session`, `destroy_all_but_current`, `clean_up_old_sessions`.
- **UA parsing**: `class SafeDeviceDetector < ::DeviceDetector` (the `device_detector` gem) with
  `USER_AGENT_MAX_SIZE = 1024` truncation — https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/safe_device_detector.rb (accessed 2026-06-11).

### Mastodon — `SessionActivation` (Postgres)

- **Schema** (model annotation): `id, ip, user_agent, created_at, updated_at, access_token_id,
  session_id, user_id, web_push_subscription_id`.
- Lifecycle: `deactivate(id)` (revoke one), `exclusive(id)` (destroy all but one), `purge_old` capped by
  `Rails.configuration.x.max_session_activations` —
  https://github.com/mastodon/mastodon/blob/main/app/models/session_activation.rb (accessed 2026-06-10).
- **Browser/platform detection via the `browser` gem**: `@detection ||= Browser.new(user_agent)`;
  `browser → detection.id`; `platform → detection.platform.id` —
  https://github.com/mastodon/mastodon/blob/main/app/models/concerns/browser_detection.rb (accessed 2026-06-11).
- UX: sessions list (browser/platform/IP/last-active) with revoke in account security settings
  (**UNVERIFIED**: exact settings path not re-checked against a live instance).

### Discourse — `UserAuthToken` (rotating hashed tokens)

- **Hashed at rest with a server-side secret**:
  `Digest::SHA1.base64digest("#{token}#{GlobalSetting.safe_secret_key_base}")`; the raw token exists only
  in memory (`attr_accessor :unhashed_auth_token`) and is never persisted.
- **Dual-token rotation**: `auth_token` + `prev_auth_token`, rotated every `ROTATE_TIME = 10.minutes`
  (`URGENT_ROTATE_TIME = 1.minute` if unseen) so a stolen-cookie replay desyncs. **Limits & hygiene**:
  `MAX_SESSION_COUNT = 60` with oldest-token eviction; `cleanup!` purges tokens past `maximum_session_age`.
- **Audit companion** `UserAuthTokenLog`: `client_ip`, `user_agent`, `seen_at`, `action`
  (generate/rotate/destroy), `path`. All from
  https://github.com/discourse/discourse/blob/main/app/models/user_auth_token.rb (accessed 2026-06-10).
- **End-user UI** — "Recently Used Devices" in user preferences: "a list of all devices you are currently
  logged in with… operating system, browser, location, and last seen time" + "Log Out All" (shipped in
  Discourse 2.2) — https://meta.discourse.org/t/see-recently-used-devices/100070 (accessed 2026-06-11).

**Conclusion:** three flagship Rails codebases independently built — and maintain, with genuinely tricky
security code (token rotation, UA-parser hardening, Redis cluster handling) — the exact feature set this
gem packages. None of their implementations is extractable or reusable by a normal app.

---

## The UX bar (SaaS examples)

What end-users have been trained to expect from a "sessions / your devices" page:

- **GitHub** — Settings → Access → **Sessions**: list of active web sessions + GitHub Mobile devices;
  "To revoke a web session, click **Revoke session**"; revoking a mobile session also removes it as a
  2FA factor —
  https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/viewing-and-managing-your-sessions
  (accessed 2026-06-10). Per-session device icon and approximate-location rendering on the live page:
  **UNVERIFIED** (requires signed-in UI).
  - Companion **security log**: "Each audit log entry shows applicable information about an event, such
    as… The user (actor) who performed the action… The action that was performed, Which country the
    action took place in, The date and time the action occurred." —
    https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log
    (accessed 2026-06-11). This pairing is precisely the gem's two-surface design: devices page + audit trail.
- **Google** — "Your devices" / Manage all devices: device name, location, last activity ("the last time
  there was communication between the device or session and Google's systems, at each location"),
  per-device **Sign out**; guidance keyed to "You don't recognize a device" —
  https://support.google.com/accounts/answer/3067630 (accessed 2026-06-10).
- **Google sign-in alerts** — the canonical **"Was this you?"** pattern: security alert email/push on
  sign-in from a new device or location; "review the sign-in details… device type, time, and location";
  one-tap "No, secure account"; legitimate alerts are mirrored in the account's Recent security
  activity — https://support.google.com/accounts/answer/2590353 (accessed 2026-06-11).
- **Slack** — Account Settings → "Sign out of all other sessions" (password-confirmed); per-device
  sign-out documented in "Sign out of Slack" —
  https://slack.com/intl/en-gb/help/articles/214613347-sign-out-of-slack (accessed 2026-06-10).
- **Stripe** — Dashboard → Personal details: "The Login sessions section at the bottom of the page shows
  the locations, IP addresses, and times of recent logins" + a **Sign out all other sessions** button —
  https://support.stripe.com/questions/sign-out-of-stripe-web-sessions (accessed 2026-06-11).
- **Shopify** — Profile → Security → **Devices**: recently logged-in devices, per-device **Log out**,
  "Log out all devices" (when >5 devices), per-device login history and pages visited; admins can revoke
  a staff member's device/app access (Settings → Users → Revoke Access) —
  https://help.shopify.com/en/manual/your-account/logging-in (accessed 2026-06-10).

**Takeaway** — the contract is standardized: **device/browser label (parsed UA) + approximate location
(from IP) + last-active timestamp + per-row revoke + "sign out everywhere" + email alert on new
sign-in.** The gem's default views should replicate exactly this, and nothing more exotic.

---

## Demand signals & competitive scan

### Devise can't do it, and users keep asking

- "**Force logout for specific user**" — heartcombo/devise issue #5262 (opened 2020-06-26, closed
  unresolved): "The method sign_out always destroy the current_user session, not the session for the
  specific user I sent as parameter." — https://github.com/heartcombo/devise/issues/5262 (accessed 2026-06-10).
- "**expire_all_remember_me_on_sign_out does not work as expected and might be obsolete**" — #5027
  (multi-device remember-me semantics) — https://github.com/heartcombo/devise/issues/5027 (accessed 2026-06-10).
- "**Disable automatic logout when log in on other browser**" — #4607 (concurrent-session pain from
  single-session hacks) — https://github.com/heartcombo/devise/issues/4607 (accessed 2026-06-10).

### A decade-deep cottage industry of workarounds

Tutorials that all reinvent the same `session_token`-in-`authenticatable_salt` hack (revoke-all-or-nothing,
no listing, no per-device revoke, no audit trail), all accessed 2026-06-10/11:

- Jon Leighton, "Revocable sessions with Devise" (2013) — https://jonleighton.name/2013/revocable-sessions-with-devise/
- makandra dev, "Devise: Invalidating all sessions for a user" — https://makandracards.com/makandra/53562-devise-invalidating-sessions-user
- "Invalidating All User Sessions With Rails and Devise Gem" — https://medium.com/better-programming/invalidating-all-user-sessions-with-rails-and-devise-gem-b457c15e0dc
- PentesterLab, "How Devise Solves Session Invalidation in Rails" — https://pentesterlab.com/blog/rails-devise-session-invalidation
- "Setting up multi-device/browser session tracking for Devise" — https://rails.substack.com/p/setting-up-multi-devicebrowser-session
- The same question has been asked-and-hacked from 2013 through today. StackOverflow per-question view
  counts: **UNVERIFIED** (Stack Exchange API unreachable from this environment; treat as directional).

### RubyGems competitive scan

Source: RubyGems API (`https://rubygems.org/api/v1/gems/NAME.json`), accessed 2026-06-10.

| Gem | Total downloads | Latest release | Verdict |
|---|---|---|---|
| `authtrail` | 4,114,257 (v1.0.0: 86,334 since 2026-04-04 ≈ 1.3k/day) | 1.0.0 — 2026-04-04 | Alive & loved ("Track Devise login activity"), but **login-event log only**: Devise-coupled, no live sessions, no devices UI, no revocation. Validates demand without occupying the space. |
| `devise-security` | 20,779,731 | 0.18.0 — 2023-04-15 | Enterprise policy modules; `session_limitable` "ensures, that there is only one session usable per account at once" — **no listing, no devices UI** (README: https://github.com/devise-security/devise-security, accessed 2026-06-11). |
| `session_tracker` | 20,192 | 0.0.5 — 2021-11-19 | Dead (Redis session lister, abandoned). |
| `sessions` | — | — | **404 — name available.** |
| `active_sessions` / `user_sessions` / `login_activity` / `sessionable` | — | — | All 404 — no squatters, no competitors. |

**Conclusion:** no living Ruby library offers session listing + device management + login audit as a
product; the closest gems prove adjacent demand (authtrail) or adjacent policy (devise-security), and
the `sessions` name is free.

---

## Compliance requirements (OWASP/ASVS/NIST/SOC2)

### OWASP ASVS v4.0.3 — V3 Session Management (released 2021-10-28)

Source: https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x12-V3-Session-management.md (accessed
2026-06-11); release date via GitHub Releases API (tag `v4.0.3_release`).

- **3.2.1** (L1+): "Verify the application generates a new session token on user authentication."
- **3.3.1** (L1+): "Verify that logout and expiration invalidate the session token, such that the back
  button or a downstream relying party does not resume an authenticated session…"
- **3.3.2**: periodic re-authentication when staying logged in — L1: 30 days; L2: "12 hours or 30 minutes
  of inactivity, 2FA optional"; L3: "12 hours or 15 minutes of inactivity, with 2FA".
- **3.3.3** (L2+): "Verify that the application gives the option to terminate all other active sessions
  after a successful password change (including change via password reset/recovery), and that this is
  effective across the application, federated login (if present), and any relying parties."
- **3.3.4** (L2+): "Verify that users are able to view and (having re-entered login credentials) log out
  of any or all currently active sessions and devices." ← **the gem's core feature is a literal ASVS
  requirement.**

### OWASP ASVS 5.0 — V7 Session Management (v5.0.0 released 2025-05-30)

Source: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md
(accessed 2026-06-11; 5.0 line, post-5.0.0 text); release date via GitHub Releases API (`v5.0.0_release`).

- **7.5.2** (L2): "Verify that users are able to view and (having authenticated again with at least one
  factor) terminate any or all currently active sessions."
- **7.4.3** (L2): terminate all other sessions "after a successful change or removal of any
  authentication factor (including password change via reset or recovery and, if present, an MFA
  settings update)."
- **7.4.1** (L1): when termination is triggered (logout/expiration), "the application disallows any
  further use of the session."
- **7.3.1 / 7.3.2** (L2): inactivity timeout and absolute maximum session lifetime enforced "according
  to risk analysis and documented security decisions."

### OWASP Session Management Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
(accessed 2026-06-11).

- **User-facing session controls are recommended outright**: "add user capabilities that allow checking
  the details of active sessions at any time, monitor and alert the user about concurrent logons, provide
  user features to remotely terminate sessions manually, and track account activity history."
- **Never log session IDs**: "Sensitive data like the session ID should not be included in the logs…";
  "It is recommended to log a salted-hash of the session ID instead of the session ID itself in order to
  allow for session-specific log correlation without exposing the session ID."
- **Server-side invalidation is mandatory**: "the web application must take active actions to invalidate
  the session on both sides, client and server. The latter is the most relevant and mandatory from a
  security perspective."
- **Timeouts**: idle "2-5 minutes for high-value applications and 15-30 minutes for low risk
  applications"; absolute "between 4 and 8 hours" for all-day applications. **Rotation**: "The session ID
  must be renewed or regenerated… after any privilege level change", most importantly at authentication.

### NIST SP 800-63B-4 (Revision 4, published 2025)

Source: https://pages.nist.gov/800-63-4/sp800-63b.html (accessed 2026-06-11).

- AAL1: "A definite reauthentication overall timeout SHALL be established, which SHOULD be no more than
  30 days" (§2.1.3). AAL2: overall timeout "SHOULD be no more than 24 hours"; "The inactivity timeout
  SHOULD be no more than 1 hour" (§2.2.3). AAL3: overall "SHALL be no more than 12 hours"; inactivity
  "SHOULD be no more than 15 minutes" (§2.3.3).
- Session management requirements live in **Section 5 ("Session")**, reauthentication in §5.2.
- PRD implication: ship idle/absolute timeout config with named presets (`:nist_aal2`, `:owasp_low_risk`…).

### SOC 2 (AICPA Trust Services Criteria) — practical expectations

- **CC6.1** criterion text: "The entity implements logical access security software, infrastructure, and
  architectures over protected information assets to protect them from security events to meet the
  entity's objectives." — reproduced at
  https://hub.powerpipe.io/mods/turbot/aws_compliance/controls/benchmark.soc_2_cc_6_1 and explained at
  https://www.hicomply.com/en-us/hub/soc-2-controls-cc6-logical-and-physical-access-controls
  (both accessed 2026-06-11).
- Auditors operationalize CC6.x as: identification & authentication of users (CC6.1), credential
  issuance/registration and **removal of access** (CC6.2/CC6.3), plus **monitoring of system activity for
  anomalies** under CC7.x. In practice: session timeout policy, the ability to terminate a departed or
  compromised user's sessions, and a reviewable login/audit trail are standard SOC 2 evidence requests.
  (Practical interpretation from the secondary sources above; exact AICPA points-of-focus wording:
  **UNVERIFIED** — the AICPA TSC PDF is behind a download wall.)

---

## Privacy & GDPR requirements

1. **IP addresses are personal data.**
   - CJEU, *Breyer v Bundesrepublik Deutschland*, C-582/14 (judgment 2016-10-19): a dynamic IP held by a
     website operator is personal data where the operator "has the legal means which enable it to
     identify the data subject with additional data which the internet service provider has" —
     https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A62014CJ0582 (accessed 2026-06-11).
   - GDPR **Recital 30**: "Natural persons may be associated with online identifiers provided by their
     devices… such as internet protocol addresses, cookie identifiers…" —
     https://gdpr-info.eu/recitals/no-30/ (accessed 2026-06-11).
   - → Everything the gem stores (IP, UA, session metadata) is PII: encryptable, purgeable, exportable.
2. **Lawful basis exists and is explicit — document it, don't ask for consent.**
   - GDPR **Recital 49**: processing "strictly necessary and proportionate for the purposes of ensuring
     network and information security" — e.g. "preventing unauthorised access to electronic
     communications networks" — "constitutes a legitimate interest" (i.e. Art. 6(1)(f)) —
     https://gdpr-info.eu/recitals/no-49/ (accessed 2026-06-11). *Breyer* itself rejected a national rule
     that would have barred storing IPs for "maintaining general website security" (same EUR-Lex source).
   - → Ship a docs section stating Art. 6(1)(f)/Recital 49 as the default basis with a balancing-test
     note; no consent banner is needed for UA+IP security logging.
3. **Retention must be bounded.**
   - CNIL, *Recommandation relative aux mesures de journalisation* (published 2021): keep logs
     "pour une durée comprise entre six mois et un an" (six months to one year), extendable to ~3 years
     only with documented necessity and proportionality —
     https://www.cnil.fr/fr/la-cnil-publie-une-recommandation-relative-aux-mesures-de-journalisation
     (accessed 2026-06-11).
   - → Default audit-trail retention ≈ 12 months, configurable, enforced by a built-in purge job.
4. **IP minimization has a famous precedent.**
   - Google Analytics IP anonymization "sets the last octet of IPv4 user IP addresses… to zeros in memory
     shortly after being sent" and "the last 80 bits of IPv6 addresses to zeros"; "the full IP address is
     never written to disk in this case" — https://support.google.com/analytics/answer/2763052
     (accessed 2026-06-11).
   - → Offer `ip_mode: :full | :truncated | :none`, with truncation applied **before persistence**.
5. **Encryption at rest, with the querying tradeoff documented.**
   - Rails Active Record Encryption: "The `:deterministic` option… will produce the same encrypted output
     given the same plaintext input… makes querying encrypted attributes possible"; but it "allows for
     querying by trading off lesser security… non-deterministic encryption is recommended… unless you
     need to query by the encrypted attribute" — https://guides.rubyonrails.org/active_record_encryption.html
     (accessed 2026-06-11).
   - → Support `encrypts :ip_address, deterministic: true` (needed for "other logins from this IP"
     queries) and non-deterministic for `user_agent`; document the tradeoff verbatim.
6. **Data minimization** (GDPR Art. 5(1)(c), https://gdpr-info.eu/art-5-gdpr/, accessed 2026-06-11):
   store only what the UX requires (IP, UA, timestamps, hashed session reference); never request bodies,
   attempted passwords, or full referrer trails — even for failed logins.

---

## Fraud-detection norms

- **Atypical/impossible travel is the canonical account-takeover signal.**
  - Microsoft Entra ID Protection, "Atypical travel": "identifies two sign-ins originating from
    geographically distant locations… takes into account… the time between the two sign-ins and the time
    it would take for the user to travel from the first location to the second"; ignores known-VPN false
    positives; "initial learning period of the earliest of 14 days or 10 logins."
  - Related detections worth mirroring conceptually: "Impossible travel" (Defender for Cloud Apps),
    "New country", "Anonymous IP address", and "Unfamiliar sign-in properties" ("IP, ASN, location,
    device, browser, and tenant IP subnet", with a ≥5-day learning mode) —
    https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
    (page dated 2026-04-22; accessed 2026-06-11).
  - → Roadmap stance: v1 stores the raw material (IP, geo, timestamps) + exposes hooks; heuristics
    (new-country, velocity/impossible-travel) come later and stay advisory, never auto-blocking.
- **New-device / new-location alerting is industry table stakes**: Google's "Did you just sign in?"
  alert (device type, time, location, "No, secure account") —
  https://support.google.com/accounts/answer/2590353 (accessed 2026-06-11); GitHub/Stripe/Shopify
  equivalents cited above.
  - → The gem ships a `new_device` mailer with a "secure your account" CTA (revoke session + change
    password) on by default.
- **Why NOT browser fingerprinting**: Article 29 Working Party, Opinion 9/2014 on device fingerprinting
  (WP224, adopted 2014-11-27): fingerprinting that stores or reads device information requires **prior
  consent under Art. 5(3) of the ePrivacy Directive**, with no general exemption for tracking purposes —
  https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp224_en.pdf
  (accessed 2026-06-11). Server-observed UA + IP (the GitLab/Mastodon/Discourse scope) stays on the
  Recital 49 legitimate-interest side of the line; canvas/JS entropy harvesting would drag every host app
  into consent territory and poison the "drop-in" pitch.

---

## Implications for the sessions gem

Hard requirements the PRD must include, each tied to evidence above:

1. **DB-backed session records bound to the user**, with at minimum `ip_address`, `user_agent`,
   `last_active_at`, `created_at` — parity with Laravel's default schema (laravel/laravel migration,
   2026-06-10) and Rails 8's generator columns (rails/rails `authentication_generator.rb`, 2026-06-11).
2. **End-user "your devices" page**: device/browser label, approximate location, last-active, per-row
   revoke, "sign out everywhere" — ASVS 4.0.3 **3.3.4** / 5.0 **7.5.2**; UX contract per
   GitHub/Google/Stripe/Shopify/Discourse (sources above).
3. **Server-side, immediate revocation**: logout/expiry/revoke must "disallow any further use of the
   session" — ASVS 7.4.1; OWASP Cheat Sheet server-side invalidation rule.
4. **Re-authentication ("sudo mode") before destructive session actions** — ASVS 3.3.4 "(having
   re-entered login credentials)" / 7.5.2 "(having authenticated again with at least one factor)".
5. **Terminate-other-sessions on password/MFA change**, default-on hook — ASVS 3.3.3 / 7.4.3; precedent:
   phx.gen.auth deletes all tokens on password change; Laravel `logoutOtherDevices`.
6. **Configurable idle + absolute timeouts with named presets** — NIST 800-63B-4 §2.2.3 (AAL2 ≤24h
   overall / ≤1h idle); OWASP Cheat Sheet ranges (idle 15–30 min low-risk; absolute 4–8h).
7. **Store only a digest of the session identifier** (salted/peppered hash) and **never write raw session
   IDs to logs or audit rows** — OWASP Cheat Sheet ("log a salted-hash of the session ID"); Discourse
   `hash_token` precedent.
8. **Login-activity audit trail** (success/failure, identifier, IP, UA, timestamp, optional path),
   separate from live sessions — Discourse `UserAuthTokenLog`; authtrail's 4.1M downloads prove
   standalone demand; SOC 2 CC6.1/CC7.x evidence needs.
9. **New-device/new-location "Was this you?" email**, on by default with opt-out, linking to revoke +
   password change — Google alert pattern (support 2590353); Entra "unfamiliar sign-in properties" as
   the detection model.
10. **Per-user session cap with oldest-eviction + scheduled cleanup** — GitLab
    `ALLOWED_NUMBER_OF_ACTIVE_SESSIONS = 100`; Discourse `MAX_SESSION_COUNT = 60`; Mastodon `purge_old`.
11. **UA parsing via an established gem** (`device_detector` per GitLab or `browser` per Mastodon), with
    input hardening (GitLab truncates UA at 1024 chars) — never roll a custom parser.
12. **Geolocation optional, coarse, labeled approximate**, degrading gracefully when absent — Google
    "Your devices" location semantics (support 3067630); avoids a hard geo-IP dependency.
13. **Treat IP/UA as personal data**: optional Active Record Encryption integration — deterministic for
    IP (keeps equality queries; documented tradeoff per Rails guide) — *Breyer* C-582/14 + Recital 30.
14. **Configurable retention + built-in purge job; default ≈12 months for audit rows** (CNIL 6–12 month
    recommendation); session rows deleted on revoke/expiry; docs name Art. 6(1)(f)/Recital 49 as basis.
15. **Optional IP anonymization before persistence** (zero last IPv4 octet / last 80 IPv6 bits — Google
    Analytics precedent) and data-minimization defaults (GDPR Art. 5(1)(c)): no bodies, no attempted
    credentials, nullable IP.
16. **Scope guardrail: no client-side fingerprinting** (no canvas/JS entropy) — WP224 makes it
    consent-gated under ePrivacy Art. 5(3); UA+IP server-side only. Impossible-travel heuristics stay
    roadmap-stage, computed from stored geo+timestamps (Entra model), advisory-only.
17. **Auth-framework-agnostic adapters**: Rails 8 generator's `Session` model (enrich the table it
    already creates), Devise/Warden hooks, OAuth/OmniAuth callbacks — justified by Devise issues
    #5262/#5027/#4607 and the workaround corpus; the ubiquitous salt-rotation hack shows hosts need the
    gem to own *revocation*, not just display.
18. **Naming/positioning**: ship as `sessions` (RubyGems 404 on 2026-06-10 — name available); position
    against `authtrail` ("events only") and `devise-security` ("policy only") as **"the missing
    GitHub-style devices page + login audit trail for Rails."**
