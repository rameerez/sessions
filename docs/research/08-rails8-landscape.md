# The Rails 8+ auth landscape (2024–2026)

> Research memo for the `sessions` gem PRD. Compiled 2026-06-11 via live web research.
> Every claim carries a URL and date. Quotes are verbatim from primary sources unless marked otherwise.
> Items that could not be confirmed against a primary source are marked **UNVERIFIED**.

---

## Top findings

1. **Rails 8.0 (released 2024-11-07) ships a first-party authentication *generator*, not an auth library.** `bin/rails generate authentication` emits ~12 files of plain app code: `User` + `Session` models, `SessionsController`, `PasswordsController`/`PasswordsMailer` (reset flow), and an `Authentication` concern ([rubyonrails.org, 2024-11-07](https://rubyonrails.org/2024/11/7/rails-8-no-paas-required)).
2. **Sessions are database-backed rows, not just cookies** — the generated `sessions` table stores `ip_address` and `user_agent` per session. Rails itself calls the result a "session-based, password-resettable, **metadata-tracking** authentication system" ([Rails 8.0 release notes](https://guides.rubyonrails.org/8_0_release_notes.html)). This is the exact substrate the `sessions` gem builds on.
3. **But the generated `Session` model is two lines** — `belongs_to :user`, nothing else (verified on `rails/rails` main, fetched 2026-06-11: [session.rb.tt](https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/authentication/templates/app/models/session.rb.tt)). No device naming, no last-seen tracking, no session listing UI, no "revoke other sessions". The metadata is captured and then **never surfaced**.
4. **DHH scoped the generator deliberately small and said so on the PR**: "This is not intended to be an all-singing, all-dancing answer to every possible authentication concern… rolling your own authentication system is not some exotic adventure" and "do not expect magic links or passkeys or 2FA. That's not going to happen with this generator" ([PR #52328, merged 2024-07-16](https://github.com/rails/rails/pull/52328)).
5. **Registration/sign-up is excluded by design**: "All you have to bring yourself is a user sign-up flow (since those are usually bespoke to each application)" ([Rails 8.0 announcement, 2024-11-07](https://rubyonrails.org/2024/11/7/rails-8-no-paas-required)). Every tutorial ecosystem promptly grew "add sign-up to Rails 8 auth" posts.
6. **Rails 8.1 (2025-10-22) and the in-progress 8.2 added essentially nothing to authentication** — 8.1's release notes contain zero auth/session entries (verified [8.1 release notes](https://guides.rubyonrails.org/8_1_release_notes.html)); 8.2 edge notes only add Argon2 for `has_secure_password` and `Sec-Fetch-Site` CSRF ([edge release notes, fetched 2026-06-10](https://edgeguides.rubyonrails.org/8_2_release_notes.html)). The generator's gaps are stable market territory, not a closing window.
7. **Devise is not dying — it's growing.** Total downloads 280.87M; v5.0.4 shipped 2026-05-08 (RubyGems API, fetched 2026-06-10). Daily downloads in June 2026 peak at ~205–239k/weekday vs ~150–192k in June 2024 (BestGems API, fetched 2026-06-10). The realistic 2026 picture: two large installed bases (Devise + Rails 8 auth) that **both** lack session/device management UI.
8. **Devise was simultaneously the most *loved* and most *frustrating* gem** in Planet Argon's 2024 Rails Community Survey (2,700+ respondents, 106 countries) ([railsdeveloper.com/survey/2024](https://railsdeveloper.com/survey/2024/), fetched 2026-06-10). The 2026 survey is open through 2026-07-03; results not yet published as of this memo ([railsdeveloper.com/survey](https://railsdeveloper.com/survey/)).
9. **authentication-zero, the closest pre-Rails-8 "generated auth" gem, stalled** — last release 4.0.3 on 2024-10-26, ~19 months silent (RubyGems API, 2026-06-10): the framework absorbed its core value. Meanwhile **authtrail ("Track Devise login activity") sits at 4.11M downloads and hit 1.0.0 on 2026-04-04** — direct, quantified demand for login-activity tracking as an add-on.
10. **The community's #1 documented post-generator chores**: sign-up/registration, OAuth/social login, magic links, email verification, test helpers — and *visible session management*. WorkOS's 2026 Rails auth guide explicitly frames the need: "You're logged in on iPhone, MacBook, and Windows PC – sign out others?" ([workos.com, 2026 guide](https://workos.com/blog/rails-authentication-guide-2026)).
11. **DHH's stated philosophy is generated-owned-code over dependencies**: "Rails won't ship with Devise, but it will generate authentication code for you… The code is an extraction from 37signals' apps" (Rails World 2024 keynote, 2024-09-26, via [Kyrylo Silin's notes, 2024-09-27](https://kyrylo.org/rails/2024/09/27/notes-from-the-opening-keynote-by-david-heinemeier-hansson-at-rails-world-2024.html)). A gem that *adds* device/session UX on top of owned auth code aligns with the doctrine instead of fighting it.
12. **There is still no dedicated official authentication guide** at guides.rubyonrails.org as of June 2026 — the generator is documented in a short section of the Securing Rails Applications guide ([security guide](https://guides.rubyonrails.org/security.html)); devs literally asked "Rails 8 Authentication generator docs?" on the official forum ([discuss.rubyonrails.org](https://discuss.rubyonrails.org/t/rails-8-authentication-generator-docs/87905)).
13. **Session-tracking how-tos exist for both stacks and predate/postdate Rails 8** — SupeRails built "manage active sessions" for Devise (2024-03-24) and "Devise has_many :sessions — track, list, and revoke" via Warden hooks; a 2025-era Substack series does multi-device session tracking for Devise. People keep re-building this by hand. (URLs in §7.)
14. **Rails World 2025 (Amsterdam, 2025-09-04/05) announced no new auth features** — keynote themes were Rails 8.1 beta, "Pax Railsana", Omarchy ([Andy Croll recap](https://andycroll.com/ruby/rails-world-2025/), [Kevin McKelvin recap, 2025-09](https://kmckelvin.com/blog/2025/09/rails-world-2025/)). Rails World 2026 is Austin, TX, 2026-09-23/24 ([rubyonrails.org](https://rubyonrails.org/2026/3/24/Rails-Versions-8-0-5-and-8-1-3-have-been-released) era announcements).
15. **The generated controller already rate-limits sign-in** (`rate_limit to: 10, within: 3.minutes, only: :create`) — verified verbatim from the template on rails/rails main (fetched 2026-06-11). Rails handles abuse at the door; it does nothing about *visibility* of what's inside.

---

## Timeline

| Date | Event | Source |
|---|---|---|
| 2023-12-26 | DHH opens issue **#50446 "Add basic authentication generator"**: gems that hide mechanics "should not be seen as a necessity" | [github.com/rails/rails/issues/50446](https://github.com/rails/rails/issues/50446) |
| 2024-07-16 | DHH's **PR #52328 "Add basic sessions generator"** merged (later renamed `authentication` generator); excludes magic links/passkeys/2FA by fiat | [github.com/rails/rails/pull/52328](https://github.com/rails/rails/pull/52328) |
| 2024-09-26/27 | **Rails World 2024** (Toronto). Opening keynote announces Rails 8 beta incl. authentication generator. Video: [youtube.com/watch?v=-cEn_83zRFw](https://www.youtube.com/watch?v=-cEn_83zRFw); official page: [rubyonrails.org/world/2024/day-1/opening-keynote-dhh](https://rubyonrails.org/world/2024/day-1/opening-keynote-dhh) | keynote notes: [kyrylo.org, 2024-09-27](https://kyrylo.org/rails/2024/09/27/notes-from-the-opening-keynote-by-david-heinemeier-hansson-at-rails-world-2024.html) |
| 2024-09-27 | **"Rails 8.0 Beta 1: No PaaS Required"** — section *"Generating the authentication basics"* | [rubyonrails.org/2024/9/27/rails-8-beta1-no-paas-required](https://rubyonrails.org/2024/9/27/rails-8-beta1-no-paas-required) |
| ~2024-10-22 | HN front-page thread **"Rails 8 Authentication Generator"** | [news.ycombinator.com/item?id=41922905](https://news.ycombinator.com/item?id=41922905) (date inferred from item ID; thread content UNVERIFIED — HN rate-limited fetch) |
| 2024-11-07 | **Rails 8.0 final: "Rails 8.0: No PaaS Required"** (author: dhh) | [rubyonrails.org/2024/11/7/rails-8-no-paas-required](https://rubyonrails.org/2024/11/7/rails-8-no-paas-required) |
| 2024-11-07/08 | DHH on X: "Rails 8.0: #NOBUILD, #NOPAAS, … **new authentication generator**, and so much more! Final release is out 🎉" | [x.com/dhh/status/1854659013604262345](https://x.com/dhh/status/1854659013604262345) (date inferred from ID) |
| 2024-11-17 | Community proposal: **"Authentication via magic links"** generator — no core-team adoption | [discuss.rubyonrails.org/t/87944](https://discuss.rubyonrails.org/t/proposal-authentication-via-magic-links/87944) |
| 2024-12-13 | Rails 8.0.1; official **"Want to learn about Rails 8? START HERE"** tutorial push | [rubyonrails.org/2024/12/13/learn-Rails-8-tutorial-and-unpacked-videos](https://rubyonrails.org/2024/12/13/learn-Rails-8-tutorial-and-unpacked-videos) |
| 2025-09-04 | **Rails 8.1 Beta 1** (announced around Rails World 2025, Amsterdam 2025-09-04/05) | [rubyonrails.org/2025/9/4/rails-8-1-beta-1](https://rubyonrails.org/2025/9/4/rails-8-1-beta-1) |
| 2025-10-22 | **Rails 8.1 final: "Job continuations, structured events, local CI"** (author: rafaelfranca). **No auth/session features** | [rubyonrails.org/2025/10/22/rails-8-1](https://rubyonrails.org/2025/10/22/rails-8-1) |
| 2025-10-29 | New releases + **end-of-support announcement** | [rubyonrails.org/2025/10/29/new-rails-releases-and-end-of-support-announcement](https://rubyonrails.org/2025/10/29/new-rails-releases-and-end-of-support-announcement) |
| 2026-03-24 | Rails **8.0.5 / 8.1.3** bugfix releases; 8.1 series gets bug fixes until Oct 2026; 8.0 moves to security-only May 2026 | [rubyonrails.org/2026/3/24/Rails-Versions-8-0-5-and-8-1-3-have-been-released](https://rubyonrails.org/2026/3/24/Rails-Versions-8-0-5-and-8-1-3-have-been-released) |
| 2026 (in progress) | **Rails 8.2 edge release notes**: Argon2 option for `has_secure_password`, `Sec-Fetch-Site` CSRF. No release date stated | [edgeguides.rubyonrails.org/8_2_release_notes.html](https://edgeguides.rubyonrails.org/8_2_release_notes.html) (fetched 2026-06-10) |
| 2026-09-23/24 | **Rails World 2026**, Austin, TX (announcements expected) | via search results incl. [rubyonrails.org blog](https://rubyonrails.org/blog/), fetched 2026-06-10 |

Key release-notes language (verbatim, [Rails 8.0 release notes §2.7](https://guides.rubyonrails.org/8_0_release_notes.html)):

> "[Authentication system generator](https://github.com/rails/rails/pull/52328), creates a starting point for a session-based, password-resettable, metadata-tracking authentication system."

Rails 8.1 release notes ([guides.rubyonrails.org/8_1_release_notes.html](https://guides.rubyonrails.org/8_1_release_notes.html), fetched 2026-06-10): **no authentication, session, or cookie entries at all** (verified by full-document review).

---

## What Rails ships vs excludes

### Ships (Rails 8.0 generator, verified against rails/rails `main` 2026-06-11)

- `User` model with `has_secure_password` (bcrypt), uniquely-indexed `email_address` ([BigBinary, 2024](https://www.bigbinary.com/blog/rails-8-introduces-a-basic-authentication-generator)).
- **`Session` model backed by a `sessions` table with `token`, `ip_address`, `user_agent`** — "the sessions table … stores the `ip_address` and `user_agent` information for every session started by the `User`" ([Avo blog, 2025-01-27](https://avohq.io/blog/rails-8-authentication)). The model itself is minimal — verbatim, entire file ([session.rb.tt](https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/authentication/templates/app/models/session.rb.tt)):
  ```ruby
  class Session < ApplicationRecord
    belongs_to :user
  end
  ```
- `SessionsController` with built-in throttling — verbatim from the template ([sessions_controller.rb.tt](https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/authentication/templates/app/controllers/sessions_controller.rb.tt), fetched 2026-06-11):
  ```ruby
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_session_path, alert: "Try again later." }
  ```
- `Authentication` concern (`start_new_session_for`, `terminate_session`, `Current.session`, signed permanent cookie), `PasswordsController` + `PasswordsMailer` (reset flow), `Current` attributes class, Action Cable connection auth (follow-up [PR #53444](https://github.com/rails/rails/pull/53444) by DHH). Component list: [Avo, 2025-01-27](https://avohq.io/blog/rails-8-authentication); [Saeloun, 2025-05-12](https://blog.saeloun.com/2025/05/12/rails-8-adds-built-in-authentication-generator/).
- Official docs: a section in the **Securing Rails Applications** guide — "Starting with version 8.0, Rails comes with a default authentication generator" ([guides.rubyonrails.org/security.html](https://guides.rubyonrails.org/security.html), fetched 2026-06-10). **No dedicated auth guide exists** as of June 2026; community asked for docs on the forum ([discuss.rubyonrails.org/t/87905](https://discuss.rubyonrails.org/t/rails-8-authentication-generator-docs/87905)).

### Deliberately excludes (with receipts)

| Excluded | Source & quote |
|---|---|
| **Registration / sign-up** | "All you have to bring yourself is a user sign-up flow (since those are usually bespoke to each application)." — [Rails 8.0 announcement, 2024-11-07](https://rubyonrails.org/2024/11/7/rails-8-no-paas-required) (same line in [Beta 1 post, 2024-09-27](https://rubyonrails.org/2024/9/27/rails-8-beta1-no-paas-required)) |
| **Magic links, passkeys, 2FA** | "So do not expect magic links or passkeys or 2FA. That's not going to happen with this generator." — DHH, [PR #52328](https://github.com/rails/rails/pull/52328), 2024-07 |
| **OAuth / social login** | Never in scope; not mentioned in any official 8.x release note (verified 8.0/8.1/8.2 notes, 2026-06-10). Community fills the gap (e.g. HN: ["Social login with the Rails 8 auth generator"](https://news.ycombinator.com/item?id=43239888), ~2025-03, date inferred from ID) |
| **Magic-link generator proposal → no** | Proposal by Alexey Ivanov, 2024-11-17; no core-team adoption. Community response: "Rails Authentication generator wants to be minimal… I would rather a gem pool of different auth generators for rails" (Igbanam, 2024-11-24) — [discuss.rubyonrails.org/t/87944](https://discuss.rubyonrails.org/t/proposal-authentication-via-magic-links/87944) |
| **Feature requests generally** | "Not as an open invitation to feature requests… the core team will propose a solution first" — DHH, [issue #50446](https://github.com/rails/rails/issues/50446), 2023-12-26 |
| **Email verification, account lockout, phone auth** | Left to the developer — "leaving you with the task of building your sign-up flow and any other feature like social login, magic links login, phone authentication, account confirmation, account locking, etc." ([Saeloun, 2025-05-12](https://blog.saeloun.com/2025/05/12/rails-8-adds-built-in-authentication-generator/)) |
| **Session/device management UI** | Nothing generated: no sessions index, no per-device naming, no "sign out everywhere", no last-active tracking. The `ip_address`/`user_agent` columns are written once at sign-in and never displayed. (Verified: generated views are only `sessions/new` + passwords views — [Avo, 2025-01-27](https://avohq.io/blog/rails-8-authentication); template tree in [PR #52328](https://github.com/rails/rails/pull/52328).) |

---

## DHH & the omakase philosophy (quotes)

**The founding issue** — DHH, 2023-12-26 ([rails/rails#50446](https://github.com/rails/rails/issues/50446)), verbatim:

> "Rails now include all the key building blocks needed to do basic authentication, but many new developers are still uncertain of how to put them together, so they end up leaning on all-in-one gems that hide the mechanics. While these gems are great, and many people enjoy using them, they should not be seen as a necessity. We can teach Rails developers how to use the basic blocks by adding a basic authentication generator that essentially works as a scaffold, but for authentication."

**The PR** — DHH, merged 2024-07-16 ([rails/rails#52328](https://github.com/rails/rails/pull/52328)), verbatim:

> "Adds a basic sessions generator to get people started with their own authentication system. This is not intended to be an all-singing, all-dancing answer to every possible authentication concern. It's merely intended to illuminate the basic path, and reveal that rolling your own authentication system is not some exotic adventure."

> "So do not expect magic links or passkeys or 2FA. That's not going to happen with this generator."

**Rails World 2024 keynote** (Toronto, 2024-09-26; video [youtube.com/watch?v=-cEn_83zRFw](https://www.youtube.com/watch?v=-cEn_83zRFw)) — as recorded in [Kyrylo Silin's contemporaneous notes, 2024-09-27](https://kyrylo.org/rails/2024/09/27/notes-from-the-opening-keynote-by-david-heinemeier-hansson-at-rails-world-2024.html):

> "Rails won't ship with Devise, but it will generate authentication code for you."
> "The code is an extraction from 37signals' apps. You can learn it and level up."
> "The mission of Rails is to compress the complexity of modern web apps."

**On dependency-aversion and learned helplessness** — reported by The New Stack in "DHH Wants To Make Web Dev Easy Again, With Ruby on Rails" ([thenewstack.io](https://thenewstack.io/dhh-wants-to-make-web-dev-easy-again-with-ruby-on-rails/); quotes surfaced via search excerpts; full article fetch failed — **partially UNVERIFIED**):

> "You actually have to realize that authenticating a user is not worth being a pink elephant for — let alone paying someone else to do it. You should understand the basics of secure passwords."
> On the generator: "It's going to put you on the path of learning what the fuck is going on…"

**The doctrine frame** — [rubyonrails.org/doctrine](https://rubyonrails.org/doctrine) (fetched 2026-06-11). Pillar 3, "The menu is omakase":

> "How do you know what to order in a restaurant when you don't know what's good? Well, if you let the chef choose, you can probably assume a good meal, even before you know what 'good' is."

Auth-in-the-box is the omakase logic finally applied to authentication, 20 years in; the *generator* form (vs. a library) honors pillar 6, "Provide sharp knives" — code you own and may cut yourself on. Other pillars: Optimize for programmer happiness; Convention over Configuration; No one paradigm; Exalt beautiful code; Value integrated systems; Progress over stability; Push up a big tent.

**Rails World 2025 keynote** (Amsterdam, 2025-09-04; video [youtube.com/watch?v=gcwzWzC7gUA](https://www.youtube.com/watch?v=gcwzWzC7gUA); official page [rubyonrails.org/world/2025/day-1/david-hansson](https://rubyonrails.org/world/2025/day-1/david-hansson)): Rails 8.1 beta, Active Job Continuations, "Pax Railsana" golden-age framing, Omarchy demo — **no auth announcements** ([Andy Croll recap](https://andycroll.com/ruby/rails-world-2025/); [Kevin McKelvin recap, 2025-09](https://kmckelvin.com/blog/2025/09/rails-world-2025/)).

**Long-form interviews** (context, no auth quotes extracted — listed for completeness): Remote Ruby, "DHH on Rails World 2024 and what's coming in Rails 8.1" (~2024-10) — [podcasts.apple.com](https://podcasts.apple.com/us/podcast/dhh-on-rails-world-2024-and-whats-coming-in-rails-8-1/id1397042613?i=1000673050958); Changelog Interviews #615, "Rails is having a moment (again)" (~2024-11) — [changelog.com/podcast/615](https://changelog.com/podcast/615); Lex Fridman #474 transcript — [lexfridman.com/dhh-david-heinemeier-hansson-transcript](https://lexfridman.com/dhh-david-heinemeier-hansson-transcript/). Auth-specific content in these: **UNVERIFIED**.

---

## Community reception & tutorials

Reception in one line: enthusiastic about *owning* auth, immediately followed by a cottage industry of "here's what it doesn't do" tutorials.

**What tutorials consistently hand-build on top of the generator** (frequency-ranked from the corpus below): (1) registration/sign-up, (2) OAuth/social login, (3) magic links, (4) email verification/confirmation, (5) tests & test helpers, (6) **session listing / device management / revocation**, (7) impersonation, admin constraints.

| # | Source (date) | One-liner |
|---|---|---|
| 1 | [GoRails — "How To Add Impersonation To Rails Authentication Generator"](https://gorails.com/episodes/how-to-add-impersonation-to-rails-authentication-generator) | Extends generated `Session`/`Current` to impersonate users — proof the Session model is the extension point ([repo](https://github.com/gorails-screencasts/impersonation-rails-8-authentication-generator)) |
| 2 | [GoRails — "Authentication Generator Test Helpers"](https://gorails.com/episodes/authentication-generator-test-helpers) | New upstream test helpers + extending them to system tests |
| 3 | [GoRails — "Routing Constraints with Rails Authentication Generator"](https://gorails.com/episodes/routing-constraints-with-rails-authentication-generator) | Authenticated routing constraints on top of generated auth |
| 4 | [GoRails — "What's New in Rails 8.0" series](https://gorails.com/series/whats-new-in-rails-8) | Multi-episode Rails 8 coverage incl. auth generator walkthrough |
| 5 | [Rob Race — "Adding Sign Up to the Rails 8 Authentication Generator"](https://robrace.dev/blog/rails-8-authentication-sign-up/) | The canonical missing piece: registration |
| 6 | [Josef Strzibny — "Extending Rails authentication generator with registration flow"](https://nts.strzibny.name/rails-authentication-registrations/) | Same gap, by the *Deployment from Scratch* author |
| 7 | [dev.to/1klap — "Extending Rails 8 authentication with OAuth sign-in and the missing RSpec test suite"](https://dev.to/1klap/extending-the-ruby-on-rails-8-authentication-with-oauth-sign-in-and-the-missing-rspec-test-suite-4ia) | OAuth + tests, both absent from the generator |
| 8 | [Rails Designer — "Adding Magic Links to Rails 8 Authentication"](https://dev.to/railsdesigner/adding-magic-links-to-rails-8-authentication-151n) | Magic links bolted onto generated auth |
| 9 | [Radan Skorić (guest) — "Migrating from Devise to Rails Auth before you can say 'Rails World keynote'"](https://radanskoric.com/guest-articles/from-devise-to-rails-auth) | Real-world Devise → Rails 8 auth migration write-up |
| 10 | [Andrii Furmanets — "Built-In Authentication in Rails 8: Deep Dive and Comparison"](https://andriifurmanets.com/blogs/built-in-authentication-in-rails) | Notes the generator "keeps track of sessions history instead of just storing the latest session information like [Devise's] trackable module" — i.e. better raw data, still no UI |
| 11 | [BigBinary — "Rails 8 introduces a basic authentication generator"](https://www.bigbinary.com/blog/rails-8-introduces-a-basic-authentication-generator) | Schema-level walkthrough (`token`, `ip_address`, `user_agent`); flags "does not handle new account creation" |
| 12 | [Saeloun — "Rails 8 adds built in authentication" (2025-05-12)](https://blog.saeloun.com/2025/05/12/rails-8-adds-built-in-authentication-generator/) | Enumerates everything left to build (sign-up, social, magic links, confirmation, locking) |
| 13 | [Avo — "Rails 8 Authentication with the auth generator" (2025-01-27)](https://avohq.io/blog/rails-8-authentication) | Full file-by-file tour; "meant to kickstart our app's authentication and leave us with a solid foundation" |
| 14 | [Money Forward Dev — "Rails v8 new authentication generator" (2024-12-10)](https://global.moneyforward-dev.jp/2024/12/10/rails-v8-new-authentication-generator/) | Enterprise (Japan) engineering-blog validation |
| 15 | [Jeremy Kreutzbender — "Controller Tests with RSpec and Rails 8 Authentication"](https://jeremykreutzbender.com/blog/controller-tests-with-rspec-and-rails-8-authentication) | Filling the missing-RSpec-support gap |
| 16 | [RubyStackNews — "Rails 8 Authentication: Why the New Built-in Generator Matters (and What It Means for Devise)" (2026-02-16)](https://rubystacknews.com/2026/02/16/rails-8-authentication-why-the-new-built-in-generator-matters-and-what-it-means-for-devise/) | 2026 retrospective on the Devise-vs-built-in question |
| 17 | [WorkOS — "Building authentication in Rails web applications: The complete guide for 2026"](https://workos.com/blog/rails-authentication-guide-2026) | Vendor-neutral 2026 state-of-auth; explicitly covers listing active sessions across devices and "sign out others" |

**Aggregator threads** (titles + IDs verified via search 2026-06-10; comment content UNVERIFIED — HN returned 429 on fetch):
- ["Rails 8 Authentication Generator"](https://news.ycombinator.com/item?id=41922905) (~2024-10)
- ["Social login with the Rails 8 auth generator"](https://news.ycombinator.com/item?id=43239888) (~2025-03) — thread title itself signals the OAuth gap
- ["Rails 8 adds built in authentication generator"](https://news.ycombinator.com/item?id=43962701) (~2025-05) — the topic resurfacing 6 months post-release
- Reddit r/rails: no single canonical "Rails 8 auth vs Devise" thread surfaced via search (2026-06-10) — **UNVERIFIED/absent**; sentiment instead distributed across the tutorial posts above.

---

## Adoption data 2026

**Surveys.**
- Planet Argon **2024 Ruby on Rails Community Survey** (2,700+ devs, 106 countries): no dedicated "which auth solution" question (verified by full review of [railsdeveloper.com/survey/2024](https://railsdeveloper.com/survey/2024/), fetched 2026-06-10), but **Devise ranked #1 in both "Which Ruby gems do you love?" and "Which Ruby gems frustrate you the most?"** — the love/hate profile that creates switching energy. Highlights also covered by [Socket.dev](https://socket.dev/blog/highlights-from-the-2024-rails-community-survey).
- **2026 survey**: open through 2026-07-03, "deeper" questions incl. AI workflows; results to be published free after close ([railsdeveloper.com/survey](https://railsdeveloper.com/survey/); [Planet Argon blog, 2026-04](https://blog.planetargon.com/blog/entries/the-2026-ruby-on-rails-community-survey-is-open); [Robby on Rails, 2026-04-27](https://robbyonrails.com/articles/2026/04/27/less-opinions-more-data-the-2026-rails-survey/)). **Auth-share numbers for 2026: not yet available** — re-check after July 2026.

**Gem telemetry** (RubyGems.org API + BestGems API, all fetched 2026-06-10/11):

| Gem | Total downloads | Latest version (date) | Read |
|---|---|---|---|
| devise | **280,870,110** | **5.0.4 (2026-05-08)** | Alive and on a 5.x major; requires railties ≥ 7.0 |
| sorcery | 7,270,473 | 0.18.0 (2025-12-06) | Niche, maintained |
| **authtrail** | **4,114,257** | **1.0.0 (2026-04-04)** | "Track Devise login activity" (ankane) — login-activity demand proxy |
| clearance | 2,158,451 | 2.12.0 (2026-04-17) | thoughtbot's minimal auth, maintained |
| rodauth | 890,858 | 2.44.0 (**2026-06-08**) | Jeremy Evans, extremely active |
| authentication-zero | 426,848 | 4.0.3 (**2024-10-26 — stalled**) | Pre-Rails-8 generator gem, obsoleted by the official one |

**Devise daily-download trend** (BestGems API [bestgems.org/api/v1/gems/devise/daily_downloads.json](https://bestgems.org/api/v1/gems/devise/daily_downloads.json), fetched 2026-06-10), weekday samples:

| Window | Typical weekday range | Peak sampled |
|---|---|---|
| Early Jun 2024 | ~98k–192k/day | 192,172 (2024-06-06) |
| Early Nov 2024 (Rails 8 launch week) | ~91k–162k/day | 162,313 (2024-11-06) |
| Early Jun 2025 | ~95k–180k/day | 179,537 (2025-06-04) |
| Early Jun 2026 | ~141k–239k/day | 238,811 (2026-06-10) |

**Interpretation:** Devise installs *grew* ~20–25% from mid-2024 to mid-2026. Downloads track CI/deploys of the installed base, not new-app choices — so the honest 2026 model is: **new apps increasingly start on the Rails 8 generator** (every official tutorial since 2024-12-13 does — [rubyonrails.org](https://rubyonrails.org/2024/12/13/learn-Rails-8-tutorial-and-unpacked-videos)), while **the Devise installed base keeps compounding**. A sessions/devices gem must serve both. No major app's public "we migrated to Rails 8 auth" case study was found beyond Radan Skorić's guest write-up ([radanskoric.com](https://radanskoric.com/guest-articles/from-devise-to-rails-auth)) — **claim of major-app migrations: UNVERIFIED/none found**.

---

## Evidence of demand for session tracking

The pattern: Rails 8 writes `ip_address`/`user_agent` to a `sessions` table and stops; Devise's `trackable` stores only the *latest* sign-in. Anyone who wants a GitHub/Google-style "Your devices" page builds it by hand — repeatedly:

1. **WorkOS 2026 Rails auth guide** ([workos.com/blog/rails-authentication-guide-2026](https://workos.com/blog/rails-authentication-guide-2026)) frames it as a checklist item: "If you need to see all active sessions across devices ('You're logged in on iPhone, MacBook, and Windows PC – sign out others?'), the database makes this straightforward." Straightforward — yet not shipped by anything in the default stack.
2. **SupeRails / Yaroslav Shmarov — "Manage active sessions in Rails"** (2024-03-24, [blog.superails.com/secutiry-manage-active-sessions](https://blog.superails.com/secutiry-manage-active-sessions)): "to enhance security of your application you will want to allow users to see all the devices/browsers they are logged in with" — full hand-rolled build (list + revoke).
3. **SupeRails — "Devise has_many :sessions — track, list, and revoke active sessions"** ([blog.superails.com/devise-multiple-sessions-warden-hooks](https://blog.superails.com/devise-multiple-sessions-warden-hooks)): Warden-hook approach, per-browser UUID in the encrypted cookie mapped to a DB Session row; "when a session is revoked, the next request from that browser forces a sign-out." Three files + migration of bespoke plumbing — exactly what a gem should absorb.
4. **"Setting up multi-device/browser session tracking for Devise"** ([rails.substack.com](https://rails.substack.com/p/setting-up-multi-devicebrowser-session), syndicated on [RubyFlow](https://rubyflow.com/p/95puif-setting-up-multi-devicebrowser-session-tracking-for-devise)): a `LoginSession` model with IP, status (`active`/`inactive`/`locked_out`), session ID — "display them in 'your active sessions' UI, and let users revoke sessions remotely."
5. **authtrail at 4.11M downloads, 1.0.0 on 2026-04-04** ([rubygems.org/gems/authtrail](https://rubygems.org/gems/authtrail), API fetch 2026-06-10): the market already pays (in installs) for *login activity tracking* — but authtrail is Devise-only and logs attempts; it doesn't manage live sessions/devices.
6. **Andrii Furmanets' comparison** ([andriifurmanets.com](https://andriifurmanets.com/blogs/built-in-authentication-in-rails)): the Rails 8 generator "keeps track of sessions history instead of just storing the latest session information like the trackable module does. This allows for a more granular control of user sessions" — the data advantage is recognized; the missing layer is product surface.
7. **GoRails impersonation episode** ([gorails.com](https://gorails.com/episodes/how-to-add-impersonation-to-rails-authentication-generator)) demonstrates the generated `Session` row as the natural place to hang per-session state — the same extension mechanism `sessions` uses.
8. **Rails security guide** ([guides.rubyonrails.org/security.html](https://guides.rubyonrails.org/security.html)): session hijacking is a first-class documented threat ("Stealing a user's session ID lets an attacker use the web application in the victim's name") — yet the framework offers no user-facing mitigation surface (view/revoke sessions). UNVERIFIED quantitative SO data: no Stack Overflow view-count evidence collected for "devise list active sessions" queries (search surfaced blogs, not SO threads; 2026-06-10).

---

## Implications for the sessions gem

1. **The substrate is now standard.** Since 2024-11-07 every new Rails app can have a DB-backed `Session` row with `ip_address`/`user_agent` for free. The gem doesn't need to argue for database sessions — DHH already did ([rubyonrails.org, 2024-11-07](https://rubyonrails.org/2024/11/7/rails-8-no-paas-required)). We are the missing presentation/management layer on data Rails already collects.
2. **The exclusions are policy, not backlog.** DHH's "not an all-singing, all-dancing answer" + "that's not going to happen with this generator" ([PR #52328](https://github.com/rails/rails/pull/52328)) and the 8.1/8.2 release notes (zero auth additions) mean Rails core is *not* going to ship a devices page, "sign out everywhere", or login notifications. Low platform risk through at least Rails 8.2.
3. **Position with the doctrine, not against it.** The winning frame: "You own your auth (omakase + sharp knives); we add the session/device layer every real app needs — drop-in, readable, removable." A heavyweight auth framework would fight the 2023-12-26 thesis ([issue #50446](https://github.com/rails/rails/issues/50446)); a focused tracking/management gem rides it — like the community's own preference for "a gem pool of different auth generators" ([discuss thread, 2024-11-24](https://discuss.rubyonrails.org/t/proposal-authentication-via-magic-links/87944)).
4. **Serve three installed bases**: (a) Rails 8 generator apps (fastest-growing, every official tutorial), (b) Devise's compounding ~280M-download base — still growing ~20-25% YoY in daily installs (BestGems, 2026-06-10) — where multi-session tracking requires hand-rolled Warden hooks today, and (c) OAuth/omniauth sign-ins, which the generator ignores entirely. First-class adapters for all three is the moat; SupeRails' two separate hand-rolled implementations (one per stack) prove the duplication pain.
5. **Ship what tutorials keep re-teaching**: active-sessions page, device naming (parse `user_agent`), per-session revoke + "sign out all other devices", session history/login activity (authtrail's 4.1M downloads validate), suspicious-login signals (new device/IP). Each maps to a documented hand-build above (§7).
6. **Timing**: 2026 surveys land in July 2026 ([railsdeveloper.com/survey](https://railsdeveloper.com/survey/)); Rails World Austin is 2026-09-23/24. Both are natural launch/content windows. Re-verify auth-share numbers when Planet Argon publishes.
7. **Naming collision note**: DHH's PR was literally titled "Add basic **sessions** generator" ([#52328](https://github.com/rails/rails/pull/52328)) before becoming `generate authentication` — the word "sessions" is now firmly associated with DB-backed auth rows in Rails mindshare. Good for discoverability of a gem named `sessions`; docs must disambiguate from `ActionDispatch::Session` cookie store.

---

*Methodology: web research 2026-06-10/11 (WebSearch + direct fetches of rubyonrails.org, guides.rubyonrails.org, github.com/rails/rails templates via raw.githubusercontent.com, RubyGems API, BestGems API). Failed fetches noted inline: thenewstack.io article body (page chrome only), news.ycombinator.com (HTTP 429), rubyevents.org (HTTP 403). Tweet dates inferred from snowflake IDs. All other quotes verified against the cited page on the fetch date.*
