# TrustCheck

[![Android CI](https://github.com/mesflit/TrustCheck/actions/workflows/android-ci.yml/badge.svg)](https://github.com/mesflit/TrustCheck/actions/workflows/android-ci.yml)
[![Latest release](https://img.shields.io/github/v/release/mesflit/TrustCheck?sort=semver)](https://github.com/mesflit/TrustCheck/releases/latest)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](LICENSE)
![Android 8.0+](https://img.shields.io/badge/Android-8.0%2B%20(API%2026)-3DDC84)

**TrustCheck** is an open-source Android security assistant by **Mesflit**. It detects
suspicious links, phishing attempts, scam messages and potentially malicious websites — on your
device first, and optionally with cloud threat intelligence.

> TrustCheck never claims a website is “safe”. The best verdict it gives is
> **No known threat detected**, and it says clearly when a link’s reputation is **Unknown**.

---

## Features

| Area | What it does |
|---|---|
| **URL analysis engine** | Parsing and normalization (IDN/punycode, full-width characters, path normalization), IP and disguised-IP hosts, `user@host` tricks, homograph attacks (mixed and look-alike scripts), typosquatting and brand impersonation (~90 frequently targeted brands), URL shorteners, HTTP vs HTTPS, unusual ports, abused TLDs, lure words, embedded redirect parameters, sensitive parameters, executable downloads |
| **Scam-message detection** | Urgency, credential/OTP requests, prize lures, and fee/payment requests, in all 9 supported languages |
| **Threat intelligence** | TrustCheck-Backend (aggregates commercial-use feeds such as Google Web Risk server-side), optional user-supplied Google Safe Browsing v4 key, and a synced on-device blocklist |
| **Notification monitoring** | Opt-in `NotificationListenerService` finds links in incoming notifications, checks them instantly on-device and warns you. Message text is never stored |
| **Sharesheet & “Open with”** | Share text, links or screenshots to TrustCheck (on-device OCR via ML Kit), use “Check with TrustCheck” on selected text, or choose TrustCheck to open a link. Links are never opened automatically |
| **Background automation** | WorkManager for deferred cloud lookups (network-aware, retried, deduplicated), daily threat-feed sync, history retention |
| **Security reports** | Risk score 0–100, classification, indicators with explanations, recommended actions, sources checked, timestamp, optional AI explanation |
| **History** | Room database with search, filters, details, deletion, clear-all and configurable retention |
| **9 languages** | English, Türkçe, Deutsch, Español, Français, Português (Brasil), العربية (RTL), 日本語, Русский — in-app selector, applied immediately |
| **Monetization** | AdMob banners (with UMP consent) outside security screens, optional rewarded ad, Google Play Billing subscriptions with server verification |

### Classifications

| Classification | Meaning |
|---|---|
| Confirmed malicious | A trusted threat-intelligence source or the synced threat feed lists it |
| Suspicious | Strong local warning signs (score ≥ 40) |
| No known threat detected | At least one threat-intelligence source answered “not listed” and no strong warning signs |
| Unknown | No reputation source could be consulted and no strong warning signs — *not* a statement of safety |
| Analysis failed | The input could not be parsed or analyzed |

Details and weights: [docs/DETECTION.md](docs/DETECTION.md).

## Installation

1. Open [**GitHub Releases**](https://github.com/mesflit/TrustCheck/releases/latest).
2. Download `TrustCheck-vX.Y.Z.apk` (and optionally `SHA256SUMS.txt`).
3. Verify the download: `sha256sum -c SHA256SUMS.txt --ignore-missing`.
4. Install the APK (allow “Install unknown apps” for your browser or file manager when prompted).

Supported Android versions: **Android 8.0 (API 26) and newer**, targeting the latest stable SDK
(API 36). The `.aab` file in each release is for Google Play distribution.

## Permissions

| Permission | Why | Required? |
|---|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | Optional cloud threat intelligence and AI, ads, billing | Offline analysis works without network |
| Notification access (`BIND_NOTIFICATION_LISTENER_SERVICE`) | Find links in incoming notifications | Optional, granted by you in system settings |
| `POST_NOTIFICATIONS` (Android 13+) | Show security alerts | Optional, requested in context |
| `RECEIVE_BOOT_COMPLETED`, `WAKE_LOCK`, `FOREGROUND_SERVICE` | Added automatically by WorkManager so scheduled jobs survive reboots | — |
| `com.google.android.gms.permission.AD_ID`, `BILLING` | Added by the AdMob and Play Billing SDKs | — |

TrustCheck does **not** use `AccessibilityService`, does not read SMS directly, and does not run a VPN.

## Architecture

Clean Architecture + MVVM in a single Gradle module with strict package boundaries:

```
com.mesflit.trustcheck
├── core.security       Pure-Kotlin analysis engine (no Android imports; unit-tested on the JVM)
├── core.localization   Languages, locale switching, enum → string-resource mapping
├── core.database       Room entities and DAOs
├── core.network        Backend client, threat-intel providers, redirect resolver, AI provider
├── core.design         Material 3 theme and shared components
├── core.ocr            ML Kit on-device text recognition
├── domain              Models, repository interfaces, ScanCoordinator
├── data                Repository implementations (Room, DataStore)
├── feature.*           dashboard, scanner, report, history, settings, premium, onboarding
├── service.notification  NotificationListenerService, alert notifier, two-stage pipeline
├── service.background  WorkManager workers and scheduler
└── monetization        AdMob/UMP, Play Billing, entitlement logic
```

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The optional backend lives in a separate
private repository, `mesflit/TrustCheck-Backend`. Its API contract is in [docs/BACKEND_API.md](docs/BACKEND_API.md).

### Background limitations (honest version)

Background work uses WorkManager, which respects Doze, App Standby and battery saver. Some
manufacturers (e.g. aggressive battery managers on Xiaomi, Huawei, Oppo, Samsung) may delay or
kill background work, and the system can unbind notification listeners under memory pressure.
TrustCheck cannot guarantee uninterrupted execution on every device. If alerts arrive late, open
**Settings → Background protection** and exempt TrustCheck from battery optimization.

## Supported languages

`en` (default and fallback), `tr`, `de`, `es`, `fr`, `pt-BR`, `ar` (RTL), `ja`, `ru`. All 291
user-facing strings are translated in every locale; a unit test fails the build if a key or a
placeholder is missing. To add or improve a translation, see [docs/TRANSLATIONS.md](docs/TRANSLATIONS.md).

## Monetization

- **AdMob**: adaptive banners only at the bottom of the Dashboard and History lists, labelled
  “Advertisement”. No ads in scanner, report or alert screens, never during a scan, never for
  Premium users. An optional, user-initiated rewarded ad grants extra AI explanations. Consent
  is gathered with Google UMP. Debug builds use Google’s public test IDs. Release builds show
  ads only when production IDs are injected by CI.
- **Google Play Billing**: monthly and annual subscriptions (suggested launch prices USD 3.99 and
  29.99, configured in Play Console, never hard-coded). Restore, grace period, account hold and
  pending purchases are handled. Premium is derived from Play on each launch and verified by the
  backend when it is configured.
- **Free forever**: all essential protection.

Setup: [docs/MONETIZATION.md](docs/MONETIZATION.md).

## Building from source

Requirements: JDK 17, Android SDK (platform 36, build-tools 36), Gradle 8.14.x.

```bash
git clone https://github.com/mesflit/TrustCheck.git && cd TrustCheck
gradle :app:testDebugUnitTest      # unit + Robolectric tests
gradle :app:assembleDebug          # app/build/outputs/apk/debug/
gradle :app:assembleRelease        # unsigned release, ads disabled
```

The Gradle wrapper JAR is not committed (binary policy). Android Studio works out of the box, or
generate a local wrapper with `gradle wrapper --gradle-version 8.14.3` (it is git-ignored).
Optional configuration (backend URL, AdMob IDs, signing) is in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## GitHub Actions

| Workflow | Trigger | Output |
|---|---|---|
| [`android-ci.yml`](.github/workflows/android-ci.yml) | push/PR to `main`, manual | Source-only policy check, Gradle validation, unit tests, debug + release builds, debug APK artifact. Optional emulator UI tests (manual) |
| [`android-release.yml`](.github/workflows/android-release.yml) | tag `v*`, manual with version | Tests, signed APK + AAB, signature verification, SHA-256 checksums, release notes, **published** GitHub Release with assets attached |

## Release process

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The release workflow builds, signs and publishes automatically. If signing secrets are missing,
it fails and lists the missing secrets; it never publishes unsigned binaries. Full guide:
[docs/RELEASING.md](docs/RELEASING.md).

## Distribution policy

This repository is **source-only**. APK/AAB files, build outputs, keystores and credentials are
never committed (`.gitignore` plus `scripts/verify-source-only.sh`, run in CI). Development builds
are GitHub Actions artifacts. Production builds are GitHub Release assets.

## Privacy

- Analysis runs on the device first. Cloud features are **off by default** and need your consent.
- Only a privacy-reduced URL (scheme, host and path, without query, fragment or user info) is
  sent for threat lookups.
- Notification text is processed in memory only. It is never stored, logged or uploaded.
- History stays on the device, is excluded from backups and is deleted according to your retention setting.

Draft policy: [docs/PRIVACY_POLICY.md](docs/PRIVACY_POLICY.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright © 2026 Mesflit. Licensed under the [GNU General Public License v3.0 only](LICENSE).
