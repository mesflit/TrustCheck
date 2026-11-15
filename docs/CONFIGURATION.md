# Build configuration

Every setting is optional. A plain `gradle :app:assembleDebug` builds a fully working app with
on-device analysis, test ads and no cloud features.

Each value is read from a Gradle property first (e.g. `~/.gradle/gradle.properties` or
`-Pname=value`), then from an environment variable. Never put real values in the repository’s
`gradle.properties`.

| Gradle property | Environment variable | Purpose |
|---|---|---|
| `trustcheck.backendBaseUrl` | `TRUSTCHECK_BACKEND_URL` | HTTPS base URL of TrustCheck-Backend; empty = cloud threat intel and AI unavailable |
| `trustcheck.admobAppId` | `ADMOB_APP_ID` | Production AdMob app ID (release only) |
| `trustcheck.admobBannerId` | `ADMOB_BANNER_ID` | Production banner unit (release only) |
| `trustcheck.versionName` | `TRUSTCHECK_VERSION_NAME` | Version name (CI sets it from the tag) |
| `trustcheck.versionCode` | `TRUSTCHECK_VERSION_CODE` | Version code (CI derives it from the tag) |
| `trustcheck.keystoreFile` | `TRUSTCHECK_KEYSTORE_FILE` | Release keystore path |
| `trustcheck.keystorePassword` | `ANDROID_KEYSTORE_PASSWORD` | Keystore password |
| `trustcheck.keyAlias` | `ANDROID_KEY_ALIAS` | Key alias |
| `trustcheck.keyPassword` | `ANDROID_KEY_PASSWORD` | Key password |

Without signing values, `assembleRelease` produces `app-release-unsigned.apk` (fine for CI checks).

## User-side configuration

- **Google Safe Browsing key** (Settings → AI and threat intelligence): users may enter their own
  key for direct lookups. It is stored only on the device. Google restricts the free API to
  non-commercial use, so the official distribution relies on the backend (Web Risk) instead.
- All cloud features also require the user’s consent toggles.
