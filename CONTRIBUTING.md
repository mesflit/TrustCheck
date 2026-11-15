# Contributing to TrustCheck

Thanks for helping make TrustCheck better! By contributing you agree that your contributions are
licensed under **GPL-3.0-only**.

## Ground rules

1. **Never fabricate security results.** Code must not return canned verdicts, fake threat
   intelligence, or simulated AI/cloud responses. Test doubles live only in `src/test` and
   `src/androidTest`.
2. **Never claim safety.** Use the existing classifications. “No known threat detected” is the
   most positive verdict.
3. **Privacy first.** Do not store or transmit notification/message text. Network requests must
   use privacy-reduced URLs (`ParsedUrl.lookupKey`) and respect user consent settings.
4. **Source only.** Never commit APK/AAB/JAR files, build outputs, keystores, API keys or
   production IDs. CI runs `scripts/verify-source-only.sh`.
5. **No hardcoded user-facing strings** in Kotlin. Add them to `res/values/strings.xml` and to
   every translation (see [docs/TRANSLATIONS.md](docs/TRANSLATIONS.md)).
6. **Ads never touch security UI.** No ads in scanner, report, alerts, or during scans.

## Development setup

- JDK 17, Android SDK 36, Gradle 8.14.x (or Android Studio).
- `gradle :app:testDebugUnitTest` must pass before you open a PR.
- The detection engine (`core.security`) is pure Kotlin. Keep Android imports out of it so it
  stays testable on the JVM.

## Pull requests

- One topic per PR, with a clear description and tests for behaviour changes.
- Detection changes: add true-positive **and** false-positive tests (see `HeuristicAnalyzerTest`).
- Adding a brand to `BrandCatalog`: include the brand’s official registrable domains and a
  source (the brand’s own website or documentation).
- Follow Kotlin official code style. Keep functions small and documented.

## Reporting bugs

Open a GitHub issue with device model, Android version, TrustCheck version and steps to
reproduce. Please **do not** include real phishing links in public issues — defang them
(`hxxps://example[.]com`). Security vulnerabilities go through [SECURITY.md](SECURITY.md).
