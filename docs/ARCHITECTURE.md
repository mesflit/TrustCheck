# Architecture

TrustCheck follows Clean Architecture with MVVM, in one Gradle module (`:app`) whose packages map
to the layers below. A single module keeps the build simple and fast. The boundaries are kept by
convention and reviewed in PRs. `core.security` deliberately has **no Android imports**, so the
detection engine compiles and is tested on a plain JVM.

```
UI (Compose, feature.*)  ──►  ViewModels  ──►  domain (ScanCoordinator, repositories)
                                                   │
                       ┌───────────────────────────┼──────────────────────────┐
                       ▼                           ▼                          ▼
             core.security engine          data (Room, DataStore)     core.network providers
             (pure Kotlin)                                            (backend, Safe Browsing,
                                                                       redirects, AI)
```

## Scan pipelines

**User-initiated** (scanner, share sheet, “Open with”, text selection, OCR):
`ScanCoordinator` → `UrlAnalysisEngine.analyze()` → heuristics → optional redirect resolution →
synced blocklist → cloud threat intel (if consented and online) → `RiskScorer` → saved to Room.

**Notifications** (two stages):
1. `TrustCheckNotificationListener` reads visible text **in memory**, extracts URLs and scam
   phrase codes, then discards the text. `NotificationScanProcessor` deduplicates (in-memory
   window plus a recent-history lookup), runs `analyzeLocally()` instantly and offline, stores
   only warnings by default, and posts a localized alert.
2. If cloud lookups are enabled, `WorkScheduler.enqueueDeferredScan()` queues a `ScanWorker`
   (unique per URL, network constraint, exponential backoff, max 3 attempts). The worker merges
   the cloud verdict with the local one (`ResultMerger.merge` never downgrades local warnings),
   updates history and alerts again only if the verdict escalated.

**Files** (scanner button, share sheet, "Open with"): `FileScanService` → `FileScanner` reads the
file on the device (SHA-256, magic bytes, ZIP entries, APK manifest, text/PDF/image OCR) →
`FileInspector` (pure Kotlin) → links inside go through the URL engine → saved as a FILE record.

**Threat list**: `ThreatFeedSyncWorker` → `ThreatFeedStore.sync()` downloads `feed.json` +
`feed.txt.gz` from the `threat-feed` GitHub Release, verifies SHA-256, builds a sorted 64-bit hash
index and writes it atomically; lookups memory-map that file.

## Dependency injection

`AppContainer` is a hand-written container created in `TrustCheckApp`. ViewModels are built
through `containerViewModel { … }`. There is no reflection or annotation-processing DI; Room is
the only KSP processor.

## Key decisions

| Decision | Reason |
|---|---|
| No server, GitHub-hosted threat list | Zero running cost; links never leave the device for list checks |
| Single module, layered packages | Fewer build-config pitfalls; easy for contributors |
| Pure-Kotlin engine | Deterministic, fast unit tests; reusable server-side |
| AppCompat per-app locales + `localizedContext()` | Immediate language switching on API 26–36, and correct language in notifications/workers |
| WorkManager only (no boot receiver, no foreground service) | System-managed persistence and battery friendliness; WorkManager reschedules after reboot itself |
| No VPN / AccessibilityService | Avoids surveillance-grade permissions; HTTPS contents cannot be inspected anyway |
| Privacy-reduced `lookupKey` | Query strings often carry personal tokens (password-reset links, sessions) |
| Entitlement recomputed from Play each launch | A stored “premium” flag is never trusted as proof of payment |

## Not implemented (by design or pending)

- **AI explanations**: removed to keep the app free of running costs; local explanations cover every indicator in 9 languages.
- **VPN/DNS protection**: not included. If added later it must be opt-in, explained, never
  silent, and must not inspect HTTPS contents.
- **Native ads**: not used, to keep ad load low. Only banners are used; Premium removes them and changes nothing else.
- **Full Public Suffix List**: a compact multi-label suffix list is used (see DETECTION.md).
