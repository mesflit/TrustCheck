// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.service.notification

import com.mesflit.trustcheck.core.security.DetectedIndicator
import com.mesflit.trustcheck.core.security.ResultMerger
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.ScanDeduplicator
import com.mesflit.trustcheck.core.security.UrlAnalysisEngine
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.ScanRepository
import com.mesflit.trustcheck.domain.SettingsRepository
import com.mesflit.trustcheck.domain.TargetType
import com.mesflit.trustcheck.service.background.WorkScheduler

/**
 * Two-stage pipeline for links found in notifications:
 *  1. Instant on-device analysis (works offline, no data leaves the device).
 *  2. Optional deferred cloud lookup through WorkManager (network-aware, retried, deduplicated).
 */
class NotificationScanProcessor(
    private val engine: UrlAnalysisEngine,
    private val scans: ScanRepository,
    private val settings: SettingsRepository,
    private val notifier: AlertNotifier,
    private val scheduler: WorkScheduler,
    private val dedup: ScanDeduplicator = ScanDeduplicator(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    suspend fun process(urls: List<String>, textIndicators: List<DetectedIndicator>, sourceApp: String?) {
        val s = settings.current()
        for (url in urls) {
            val now = clock()
            val key = ScanDeduplicator.keyFor(url)
            if (!dedup.tryAcquire(key, now)) continue
            if (scans.findRecent(key, now - RECENT_WINDOW_MS) != null) continue

            val local = ResultMerger.withTextSignals(engine.analyzeLocally(url), textIndicators)
            if (local.classification == RiskClassification.ANALYSIS_FAILED) continue
            settings.incrementTotalScans()

            val warn = local.classification == RiskClassification.SUSPICIOUS || local.classification == RiskClassification.CONFIRMED_MALICIOUS
            val id = if (warn || s.keepCleanNotificationScans) scans.save(local, TargetType.URL, ScanOrigin.NOTIFICATION, sourceApp) else null
            if (warn && id != null && s.alertsEnabled) notifier.postAlert(id, local, sourceApp, s.language)

            if (s.cloudThreatIntel || s.resolveRedirects) {
                scheduler.enqueueDeferredScan(local, id, sourceApp)
            }
        }
    }

    companion object {
        const val RECENT_WINDOW_MS = 10 * 60 * 1000L
    }
}
