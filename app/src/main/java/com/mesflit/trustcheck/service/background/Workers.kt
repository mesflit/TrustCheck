// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.service.background

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.mesflit.trustcheck.TrustCheckApp
import com.mesflit.trustcheck.core.network.ThreatFeedStore
import com.mesflit.trustcheck.core.security.AnalysisOptions
import com.mesflit.trustcheck.core.security.AnalysisSource
import com.mesflit.trustcheck.core.security.ResultMerger
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.SourceResult
import com.mesflit.trustcheck.core.security.SourceStatus
import com.mesflit.trustcheck.core.security.isReputation
import com.mesflit.trustcheck.data.StorageJson
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.TargetType

/** Deferred, network-backed re-analysis of a link first analyzed locally (e.g. from a notification). */
class ScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val c = (applicationContext as TrustCheckApp).container
        val url = inputData.getString(KEY_URL) ?: return Result.failure()
        val recordId = inputData.getLong(KEY_RECORD_ID, -1L).takeIf { it > 0 }
        val sourceApp = inputData.getString(KEY_SOURCE_APP)
        val localIndicators = StorageJson.decodeIndicators(inputData.getString(KEY_LOCAL_INDICATORS) ?: "[]")
        val s = c.settings.current()
        if (!s.cloudThreatIntel && !s.resolveRedirects) return Result.success()

        val remote = c.engine.analyze(url, AnalysisOptions(allowNetwork = true, resolveRedirects = s.resolveRedirects))
        val cloud = remote.sources.filter { it.source.isReputation && it.source != AnalysisSource.LOCAL_BLOCKLIST }
        if (cloud.isNotEmpty() && cloud.all { it.status == SourceStatus.ERROR } && runAttemptCount < MAX_ATTEMPTS) {
            return Result.retry()
        }

        val localBase = remote.copy(indicators = localIndicators, sources = listOf(SourceResult(AnalysisSource.LOCAL_HEURISTICS, SourceStatus.NO_MATCH)))
        val merged = ResultMerger.merge(ResultMerger.recompute(localBase, localIndicators, localBase.sources), remote)

        val previous = recordId?.let { c.scans.get(it) }
        val escalated = previous == null || merged.classification.ordinal < previous.classification.ordinal
        val warn = merged.classification == RiskClassification.CONFIRMED_MALICIOUS || merged.classification == RiskClassification.SUSPICIOUS

        val id = when {
            previous != null -> { c.scans.updateResult(previous.id, merged); previous.id }
            warn || s.keepCleanNotificationScans -> c.scans.save(merged, TargetType.URL, ScanOrigin.NOTIFICATION, sourceApp)
            else -> null
        }
        if (id != null && warn && escalated && s.alertsEnabled) c.notifier.postAlert(id, merged, sourceApp, s.language)
        return Result.success()
    }

    companion object {
        const val KEY_URL = "url"
        const val KEY_RECORD_ID = "record_id"
        const val KEY_SOURCE_APP = "source_app"
        const val KEY_LOCAL_INDICATORS = "local_indicators"
        const val MAX_ATTEMPTS = 3
    }
}

/** Deletes history older than the user's retention setting. */
class HistoryRetentionWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val c = (applicationContext as TrustCheckApp).container
        val days = c.settings.current().retentionDays.coerceAtLeast(1)
        c.scans.purgeOlderThan(System.currentTimeMillis() - days * 86_400_000L)
        return Result.success()
    }
}

/**
 * Downloads the daily threat list published by this repository's `threat-feed` workflow
 * (GitHub Release asset — free, no server). Links are then checked on the device only.
 */
class ThreatFeedSyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val c = (applicationContext as TrustCheckApp).container
        if (!c.settings.current().threatFeed) return Result.success()
        return when (val r = c.threatFeed.sync(force = inputData.getBoolean(KEY_FORCE, false))) {
            is ThreatFeedStore.SyncResult.Updated, ThreatFeedStore.SyncResult.UpToDate -> Result.success()
            is ThreatFeedStore.SyncResult.Failed -> if (r.retryable && runAttemptCount < 3) Result.retry() else Result.failure()
        }
    }

    companion object {
        const val KEY_FORCE = "force"
    }
}
