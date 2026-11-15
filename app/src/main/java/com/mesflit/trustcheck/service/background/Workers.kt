// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.service.background

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.mesflit.trustcheck.TrustCheckApp
import com.mesflit.trustcheck.core.database.BlocklistEntity
import com.mesflit.trustcheck.core.network.ApiResult
import com.mesflit.trustcheck.core.network.dto.BlocklistResponse
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
 * Syncs the domain blocklist from TrustCheck-Backend (aggregated from public/commercial threat
 * feeds server-side). Only runs when the backend is configured and the user consented to cloud
 * threat intelligence. Without it, the local blocklist stays empty — nothing is bundled.
 */
class ThreatFeedSyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val c = (applicationContext as TrustCheckApp).container
        if (!c.backend.isConfigured || !c.settings.current().cloudThreatIntel) return Result.success()
        val prefs = applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val since = prefs.getString(KEY_VERSION, null)
        val query = if (since != null) mapOf("since" to since) else emptyMap()
        return when (val r = c.backend.get("v1/blocklist", query, BlocklistResponse.serializer())) {
            is ApiResult.Ok -> {
                val now = System.currentTimeMillis()
                val entries = r.value.added.mapNotNull { e ->
                    val d = e.domain.trim().lowercase().trimEnd('.')
                    if (d.isEmpty() || d.length > 253 || !d.contains('.')) null else BlocklistEntity(d, e.category, e.source, now)
                }
                if (r.value.full) c.blocklist.replaceAll(entries) else {
                    c.blocklist.upsert(entries)
                    if (r.value.removed.isNotEmpty()) c.blocklist.remove(r.value.removed.map { it.lowercase() })
                }
                prefs.edit().putString(KEY_VERSION, r.value.version).apply()
                Result.success()
            }
            ApiResult.NotConfigured -> Result.success()
            ApiResult.RateLimited, is ApiResult.NetworkError -> if (runAttemptCount < 3) Result.retry() else Result.success()
            is ApiResult.HttpError -> Result.success()
        }
    }

    companion object {
        private const val PREFS = "threat_feed"
        private const val KEY_VERSION = "version"
    }
}
