// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.service.background

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.mesflit.trustcheck.core.security.UrlAnalysisResult
import com.mesflit.trustcheck.data.StorageJson
import com.mesflit.trustcheck.domain.AppSettings
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * All background work goes through WorkManager, which persists jobs across process death and
 * reboots (it re-schedules itself after boot; no custom boot receiver is needed) and respects
 * Doze, App Standby buckets and battery saver. Exact timing is therefore not guaranteed.
 */
class WorkScheduler(context: Context) {
    private val wm = WorkManager.getInstance(context.applicationContext)

    fun schedulePeriodic(settings: AppSettings, firstFeedNeeded: Boolean = false) {
        val retention = PeriodicWorkRequestBuilder<HistoryRetentionWorker>(1, TimeUnit.DAYS)
            .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
            .build()
        wm.enqueueUniquePeriodicWork(WORK_RETENTION, ExistingPeriodicWorkPolicy.KEEP, retention)

        if (settings.threatFeed) {
            // Daily refresh on Wi-Fi / unmetered networks to save mobile data.
            val feed = PeriodicWorkRequestBuilder<ThreatFeedSyncWorker>(1, TimeUnit.DAYS, 6, TimeUnit.HOURS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.UNMETERED)
                        .setRequiresBatteryNotLow(true)
                        .build(),
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
                .build()
            wm.enqueueUniquePeriodicWork(WORK_FEED, ExistingPeriodicWorkPolicy.KEEP, feed)
            // The very first download may use any network so protection starts right away.
            if (firstFeedNeeded) updateThreatFeedNow(force = false, policy = ExistingWorkPolicy.KEEP)
        } else {
            wm.cancelUniqueWork(WORK_FEED)
            wm.cancelUniqueWork(WORK_FEED_NOW)
        }
    }

    /** One-off threat list download on any connected network (also used by "Update now"). */
    fun updateThreatFeedNow(force: Boolean = true, policy: ExistingWorkPolicy = ExistingWorkPolicy.REPLACE) {
        val req = OneTimeWorkRequestBuilder<ThreatFeedSyncWorker>()
            .setInputData(workDataOf(ThreatFeedSyncWorker.KEY_FORCE to force))
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        wm.enqueueUniqueWork(WORK_FEED_NOW, policy, req)
    }

    /** True while a one-off threat list download is queued or running. */
    fun threatFeedUpdating(): Flow<Boolean> = wm.getWorkInfosForUniqueWorkFlow(WORK_FEED_NOW)
        .map { infos -> infos.any { it.state == WorkInfo.State.RUNNING || it.state == WorkInfo.State.ENQUEUED } }

    /** Enqueues a cloud lookup for a link already analyzed locally. Duplicate keys are ignored. */
    fun enqueueDeferredScan(local: UrlAnalysisResult, recordId: Long?, sourceApp: String?) {
        val key = local.normalizedUrl ?: return
        val request = OneTimeWorkRequestBuilder<ScanWorker>()
            .setInputData(
                workDataOf(
                    ScanWorker.KEY_URL to key,
                    ScanWorker.KEY_RECORD_ID to (recordId ?: -1L),
                    ScanWorker.KEY_SOURCE_APP to sourceApp,
                    ScanWorker.KEY_LOCAL_INDICATORS to StorageJson.encodeIndicators(local.indicators),
                ),
            )
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .addTag(TAG_SCAN)
            .build()
        wm.enqueueUniqueWork(uniqueScanName(key), ExistingWorkPolicy.KEEP, request)
    }

    fun cancelAllScans() = wm.cancelAllWorkByTag(TAG_SCAN)

    companion object {
        const val WORK_RETENTION = "history-retention"
        const val WORK_FEED = "threat-feed-sync"
        const val WORK_FEED_NOW = "threat-feed-now"
        const val TAG_SCAN = "deferred-scan"

        fun uniqueScanName(key: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(key.toByteArray())
            return "scan-" + digest.take(16).joinToString("") { "%02x".format(it) }
        }
    }
}
