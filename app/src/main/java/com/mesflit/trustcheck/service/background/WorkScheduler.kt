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
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.mesflit.trustcheck.core.security.UrlAnalysisResult
import com.mesflit.trustcheck.data.StorageJson
import com.mesflit.trustcheck.domain.AppSettings
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * All background work goes through WorkManager, which persists jobs across process death and
 * reboots (it re-schedules itself after boot; no custom boot receiver is needed) and respects
 * Doze, App Standby buckets and battery saver. Exact timing is therefore not guaranteed.
 */
class WorkScheduler(context: Context) {
    private val wm = WorkManager.getInstance(context.applicationContext)

    fun schedulePeriodic(settings: AppSettings, backendConfigured: Boolean) {
        val retention = PeriodicWorkRequestBuilder<HistoryRetentionWorker>(1, TimeUnit.DAYS)
            .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
            .build()
        wm.enqueueUniquePeriodicWork(WORK_RETENTION, ExistingPeriodicWorkPolicy.KEEP, retention)

        if (backendConfigured && settings.cloudThreatIntel) {
            val feed = PeriodicWorkRequestBuilder<ThreatFeedSyncWorker>(1, TimeUnit.DAYS, 6, TimeUnit.HOURS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .setRequiresBatteryNotLow(true)
                        .build(),
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
                .build()
            wm.enqueueUniquePeriodicWork(WORK_FEED, ExistingPeriodicWorkPolicy.KEEP, feed)
        } else {
            wm.cancelUniqueWork(WORK_FEED)
        }
    }

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
        const val TAG_SCAN = "deferred-scan"

        fun uniqueScanName(key: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(key.toByteArray())
            return "scan-" + digest.take(16).joinToString("") { "%02x".format(it) }
        }
    }
}
