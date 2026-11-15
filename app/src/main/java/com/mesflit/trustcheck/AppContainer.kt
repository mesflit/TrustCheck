// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck

import android.content.Context
import android.net.Uri
import com.mesflit.trustcheck.core.database.TrustCheckDatabase
import com.mesflit.trustcheck.core.network.BackendAiAnalysisProvider
import com.mesflit.trustcheck.core.network.BackendClient
import com.mesflit.trustcheck.core.network.BackendThreatIntelProvider
import com.mesflit.trustcheck.core.network.Connectivity
import com.mesflit.trustcheck.core.network.OkHttpRedirectResolver
import com.mesflit.trustcheck.core.network.SafeBrowsingProvider
import com.mesflit.trustcheck.core.ocr.OcrTextExtractor
import com.mesflit.trustcheck.core.security.UrlAnalysisEngine
import com.mesflit.trustcheck.data.RoomBlocklist
import com.mesflit.trustcheck.data.ScanRepositoryImpl
import com.mesflit.trustcheck.data.SettingsRepositoryImpl
import com.mesflit.trustcheck.domain.AiAnalysisProvider
import com.mesflit.trustcheck.domain.ScanCoordinator
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.ScanRepository
import com.mesflit.trustcheck.domain.SettingsRepository
import com.mesflit.trustcheck.monetization.AdsManager
import com.mesflit.trustcheck.monetization.BillingManager
import com.mesflit.trustcheck.service.background.WorkScheduler
import com.mesflit.trustcheck.service.notification.AlertNotifier
import com.mesflit.trustcheck.service.notification.NotificationScanProcessor
import kotlinx.coroutines.flow.MutableStateFlow
import java.util.concurrent.ConcurrentHashMap

/** Content handed to the scanner from outside (share sheet, "open with", text selection). */
sealed interface PendingScan {
    data class Text(val text: String, val origin: ScanOrigin) : PendingScan
    data class Image(val uri: Uri) : PendingScan
}

/**
 * Memory-only holder for the original input of recent scans (full URL with query, or the
 * shared message) so the user can choose "open anyway" or "include message in AI analysis"
 * in the same session. Never persisted; cleared when the process ends.
 */
class ScanSession {
    data class Entry(val originalInput: String, val messageText: String?)
    private val map = ConcurrentHashMap<Long, Entry>()
    fun put(id: Long, entry: Entry) { if (map.size > 50) map.clear(); map[id] = entry }
    fun get(id: Long): Entry? = map[id]
    fun clear() = map.clear()
}

/** Manual dependency container (keeps the build simple; no reflection/annotation processing). */
class AppContainer(context: Context) {
    val appContext: Context = context.applicationContext

    val database by lazy { TrustCheckDatabase.create(appContext) }
    val settings: SettingsRepository = SettingsRepositoryImpl(appContext)
    val scans: ScanRepository by lazy { ScanRepositoryImpl(database.scanDao()) }
    val blocklist by lazy { RoomBlocklist(database.blocklistDao()) }
    val connectivity = Connectivity(appContext)
    val backend = BackendClient(settings)

    val engine by lazy {
        UrlAnalysisEngine(
            threatIntel = listOf(BackendThreatIntelProvider(backend, settings), SafeBrowsingProvider(settings)),
            blocklist = blocklist,
            redirectResolver = OkHttpRedirectResolver(),
        )
    }
    val scanCoordinator by lazy { ScanCoordinator(engine, scans, settings, connectivity::isOnline) }
    val ai: AiAnalysisProvider by lazy { BackendAiAnalysisProvider(backend, settings) }
    val notifier = AlertNotifier(appContext)
    val scheduler by lazy { WorkScheduler(appContext) }
    val notificationProcessor by lazy { NotificationScanProcessor(engine, scans, settings, notifier, scheduler) }
    val ocr by lazy { OcrTextExtractor(appContext) }
    val billing by lazy { BillingManager(appContext, backend) }
    val ads by lazy { AdsManager(appContext) }

    val session = ScanSession()
    val pendingScan = MutableStateFlow<PendingScan?>(null)
}
