// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.service.notification

import android.app.Notification
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Parcelable
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.mesflit.trustcheck.TrustCheckApp
import com.mesflit.trustcheck.core.security.ScamTextAnalyzer
import com.mesflit.trustcheck.core.security.UrlExtractor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Notification monitoring (opt-in).
 *
 * Runs only after the user explicitly grants Notification Access in system settings AND enables
 * monitoring in TrustCheck. Per notification, the visible text is read in memory, URLs and
 * scam-phrase indicator codes are extracted, and the text is discarded immediately. Message text
 * is never written to disk, logged, or sent anywhere.
 */
class TrustCheckNotificationListener : NotificationListenerService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var settingsJob: Job? = null

    @Volatile private var monitoringEnabled = false

    private val container get() = (application as TrustCheckApp).container

    override fun onListenerConnected() {
        super.onListenerConnected()
        settingsJob?.cancel()
        settingsJob = scope.launch {
            container.settings.settings.collect { monitoringEnabled = it.notificationMonitoring }
        }
    }

    override fun onListenerDisconnected() {
        settingsJob?.cancel()
        super.onListenerDisconnected()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (!monitoringEnabled) return
        if (!shouldInspect(sbn)) return
        // Hidden/redacted content (e.g. "Sensitive notification content hidden") simply yields no text.
        val text = extractVisibleText(sbn.notification) ?: return
        val urls = UrlExtractor.extract(text)
        if (urls.isEmpty()) return
        val textIndicators = ScamTextAnalyzer.analyze(text)
        val app = appLabel(sbn.packageName)
        scope.launch { container.notificationProcessor.process(urls, textIndicators, app) }
    }

    private fun shouldInspect(sbn: StatusBarNotification): Boolean {
        if (sbn.packageName == packageName) return false
        val n = sbn.notification ?: return false
        if (sbn.isOngoing) return false
        if ((n.flags and Notification.FLAG_GROUP_SUMMARY) != 0) return false
        if ((n.flags and Notification.FLAG_FOREGROUND_SERVICE) != 0) return false
        val skipCategories = setOf(Notification.CATEGORY_CALL, Notification.CATEGORY_PROGRESS, Notification.CATEGORY_TRANSPORT, Notification.CATEGORY_SYSTEM, Notification.CATEGORY_ALARM)
        return n.category !in skipCategories
    }

    private fun appLabel(pkg: String): String = try {
        val pm = packageManager
        val info = if (Build.VERSION.SDK_INT >= 33) pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0)) else @Suppress("DEPRECATION") pm.getApplicationInfo(pkg, 0)
        pm.getApplicationLabel(info).toString()
    } catch (e: PackageManager.NameNotFoundException) {
        pkg
    }

    companion object {
        private const val MAX_CHARS = 8_000

        /** Collects only the user-visible text fields of a notification. */
        fun extractVisibleText(n: Notification?): String? {
            val extras: Bundle = n?.extras ?: return null
            val parts = mutableListOf<CharSequence>()
            listOf(Notification.EXTRA_TITLE, Notification.EXTRA_TEXT, Notification.EXTRA_BIG_TEXT, Notification.EXTRA_SUB_TEXT, Notification.EXTRA_SUMMARY_TEXT)
                .forEach { key -> extras.getCharSequence(key)?.let(parts::add) }
            extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.let { parts.addAll(it) }
            @Suppress("DEPRECATION")
            val messages: Array<Parcelable>? = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
            messages?.forEach { m -> (m as? Bundle)?.getCharSequence("text")?.let(parts::add) }
            if (parts.isEmpty()) return null
            return parts.joinToString("\n").take(MAX_CHARS)
        }
    }
}
