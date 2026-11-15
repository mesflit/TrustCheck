// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.service.notification

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.mesflit.trustcheck.MainActivity
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.localization.AppLanguage
import com.mesflit.trustcheck.core.localization.LocaleController
import com.mesflit.trustcheck.core.localization.SecurityStrings
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.UrlAnalysisResult

/**
 * Posts localized security alerts. Alerts never contain ads and never open the link — tapping an
 * alert opens TrustCheck's report screen.
 */
class AlertNotifier(private val appContext: Context) {

    fun ensureChannels(language: AppLanguage) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val ctx = LocaleController.localizedContext(appContext, language)
        val nm = appContext.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERTS, ctx.getString(R.string.channel_alerts), NotificationManager.IMPORTANCE_HIGH).apply {
                description = ctx.getString(R.string.channel_alerts_desc)
            },
        )
    }

    fun canPost(): Boolean {
        val granted = Build.VERSION.SDK_INT < 33 ||
            ContextCompat.checkSelfPermission(appContext, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        return granted && NotificationManagerCompat.from(appContext).areNotificationsEnabled()
    }

    @SuppressLint("MissingPermission") // checked in canPost()
    fun postAlert(recordId: Long, result: UrlAnalysisResult, sourceApp: String?, language: AppLanguage) {
        if (!canPost()) return
        if (result.classification != RiskClassification.CONFIRMED_MALICIOUS && result.classification != RiskClassification.SUSPICIOUS) return
        ensureChannels(language)
        val ctx = LocaleController.localizedContext(appContext, language)
        val title = ctx.getString(
            if (result.classification == RiskClassification.CONFIRMED_MALICIOUS) R.string.alert_title_malicious else R.string.alert_title_suspicious,
        )
        val host = result.displayHost ?: result.normalizedUrl ?: ""
        val reason = result.indicators.firstOrNull()?.let { ctx.getString(SecurityStrings.indicatorTitle(it.indicator)) }
        val body = buildString {
            append(if (sourceApp != null) ctx.getString(R.string.alert_body_from_app, host, sourceApp) else ctx.getString(R.string.alert_body, host))
            if (reason != null) append('\n').append(reason)
        }
        val intent = Intent(appContext, MainActivity::class.java).apply {
            action = ACTION_OPEN_REPORT
            putExtra(EXTRA_SCAN_ID, recordId)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pi = PendingIntent.getActivity(appContext, recordId.toInt(), intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = NotificationCompat.Builder(appContext, CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(body.substringBefore('\n'))
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .setColor(ContextCompat.getColor(appContext, R.color.alert_red))
            .setAutoCancel(true)
            .setContentIntent(pi)
            .addAction(0, ctx.getString(R.string.alert_action_view), pi)
            .build()
        try {
            NotificationManagerCompat.from(appContext).notify(TAG, recordId.toInt(), notification)
        } catch (e: SecurityException) {
            // Permission revoked between check and post; nothing else to do.
        }
    }

    companion object {
        const val CHANNEL_ALERTS = "security_alerts"
        const val TAG = "trustcheck_alert"
        const val ACTION_OPEN_REPORT = "com.mesflit.trustcheck.action.OPEN_REPORT"
        const val EXTRA_SCAN_ID = "scan_id"
    }
}
