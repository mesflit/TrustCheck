// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.domain

import com.mesflit.trustcheck.core.localization.AppLanguage
import com.mesflit.trustcheck.core.security.DetectedIndicator
import com.mesflit.trustcheck.core.security.FileFacts
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.SourceResult

enum class TargetType { URL, TEXT, FILE }

enum class ScanOrigin { MANUAL, SHARE_TEXT, SHARE_IMAGE, LINK_OPEN, TEXT_SELECTION, NOTIFICATION, FILE, QR_CODE }

enum class UserAction { NONE, OPENED_ANYWAY, DISMISSED }

data class ScanRecord(
    val id: Long,
    val targetType: TargetType,
    val normalizedUrl: String?,
    val displayHost: String?,
    val registrableDomain: String?,
    val finalUrl: String?,
    val classification: RiskClassification,
    val riskScore: Int,
    val indicators: List<DetectedIndicator>,
    val sources: List<SourceResult>,
    val origin: ScanOrigin,
    val sourceApp: String?,
    val userAction: UserAction,
    /** File metadata (name, size, type, SHA-256, APK facts) for FILE scans; never file contents. */
    val file: FileFacts? = null,
    val timestamp: Long,
)

data class ScanStats(val total: Int, val suspicious: Int, val malicious: Int)

enum class ThemeMode { SYSTEM, LIGHT, DARK }

data class AppSettings(
    val onboardingCompleted: Boolean = false,
    val theme: ThemeMode = ThemeMode.SYSTEM,
    val language: AppLanguage = AppLanguage.SYSTEM,
    /** In-app switch; the system Notification Access grant is required as well. */
    val notificationMonitoring: Boolean = false,
    val alertsEnabled: Boolean = true,
    /** Download the daily threat list from GitHub and check links against it on the device. */
    val threatFeed: Boolean = true,
    /** Consent to send privacy-reduced URLs to online lookup services (own Safe Browsing key / optional backend). */
    val cloudThreatIntel: Boolean = false,
    /** Contact URL shorteners (HEAD request only) to reveal the destination. */
    val resolveRedirects: Boolean = false,
    /** Keep notification links with no warning signs in history (default: only warnings are kept). */
    val keepCleanNotificationScans: Boolean = false,
    val retentionDays: Int = 30,
    /** Attach app/OS version to backend requests to help debugging. */
    val diagnostics: Boolean = false,
    /** User-supplied Google Safe Browsing key (stored only on this device). */
    val safeBrowsingApiKey: String = "",
    val totalScans: Long = 0,
)
