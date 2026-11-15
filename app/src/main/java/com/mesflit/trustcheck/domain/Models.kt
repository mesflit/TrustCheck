// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.domain

import com.mesflit.trustcheck.core.localization.AppLanguage
import com.mesflit.trustcheck.core.network.DailyQuota
import com.mesflit.trustcheck.core.security.DetectedIndicator
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.SourceResult

enum class TargetType { URL, TEXT }

enum class ScanOrigin { MANUAL, SHARE_TEXT, SHARE_IMAGE, LINK_OPEN, TEXT_SELECTION, NOTIFICATION }

enum class UserAction { NONE, OPENED_ANYWAY, DISMISSED }

data class AiIndicatorNote(val code: String, val explanation: String)

/** Structured, provider-independent AI explanation. Only ever produced by a real AI response. */
data class AiExplanation(
    val verdict: String,
    val riskScore: Int?,
    val summary: String,
    val notes: List<AiIndicatorNote>,
    val recommendations: List<String>,
    val language: String,
    val model: String,
    val createdAt: Long,
)

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
    val ai: AiExplanation?,
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
    /** Consent to send privacy-reduced URLs to threat-intelligence services. */
    val cloudThreatIntel: Boolean = false,
    /** Consent to send content to the AI explanation service when the user asks for it. */
    val cloudAi: Boolean = false,
    /** Contact URL shorteners (HEAD request only) to reveal the destination. */
    val resolveRedirects: Boolean = false,
    /** Keep notification links with no warning signs in history (default: only warnings are kept). */
    val keepCleanNotificationScans: Boolean = false,
    val retentionDays: Int = 30,
    /** Attach app/OS version to backend requests to help debugging. */
    val diagnostics: Boolean = false,
    /** User-supplied Google Safe Browsing key (stored only on this device). */
    val safeBrowsingApiKey: String = "",
    val aiQuota: DailyQuota = DailyQuota(0, 0),
    val totalScans: Long = 0,
)
