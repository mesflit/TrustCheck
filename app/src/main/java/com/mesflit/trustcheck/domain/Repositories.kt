// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.domain

import com.mesflit.trustcheck.core.localization.AppLanguage
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.UrlAnalysisResult
import kotlinx.coroutines.flow.Flow

interface ScanRepository {
    suspend fun save(
        result: UrlAnalysisResult,
        targetType: TargetType,
        origin: ScanOrigin,
        sourceApp: String?,
    ): Long

    suspend fun updateResult(id: Long, result: UrlAnalysisResult)
    suspend fun get(id: Long): ScanRecord?
    fun observe(id: Long): Flow<ScanRecord?>
    fun observeHistory(query: String, filter: Set<RiskClassification>): Flow<List<ScanRecord>>
    fun observeRecentAlerts(limit: Int): Flow<List<ScanRecord>>
    fun observeStats(): Flow<ScanStats>
    suspend fun findRecent(normalizedUrl: String, sinceMillis: Long): ScanRecord?
    suspend fun setUserAction(id: Long, action: UserAction)
    suspend fun attachAi(id: Long, ai: AiExplanation)
    suspend fun delete(id: Long)
    suspend fun clearAll()
    suspend fun purgeOlderThan(cutoffMillis: Long): Int
}

interface SettingsRepository {
    val settings: Flow<AppSettings>
    suspend fun current(): AppSettings
    suspend fun update(transform: (AppSettings) -> AppSettings)
    suspend fun setLanguage(language: AppLanguage)
    suspend fun incrementTotalScans(by: Int = 1)
    suspend fun consumeAiQuota(day: Long)
    suspend fun addAiBonus(day: Long, amount: Int)
    suspend fun backendToken(): String?
    suspend fun setBackendToken(token: String?)
}

/** Result of an AI explanation request. Never synthesized locally. */
sealed interface AiResult {
    data class Success(val explanation: AiExplanation) : AiResult
    data object NotConfigured : AiResult
    data object NoConsent : AiResult
    data object QuotaExceeded : AiResult
    data object RateLimited : AiResult
    data class Error(val reason: String) : AiResult
}

data class AiRequest(
    val url: String?,
    /** Message text, only when the user explicitly chose to include it. */
    val text: String?,
    val localIndicators: List<String>,
    val localClassification: String,
    val language: String,
)

/** Provider-independent interface for cloud AI analysis. */
interface AiAnalysisProvider {
    suspend fun isConfigured(): Boolean
    suspend fun explain(request: AiRequest): AiResult
}
