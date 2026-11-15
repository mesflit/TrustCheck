// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.network

import com.mesflit.trustcheck.core.network.dto.AiAnalyzeRequest
import com.mesflit.trustcheck.core.network.dto.AiAnalyzeResponse
import com.mesflit.trustcheck.domain.AiAnalysisProvider
import com.mesflit.trustcheck.domain.AiExplanation
import com.mesflit.trustcheck.domain.AiIndicatorNote
import com.mesflit.trustcheck.domain.AiRequest
import com.mesflit.trustcheck.domain.AiResult
import com.mesflit.trustcheck.domain.SettingsRepository

/**
 * AI explanations through TrustCheck-Backend. The backend owns the model provider and its key;
 * the app only sees structured JSON. Responses are shown as-is and labelled as AI-generated.
 */
class BackendAiAnalysisProvider(
    private val backend: BackendClient,
    private val settings: SettingsRepository,
    private val limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(5, 60_000),
) : AiAnalysisProvider {

    override suspend fun isConfigured(): Boolean = backend.isConfigured

    override suspend fun explain(request: AiRequest): AiResult {
        if (!backend.isConfigured) return AiResult.NotConfigured
        if (!settings.current().cloudAi) return AiResult.NoConsent
        if (!limiter.tryAcquire(System.currentTimeMillis())) return AiResult.RateLimited
        val body = AiAnalyzeRequest(
            url = request.url,
            text = request.text?.take(4_000),
            language = request.language,
            localIndicators = request.localIndicators,
            localClassification = request.localClassification,
        )
        return when (val r = backend.post("v1/ai/analyze", body, AiAnalyzeRequest.serializer(), AiAnalyzeResponse.serializer(), timeoutSeconds = 30)) {
            is ApiResult.Ok -> {
                val v = r.value
                if (v.summary.isBlank()) return AiResult.Error("empty_response")
                AiResult.Success(
                    AiExplanation(
                        verdict = v.verdict,
                        riskScore = v.riskScore?.coerceIn(0, 100),
                        summary = v.summary,
                        notes = v.indicators.map { AiIndicatorNote(it.code, it.explanation) },
                        recommendations = v.recommendations,
                        language = v.language,
                        model = v.model,
                        createdAt = System.currentTimeMillis(),
                    ),
                )
            }
            ApiResult.NotConfigured -> AiResult.NotConfigured
            ApiResult.RateLimited -> AiResult.RateLimited
            is ApiResult.HttpError -> AiResult.Error("http_${r.code}")
            is ApiResult.NetworkError -> AiResult.Error(r.message)
        }
    }
}
