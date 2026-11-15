// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/** Pure helpers to combine partial results (instant local scan + deferred cloud scan, URL + message text). */
object ResultMerger {

    private val reputationIndicators = setOf(Indicator.THREAT_INTEL_MATCH, Indicator.BLOCKLIST_MATCH)

    fun recompute(base: UrlAnalysisResult, indicators: List<DetectedIndicator>, sources: List<SourceResult>, now: Long = base.timestampMillis): UrlAnalysisResult {
        val unique = indicators.distinctBy { it.indicator }
        val score = RiskScorer.score(unique.filter { it.indicator !in reputationIndicators })
        val classification = RiskScorer.classify(score, sources)
        return base.copy(
            indicators = unique.sortedByDescending { it.indicator.weight },
            sources = sources,
            riskScore = RiskScorer.finalScore(score, classification),
            classification = classification,
            timestampMillis = now,
        )
    }

    /** Deferred (network) result merged into the earlier local one. Never downgrades local warnings. */
    fun merge(local: UrlAnalysisResult, remote: UrlAnalysisResult): UrlAnalysisResult {
        if (remote.classification == RiskClassification.ANALYSIS_FAILED) return local
        val indicators = local.indicators + remote.indicators
        val sources = (remote.sources + local.sources).distinctBy { it.source }
        return recompute(local.copy(finalUrl = remote.finalUrl ?: local.finalUrl), indicators, sources, remote.timestampMillis)
    }

    /** Adds message-level phrase indicators to a URL found in that message. */
    fun withTextSignals(url: UrlAnalysisResult, textIndicators: List<DetectedIndicator>): UrlAnalysisResult {
        if (textIndicators.isEmpty() || url.classification == RiskClassification.ANALYSIS_FAILED) return url
        return recompute(url, url.indicators + textIndicators, url.sources)
    }

    /** A message with no links: only phrase indicators; can reach SUSPICIOUS at most. */
    fun textOnly(textIndicators: List<DetectedIndicator>, now: Long): UrlAnalysisResult {
        val score = RiskScorer.score(textIndicators)
        val sources = listOf(SourceResult(AnalysisSource.LOCAL_HEURISTICS, if (textIndicators.isEmpty()) SourceStatus.NO_MATCH else SourceStatus.MATCH))
        return UrlAnalysisResult(
            input = "",
            normalizedUrl = null,
            displayHost = null,
            registrableDomain = null,
            finalUrl = null,
            indicators = textIndicators.sortedByDescending { it.indicator.weight },
            riskScore = score,
            classification = RiskScorer.classify(score, sources),
            sources = sources,
            timestampMillis = now,
        )
    }
}
