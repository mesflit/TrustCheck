// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

object RiskScorer {
    const val SUSPICIOUS_THRESHOLD = 40
    private const val KEYWORD_CAP = 3

    /** Sums indicator weights (keywords counted per hit up to a cap) into 0–100. */
    fun score(indicators: List<DetectedIndicator>): Int {
        var total = 0
        for (d in indicators.distinctBy { it.indicator }) {
            total += if (d.indicator == Indicator.SUSPICIOUS_KEYWORDS) {
                val hits = d.detail?.split(',')?.size ?: 1
                d.indicator.weight * hits.coerceAtMost(KEYWORD_CAP)
            } else {
                d.indicator.weight
            }
        }
        return total.coerceIn(0, 100)
    }

    /**
     * Classification rules (see docs/DETECTION.md):
     *  1. Any reputation MATCH → CONFIRMED_MALICIOUS.
     *  2. Local score ≥ threshold → SUSPICIOUS.
     *  3. At least one reputation source answered NO_MATCH → NO_KNOWN_THREAT.
     *  4. Otherwise → UNKNOWN (absence of evidence is not evidence of safety).
     */
    fun classify(score: Int, sources: List<SourceResult>): RiskClassification {
        val reputation = sources.filter { it.source.isReputation }
        return when {
            reputation.any { it.status == SourceStatus.MATCH } -> RiskClassification.CONFIRMED_MALICIOUS
            score >= SUSPICIOUS_THRESHOLD -> RiskClassification.SUSPICIOUS
            reputation.any { it.status == SourceStatus.NO_MATCH } -> RiskClassification.NO_KNOWN_THREAT
            else -> RiskClassification.UNKNOWN
        }
    }

    fun finalScore(score: Int, classification: RiskClassification): Int = when (classification) {
        RiskClassification.CONFIRMED_MALICIOUS -> maxOf(score, 95)
        RiskClassification.ANALYSIS_FAILED -> 0
        else -> score
    }
}
