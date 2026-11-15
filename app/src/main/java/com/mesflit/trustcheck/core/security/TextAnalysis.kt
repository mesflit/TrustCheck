// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/** Result of analyzing a shared message: per-URL results plus message-level phrase indicators. */
data class TextAnalysisResult(
    val urlResults: List<UrlAnalysisResult>,
    val textIndicators: List<DetectedIndicator>,
    val textScore: Int,
) {
    /** The worst classification across URLs and text. Text alone can reach SUSPICIOUS at most. */
    val overall: RiskClassification
        get() {
            val urlWorst = urlResults.map { it.classification }.minByOrNull { it.ordinal }
            val textClass = if (textScore >= RiskScorer.SUSPICIOUS_THRESHOLD) RiskClassification.SUSPICIOUS else RiskClassification.UNKNOWN
            // Enum order is worst-first, so the minimum ordinal is the most severe verdict.
            // Text can never produce NO_KNOWN_THREAT on its own.
            return listOfNotNull(urlWorst, textClass).minBy { it.ordinal }
        }
}

class TextAnalyzer(private val engine: UrlAnalysisEngine) {
    suspend fun analyze(text: String, options: AnalysisOptions): TextAnalysisResult {
        val urls = UrlExtractor.extract(text)
        val results = urls.map { engine.analyze(it, options) }
        val textIndicators = ScamTextAnalyzer.analyze(text)
        // Message cues raise concern more when the message also carries a link.
        val base = RiskScorer.score(textIndicators)
        val textScore = if (urls.isEmpty()) base else (base + base / 2).coerceAtMost(100)
        return TextAnalysisResult(results, textIndicators, textScore)
    }
}
