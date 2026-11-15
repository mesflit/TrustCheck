// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.domain

import com.mesflit.trustcheck.core.security.AnalysisOptions
import com.mesflit.trustcheck.core.security.DetectedIndicator
import com.mesflit.trustcheck.core.security.ResultMerger
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.ScamTextAnalyzer
import com.mesflit.trustcheck.core.security.UrlAnalysisEngine
import com.mesflit.trustcheck.core.security.UrlAnalysisResult
import com.mesflit.trustcheck.core.security.UrlExtractor

data class ScanOutcome(val recordId: Long?, val result: UrlAnalysisResult)

data class TextScanOutcome(
    val items: List<ScanOutcome>,
    val textIndicators: List<DetectedIndicator>,
    val overall: RiskClassification,
)

/**
 * Single entry point for user-initiated scans (scanner, share sheet, link open, OCR).
 * Results are always produced by [UrlAnalysisEngine]; nothing here invents verdicts.
 */
class ScanCoordinator(
    private val engine: UrlAnalysisEngine,
    private val scans: ScanRepository,
    private val settings: SettingsRepository,
    private val isOnline: () -> Boolean,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    suspend fun options(): AnalysisOptions {
        val s = settings.current()
        return AnalysisOptions(
            allowNetwork = isOnline() && (s.cloudThreatIntel || s.resolveRedirects),
            resolveRedirects = s.resolveRedirects,
        )
    }

    suspend fun scanUrl(input: String, origin: ScanOrigin, sourceApp: String? = null): ScanOutcome {
        val result = engine.analyze(input, options())
        settings.incrementTotalScans()
        val id = if (result.classification == RiskClassification.ANALYSIS_FAILED) null
        else scans.save(result, TargetType.URL, origin, sourceApp)
        return ScanOutcome(id, result)
    }

    /** Scans free text. Only extracted URLs and indicator codes are stored — never the text. */
    suspend fun scanText(text: String, origin: ScanOrigin): TextScanOutcome {
        val opts = options()
        val urls = UrlExtractor.extract(text)
        val textIndicators = ScamTextAnalyzer.analyze(text)
        val items = if (urls.isEmpty()) {
            val r = ResultMerger.textOnly(textIndicators, clock())
            listOf(ScanOutcome(scans.save(r, TargetType.TEXT, origin, null), r))
        } else {
            urls.map { u ->
                val r = ResultMerger.withTextSignals(engine.analyze(u, opts), textIndicators)
                val id = if (r.classification == RiskClassification.ANALYSIS_FAILED) null else scans.save(r, TargetType.URL, origin, null)
                ScanOutcome(id, r)
            }
        }
        settings.incrementTotalScans(items.size)
        val overall = items.map { it.result.classification }.minBy { it.ordinal }
        return TextScanOutcome(items, textIndicators, overall)
    }
}
