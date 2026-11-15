// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.files

import android.net.Uri
import com.mesflit.trustcheck.core.security.DetectedIndicator
import com.mesflit.trustcheck.core.security.DomainUtils
import com.mesflit.trustcheck.core.security.FileFacts
import com.mesflit.trustcheck.core.security.FileInspector
import com.mesflit.trustcheck.core.security.Indicator
import com.mesflit.trustcheck.core.security.ParseOutcome
import com.mesflit.trustcheck.core.security.ResultMerger
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.ScamTextAnalyzer
import com.mesflit.trustcheck.core.security.UrlAnalysisEngine
import com.mesflit.trustcheck.core.security.UrlAnalysisResult
import com.mesflit.trustcheck.core.security.UrlExtractor
import com.mesflit.trustcheck.core.security.UrlNormalizer
import com.mesflit.trustcheck.domain.ScanCoordinator
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.ScanOutcome
import com.mesflit.trustcheck.domain.ScanRepository
import com.mesflit.trustcheck.domain.SettingsRepository
import com.mesflit.trustcheck.domain.TargetType

data class FileScanOutcome(
    val file: ScanOutcome?,
    val facts: FileFacts?,
    /** Links found inside the file, each analyzed and saved separately. */
    val links: List<ScanOutcome>,
    val failure: String? = null,
)

/** File scanning: on-device inspection, then analysis of every link found inside the file. */
class FileScanService(
    private val scanner: FileScanner,
    private val engine: UrlAnalysisEngine,
    private val coordinator: ScanCoordinator,
    private val scans: ScanRepository,
    private val settings: SettingsRepository,
    private val homeCountry: () -> String? = { null },
    private val clock: () -> Long = System::currentTimeMillis,
) {
    suspend fun scan(uri: Uri, origin: ScanOrigin = ScanOrigin.FILE): FileScanOutcome {
        val inspected = when (val o = scanner.inspect(uri)) {
            is FileScanner.Outcome.Failed -> return FileScanOutcome(null, null, emptyList(), o.reason)
            is FileScanner.Outcome.Success -> o
        }
        val facts = inspected.facts
        val text = inspected.text
        val indicators = FileInspector.analyze(facts).toMutableList()

        val links = mutableListOf<ScanOutcome>()
        var phraseIndicators: List<DetectedIndicator> = emptyList()
        if (text != null) {
            val options = coordinator.options()
            val urls = UrlExtractor.extract(text).filter { isRealLink(it) }.take(MAX_LINKS)
            phraseIndicators = ScamTextAnalyzer.analyze(text, homeCountry())
            for (u in urls) {
                val r: UrlAnalysisResult = ResultMerger.withTextSignals(engine.analyze(u, options), phraseIndicators)
                if (r.classification == RiskClassification.ANALYSIS_FAILED) continue
                links += ScanOutcome(scans.save(r, TargetType.URL, origin, null), r)
            }
            val worst = links.minByOrNull { it.result.classification.ordinal }?.result
            if (worst != null && worst.classification.ordinal <= RiskClassification.SUSPICIOUS.ordinal) {
                indicators += DetectedIndicator(Indicator.FILE_CONTAINS_DANGEROUS_LINK, worst.displayHost)
            }
        }

        val result = FileInspector.result(facts, indicators + phraseIndicators, clock())
        val id = scans.save(result, TargetType.FILE, origin, null, facts)
        settings.incrementTotalScans(1 + links.size)
        return FileScanOutcome(ScanOutcome(id, result), facts, links)
    }

    /** Skips XML namespace URIs and similar non-links found inside Office/SVG files. */
    private fun isRealLink(url: String): Boolean {
        val host = (UrlNormalizer.parse(url) as? ParseOutcome.Success)?.url?.asciiHost ?: return url.contains(':')
        return host !in FileInspector.NON_LINK_HOSTS && DomainUtils.registrableDomain(host) !in FileInspector.NON_LINK_HOSTS
    }

    companion object {
        const val MAX_LINKS = 20
    }
}
