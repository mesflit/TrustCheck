package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ResultMergerTest {
    private val engine = UrlAnalysisEngine(clock = { 1_000L })

    private fun remote(status: SourceStatus, indicators: List<DetectedIndicator> = emptyList()) = engine.analyzeLocally("https://example.com/").copy(
        indicators = indicators,
        sources = listOf(SourceResult(AnalysisSource.TRUSTCHECK_BACKEND, status)),
        timestampMillis = 2_000L,
    )

    @Test fun remoteMatchEscalatesToMalicious() {
        val local = engine.analyzeLocally("https://example.com/")
        val merged = ResultMerger.merge(local, remote(SourceStatus.MATCH, listOf(DetectedIndicator(Indicator.THREAT_INTEL_MATCH, "MALWARE"))))
        assertEquals(RiskClassification.CONFIRMED_MALICIOUS, merged.classification)
        assertEquals(2_000L, merged.timestampMillis)
    }

    @Test fun cleanRemoteNeverDowngradesLocalWarning() {
        val local = engine.analyzeLocally("http://paypal.com.account-verify.top/login")
        assertEquals(RiskClassification.SUSPICIOUS, local.classification)
        val merged = ResultMerger.merge(local, remote(SourceStatus.NO_MATCH))
        assertEquals(RiskClassification.SUSPICIOUS, merged.classification)
        assertTrue(merged.riskScore >= local.riskScore)
    }

    @Test fun cleanRemoteUpgradesUnknownToNoKnownThreat() {
        val local = engine.analyzeLocally("https://example.com/")
        assertEquals(RiskClassification.UNKNOWN, local.classification)
        assertEquals(RiskClassification.NO_KNOWN_THREAT, ResultMerger.merge(local, remote(SourceStatus.NO_MATCH)).classification)
    }

    @Test fun textSignalsRaiseUrlRisk() {
        val url = engine.analyzeLocally("https://bit.ly/abc")
        assertEquals(RiskClassification.UNKNOWN, url.classification)
        val text = ScamTextAnalyzer.analyze("URGENT: customs fee unpaid, verify your account")
        assertEquals(RiskClassification.SUSPICIOUS, ResultMerger.withTextSignals(url, text).classification)
    }

    @Test fun textOnly() {
        assertEquals(RiskClassification.UNKNOWN, ResultMerger.textOnly(emptyList(), 0).classification)
        val r = ResultMerger.textOnly(ScamTextAnalyzer.analyze("You have won! Pay the delivery fee and send the verification code"), 0)
        assertEquals(RiskClassification.SUSPICIOUS, r.classification)
    }
}
