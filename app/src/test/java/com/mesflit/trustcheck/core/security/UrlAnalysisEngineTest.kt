package com.mesflit.trustcheck.core.security

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Engine classification tests. The providers below are *test doubles* that live only in the test
 * source set; production code never contains canned verdicts.
 */
class UrlAnalysisEngineTest {

    private class StubProvider(
        private val available: Boolean,
        private val answer: (List<String>) -> SourceResult,
        override val source: AnalysisSource = AnalysisSource.TRUSTCHECK_BACKEND,
    ) : ThreatIntelProvider {
        var calls = 0
        override suspend fun isAvailable() = available
        override suspend fun lookup(urlKeys: List<String>): SourceResult { calls++; return answer(urlKeys) }
    }

    private val online = AnalysisOptions(allowNetwork = true, resolveRedirects = true, lookupTimeoutMillis = 500)
    private val offline = online.copy(allowNetwork = false)

    @Test fun threatIntelMatchIsConfirmedMalicious() = runBlocking {
        val p = StubProvider(true, { SourceResult(AnalysisSource.TRUSTCHECK_BACKEND, SourceStatus.MATCH, "SOCIAL_ENGINEERING") })
        val r = UrlAnalysisEngine(listOf(p)).analyze("https://example.com/", online)
        assertEquals(RiskClassification.CONFIRMED_MALICIOUS, r.classification)
        assertTrue(r.riskScore >= 95)
        assertTrue(r.indicators.any { it.indicator == Indicator.THREAT_INTEL_MATCH })
    }

    @Test fun cleanLookupIsNoKnownThreatNeverSafe() = runBlocking {
        val p = StubProvider(true, { SourceResult(AnalysisSource.TRUSTCHECK_BACKEND, SourceStatus.NO_MATCH) })
        val r = UrlAnalysisEngine(listOf(p)).analyze("https://example.com/", online)
        assertEquals(RiskClassification.NO_KNOWN_THREAT, r.classification)
    }

    @Test fun offlineIsUnknownNotSafe() = runBlocking {
        val p = StubProvider(true, { error("must not be called offline") })
        val r = UrlAnalysisEngine(listOf(p)).analyze("https://example.com/", offline)
        assertEquals(RiskClassification.UNKNOWN, r.classification)
        assertEquals(0, p.calls)
        assertTrue(r.sources.any { it.status == SourceStatus.SKIPPED })
    }

    @Test fun unconfiguredProviderIsUnknown() = runBlocking {
        val p = StubProvider(false, { error("not available") })
        val r = UrlAnalysisEngine(listOf(p)).analyze("https://example.com/", online)
        assertEquals(RiskClassification.UNKNOWN, r.classification)
        assertTrue(r.sources.any { it.status == SourceStatus.UNAVAILABLE })
    }

    @Test fun errorOrTimeoutIsUnknown() = runBlocking {
        val slow = object : ThreatIntelProvider {
            override val source = AnalysisSource.GOOGLE_SAFE_BROWSING
            override suspend fun isAvailable() = true
            override suspend fun lookup(urlKeys: List<String>): SourceResult { delay(5_000); return SourceResult(source, SourceStatus.NO_MATCH) }
        }
        val r = UrlAnalysisEngine(listOf(slow)).analyze("https://example.com/", online)
        assertEquals(RiskClassification.UNKNOWN, r.classification)
        assertTrue(r.sources.any { it.status == SourceStatus.ERROR && it.detail == "timeout" })
    }

    @Test fun heuristicsWinOverCleanLookup() = runBlocking {
        val p = StubProvider(true, { SourceResult(AnalysisSource.TRUSTCHECK_BACKEND, SourceStatus.NO_MATCH) })
        val r = UrlAnalysisEngine(listOf(p)).analyze("http://paypal.com.account-verify.top/login", online)
        assertEquals(RiskClassification.SUSPICIOUS, r.classification)
    }

    @Test fun blocklistMatchIsConfirmed() = runBlocking {
        val bl = object : LocalBlocklist {
            override suspend fun isEmpty() = false
            override suspend fun match(hostAndParents: List<String>) = if ("bad.example" in hostAndParents) "phishing" else null
        }
        val r = UrlAnalysisEngine(blocklist = bl).analyze("https://login.bad.example/x", offline)
        assertEquals(RiskClassification.CONFIRMED_MALICIOUS, r.classification)
    }

    @Test fun lookupReceivesPrivacyReducedKeys() = runBlocking {
        var seen: List<String> = emptyList()
        val p = StubProvider(true, { keys -> seen = keys; SourceResult(AnalysisSource.TRUSTCHECK_BACKEND, SourceStatus.NO_MATCH) })
        UrlAnalysisEngine(listOf(p)).analyze("https://user:pw@example.com/reset?token=abc#f", online)
        assertEquals(listOf("https://example.com/reset"), seen)
    }

    @Test fun redirectsAreFollowedAndFinalDomainAnalyzed() = runBlocking {
        val resolver = object : RedirectResolver {
            override suspend fun resolve(url: String, maxHops: Int) = listOf("https://paypal-secure-login.top/verify")
        }
        val r = UrlAnalysisEngine(redirectResolver = resolver).analyze("https://bit.ly/abc", online)
        assertEquals("https://paypal-secure-login.top/verify", r.finalUrl)
        assertTrue(r.indicators.any { it.indicator == Indicator.REDIRECTS_TO_OTHER_DOMAIN })
        assertEquals(RiskClassification.SUSPICIOUS, r.classification)
    }

    @Test fun dangerousSchemeAndFailure() = runBlocking {
        val js = UrlAnalysisEngine().analyze("javascript:alert(document.cookie)", offline)
        assertEquals(RiskClassification.SUSPICIOUS, js.classification)
        val bad = UrlAnalysisEngine().analyze("not a url at all", offline)
        assertEquals(RiskClassification.ANALYSIS_FAILED, bad.classification)
        assertEquals(0, bad.riskScore)
    }

    @Test fun textAnalysisCombinesUrlAndPhrases() = runBlocking {
        val r = TextAnalyzer(UrlAnalysisEngine()).analyze(
            "URGENT: your account will be suspended. Verify your account at http://45.67.89.10/login",
            offline,
        )
        assertEquals(1, r.urlResults.size)
        assertTrue(r.textIndicators.any { it.indicator == Indicator.URGENCY_LANGUAGE })
        assertTrue(r.textIndicators.any { it.indicator == Indicator.CREDENTIAL_REQUEST })
        assertEquals(RiskClassification.SUSPICIOUS, r.overall)
    }

    @Test fun benignTextIsUnknown() = runBlocking {
        val r = TextAnalyzer(UrlAnalysisEngine()).analyze("See you at dinner tomorrow", offline)
        assertEquals(RiskClassification.UNKNOWN, r.overall)
    }
}
