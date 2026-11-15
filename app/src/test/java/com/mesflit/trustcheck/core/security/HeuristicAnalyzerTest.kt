package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HeuristicAnalyzerTest {

    private fun indicators(url: String): Set<Indicator> =
        HeuristicAnalyzer.analyze((UrlNormalizer.parse(url) as ParseOutcome.Success).url).map { it.indicator }.toSet()

    @Test fun cleanWellKnownSitesHaveNoStrongIndicators() {
        for (u in listOf(
            "https://www.google.com/search", "https://www.paypal.com/signin", "https://accounts.google.com/",
            "https://www.amazon.de/", "https://www.google.com.tr/", "https://www.turkiye.gov.tr/",
            "https://github.com/mesflit/TrustCheck", "https://en.wikipedia.org/wiki/Phishing",
            "https://www.garantibbva.com.tr/", "https://support.apple.com/en-us",
        )) {
            val score = RiskScorer.score(HeuristicAnalyzer.analyze((UrlNormalizer.parse(u) as ParseOutcome.Success).url))
            assertTrue("$u scored $score", score < RiskScorer.SUSPICIOUS_THRESHOLD)
        }
    }

    @Test fun ipHosts() {
        assertTrue(Indicator.IP_ADDRESS_HOST in indicators("http://45.67.89.10/login"))
        assertTrue(Indicator.OBFUSCATED_IP_HOST in indicators("http://3232235777/"))
        assertTrue(Indicator.PRIVATE_NETWORK_HOST in indicators("http://192.168.1.1/"))
        assertFalse(Indicator.INSECURE_HTTP in indicators("http://192.168.1.1/"))
    }

    @Test fun userInfoTrick() {
        assertTrue(Indicator.USERINFO_IN_URL in indicators("https://www.paypal.com@203.0.113.9/"))
    }

    @Test fun lookalikesAndTyposquats() {
        assertTrue(Indicator.LOOKALIKE_BRAND in indicators("https://paypa1.com/"))
        assertTrue(Indicator.LOOKALIKE_BRAND in indicators("https://pay-pal.com/"))
        assertTrue(Indicator.LOOKALIKE_BRAND in indicators("https://rnicrosoft.com/"))
        assertTrue(Indicator.LOOKALIKE_BRAND in indicators("https://paypall.com/"))
        assertTrue(Indicator.LOOKALIKE_BRAND in indicators("https://netflix.top/"))
        assertFalse(Indicator.LOOKALIKE_BRAND in indicators("https://cooking.com/"))
    }

    @Test fun brandInSubdomainAndLabel() {
        assertTrue(Indicator.BRAND_IN_SUBDOMAIN in indicators("https://paypal.com.secure-check.xyz/"))
        assertTrue(Indicator.BRAND_IN_DOMAIN_LABEL in indicators("https://paypal-secure-login.com/"))
        assertTrue(Indicator.BRAND_IN_DOMAIN_LABEL in indicators("https://applesupport.net/"))
        assertFalse(Indicator.BRAND_IN_DOMAIN_LABEL in indicators("https://applebees.com/"))
        assertFalse(Indicator.BRAND_IN_DOMAIN_LABEL in indicators("https://googleusercontent.com/"))
    }

    @Test fun homographs() {
        // Cyrillic "аррӏе"
        val cyr = indicators("https://аррӏе.com/")
        assertTrue(Indicator.HOMOGRAPH_OF_BRAND in cyr)
        assertTrue(Indicator.WHOLE_SCRIPT_CONFUSABLE in cyr)
        assertTrue(Indicator.PUNYCODE_DOMAIN in cyr)
        // Latin "p" + Cyrillic "а"
        assertTrue(Indicator.MIXED_SCRIPT_DOMAIN in indicators("https://pаypal.com/"))
        // Legitimate IDNs are not treated as homographs
        assertFalse(Indicator.MIXED_SCRIPT_DOMAIN in indicators("https://türkiye.example/"))
        assertFalse(Indicator.WHOLE_SCRIPT_CONFUSABLE in indicators("https://яндекс.рф/"))
        assertFalse(Indicator.MIXED_SCRIPT_DOMAIN in indicators("https://日本語ドメイン.jp/"))
    }

    @Test fun shortenersAndTransport() {
        assertTrue(Indicator.URL_SHORTENER in indicators("https://bit.ly/abc"))
        assertFalse(Indicator.URL_SHORTENER in indicators("https://youtu.be/abc"))
        assertTrue(Indicator.INSECURE_HTTP in indicators("http://example.com/"))
        assertTrue(Indicator.NON_STANDARD_PORT in indicators("https://example.com:2083/"))
    }

    @Test fun pathAndQuerySignals() {
        assertTrue(Indicator.EXECUTABLE_DOWNLOAD in indicators("https://example.com/update/WhatsApp.apk"))
        assertTrue(Indicator.EMBEDDED_URL_PARAMETER in indicators("https://example.com/r?url=https%3A%2F%2Fevil.example"))
        assertTrue(Indicator.SENSITIVE_DATA_IN_URL in indicators("https://example.com/x?password=hunter2"))
        assertTrue(Indicator.SUSPICIOUS_KEYWORDS in indicators("https://example.com/secure/login/verify"))
        assertTrue(Indicator.SUSPICIOUS_TLD in indicators("https://example.xyz/"))
        assertTrue(Indicator.EXCESSIVE_SUBDOMAINS in indicators("https://a.b.c.d.example.com/"))
        assertTrue(Indicator.MANY_HYPHENS in indicators("https://secure-account-update-now.com/"))
    }

    @Test fun phishingExamplesAreSuspicious() {
        for (u in listOf(
            "http://paypal.com.account-verify.top/login",
            "https://аррӏе.com/icloud/unlock",
            "http://45.67.89.10/garanti/giris",
            "https://ziraat-bank-giris.xyz/",
            "https://www.paypal.com@203.0.113.9/signin",
        )) {
            val r = UrlAnalysisEngine().analyzeLocally(u)
            assertEquals(u, RiskClassification.SUSPICIOUS, r.classification)
        }
    }
}
