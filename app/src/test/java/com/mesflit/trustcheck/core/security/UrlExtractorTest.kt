package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlExtractorTest {
    @Test fun findsSchemeWwwAndBareDomains() {
        val text = "Your parcel is held: https://dhl-track.top/pay?id=9. Or visit www.example.com, or paypal-verify.xyz/login now!"
        assertEquals(
            listOf("https://dhl-track.top/pay?id=9", "www.example.com", "paypal-verify.xyz/login"),
            UrlExtractor.extract(text),
        )
    }

    @Test fun stripsTrailingPunctuationAndUnbalancedParens() {
        assertEquals(listOf("https://example.com/a_(b)"), UrlExtractor.extract("(see https://example.com/a_(b)))."))
    }

    @Test fun ignoresFileNamesAndVersionNumbers() {
        assertTrue(UrlExtractor.extract("open report.pdf and notes.txt, version 1.2.3").isEmpty())
    }

    @Test fun handlesDefangedAndDangerousUrls() {
        val found = UrlExtractor.extract("hxxps://evil.example/x and javascript:alert(1)")
        assertTrue(found.contains("https://evil.example/x"))
        assertTrue(found.any { it.startsWith("javascript:") })
    }

    @Test fun findsUnicodeHosts() {
        assertEquals(listOf("https://аррӏе.com/id"), UrlExtractor.extract("Apple ID locked: https://аррӏе.com/id"))
    }

    @Test fun deduplicatesAndCaps() {
        val many = (1..50).joinToString(" ") { "https://site$it.com" }
        assertEquals(UrlExtractor.MAX_RESULTS, UrlExtractor.extract(many).size)
        assertEquals(1, UrlExtractor.extract("https://a.com https://a.com").size)
    }

    @Test fun emptyInput() {
        assertTrue(UrlExtractor.extract("   ").isEmpty())
    }
}
