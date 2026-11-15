package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlNormalizerTest {

    private fun ok(s: String) = (UrlNormalizer.parse(s) as ParseOutcome.Success).url

    @Test fun lowercasesHostAndDropsDefaultPortAndFragment() {
        val u = ok("HTTPS://WWW.Example.COM:443/a/./b/../c?x=1#frag")
        assertEquals("www.example.com", u.asciiHost)
        assertNull(u.port)
        assertEquals("/a/c", u.path)
        assertEquals("x=1", u.query)
        assertEquals("https://www.example.com/a/c", u.lookupKey)
    }

    @Test fun infersHttpsWhenSchemeMissing() {
        val u = ok("example.org/path")
        assertTrue(u.schemeInferred)
        assertEquals("https", u.scheme)
        assertEquals("https://example.org/path", u.lookupKey)
    }

    @Test fun keepsNonDefaultPort() {
        assertEquals("http://example.com:8081/", ok("http://example.com:8081").lookupKey)
    }

    @Test fun extractsUserInfo() {
        val u = ok("https://paypal.com@evil.example/login")
        assertEquals("paypal.com", u.userInfo)
        assertEquals("evil.example", u.asciiHost)
    }

    @Test fun convertsUnicodeHostToPunycode() {
        val u = ok("https://bücher.de/")
        assertEquals("xn--bcher-kva.de", u.asciiHost)
        assertEquals("bücher.de", u.unicodeHost)
    }

    @Test fun normalizesFullwidthCharacters() {
        assertEquals("example.com", ok("https://ｅｘａｍｐｌｅ．ｃｏｍ/").asciiHost)
    }

    @Test fun rejectsDangerousSchemes() {
        assertTrue(UrlNormalizer.parse("javascript:alert(1)") is ParseOutcome.DangerousScheme)
        assertTrue(UrlNormalizer.parse("data:text/html;base64,AAAA") is ParseOutcome.DangerousScheme)
    }

    @Test fun rejectsGarbage() {
        assertTrue(UrlNormalizer.parse("") is ParseOutcome.Failure)
        assertTrue(UrlNormalizer.parse("ftp://example.com") is ParseOutcome.Failure)
        assertTrue(UrlNormalizer.parse("https://exa mple") is ParseOutcome.Failure)
        assertTrue(UrlNormalizer.parse("https://example.com:99999") is ParseOutcome.Failure)
    }

    @Test fun lookupKeyNeverContainsQueryOrUserInfo() {
        val u = ok("https://user:pw@example.com/reset?token=secret#x")
        assertEquals("https://example.com/reset", u.lookupKey)
    }
}
