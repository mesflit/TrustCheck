package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatFeedIndexTest {
    @Test fun parsesCommonFeedFormats() {
        assertEquals("evil-login.example", ThreatFeedIndex.parseLine("evil-login.example"))
        assertEquals("evil.example", ThreatFeedIndex.parseLine("0.0.0.0 evil.example"))
        assertEquals("evil.example", ThreatFeedIndex.parseLine("https://www.EVIL.example/path?q=1"))
        assertEquals("sub.evil.example", ThreatFeedIndex.parseLine("  *.sub.evil.example.  # comment"))
        assertEquals("xn--bcher-kva.example", ThreatFeedIndex.parseLine("bücher.example"))
    }

    @Test fun rejectsJunkIpsAndSuffixes() {
        assertNull(ThreatFeedIndex.parseLine("# header"))
        assertNull(ThreatFeedIndex.parseLine(""))
        assertNull(ThreatFeedIndex.parseLine("localhost"))
        assertNull(ThreatFeedIndex.parseLine("1.2.3.4"))
        assertNull(ThreatFeedIndex.parseLine("github.io"))
        assertNull(ThreatFeedIndex.parseLine("not a domain"))
    }

    @Test fun buildSortsDeduplicatesAndFinds() {
        val keys = ThreatFeedIndex.build(sequenceOf("b.example", "a.example", "a.example", "# x", "junk", "c.example"))
        assertEquals(3, keys.size)
        assertTrue(keys.toList() == keys.sorted())
        assertTrue(ThreatFeedIndex.contains(keys, "a.example"))
        assertTrue(ThreatFeedIndex.contains(keys, "c.example"))
        assertFalse(ThreatFeedIndex.contains(keys, "d.example"))
        assertFalse(ThreatFeedIndex.contains(LongArray(0), "a.example"))
    }

    @Test fun largeIndexLookupIsCorrect() {
        val keys = ThreatFeedIndex.build((0 until 50_000).asSequence().map { "phish$it.example" })
        assertEquals(50_000, keys.size)
        assertTrue(ThreatFeedIndex.contains(keys, "phish49999.example"))
        assertFalse(ThreatFeedIndex.contains(keys, "phish50000.example"))
    }

    @Test fun engineTreatsFeedHitAsConfirmed() = kotlinx.coroutines.runBlocking {
        val keys = ThreatFeedIndex.build(sequenceOf("bad.example"))
        val bl = object : LocalBlocklist {
            override suspend fun isEmpty() = false
            override suspend fun match(hostAndParents: List<String>) =
                hostAndParents.firstOrNull { ThreatFeedIndex.contains(keys, it) }?.let { "phishing@Phishing.Database" }
        }
        val engine = UrlAnalysisEngine(blocklist = bl)
        val opts = AnalysisOptions(allowNetwork = false, resolveRedirects = false)
        assertEquals(RiskClassification.CONFIRMED_MALICIOUS, engine.analyze("https://login.bad.example/x", opts).classification)
        assertEquals(RiskClassification.NO_KNOWN_THREAT, engine.analyze("https://good.example/", opts).classification)
    }
}
