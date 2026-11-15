package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanDeduplicatorTest {
    @Test fun suppressesDuplicatesWithinWindow() {
        val d = ScanDeduplicator(windowMillis = 1_000)
        assertTrue(d.tryAcquire("a", 0))
        assertFalse(d.tryAcquire("a", 500))
        assertTrue(d.tryAcquire("b", 500))
        assertTrue(d.tryAcquire("a", 1_500))
    }

    @Test fun evictsOldestBeyondCapacity() {
        val d = ScanDeduplicator(windowMillis = 10_000, maxEntries = 2)
        d.tryAcquire("a", 0); d.tryAcquire("b", 0); d.tryAcquire("c", 0)
        assertTrue(d.tryAcquire("a", 1)) // evicted, so processed again
    }

    @Test fun keyIgnoresQueryFragmentAndCase() {
        assertEquals(
            ScanDeduplicator.keyFor("https://EXAMPLE.com/a?utm=1#x"),
            ScanDeduplicator.keyFor("https://example.com/a?utm=2"),
        )
    }
}
