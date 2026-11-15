package com.mesflit.trustcheck.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RateLimiterTest {
    @Test fun slidingWindow() {
        val l = SlidingWindowRateLimiter(maxEvents = 2, windowMillis = 1_000)
        assertTrue(l.tryAcquire(0))
        assertTrue(l.tryAcquire(10))
        assertFalse(l.tryAcquire(20))
        assertEquals(0, l.remaining(20))
        assertTrue(l.tryAcquire(1_001))
    }

    @Test fun dailyQuotaResetsEachDay() {
        var q = DailyQuota(epochDay = 10, used = 0)
        repeat(5) { q = q.consume(10) }
        assertFalse(q.canUse(10, 5))
        assertTrue(q.canUse(11, 5))
        assertEquals(5, q.remaining(11, 5))
        assertEquals(1, q.consume(11).used)
    }

    @Test fun epochDay() {
        assertEquals(0, DailyQuota.epochDay(86_399_999))
        assertEquals(1, DailyQuota.epochDay(86_400_000))
    }
}
