// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.network

/**
 * Client-side sliding-window limiter protecting cloud services from bursts (e.g. a flood of
 * notifications). This is a courtesy limit only; the backend enforces the authoritative one.
 */
class SlidingWindowRateLimiter(
    private val maxEvents: Int,
    private val windowMillis: Long,
) {
    private val events = ArrayDeque<Long>()

    @Synchronized
    fun tryAcquire(now: Long): Boolean {
        while (events.isNotEmpty() && now - events.first() >= windowMillis) events.removeFirst()
        if (events.size >= maxEvents) return false
        events.addLast(now)
        return true
    }

    @Synchronized
    fun remaining(now: Long): Int {
        while (events.isNotEmpty() && now - events.first() >= windowMillis) events.removeFirst()
        return (maxEvents - events.size).coerceAtLeast(0)
    }
}

/** Persistable daily quota (e.g. cloud AI explanations). Pure value type for easy testing. */
data class DailyQuota(val epochDay: Long, val used: Int) {
    fun forDay(day: Long): DailyQuota = if (day == epochDay) this else DailyQuota(day, 0)
    fun canUse(day: Long, limit: Int): Boolean = forDay(day).used < limit
    fun consume(day: Long): DailyQuota = forDay(day).let { it.copy(used = it.used + 1) }
    fun remaining(day: Long, limit: Int): Int = (limit - forDay(day).used).coerceAtLeast(0)

    companion object {
        fun epochDay(millis: Long): Long = Math.floorDiv(millis, 86_400_000L)
    }
}
