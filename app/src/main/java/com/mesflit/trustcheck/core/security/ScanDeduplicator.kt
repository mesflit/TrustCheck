// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/**
 * In-memory duplicate-scan suppression. The same URL arriving from repeated notifications
 * (message updates, group summaries, re-posts) is only processed once per [windowMillis].
 * Persistent deduplication is additionally enforced by unique WorkManager work names.
 */
class ScanDeduplicator(
    private val windowMillis: Long = 10 * 60 * 1000L,
    private val maxEntries: Int = 500,
) {
    private val seen = object : LinkedHashMap<String, Long>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > maxEntries
    }

    /** Returns true if [key] should be processed now, and records it. */
    @Synchronized
    fun tryAcquire(key: String, now: Long): Boolean {
        val last = seen[key]
        if (last != null && now - last < windowMillis) return false
        seen[key] = now
        return true
    }

    @Synchronized
    fun clear() = seen.clear()

    companion object {
        /** Stable key for a URL, independent of query string, fragment and case. */
        fun keyFor(url: String): String =
            (UrlNormalizer.parse(url) as? ParseOutcome.Success)?.url?.lookupKey ?: url.trim().lowercase()
    }
}
