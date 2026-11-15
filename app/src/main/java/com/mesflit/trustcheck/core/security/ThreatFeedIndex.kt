// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

import java.net.IDN
import java.security.MessageDigest

/**
 * Compact on-device threat list: each domain is stored as the first 64 bits of its SHA-256,
 * sorted, and looked up by binary search. One million domains take ~8 MB and a lookup is
 * ~20 comparisons. Collisions are negligible (≈ n / 2^64).
 */
object ThreatFeedIndex {

    private val hostRegex = Regex("^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\\.)+[a-z0-9-]{2,63}$")

    /** 64-bit key for a normalized (lower-case, ASCII/punycode) domain. */
    fun keyOf(domain: String): Long {
        val d = MessageDigest.getInstance("SHA-256").digest(domain.toByteArray(Charsets.UTF_8))
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (d[i].toLong() and 0xFF)
        return v
    }

    /**
     * Parses one feed line. Accepts plain domains and hosts-file style lines ("0.0.0.0 evil.com"),
     * ignores comments, URLs are reduced to their host. Returns null for anything invalid.
     */
    fun parseLine(line: String): String? {
        var s = line.substringBefore('#').trim()
        if (s.isEmpty()) return null
        s = s.split(Regex("\\s+")).last()
        if (s.contains("://")) s = s.substringAfter("://")
        s = s.substringBefore('/').substringBefore(':').trimEnd('.').lowercase()
        if (s.startsWith("*.")) s = s.removePrefix("*.")
        if (s.startsWith("www.")) s = s.removePrefix("www.")
        if (s.any { it.code > 127 }) s = try { IDN.toASCII(s, IDN.ALLOW_UNASSIGNED).lowercase() } catch (e: IllegalArgumentException) { return null }
        if (!hostRegex.matches(s)) return null
        if (DomainUtils.isIpv4(s)) return null
        // Never list a shared-hosting or multi-label public suffix itself (would block whole platforms).
        if (s in DomainUtils.MULTI_LABEL_SUFFIXES) return null
        return s
    }

    /** Sorted, de-duplicated keys for the given domains (input may be unsorted and contain junk). */
    fun build(lines: Sequence<String>, maxEntries: Int = 3_000_000): LongArray {
        var keys = LongArray(1024)
        var n = 0
        for (line in lines) {
            val d = parseLine(line) ?: continue
            if (n == keys.size) keys = keys.copyOf(keys.size * 2)
            keys[n++] = keyOf(d)
            if (n >= maxEntries) break
        }
        val sorted = keys.copyOf(n)
        sorted.sort()
        // de-duplicate in place
        if (sorted.isEmpty()) return sorted
        var w = 1
        for (i in 1 until sorted.size) if (sorted[i] != sorted[w - 1]) sorted[w++] = sorted[i]
        return sorted.copyOf(w)
    }

    /** Binary search over any random-access source of sorted keys (array or memory-mapped file). */
    inline fun contains(size: Int, key: Long, get: (Int) -> Long): Boolean {
        var lo = 0
        var hi = size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            val v = get(mid)
            when {
                v < key -> lo = mid + 1
                v > key -> hi = mid - 1
                else -> return true
            }
        }
        return false
    }

    fun contains(sorted: LongArray, domain: String): Boolean = contains(sorted.size, keyOf(domain)) { sorted[it] }
}
