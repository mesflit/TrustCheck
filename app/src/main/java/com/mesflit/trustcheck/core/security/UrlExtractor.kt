// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/**
 * Finds URL candidates in free text (notifications, shared messages, OCR output).
 *
 * Detects explicit schemes (http, https, and dangerous ones like javascript:), "www." links and
 * bare domains that end in a known TLD. Only the URL strings are returned — callers must not keep
 * the surrounding message text.
 */
object UrlExtractor {
    const val MAX_INPUT_CHARS = 20_000
    const val MAX_RESULTS = 20

    private const val HOST_CHAR = "[\\p{L}\\p{N}\\-]"
    private val schemeUrl = Regex(
        "(?i)(?<![\\p{L}\\p{N}])(?:https?://|hxxps?://)[^\\s<>\"'`]+",
    )
    private val dangerousScheme = Regex(
        "(?i)(?<![\\p{L}\\p{N}])(?:javascript|data|vbscript):[^\\s<>\"'`]+",
    )
    private val wwwUrl = Regex("(?i)(?<![\\p{L}\\p{N}./@])www\\.$HOST_CHAR+(?:\\.$HOST_CHAR+)+[^\\s<>\"'`]*")
    private val bareDomain = Regex(
        "(?i)(?<![\\p{L}\\p{N}./@\\-])((?:$HOST_CHAR+\\.)+)([a-z]{2,24})(?![\\p{L}\\p{N}\\-])((?::\\d{2,5})?(?:/[^\\s<>\"'`]*)?)",
    )

    private val trailingJunk = ".,;:!?…'\"»«“”‘’>"

    fun extract(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        val input = if (text.length > MAX_INPUT_CHARS) text.substring(0, MAX_INPUT_CHARS) else text
        val found = LinkedHashMap<String, IntRange>()

        fun add(raw: String, range: IntRange) {
            if (found.values.any { it.first <= range.first && it.last >= range.last }) return
            val cleaned = clean(raw)
            if (cleaned.length < 4) return
            found.putIfAbsent(cleaned, range)
        }

        schemeUrl.findAll(input).forEach { add(it.value.replaceFirst(Regex("(?i)^hxxp"), "http"), it.range) }
        dangerousScheme.findAll(input).forEach { add(it.value, it.range) }
        wwwUrl.findAll(input).forEach { add(it.value, it.range) }
        bareDomain.findAll(input).forEach { m ->
            val tld = m.groupValues[2].lowercase()
            if (tld in DomainUtils.KNOWN_TLDS) add(m.value, m.range)
        }
        return found.entries.sortedBy { it.value.first }.map { it.key }.take(MAX_RESULTS)
    }

    /** Strips trailing punctuation and unbalanced closing brackets that belong to the sentence. */
    internal fun clean(raw: String): String {
        var s = raw.trim()
        while (s.isNotEmpty()) {
            val last = s.last()
            when {
                last in trailingJunk -> s = s.dropLast(1)
                last == ')' && s.count { it == '(' } < s.count { it == ')' } -> s = s.dropLast(1)
                last == ']' && s.count { it == '[' } < s.count { it == ']' } -> s = s.dropLast(1)
                last == '}' && s.count { it == '{' } < s.count { it == '}' } -> s = s.dropLast(1)
                else -> break
            }
        }
        return s
    }
}
