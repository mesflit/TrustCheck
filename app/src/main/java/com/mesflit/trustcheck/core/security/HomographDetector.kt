// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

import java.lang.Character.UnicodeScript

/**
 * Detects IDN homograph attacks: labels mixing scripts (e.g. Latin + Cyrillic) and labels written
 * entirely in characters that imitate Latin letters (e.g. Cyrillic "аррӏе" for "apple").
 */
object HomographDetector {

    /** Subset of Unicode TR39 confusables that map to ASCII letters. */
    private val confusables: Map<Char, Char> = mapOf(
        // Cyrillic
        'а' to 'a', 'в' to 'b', 'е' to 'e', 'ё' to 'e', 'һ' to 'h', 'і' to 'i', 'ї' to 'i', 'ј' to 'j',
        'к' to 'k', 'ӏ' to 'l', 'м' to 'm', 'н' to 'h', 'о' to 'o', 'р' to 'p', 'с' to 'c', 'ѕ' to 's',
        'т' to 't', 'у' to 'y', 'х' to 'x', 'ԁ' to 'd', 'ԛ' to 'q', 'ԝ' to 'w', 'ү' to 'y', 'ɡ' to 'g',
        'ո' to 'n', 'ս' to 'u', 'օ' to 'o', 'ց' to 'g', 'հ' to 'h', 'զ' to 'q', // Armenian
        // Greek
        'α' to 'a', 'β' to 'b', 'ε' to 'e', 'η' to 'n', 'ι' to 'i', 'κ' to 'k', 'ν' to 'v', 'ο' to 'o',
        'ρ' to 'p', 'τ' to 't', 'υ' to 'u', 'χ' to 'x', 'γ' to 'y', 'ϲ' to 'c', 'ϳ' to 'j',
        // Latin look-alikes outside ASCII
        'ı' to 'i', 'ł' to 'l', 'ƚ' to 'l', 'ɩ' to 'i', 'ɑ' to 'a', 'ȷ' to 'j', 'ƙ' to 'k', 'ʏ' to 'y',
        'ⅼ' to 'l', 'ⅰ' to 'i', 'ꞵ' to 'b', 'ɢ' to 'g', 'ɴ' to 'n', 'ꮃ' to 'w',
        'à' to 'a', 'á' to 'a', 'â' to 'a', 'ã' to 'a', 'ä' to 'a', 'å' to 'a', 'ā' to 'a',
        'ç' to 'c', 'è' to 'e', 'é' to 'e', 'ê' to 'e', 'ë' to 'e', 'ē' to 'e', 'ì' to 'i', 'í' to 'i',
        'î' to 'i', 'ï' to 'i', 'ñ' to 'n', 'ò' to 'o', 'ó' to 'o', 'ô' to 'o', 'õ' to 'o', 'ö' to 'o',
        'ø' to 'o', 'ù' to 'u', 'ú' to 'u', 'û' to 'u', 'ü' to 'u', 'ý' to 'y', 'ÿ' to 'y', 'ş' to 's',
        'ğ' to 'g', 'ž' to 'z', 'š' to 's', 'č' to 'c',
    )

    private val leet: Map<Char, Char> = mapOf('0' to 'o', '1' to 'l', '3' to 'e', '4' to 'a', '5' to 's', '7' to 't', '8' to 'b', '$' to 's', '@' to 'a')

    private val dangerousMixes = setOf(UnicodeScript.CYRILLIC, UnicodeScript.GREEK, UnicodeScript.ARMENIAN, UnicodeScript.CHEROKEE)
    private val cjk = setOf(UnicodeScript.HAN, UnicodeScript.HIRAGANA, UnicodeScript.KATAKANA, UnicodeScript.HANGUL)

    fun scriptsOf(label: String): Set<UnicodeScript> = label.codePoints().toArray()
        .map { UnicodeScript.of(it) }
        .filter { it != UnicodeScript.COMMON && it != UnicodeScript.INHERITED }
        .toSet()

    /** True when a single label mixes Latin with a script containing Latin look-alikes (or two such scripts). */
    fun isMixedScript(label: String): Boolean {
        val scripts = scriptsOf(label) - cjk
        if (scripts.size < 2) return false
        val risky = scripts.intersect(dangerousMixes)
        return risky.isNotEmpty() && (UnicodeScript.LATIN in scripts || risky.size >= 2)
    }

    /** Maps confusable characters to ASCII; returns null if any letter has no ASCII look-alike. */
    fun toAsciiSkeleton(label: String): String? {
        val sb = StringBuilder()
        for (ch in label.lowercase()) {
            when {
                ch in 'a'..'z' || ch in '0'..'9' || ch == '-' -> sb.append(ch)
                confusables.containsKey(ch) -> sb.append(confusables.getValue(ch))
                else -> return null
            }
        }
        return sb.toString()
    }

    /**
     * Brand-comparison skeleton: confusables → ASCII, leet digits → letters, hyphens dropped,
     * common multi-letter tricks collapsed ("rn"→"m", "vv"→"w", "cl"→"d" is NOT applied: too noisy).
     */
    fun brandSkeleton(label: String): String {
        val base = toAsciiSkeleton(label) ?: label.lowercase()
        return base.map { leet[it] ?: it }.joinToString("")
            .replace("-", "")
            .replace("rn", "m")
            .replace("vv", "w")
    }

    /** True if the label uses non-ASCII letters that all imitate Latin ones (whole-script confusable). */
    fun isWholeScriptConfusable(label: String): Boolean {
        if (label.all { it.code < 128 }) return false
        val skeleton = toAsciiSkeleton(label) ?: return false
        val scripts = scriptsOf(label)
        // Accented Latin (e.g. Turkish "ş", "ü") is normal; only flag foreign-script imitations.
        return skeleton.length >= 3 && scripts.any { it in dangerousMixes }
    }
}
