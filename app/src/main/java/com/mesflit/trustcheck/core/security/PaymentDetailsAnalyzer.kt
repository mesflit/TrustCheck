// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Checks phone numbers, IBANs and crypto-wallet addresses found in a message.
 *
 * Everything is offline and rule-based. Values are reported **masked** (e.g. `TR12 •••• 1234`)
 * so a number or account that may belong to the user is never stored in full.
 */
object PaymentDetailsAnalyzer {

    /** National significant number prefixes of premium-rate services, by country calling code. */
    private val premiumPrefixes: Map<String, List<String>> = mapOf(
        "90" to listOf("900"),                          // Türkiye 0900
        "49" to listOf("900", "137", "138"),            // Germany
        "43" to listOf("900", "901", "930", "931", "939"), // Austria
        "41" to listOf("900", "901", "906"),            // Switzerland
        "33" to listOf("89"),                           // France 089x
        "34" to listOf("803", "806", "807", "905"),     // Spain
        "351" to listOf("760", "761"),                  // Portugal
        "55" to listOf("900"),                          // Brazil 0900
        "44" to listOf("9", "871", "872", "873"),       // UK 09xx, 087x
        "39" to listOf("899", "892"),                   // Italy
        "7" to listOf("809"),                           // Russia 8-809
        "1" to listOf("900", "976"),                    // USA/Canada
    )

    /** Satellite / international-network codes: very expensive, typical of "missed call" scams. */
    private val internationalNetworks = listOf("870", "881", "882", "883", "979")

    /** ISO 3166 country → calling code (for the user's home country). */
    val CALLING_CODES: Map<String, String> = mapOf(
        "TR" to "90", "DE" to "49", "AT" to "43", "CH" to "41", "FR" to "33", "BE" to "32", "NL" to "31",
        "ES" to "34", "PT" to "351", "IT" to "39", "GB" to "44", "IE" to "353", "SE" to "46", "NO" to "47",
        "DK" to "45", "FI" to "358", "PL" to "48", "GR" to "30", "RU" to "7", "KZ" to "7", "UA" to "380",
        "AZ" to "994", "US" to "1", "CA" to "1", "MX" to "52", "BR" to "55", "AR" to "54", "CL" to "56",
        "CO" to "57", "PE" to "51", "SA" to "966", "AE" to "971", "QA" to "974", "KW" to "965", "EG" to "20",
        "MA" to "212", "DZ" to "213", "TN" to "216", "JO" to "962", "IQ" to "964", "JP" to "81", "KR" to "82",
        "CN" to "86", "IN" to "91", "PK" to "92", "ID" to "62", "AU" to "61", "NZ" to "64", "ZA" to "27",
    )

    /** Expected IBAN lengths (a mismatch means "not an IBAN", not "invalid IBAN"). */
    private val ibanLengths: Map<String, Int> = mapOf(
        "TR" to 26, "DE" to 22, "AT" to 20, "CH" to 21, "FR" to 27, "BE" to 16, "NL" to 18, "ES" to 24,
        "PT" to 25, "IT" to 27, "GB" to 22, "IE" to 22, "SE" to 24, "NO" to 15, "DK" to 18, "FI" to 18,
        "PL" to 28, "GR" to 27, "LT" to 20, "LV" to 21, "EE" to 20, "LU" to 20, "MT" to 31, "CY" to 28,
        "BG" to 22, "RO" to 24, "HR" to 21, "SI" to 19, "SK" to 24, "CZ" to 24, "HU" to 28, "UA" to 29,
        "AZ" to 28, "KZ" to 20, "GE" to 22, "SA" to 24, "AE" to 23, "QA" to 29, "KW" to 30, "JO" to 30,
        "EG" to 29, "BR" to 29, "IL" to 23, "MC" to 27, "GI" to 23, "IS" to 26,
    )

    private val phoneRegex = Regex("(?<![\\w+])(?:\\+|00)?\\d[\\d ().\\-]{6,20}\\d(?!\\w)")
    private val ibanRegex = Regex("(?i)(?<![A-Z0-9])([A-Z]{2}\\d{2}(?: ?[A-Z0-9]){10,30})(?![A-Z0-9])")
    private val ethRegex = Regex("(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])")
    private val btcBech32 = Regex("(?i)(?<![A-Za-z0-9])bc1[ac-hj-np-z02-9]{11,71}(?![A-Za-z0-9])")
    private val base58Addr = Regex("(?<![A-Za-z0-9])[13T][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])")

    fun analyze(text: String, homeCountry: String?): List<DetectedIndicator> {
        if (text.isBlank()) return emptyList()
        // Links are analyzed separately; remove them so digits in URLs are not read as numbers.
        var t = text.take(UrlExtractor.MAX_INPUT_CHARS)
        UrlExtractor.extract(t).forEach { t = t.replace(it, " ") }
        val home = homeCountry?.uppercase()
        val out = mutableListOf<DetectedIndicator>()
        out += phoneIndicators(t, home)
        out += ibanIndicators(t, home)
        cryptoIndicator(t)?.let { out += it }
        return out.distinctBy { it.indicator }
    }

    // --- Phone numbers ----------------------------------------------------------------------

    fun phoneIndicators(text: String, homeCountry: String?): List<DetectedIndicator> {
        val homeCc = homeCountry?.let { CALLING_CODES[it] }
        val out = mutableListOf<DetectedIndicator>()
        for (m in phoneRegex.findAll(text)) {
            val raw = m.value.trim()
            val digits = raw.filter { it.isDigit() }
            val international = raw.startsWith("+") || raw.startsWith("00")
            val intl = when {
                raw.startsWith("+") -> digits
                raw.startsWith("00") -> digits.drop(2)
                else -> null
            }
            if (digits.length !in 8..15) continue
            // Skip dates, amounts and similar: a phone number needs few separators of one kind.
            if (raw.count { it == '.' } >= 2 && !international) continue

            val masked = mask(if (international) "+${intl.orEmpty()}" else digits)
            if (intl != null) {
                if (internationalNetworks.any { intl.startsWith(it) }) {
                    out += DetectedIndicator(Indicator.INTERNATIONAL_NETWORK_NUMBER, masked); continue
                }
                if (premiumPrefixes.any { (cc, prefixes) -> intl.startsWith(cc) && prefixes.any { p -> intl.removePrefix(cc).startsWith(p) } }) {
                    out += DetectedIndicator(Indicator.PREMIUM_RATE_NUMBER, masked); continue
                }
                if (homeCc != null && !intl.startsWith(homeCc)) out += DetectedIndicator(Indicator.FOREIGN_PHONE_NUMBER, masked)
            } else if (homeCc != null) {
                // National format: strip the trunk prefix (0, or 1 in NANP, or 8 in Russia/Kazakhstan).
                val nsn = when {
                    homeCc == "1" -> digits.removePrefix("1")
                    homeCc == "7" -> digits.removePrefix("8")
                    else -> digits.removePrefix("0")
                }
                if (premiumPrefixes[homeCc].orEmpty().any { nsn.startsWith(it) } && digits.startsWith(if (homeCc == "1") "1" else if (homeCc == "7") "8" else "0")) {
                    out += DetectedIndicator(Indicator.PREMIUM_RATE_NUMBER, masked)
                }
            }
        }
        return out.distinctBy { it.indicator }
    }

    // --- IBAN -------------------------------------------------------------------------------

    fun ibanIndicators(text: String, homeCountry: String?): List<DetectedIndicator> {
        val out = mutableListOf<DetectedIndicator>()
        for (m in ibanRegex.findAll(text)) {
            val iban = m.groupValues[1].replace(" ", "").uppercase()
            val country = iban.take(2)
            val expected = ibanLengths[country] ?: continue // unknown country prefix → probably not an IBAN
            if (iban.length != expected) continue
            val masked = "${iban.take(4)} •••• ${iban.takeLast(4)}"
            when {
                !isValidIban(iban) -> out += DetectedIndicator(Indicator.INVALID_IBAN, masked)
                homeCountry != null && country != homeCountry.uppercase() -> out += DetectedIndicator(Indicator.FOREIGN_IBAN, masked)
            }
        }
        return out.distinctBy { it.indicator }
    }

    /** ISO 13616 mod-97 check. */
    fun isValidIban(iban: String): Boolean {
        val s = iban.replace(" ", "").uppercase()
        if (s.length < 15 || s.length > 34 || !s.all { it.isLetterOrDigit() }) return false
        val rearranged = s.drop(4) + s.take(4)
        val numeric = buildString { rearranged.forEach { c -> if (c.isDigit()) append(c) else append(c - 'A' + 10) } }
        return BigInteger(numeric).mod(BigInteger.valueOf(97)) == BigInteger.ONE
    }

    // --- Crypto -----------------------------------------------------------------------------

    fun cryptoIndicator(text: String): DetectedIndicator? {
        ethRegex.find(text)?.let { return DetectedIndicator(Indicator.CRYPTO_ADDRESS, maskAddr(it.value)) }
        btcBech32.find(text)?.let { return DetectedIndicator(Indicator.CRYPTO_ADDRESS, maskAddr(it.value)) }
        base58Addr.findAll(text).firstOrNull { isBase58Check(it.value) }?.let { return DetectedIndicator(Indicator.CRYPTO_ADDRESS, maskAddr(it.value)) }
        return null
    }

    private const val B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    /** Bitcoin legacy / TRON addresses carry a 4-byte double-SHA-256 checksum. */
    fun isBase58Check(s: String): Boolean {
        var n = BigInteger.ZERO
        for (c in s) {
            val v = B58.indexOf(c)
            if (v < 0) return false
            n = n.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(v.toLong()))
        }
        var bytes = n.toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        val leadingZeros = s.takeWhile { it == '1' }.length
        bytes = ByteArray(leadingZeros) + bytes
        if (bytes.size < 5) return false
        val payload = bytes.copyOfRange(0, bytes.size - 4)
        val checksum = bytes.copyOfRange(bytes.size - 4, bytes.size)
        val sha = MessageDigest.getInstance("SHA-256")
        val h = sha.digest(sha.digest(payload))
        return h.copyOfRange(0, 4).contentEquals(checksum)
    }

    private fun mask(n: String): String = if (n.length <= 6) n else n.take(4) + "•".repeat((n.length - 6).coerceAtMost(6)) + n.takeLast(2)
    private fun maskAddr(a: String): String = if (a.length <= 10) a else "${a.take(6)}…${a.takeLast(4)}"
}
