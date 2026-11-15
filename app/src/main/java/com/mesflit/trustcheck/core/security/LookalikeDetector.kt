// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/** Detects typosquatting, brand-in-subdomain and brand-plus-keyword impersonation. */
object LookalikeDetector {

    fun detect(url: ParsedUrl): List<DetectedIndicator> {
        val host = url.asciiHost
        if (DomainUtils.isIpHost(host)) return emptyList()
        val out = mutableListOf<DetectedIndicator>()
        val unicodeLabel = DomainUtils.registrableLabel(url.unicodeHost)
        val asciiLabel = DomainUtils.registrableLabel(host)
        val skeleton = HomographDetector.brandSkeleton(unicodeLabel)
        val tokens = asciiLabel.split('-', '_').filter { it.isNotEmpty() }

        for (brand in BrandCatalog.brands) {
            if (BrandCatalog.isOfficial(brand, host)) continue
            val kw = brand.keyword
            val nonAsciiLabel = unicodeLabel.any { it.code >= 128 }

            when {
                // Exact brand label on an abused TLD, e.g. paypal.top
                asciiLabel == kw -> out += DetectedIndicator(Indicator.LOOKALIKE_BRAND, kw)

                // Unicode imitation, e.g. "раураl" (Cyrillic) -> paypal
                nonAsciiLabel && skeleton == kw -> out += DetectedIndicator(Indicator.HOMOGRAPH_OF_BRAND, kw)

                // Leet / hyphen / rn->m tricks, e.g. paypa1, pay-pal, rnicrosoft
                skeleton == kw -> out += DetectedIndicator(Indicator.LOOKALIKE_BRAND, kw)

                // One edit away from a long brand name, e.g. paypall, gooogle, netfllx
                // (first letter must match: real typosquats keep it, and it avoids hits on
                // ordinary words such as "cooking" vs "booking")
                kw.length >= 6 && skeleton.length >= 5 && skeleton[0] == kw[0] &&
                    damerauLevenshtein(skeleton, kw) == 1 &&
                    !BrandCatalog.isAnyOfficial(host) -> out += DetectedIndicator(Indicator.LOOKALIKE_BRAND, kw)

                // Brand as a hyphen-separated token or joined with a lure word, e.g.
                // paypal-secure-login.com, applesupport.net, secure-netflix.co
                kw.length >= 3 && (kw in tokens || joinsLure(asciiLabel, kw)) ->
                    out += DetectedIndicator(Indicator.BRAND_IN_DOMAIN_LABEL, kw)
            }

            // Brand placed in the subdomain of an unrelated domain, e.g. paypal.com.verify-acc.xyz
            val sub = DomainUtils.subdomainLabels(host)
            if (sub.isNotEmpty() && sub.any { it == kw || HomographDetector.brandSkeleton(it) == kw || it.split('-').contains(kw) }) {
                out += DetectedIndicator(Indicator.BRAND_IN_SUBDOMAIN, kw)
            }
        }
        // Keep the strongest indicator per type.
        return out.distinctBy { it.indicator }
    }

    private fun joinsLure(label: String, kw: String): Boolean {
        if (kw.length < 4 || label == kw || !label.contains(kw)) return false
        val before = label.substringBefore(kw)
        val after = label.substringAfter(kw)
        return (before.isEmpty() || before.trimEnd('-') in HeuristicAnalyzer.LURE_WORDS) &&
            (after.isEmpty() || after.trimStart('-') in HeuristicAnalyzer.LURE_WORDS) &&
            (before.isNotEmpty() || after.isNotEmpty())
    }

    /** Optimal string alignment distance (Damerau–Levenshtein with adjacent transpositions). */
    fun damerauLevenshtein(a: String, b: String): Int {
        val d = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) d[i][0] = i
        for (j in 0..b.length) d[0][j] = j
        for (i in 1..a.length) for (j in 1..b.length) {
            val cost = if (a[i - 1] == b[j - 1]) 0 else 1
            d[i][j] = minOf(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) {
                d[i][j] = minOf(d[i][j], d[i - 2][j - 2] + 1)
            }
        }
        return d[a.length][b.length]
    }
}
