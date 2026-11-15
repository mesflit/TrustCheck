// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/**
 * Domain helpers.
 *
 * Registrable-domain detection uses a compact list of common multi-label public suffixes rather
 * than the full Public Suffix List. This is accurate for the vast majority of consumer domains;
 * the limitation is documented in docs/DETECTION.md.
 */
object DomainUtils {

    val MULTI_LABEL_SUFFIXES: Set<String> = setOf(
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
        "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "k12.tr", "av.tr", "bel.tr", "gen.tr",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp",
        "com.au", "net.au", "org.au", "gov.au", "edu.au",
        "co.nz", "org.nz", "govt.nz", "co.za", "org.za", "gov.za",
        "com.mx", "gob.mx", "com.ar", "gob.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my", "com.ph",
        "co.kr", "or.kr", "go.kr", "co.id", "or.id", "go.id", "co.th", "in.th", "go.th",
        "com.sa", "gov.sa", "com.eg", "gov.eg", "com.ae", "gov.ae", "com.qa", "com.kw", "com.pk",
        "com.ua", "org.ua", "gov.ua", "com.ru", "org.ru", "net.ru", "msk.ru", "spb.ru", "com.pl",
        "com.es", "org.es", "gob.es", "com.pt", "gov.pt", "co.il", "org.il", "gov.il", "co.at", "or.at",
        "com.ng", "gov.ng", "co.ke", "com.vn", "com.bd", "com.np", "com.lk",
        // Common shared-hosting suffixes where every subdomain is a different owner.
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
        "web.app", "firebaseapp.com", "herokuapp.com", "blogspot.com", "azurewebsites.net",
        "appspot.com", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
        "weebly.com", "wixsite.com", "000webhostapp.com", "r2.dev", "onrender.com",
    )

    /** TLDs frequently abused for phishing/malware in public abuse reports. A weak signal only. */
    val SUSPICIOUS_TLDS: Set<String> = setOf(
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "cyou", "cfd", "sbs", "bond", "click",
        "country", "kim", "work", "rest", "zip", "mov", "cam", "buzz", "loan", "men", "date",
        "racing", "win", "review", "stream", "download", "gdn", "monster", "quest", "lol", "beauty",
        "hair", "mom", "skin", "autos", "boats", "help",
    )

    /** TLDs accepted when detecting bare domains (no scheme) in free text. */
    val KNOWN_TLDS: Set<String> = setOf(
        "com", "net", "org", "info", "biz", "io", "co", "me", "app", "dev", "ai", "gov", "edu", "mil",
        "tr", "de", "es", "fr", "br", "pt", "ru", "jp", "uk", "us", "eu", "it", "nl", "be", "ch",
        "at", "pl", "se", "no", "dk", "fi", "ie", "gr", "cz", "sk", "hu", "ro", "bg", "ua", "by",
        "kz", "az", "ge", "sa", "ae", "eg", "qa", "kw", "ma", "dz", "tn", "jo", "lb", "iq", "in",
        "pk", "bd", "cn", "hk", "tw", "kr", "sg", "my", "id", "th", "vn", "ph", "au", "nz", "ca",
        "mx", "ar", "cl", "pe", "ve", "uy", "za", "ng", "ke", "online", "site", "store", "shop",
        "live", "link", "page", "tech", "cloud", "one", "pro", "tv", "cc", "ly", "gl", "gd", "to",
        "ws", "su", "asia", "mobi", "network", "support", "services", "money", "bank", "pay",
    ) + SUSPICIOUS_TLDS

    private val ipv4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")

    fun isIpv4(host: String): Boolean =
        ipv4.matchEntire(host)?.groupValues?.drop(1)?.all { it.toInt() in 0..255 } == true

    fun isIpv6(host: String): Boolean = host.startsWith("[") && host.endsWith("]") && host.contains(':')

    /**
     * Hosts that browsers resolve as IPv4 but that are written to hide it:
     * decimal (3232235777), hex (0x7f000001), octal / mixed dotted forms (0177.0.0.1, 0x7f.1).
     */
    fun isObfuscatedIp(host: String): Boolean {
        if (isIpv4(host) && host.split('.').none { it.length > 1 && it.startsWith("0") }) return false
        if (host.matches(Regex("^\\d{8,10}$"))) return host.toLongOrNull()?.let { it in 16_777_216L..4_294_967_295L } == true
        if (host.matches(Regex("(?i)^0x[0-9a-f]{1,8}$"))) return true
        val parts = host.split('.')
        if (parts.size !in 2..4) return false
        val numeric = Regex("(?i)^(0x[0-9a-f]+|0[0-7]*|[1-9]\\d*)$")
        return parts.all { numeric.matches(it) } &&
            parts.any { it.startsWith("0x", ignoreCase = true) || (it.length > 1 && it.startsWith("0")) || parts.size < 4 }
    }

    fun isPrivateOrLocal(host: String): Boolean {
        if (host == "localhost" || host.endsWith(".local") || host.endsWith(".localhost")) return true
        if (host == "[::1]") return true
        val m = ipv4.matchEntire(host) ?: return false
        val (a, b) = m.groupValues.drop(1).map { it.toInt() }
        return a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && b in 16..31) || (a == 169 && b == 254)
    }

    fun isIpHost(host: String) = isIpv4(host) || isIpv6(host) || isObfuscatedIp(host)

    /** eTLD+1 approximation, e.g. "login.paypal.com.evil.co.uk" -> "evil.co.uk". */
    fun registrableDomain(host: String): String {
        if (isIpHost(host)) return host
        val labels = host.trimEnd('.').split('.').filter { it.isNotEmpty() }
        if (labels.size <= 2) return labels.joinToString(".")
        val lastTwo = labels.takeLast(2).joinToString(".")
        val lastThree = labels.takeLast(3).joinToString(".")
        return when {
            MULTI_LABEL_SUFFIXES.contains(lastTwo) -> lastThree
            labels.size >= 4 && MULTI_LABEL_SUFFIXES.contains(lastThree) -> labels.takeLast(4).joinToString(".")
            else -> lastTwo
        }
    }

    fun publicSuffix(host: String): String {
        val reg = registrableDomain(host)
        return reg.substringAfter('.', "")
    }

    /** The registrable label without suffix: "paypal" for "www.paypal.co.uk". */
    fun registrableLabel(host: String): String = registrableDomain(host).substringBefore('.')

    /** Labels left of the registrable domain: ["login","paypal","com"] for login.paypal.com.evil.xyz. */
    fun subdomainLabels(host: String): List<String> {
        val reg = registrableDomain(host)
        if (reg == host || !host.endsWith(".$reg")) return emptyList()
        return host.removeSuffix(".$reg").split('.').filter { it.isNotEmpty() }
    }

    /** host plus every parent domain down to the registrable domain (for blocklist matching). */
    fun hostAndParents(host: String): List<String> {
        if (isIpHost(host)) return listOf(host)
        val reg = registrableDomain(host)
        val out = mutableListOf<String>()
        var h = host
        while (true) {
            out += h
            if (h == reg || !h.contains('.')) break
            h = h.substringAfter('.')
        }
        return out
    }
}
