// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/** Offline, deterministic URL heuristics. No network access. */
object HeuristicAnalyzer {

    val URL_SHORTENERS: Set<String> = setOf(
        "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink", "t.ly", "s.id",
        "lnkd.in", "qrco.de", "shorte.st", "adf.ly", "bit.do", "soo.gd", "clck.ru", "u.to",
        "linktr.ee", "tr.ee", "short.io", "surl.li", "urlz.fr", "shorturl.asia", "x.gd", "1url.com",
        "2u.pw", "trib.al", "dlvr.it", "spoo.me", "gg.gg", "chilp.it", "yourls.org", "ln.run",
        "amzn.to", "youtu.be", "wa.me", "t.me", "fb.me", "aka.ms",
    )

    /** First-party shorteners that only point to their owner's own domains. */
    private val firstPartyShorteners = setOf("amzn.to", "youtu.be", "wa.me", "t.me", "fb.me", "aka.ms")

    val LURE_WORDS: Set<String> = setOf(
        "login", "log-in", "signin", "sign-in", "verify", "verification", "account", "accounts",
        "secure", "security", "update", "confirm", "banking", "wallet", "password", "unlock",
        "suspend", "suspended", "support", "billing", "invoice", "refund", "prize", "gift", "bonus",
        "claim", "kyc", "otp", "auth", "authenticate", "webscr", "recovery", "helpdesk", "service",
        "online", "payment", "pay", "giris", "dogrulama", "guvenlik", "hesap", "iade", "odeme",
        "kargo", "takip", "anmelden", "konto", "verificar", "cuenta", "connexion", "compte",
        "verifica", "conta", "entrar", "vhod", "app", "official", "help", "reset", "alert",
    )

    private val executableExtensions = setOf(".apk", ".xapk", ".apks", ".exe", ".scr", ".msi", ".bat", ".cmd", ".jar", ".vbs", ".ps1", ".dmg", ".pkg")
    private val embeddedUrlParam = Regex("(?i)(?:^|&)(?:url|u|redirect|redirect_uri|redir|next|target|dest|destination|goto|return|returnurl|continue|r|link)=(?:https?%3a|https?:|%2f%2f|//)")
    private val sensitiveParam = Regex("(?i)(?:^|&)(?:password|passwd|pwd|pass|otp|pin|cvv|ssn|card|cc|tckn|iban)=")

    fun analyze(url: ParsedUrl): List<DetectedIndicator> {
        val out = mutableListOf<DetectedIndicator>()
        val host = url.asciiHost
        val registrable = DomainUtils.registrableDomain(host)

        // --- Host form ---
        when {
            DomainUtils.isPrivateOrLocal(host) -> out += DetectedIndicator(Indicator.PRIVATE_NETWORK_HOST)
            DomainUtils.isObfuscatedIp(host) -> out += DetectedIndicator(Indicator.OBFUSCATED_IP_HOST)
            DomainUtils.isIpHost(host) -> out += DetectedIndicator(Indicator.IP_ADDRESS_HOST)
        }

        if (url.userInfo != null) out += DetectedIndicator(Indicator.USERINFO_IN_URL, url.userInfo.substringBefore(':').take(64)) // never keep a password part

        if (!DomainUtils.isIpHost(host)) {
            val unicodeLabels = url.unicodeHost.split('.')
            if (host.split('.').any { it.startsWith("xn--") }) out += DetectedIndicator(Indicator.PUNYCODE_DOMAIN, url.unicodeHost)
            if (unicodeLabels.any { HomographDetector.isMixedScript(it) }) {
                out += DetectedIndicator(Indicator.MIXED_SCRIPT_DOMAIN, url.unicodeHost)
            } else if (unicodeLabels.any { HomographDetector.isWholeScriptConfusable(it) }) {
                out += DetectedIndicator(Indicator.WHOLE_SCRIPT_CONFUSABLE, url.unicodeHost)
            }

            out += LookalikeDetector.detect(url)

            val tld = host.substringAfterLast('.')
            if (tld in DomainUtils.SUSPICIOUS_TLDS) out += DetectedIndicator(Indicator.SUSPICIOUS_TLD, tld)

            val labels = host.split('.')
            if (labels.size >= 5) out += DetectedIndicator(Indicator.EXCESSIVE_SUBDOMAINS, labels.size.toString())

            val regLabel = registrable.substringBefore('.')
            if (regLabel.count { it == '-' } >= 3) out += DetectedIndicator(Indicator.MANY_HYPHENS)

            if (registrable in URL_SHORTENERS || host in URL_SHORTENERS) {
                if (registrable !in firstPartyShorteners && host !in firstPartyShorteners) {
                    out += DetectedIndicator(Indicator.URL_SHORTENER, registrable)
                }
            }
        }

        // --- Transport ---
        if (!url.isHttps && !DomainUtils.isPrivateOrLocal(host)) out += DetectedIndicator(Indicator.INSECURE_HTTP)
        if (url.port != null && url.port !in setOf(80, 443, 8080, 8443)) out += DetectedIndicator(Indicator.NON_STANDARD_PORT, url.port.toString())

        // --- Path & query ---
        val lowerPath = UrlNormalizer.percentDecode(url.path).lowercase()
        val lureHits = LURE_WORDS.filter { w ->
            w.length >= 4 && (host.contains(w) && !BrandCatalog.isAnyOfficial(host) || Regex("(?:^|[/._\\-])${Regex.escape(w)}(?:$|[/._\\-])").containsMatchIn(lowerPath))
        }
        if (lureHits.isNotEmpty() && !BrandCatalog.isAnyOfficial(host)) {
            out += DetectedIndicator(Indicator.SUSPICIOUS_KEYWORDS, lureHits.take(5).joinToString(","))
        }

        if (executableExtensions.any { lowerPath.endsWith(it) }) {
            out += DetectedIndicator(Indicator.EXECUTABLE_DOWNLOAD, lowerPath.substringAfterLast('.'))
        }

        val full = url.analysisUrl
        if (full.length > 200) out += DetectedIndicator(Indicator.LONG_URL, full.length.toString())

        val encoded = Regex("%[0-9a-fA-F]{2}").findAll(url.path + (url.query ?: "")).count()
        if (encoded >= 10) out += DetectedIndicator(Indicator.EXCESSIVE_ENCODING, encoded.toString())

        url.query?.let { q ->
            if (embeddedUrlParam.containsMatchIn(q)) out += DetectedIndicator(Indicator.EMBEDDED_URL_PARAMETER)
            if (sensitiveParam.containsMatchIn(q)) out += DetectedIndicator(Indicator.SENSITIVE_DATA_IN_URL)
        }
        return out
    }

    fun isShortener(url: ParsedUrl): Boolean {
        val reg = DomainUtils.registrableDomain(url.asciiHost)
        return reg in URL_SHORTENERS || url.asciiHost in URL_SHORTENERS
    }
}
