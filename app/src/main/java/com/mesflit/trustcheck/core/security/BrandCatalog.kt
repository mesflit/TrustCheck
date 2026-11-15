// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/**
 * Frequently impersonated brands and the registrable domains they actually use.
 *
 * A domain whose registrable label equals the brand keyword on a non-abused TLD (e.g. amazon.de,
 * google.com.tr) is treated as official, because large brands own many country domains.
 * Contributions that add brands must cite the official domain list (see CONTRIBUTING.md).
 */
data class Brand(val keyword: String, val officialDomains: Set<String>)

object BrandCatalog {
    val brands: List<Brand> = listOf(
        Brand("paypal", setOf("paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com")),
        Brand("apple", setOf("apple.com", "icloud.com", "apple.news", "apple.co", "me.com", "mzstatic.com")),
        Brand("icloud", setOf("icloud.com", "apple.com")),
        Brand("google", setOf("google.com", "goo.gl", "googleusercontent.com", "gstatic.com", "googleapis.com", "youtube.com", "g.co", "withgoogle.com", "blog.google")),
        Brand("gmail", setOf("gmail.com", "google.com")),
        Brand("youtube", setOf("youtube.com", "youtu.be", "google.com")),
        Brand("microsoft", setOf("microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "azure.com", "windows.com", "msn.com", "bing.com", "sharepoint.com", "aka.ms")),
        Brand("outlook", setOf("outlook.com", "live.com", "office.com", "microsoft.com")),
        Brand("office365", setOf("office.com", "microsoft.com", "microsoftonline.com")),
        Brand("amazon", setOf("amazon.com", "amazon.co.uk", "amazon.de", "amazon.com.tr", "amazon.co.jp", "amazon.com.br", "amazon.fr", "amazon.es", "amzn.to", "a.co", "amazonaws.com", "media-amazon.com")),
        Brand("netflix", setOf("netflix.com", "nflxext.com", "nflximg.net")),
        Brand("facebook", setOf("facebook.com", "fb.com", "fb.me", "meta.com", "fbcdn.net", "messenger.com")),
        Brand("instagram", setOf("instagram.com", "cdninstagram.com", "meta.com")),
        Brand("whatsapp", setOf("whatsapp.com", "whatsapp.net", "wa.me", "meta.com")),
        Brand("telegram", setOf("telegram.org", "t.me", "telegram.me")),
        Brand("linkedin", setOf("linkedin.com", "lnkd.in", "licdn.com")),
        Brand("twitter", setOf("twitter.com", "x.com", "t.co", "twimg.com")),
        Brand("tiktok", setOf("tiktok.com", "tiktokv.com", "tiktokcdn.com")),
        Brand("snapchat", setOf("snapchat.com", "snap.com")),
        Brand("discord", setOf("discord.com", "discord.gg", "discordapp.com", "discord.media")),
        Brand("steam", setOf("steampowered.com", "steamcommunity.com", "steamstatic.com")),
        Brand("steamcommunity", setOf("steamcommunity.com")),
        Brand("roblox", setOf("roblox.com", "rbxcdn.com")),
        Brand("binance", setOf("binance.com", "binance.us", "binance.tr", "bnbstatic.com")),
        Brand("coinbase", setOf("coinbase.com")),
        Brand("metamask", setOf("metamask.io")),
        Brand("dropbox", setOf("dropbox.com", "dropboxusercontent.com", "db.tt")),
        Brand("docusign", setOf("docusign.com", "docusign.net")),
        Brand("adobe", setOf("adobe.com", "adobelogin.com", "adobe.ly")),
        Brand("dhl", setOf("dhl.com", "dhl.de", "dhl.com.tr", "dhl.co.uk")),
        Brand("fedex", setOf("fedex.com")),
        Brand("ups", setOf("ups.com")),
        Brand("usps", setOf("usps.com", "usps.gov")),
        Brand("royalmail", setOf("royalmail.com")),
        Brand("chase", setOf("chase.com", "jpmorganchase.com")),
        Brand("wellsfargo", setOf("wellsfargo.com", "wf.com")),
        Brand("bankofamerica", setOf("bankofamerica.com", "bofa.com")),
        Brand("hsbc", setOf("hsbc.com", "hsbc.co.uk", "hsbc.com.tr")),
        Brand("santander", setOf("santander.com", "santander.co.uk", "santander.com.br", "santander.de")),
        Brand("bbva", setOf("bbva.com", "bbva.es", "bbva.mx")),
        Brand("revolut", setOf("revolut.com", "revolut.me")),
        Brand("sparkasse", setOf("sparkasse.de")),
        Brand("deutschebank", setOf("deutsche-bank.de", "db.com")),
        Brand("commerzbank", setOf("commerzbank.de")),
        Brand("garanti", setOf("garantibbva.com.tr", "garanti.com.tr")),
        Brand("garantibbva", setOf("garantibbva.com.tr")),
        Brand("ziraat", setOf("ziraatbank.com.tr", "ziraatkatilim.com.tr")),
        Brand("ziraatbank", setOf("ziraatbank.com.tr")),
        Brand("isbank", setOf("isbank.com.tr", "isbank.com")),
        Brand("akbank", setOf("akbank.com", "akbank.com.tr")),
        Brand("yapikredi", setOf("yapikredi.com.tr")),
        Brand("halkbank", setOf("halkbank.com.tr")),
        Brand("vakifbank", setOf("vakifbank.com.tr")),
        Brand("enpara", setOf("enpara.com")),
        Brand("papara", setOf("papara.com")),
        Brand("turkcell", setOf("turkcell.com.tr")),
        Brand("vodafone", setOf("vodafone.com", "vodafone.com.tr", "vodafone.de", "vodafone.co.uk", "vodafone.es")),
        Brand("edevlet", setOf("turkiye.gov.tr")),
        Brand("turkiye", setOf("turkiye.gov.tr")),
        Brand("hepsiburada", setOf("hepsiburada.com")),
        Brand("trendyol", setOf("trendyol.com")),
        Brand("sahibinden", setOf("sahibinden.com")),
        Brand("ptt", setOf("ptt.gov.tr")),
        Brand("yurtici", setOf("yurticikargo.com")),
        Brand("aras", setOf("araskargo.com.tr")),
        Brand("itau", setOf("itau.com.br")),
        Brand("bradesco", setOf("bradesco.com.br")),
        Brand("nubank", setOf("nubank.com.br", "nu.com.mx")),
        Brand("mercadolivre", setOf("mercadolivre.com.br")),
        Brand("mercadolibre", setOf("mercadolibre.com", "mercadolibre.com.mx", "mercadolibre.com.ar")),
        Brand("correos", setOf("correos.es")),
        Brand("laposte", setOf("laposte.fr", "laposte.net")),
        Brand("ameli", setOf("ameli.fr")),
        Brand("sberbank", setOf("sberbank.ru", "sber.ru", "sberbank.com")),
        Brand("gosuslugi", setOf("gosuslugi.ru")),
        Brand("tinkoff", setOf("tinkoff.ru", "tbank.ru")),
        Brand("yandex", setOf("yandex.ru", "yandex.com", "ya.ru", "yandex.com.tr")),
        Brand("rakuten", setOf("rakuten.co.jp", "rakuten.com")),
        Brand("docomo", setOf("docomo.ne.jp", "nttdocomo.co.jp")),
        Brand("aliexpress", setOf("aliexpress.com", "aliexpress.ru")),
        Brand("ebay", setOf("ebay.com", "ebay.de", "ebay.co.uk", "ebay.fr", "ebay.es")),
        Brand("spotify", setOf("spotify.com", "spotify.link", "scdn.co")),
        Brand("airbnb", setOf("airbnb.com")),
        Brand("booking", setOf("booking.com")),
        Brand("stcpay", setOf("stcpay.com.sa")),
        Brand("alrajhi", setOf("alrajhibank.com.sa")),
        Brand("emiratesnbd", setOf("emiratesnbd.com")),
    )

    private val byKeyword: Map<String, Brand> = brands.associateBy { it.keyword }

    fun forKeyword(keyword: String): Brand? = byKeyword[keyword]

    fun isOfficial(brand: Brand, host: String): Boolean {
        val reg = DomainUtils.registrableDomain(host)
        if (reg in brand.officialDomains) return true
        if (brand.officialDomains.any { host == it || host.endsWith(".$it") }) return true
        val label = DomainUtils.registrableLabel(host)
        val tld = host.substringAfterLast('.')
        return label == brand.keyword && tld !in DomainUtils.SUSPICIOUS_TLDS
    }

    /** True if the host belongs to any catalogued brand (used to suppress false positives). */
    fun isAnyOfficial(host: String): Boolean = brands.any { b -> b.officialDomains.any { host == it || host.endsWith(".$it") } }
}
