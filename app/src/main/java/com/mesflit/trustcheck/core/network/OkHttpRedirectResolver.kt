// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.network

import com.mesflit.trustcheck.core.security.RedirectResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException

/**
 * Reveals where a short link points by issuing HEAD requests with redirects disabled.
 * The destination page is never requested, downloaded, rendered or executed. Cookies are not
 * stored. Only HTTPS is used; plain-HTTP short links are upgraded or not resolved.
 */
class OkHttpRedirectResolver(base: OkHttpClient = Http.client) : RedirectResolver {
    private val client = base.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    override suspend fun resolve(url: String, maxHops: Int): List<String>? = withContext(Dispatchers.IO) {
        val chain = mutableListOf<String>()
        var current = url.replaceFirst(Regex("^http://", RegexOption.IGNORE_CASE), "https://").toHttpUrlOrNull() ?: return@withContext null
        repeat(maxHops) {
            val req = Request.Builder().url(current).head()
                .header("User-Agent", "TrustCheck-LinkPreview/1.0 (+https://github.com/mesflit/TrustCheck)")
                .build()
            val location = try {
                client.newCall(req).execute().use { resp ->
                    if (resp.code in 300..399) resp.header("Location") else null
                }
            } catch (e: IOException) {
                return@withContext if (chain.isEmpty()) null else chain
            } ?: return@withContext chain
            val next = current.resolve(location) ?: return@withContext chain
            chain += next.toString()
            if (next.scheme != "https") return@withContext chain // reported, but never contacted over cleartext
            current = next
        }
        chain
    }
}
