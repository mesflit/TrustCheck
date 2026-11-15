// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

import java.net.IDN
import java.net.URLDecoder
import java.text.Normalizer

/** A URL broken into parts. Hosts are lower-case; [asciiHost] is punycode, [unicodeHost] is display form. */
data class ParsedUrl(
    val original: String,
    val scheme: String,
    val schemeInferred: Boolean,
    val userInfo: String?,
    val asciiHost: String,
    val unicodeHost: String,
    val port: Int?,
    val path: String,
    val query: String?,
    val fragment: String?,
) {
    val isHttps get() = scheme == "https"
    val defaultPort get() = if (scheme == "https") 443 else 80
    val effectivePort get() = port ?: defaultPort

    /** Privacy-reduced form used for storage, dedup and reputation lookups (no query/fragment/userinfo). */
    val lookupKey: String
        get() = buildString {
            append(scheme).append("://").append(asciiHost)
            if (port != null && port != defaultPort) append(':').append(port)
            append(if (path.isEmpty()) "/" else path)
        }

    /** Full normalized form without fragment and userinfo, used for in-memory analysis only. */
    val analysisUrl: String
        get() = lookupKey + (query?.let { "?$it" } ?: "")
}

sealed interface ParseOutcome {
    data class Success(val url: ParsedUrl) : ParseOutcome
    data class DangerousScheme(val scheme: String) : ParseOutcome
    data class Failure(val reason: String) : ParseOutcome
}

object UrlNormalizer {
    private val schemeRegex = Regex("^([a-zA-Z][a-zA-Z0-9+.\\-]*):")
    private val dangerousSchemes = setOf("javascript", "data", "vbscript", "file", "intent", "content")
    private val hostLabel = Regex("^[a-z0-9\\-_]{1,63}$")
    const val MAX_URL_LENGTH = 8_192

    fun parse(input: String): ParseOutcome {
        var s = input.trim().removePrefix("<").removeSuffix(">").trim()
        if (s.isEmpty()) return ParseOutcome.Failure("empty")
        if (s.length > MAX_URL_LENGTH) return ParseOutcome.Failure("too_long")
        if (s.any { it.isWhitespace() }) s = s.replace(Regex("\\s+"), "")

        var scheme: String
        var inferred = false
        val m = schemeRegex.find(s)
        if (m != null && (s.length > m.value.length && s[m.value.length] == '/' || m.groupValues[1].lowercase() in dangerousSchemes)) {
            scheme = m.groupValues[1].lowercase()
            if (scheme in dangerousSchemes) return ParseOutcome.DangerousScheme(scheme)
            if (scheme == "hxxp") scheme = "http"
            if (scheme == "hxxps") scheme = "https"
            if (scheme != "http" && scheme != "https") return ParseOutcome.Failure("unsupported_scheme")
            s = s.substring(m.value.length)
        } else {
            // No scheme: assume https, as a modern browser would try first.
            scheme = "https"
            inferred = true
        }
        s = s.trimStart('/', '\\')

        val authorityEnd = s.indexOfFirst { it == '/' || it == '?' || it == '#' || it == '\\' }.let { if (it < 0) s.length else it }
        val authority = s.substring(0, authorityEnd)
        val rest = s.substring(authorityEnd).replace('\\', '/')

        val at = authority.lastIndexOf('@')
        val userInfo = if (at >= 0) authority.substring(0, at).ifEmpty { null } else null
        val hostPort = if (at >= 0) authority.substring(at + 1) else authority

        var host: String
        var port: Int? = null
        if (hostPort.startsWith("[")) {
            val close = hostPort.indexOf(']')
            if (close < 0) return ParseOutcome.Failure("bad_ipv6")
            host = hostPort.substring(0, close + 1).lowercase()
            val after = hostPort.substring(close + 1)
            if (after.startsWith(":")) port = after.drop(1).toIntOrNull() ?: return ParseOutcome.Failure("bad_port")
        } else {
            val colon = hostPort.lastIndexOf(':')
            if (colon >= 0) {
                val p = hostPort.substring(colon + 1)
                port = if (p.isEmpty()) null else p.toIntOrNull() ?: return ParseOutcome.Failure("bad_port")
                host = hostPort.substring(0, colon)
            } else {
                host = hostPort
            }
            host = percentDecode(host)
            host = Normalizer.normalize(host, Normalizer.Form.NFKC).lowercase().trimEnd('.')
            host = host.replace('。', '.').replace('．', '.').replace('｡', '.')
        }
        if (port != null && port !in 1..65535) return ParseOutcome.Failure("bad_port")
        if (host.isEmpty()) return ParseOutcome.Failure("no_host")

        val asciiHost: String
        val unicodeHost: String
        if (host.startsWith("[")) {
            asciiHost = host; unicodeHost = host
        } else {
            asciiHost = try {
                IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).lowercase()
            } catch (e: IllegalArgumentException) {
                return ParseOutcome.Failure("bad_host")
            }
            unicodeHost = try {
                IDN.toUnicode(asciiHost, IDN.ALLOW_UNASSIGNED).lowercase()
            } catch (e: IllegalArgumentException) {
                asciiHost
            }
            val labels = asciiHost.split('.')
            if (labels.any { !hostLabel.matches(it) }) return ParseOutcome.Failure("bad_host")
            if (!DomainUtils.isIpHost(asciiHost) && labels.size < 2 && asciiHost != "localhost") {
                return ParseOutcome.Failure("no_tld")
            }
        }

        val fragIdx = rest.indexOf('#')
        val beforeFrag = if (fragIdx >= 0) rest.substring(0, fragIdx) else rest
        val fragment = if (fragIdx >= 0) rest.substring(fragIdx + 1) else null
        val qIdx = beforeFrag.indexOf('?')
        val path = normalizePath(if (qIdx >= 0) beforeFrag.substring(0, qIdx) else beforeFrag)
        val query = if (qIdx >= 0) beforeFrag.substring(qIdx + 1).ifEmpty { null } else null

        return ParseOutcome.Success(
            ParsedUrl(
                original = input,
                scheme = scheme,
                schemeInferred = inferred,
                userInfo = userInfo,
                asciiHost = asciiHost,
                unicodeHost = unicodeHost,
                port = port?.takeIf { it != (if (scheme == "https") 443 else 80) },
                path = path,
                query = query,
                fragment = fragment,
            ),
        )
    }

    /** Collapses duplicate slashes and resolves "." / ".." segments. */
    internal fun normalizePath(raw: String): String {
        if (raw.isEmpty()) return "/"
        val out = ArrayDeque<String>()
        raw.split('/').forEach { seg ->
            when (seg) {
                "", "." -> Unit
                ".." -> out.removeLastOrNull()
                else -> out.addLast(seg)
            }
        }
        val trailing = raw.endsWith("/") && out.isNotEmpty()
        return "/" + out.joinToString("/") + if (trailing) "/" else ""
    }

    fun percentDecode(s: String): String =
        if (!s.contains('%')) s else try {
            URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")
        } catch (e: IllegalArgumentException) {
            s
        }
}
