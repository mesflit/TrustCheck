// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.network

import com.mesflit.trustcheck.BuildConfig
import com.mesflit.trustcheck.core.network.dto.SbClient
import com.mesflit.trustcheck.core.network.dto.SbFindRequest
import com.mesflit.trustcheck.core.network.dto.SbFindResponse
import com.mesflit.trustcheck.core.network.dto.SbThreatEntry
import com.mesflit.trustcheck.core.network.dto.SbThreatInfo
import com.mesflit.trustcheck.core.network.dto.ThreatLookupRequest
import com.mesflit.trustcheck.core.network.dto.ThreatLookupResponse
import com.mesflit.trustcheck.core.security.AnalysisSource
import com.mesflit.trustcheck.core.security.SourceResult
import com.mesflit.trustcheck.core.security.SourceStatus
import com.mesflit.trustcheck.core.security.ThreatIntelProvider
import com.mesflit.trustcheck.domain.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

/**
 * Threat intelligence via TrustCheck-Backend, which aggregates commercial-use providers
 * (e.g. Google Web Risk) server-side so that no provider credential is ever in the APK.
 */
class BackendThreatIntelProvider(
    private val backend: BackendClient,
    private val settings: SettingsRepository,
    private val limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(30, 60_000),
) : ThreatIntelProvider {
    override val source = AnalysisSource.TRUSTCHECK_BACKEND

    override suspend fun isAvailable(): Boolean = backend.isConfigured && settings.current().cloudThreatIntel

    override suspend fun lookup(urlKeys: List<String>): SourceResult {
        if (!limiter.tryAcquire(System.currentTimeMillis())) return SourceResult(source, SourceStatus.ERROR, "client_rate_limited")
        return when (val r = backend.post("v1/threat/lookup", ThreatLookupRequest(urlKeys), ThreatLookupRequest.serializer(), ThreatLookupResponse.serializer())) {
            is ApiResult.Ok -> {
                val bad = r.value.results.filter { it.verdict.equals("malicious", ignoreCase = true) }
                val answered = r.value.results.filter { it.verdict.equals("malicious", true) || it.verdict.equals("clean", true) }
                when {
                    bad.isNotEmpty() -> SourceResult(source, SourceStatus.MATCH, bad.flatMap { it.threatTypes }.distinct().joinToString(",").ifEmpty { "MALICIOUS" })
                    // Only an explicit "clean" counts as an answer; "unknown" is not evidence of safety.
                    answered.isNotEmpty() -> SourceResult(source, SourceStatus.NO_MATCH, answered.mapNotNull { it.source }.distinct().joinToString(",").takeIf { it.isNotEmpty() })
                    else -> SourceResult(source, SourceStatus.UNAVAILABLE, "no_verdict")
                }
            }
            ApiResult.NotConfigured -> SourceResult(source, SourceStatus.UNAVAILABLE, "not_configured")
            ApiResult.RateLimited -> SourceResult(source, SourceStatus.ERROR, "rate_limited")
            is ApiResult.HttpError -> SourceResult(source, SourceStatus.ERROR, "http_${r.code}")
            is ApiResult.NetworkError -> SourceResult(source, SourceStatus.ERROR, r.message)
        }
    }
}

/**
 * Direct Google Safe Browsing v4 Lookup API using a key the *user* enters in Settings.
 *
 * Google restricts the free Safe Browsing API to non-commercial use; commercial deployments should
 * use the backend with Google Web Risk instead. This option exists for self-builders and
 * privacy-minded users who want to use their own key. No key is ever compiled into the app.
 */
class SafeBrowsingProvider(
    private val settings: SettingsRepository,
    private val http: OkHttpClient = Http.client,
    private val limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(30, 60_000),
) : ThreatIntelProvider {
    override val source = AnalysisSource.GOOGLE_SAFE_BROWSING

    override suspend fun isAvailable(): Boolean = settings.current().let { it.cloudThreatIntel && it.safeBrowsingApiKey.isNotBlank() }

    override suspend fun lookup(urlKeys: List<String>): SourceResult = withContext(Dispatchers.IO) {
        val key = settings.current().safeBrowsingApiKey
        if (key.isBlank()) return@withContext SourceResult(source, SourceStatus.UNAVAILABLE, "not_configured")
        if (!limiter.tryAcquire(System.currentTimeMillis())) return@withContext SourceResult(source, SourceStatus.ERROR, "client_rate_limited")
        val body = SbFindRequest(
            client = SbClient("com.mesflit.trustcheck", BuildConfig.VERSION_NAME),
            threatInfo = SbThreatInfo(
                threatTypes = listOf("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"),
                platformTypes = listOf("ANY_PLATFORM"),
                threatEntryTypes = listOf("URL"),
                threatEntries = urlKeys.map { SbThreatEntry(it) },
            ),
        )
        val url = "https://safebrowsing.googleapis.com/v4/threatMatches:find".toHttpUrl().newBuilder().addQueryParameter("key", key).build()
        val request = Request.Builder().url(url)
            .post(Http.json.encodeToString(SbFindRequest.serializer(), body).toRequestBody(Http.JSON_TYPE))
            .build()
        try {
            http.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) return@withContext SourceResult(source, SourceStatus.ERROR, "http_${resp.code}")
                val parsed = Http.json.decodeFromString(SbFindResponse.serializer(), resp.body?.string().orEmpty().ifBlank { "{}" })
                if (parsed.matches.isEmpty()) {
                    SourceResult(source, SourceStatus.NO_MATCH)
                } else {
                    SourceResult(source, SourceStatus.MATCH, parsed.matches.map { it.threatType }.distinct().joinToString(","))
                }
            }
        } catch (e: IOException) {
            SourceResult(source, SourceStatus.ERROR, e.javaClass.simpleName)
        } catch (e: kotlinx.serialization.SerializationException) {
            SourceResult(source, SourceStatus.ERROR, "bad_response")
        }
    }
}
