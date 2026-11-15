// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.network

import android.os.Build
import com.mesflit.trustcheck.BuildConfig
import com.mesflit.trustcheck.core.network.dto.InstallRegistrationRequest
import com.mesflit.trustcheck.core.network.dto.InstallRegistrationResponse
import com.mesflit.trustcheck.domain.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.UUID
import java.util.concurrent.TimeUnit

sealed interface ApiResult<out T> {
    data class Ok<T>(val value: T) : ApiResult<T>
    data object NotConfigured : ApiResult<Nothing>
    data object RateLimited : ApiResult<Nothing>
    data class HttpError(val code: Int) : ApiResult<Nothing>
    data class NetworkError(val message: String) : ApiResult<Nothing>
}

object Http {
    val json = Json { ignoreUnknownKeys = true; explicitNulls = false; encodeDefaults = true }
    val JSON_TYPE = "application/json; charset=utf-8".toMediaType()

    /** Shared client: short timeouts, no cookies, no cache, HTTPS enforced by network_security_config. */
    val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .callTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }
}

/**
 * Client for the optional private backend (mesflit/TrustCheck-Backend).
 *
 * No secret is shipped in the APK. Each install registers an anonymous random ID and receives a
 * short-lived bearer token; the backend applies per-install and per-IP rate limits and should
 * additionally verify Play Integrity verdicts in production (see docs/BACKEND_API.md).
 */
class BackendClient(
    private val settings: SettingsRepository,
    baseUrl: String = BuildConfig.BACKEND_BASE_URL,
    private val http: OkHttpClient = Http.client,
) {
    private val base: HttpUrl? = baseUrl.takeIf { it.startsWith("https://") }?.toHttpUrlOrNull()
    private val tokenMutex = Mutex()

    val isConfigured: Boolean get() = base != null

    suspend fun <Req, Res> post(path: String, body: Req, reqSer: KSerializer<Req>, resSer: KSerializer<Res>, timeoutSeconds: Long = 20): ApiResult<Res> =
        call(path, timeoutSeconds) { builder -> builder.post(Http.json.encodeToString(reqSer, body).toRequestBody(Http.JSON_TYPE)) }
            .let { r -> if (r is ApiResult.Ok) decode(r.value, resSer) else r as ApiResult<Res> }

    suspend fun <Res> get(path: String, query: Map<String, String>, resSer: KSerializer<Res>): ApiResult<Res> =
        call(path, 20, query) { it.get() }.let { r -> if (r is ApiResult.Ok) decode(r.value, resSer) else r as ApiResult<Res> }

    private fun <Res> decode(body: String, ser: KSerializer<Res>): ApiResult<Res> =
        try { ApiResult.Ok(Http.json.decodeFromString(ser, body)) } catch (e: Exception) { ApiResult.NetworkError("bad_response") }

    private suspend fun call(
        path: String,
        timeoutSeconds: Long,
        query: Map<String, String> = emptyMap(),
        configure: (Request.Builder) -> Request.Builder,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        val b = base ?: return@withContext ApiResult.NotConfigured
        val token = ensureToken() ?: return@withContext ApiResult.NetworkError("auth_unavailable")
        val first = execute(b, path, query, token, timeoutSeconds, configure)
        if (first is ApiResult.HttpError && first.code == 401) {
            settings.setBackendToken(null)
            val fresh = ensureToken() ?: return@withContext first
            execute(b, path, query, fresh, timeoutSeconds, configure)
        } else first
    }

    private suspend fun execute(
        b: HttpUrl, path: String, query: Map<String, String>, token: String, timeoutSeconds: Long,
        configure: (Request.Builder) -> Request.Builder,
    ): ApiResult<String> {
        val url = b.newBuilder().addPathSegments(path.trimStart('/')).apply { query.forEach { (k, v) -> addQueryParameter(k, v) } }.build()
        val builder = Request.Builder().url(url)
            .header("Authorization", "Bearer $token")
            .header("Accept", "application/json")
        if (settings.current().diagnostics) {
            builder.header("X-TrustCheck-App", BuildConfig.VERSION_NAME).header("X-TrustCheck-Sdk", Build.VERSION.SDK_INT.toString())
        }
        val client = http.newBuilder().callTimeout(timeoutSeconds, TimeUnit.SECONDS).build()
        return try {
            client.newCall(configure(builder).build()).execute().use { resp ->
                when {
                    resp.code == 429 -> ApiResult.RateLimited
                    !resp.isSuccessful -> ApiResult.HttpError(resp.code)
                    else -> ApiResult.Ok(resp.body?.string().orEmpty())
                }
            }
        } catch (e: IOException) {
            ApiResult.NetworkError(e.javaClass.simpleName)
        }
    }

    private suspend fun ensureToken(): String? = tokenMutex.withLock {
        settings.backendToken()?.let { return it }
        val b = base ?: return null
        val installId = UUID.randomUUID().toString()
        val req = InstallRegistrationRequest(installId, appVersion = BuildConfig.VERSION_NAME, osVersion = Build.VERSION.SDK_INT)
        val request = Request.Builder()
            .url(b.newBuilder().addPathSegments("v1/auth/install").build())
            .post(Http.json.encodeToString(InstallRegistrationRequest.serializer(), req).toRequestBody(Http.JSON_TYPE))
            .build()
        return try {
            http.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) return null
                val token = Http.json.decodeFromString(InstallRegistrationResponse.serializer(), resp.body?.string().orEmpty()).token
                settings.setBackendToken(token)
                token
            }
        } catch (e: Exception) {
            null
        }
    }
}
