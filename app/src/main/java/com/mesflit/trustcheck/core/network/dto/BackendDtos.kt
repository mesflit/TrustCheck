// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.network.dto

import kotlinx.serialization.Serializable

// Wire contract for mesflit/TrustCheck-Backend. See docs/BACKEND_API.md.

@Serializable
data class InstallRegistrationRequest(val installId: String, val platform: String = "android", val appVersion: String? = null, val osVersion: Int? = null)

@Serializable
data class InstallRegistrationResponse(val token: String, val expiresAt: Long? = null)

@Serializable
data class ThreatLookupRequest(val urls: List<String>)

@Serializable
data class ThreatLookupResult(val url: String, val verdict: String, val threatTypes: List<String> = emptyList(), val source: String? = null)

@Serializable
data class ThreatLookupResponse(val results: List<ThreatLookupResult>)

@Serializable
data class AiAnalyzeRequest(
    val url: String? = null,
    val text: String? = null,
    val language: String,
    val localIndicators: List<String> = emptyList(),
    val localClassification: String,
)

@Serializable
data class AiIndicatorDto(val code: String, val explanation: String)

@Serializable
data class AiAnalyzeResponse(
    val verdict: String,
    val riskScore: Int? = null,
    val summary: String,
    val indicators: List<AiIndicatorDto> = emptyList(),
    val recommendations: List<String> = emptyList(),
    val language: String,
    val model: String,
)

@Serializable
data class BlocklistEntryDto(val domain: String, val category: String, val source: String)

@Serializable
data class BlocklistResponse(
    val version: String,
    /** true: [added] is the full list; false: apply [added]/[removed] as a delta since the given version. */
    val full: Boolean,
    val added: List<BlocklistEntryDto> = emptyList(),
    val removed: List<String> = emptyList(),
)

@Serializable
data class BillingVerifyRequest(val packageName: String, val productId: String, val purchaseToken: String)

@Serializable
data class BillingVerifyResponse(
    val active: Boolean,
    val state: String,
    val inGracePeriod: Boolean = false,
    val onHold: Boolean = false,
    val expiryTimeMillis: Long? = null,
    val acknowledged: Boolean = false,
)

// --- Google Safe Browsing v4 Lookup API ---

@Serializable
data class SbClient(val clientId: String, val clientVersion: String)

@Serializable
data class SbThreatEntry(val url: String)

@Serializable
data class SbThreatInfo(
    val threatTypes: List<String>,
    val platformTypes: List<String>,
    val threatEntryTypes: List<String>,
    val threatEntries: List<SbThreatEntry>,
)

@Serializable
data class SbFindRequest(val client: SbClient, val threatInfo: SbThreatInfo)

@Serializable
data class SbMatch(val threatType: String, val platformType: String? = null, val threat: SbThreatEntry? = null)

@Serializable
data class SbFindResponse(val matches: List<SbMatch> = emptyList())
