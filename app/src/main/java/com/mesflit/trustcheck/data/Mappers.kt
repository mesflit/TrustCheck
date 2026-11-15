// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.data

import com.mesflit.trustcheck.core.database.ScanEntity
import com.mesflit.trustcheck.core.security.AnalysisSource
import com.mesflit.trustcheck.core.security.DetectedIndicator
import com.mesflit.trustcheck.core.security.Indicator
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.SourceResult
import com.mesflit.trustcheck.core.security.SourceStatus
import com.mesflit.trustcheck.domain.AiExplanation
import com.mesflit.trustcheck.domain.AiIndicatorNote
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.ScanRecord
import com.mesflit.trustcheck.domain.TargetType
import com.mesflit.trustcheck.domain.UserAction
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
internal data class StoredIndicator(val code: String, val detail: String? = null)

@Serializable
internal data class StoredSource(val source: String, val status: String, val detail: String? = null)

@Serializable
internal data class StoredAiNote(val code: String, val explanation: String)

@Serializable
internal data class StoredAi(
    val verdict: String,
    val riskScore: Int? = null,
    val summary: String,
    val notes: List<StoredAiNote> = emptyList(),
    val recommendations: List<String> = emptyList(),
    val language: String,
    val model: String,
    val createdAt: Long,
)

internal object StorageJson {
    val json = Json { ignoreUnknownKeys = true; encodeDefaults = false }

    fun encodeIndicators(list: List<DetectedIndicator>): String =
        json.encodeToString(list.map { StoredIndicator(it.indicator.name, it.detail) })

    fun decodeIndicators(s: String): List<DetectedIndicator> = runCatching {
        json.decodeFromString<List<StoredIndicator>>(s).mapNotNull { st ->
            enumValueOrNull<Indicator>(st.code)?.let { DetectedIndicator(it, st.detail) }
        }
    }.getOrDefault(emptyList())

    fun encodeSources(list: List<SourceResult>): String =
        json.encodeToString(list.map { StoredSource(it.source.name, it.status.name, it.detail) })

    fun decodeSources(s: String): List<SourceResult> = runCatching {
        json.decodeFromString<List<StoredSource>>(s).mapNotNull { st ->
            val src = enumValueOrNull<AnalysisSource>(st.source) ?: return@mapNotNull null
            val status = enumValueOrNull<SourceStatus>(st.status) ?: return@mapNotNull null
            SourceResult(src, status, st.detail)
        }
    }.getOrDefault(emptyList())

    fun encodeAi(ai: AiExplanation): String = json.encodeToString(
        StoredAi(ai.verdict, ai.riskScore, ai.summary, ai.notes.map { StoredAiNote(it.code, it.explanation) }, ai.recommendations, ai.language, ai.model, ai.createdAt),
    )

    fun decodeAi(s: String?): AiExplanation? = s?.let {
        runCatching {
            val a = json.decodeFromString<StoredAi>(it)
            AiExplanation(a.verdict, a.riskScore, a.summary, a.notes.map { n -> AiIndicatorNote(n.code, n.explanation) }, a.recommendations, a.language, a.model, a.createdAt)
        }.getOrNull()
    }
}

internal inline fun <reified T : Enum<T>> enumValueOrNull(name: String?): T? =
    name?.let { n -> enumValues<T>().firstOrNull { it.name == n } }

internal fun ScanEntity.toDomain() = ScanRecord(
    id = id,
    targetType = enumValueOrNull<TargetType>(targetType) ?: TargetType.URL,
    normalizedUrl = normalizedUrl,
    displayHost = displayHost,
    registrableDomain = registrableDomain,
    finalUrl = finalUrl,
    classification = enumValueOrNull<RiskClassification>(classification) ?: RiskClassification.UNKNOWN,
    riskScore = riskScore,
    indicators = StorageJson.decodeIndicators(indicators),
    sources = StorageJson.decodeSources(sources),
    origin = enumValueOrNull<ScanOrigin>(origin) ?: ScanOrigin.MANUAL,
    sourceApp = sourceApp,
    userAction = enumValueOrNull<UserAction>(userAction) ?: UserAction.NONE,
    ai = StorageJson.decodeAi(aiExplanation),
    timestamp = timestamp,
)
