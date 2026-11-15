// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.data

import com.mesflit.trustcheck.core.database.ScanEntity
import com.mesflit.trustcheck.core.security.AnalysisSource
import com.mesflit.trustcheck.core.security.ApkFacts
import com.mesflit.trustcheck.core.security.DetectedIndicator
import com.mesflit.trustcheck.core.security.FileFacts
import com.mesflit.trustcheck.core.security.FileKind
import com.mesflit.trustcheck.core.security.Indicator
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.SourceResult
import com.mesflit.trustcheck.core.security.SourceStatus
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
internal data class StoredApk(
    val packageName: String? = null,
    val appLabel: String? = null,
    val versionName: String? = null,
    val permissions: List<String> = emptyList(),
    val accessibility: Boolean = false,
    val notificationListener: Boolean = false,
    val deviceAdmin: Boolean = false,
    val debugSigned: Boolean = false,
)

@Serializable
internal data class StoredFile(
    val name: String,
    val size: Long,
    val mime: String? = null,
    val kind: String,
    val sha256: String,
    val apk: StoredApk? = null,
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

    fun encodeFile(f: FileFacts): String = json.encodeToString(
        StoredFile(
            f.displayName, f.sizeBytes, f.declaredMime, f.kind.name, f.sha256,
            f.apk?.let { StoredApk(it.packageName, it.appLabel, it.versionName, it.permissions, it.hasAccessibilityService, it.hasNotificationListener, it.hasDeviceAdmin, it.debugSigned) },
        ),
    )

    fun decodeFile(s: String?): FileFacts? = s?.let {
        runCatching {
            val f = json.decodeFromString<StoredFile>(it)
            FileFacts(
                f.name, f.size, f.mime, enumValueOrNull<FileKind>(f.kind) ?: FileKind.UNKNOWN, f.sha256,
                f.apk?.let { a -> ApkFacts(a.packageName, a.appLabel, a.versionName, a.permissions, a.accessibility, a.notificationListener, a.deviceAdmin, a.debugSigned) },
            )
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
    file = StorageJson.decodeFile(fileInfo),
    timestamp = timestamp,
)
