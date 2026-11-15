// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.data

import com.mesflit.trustcheck.core.database.ScanDao
import com.mesflit.trustcheck.core.database.ScanEntity
import com.mesflit.trustcheck.core.security.FileFacts
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.UrlAnalysisResult
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.ScanRecord
import com.mesflit.trustcheck.domain.ScanRepository
import com.mesflit.trustcheck.domain.ScanStats
import com.mesflit.trustcheck.domain.TargetType
import com.mesflit.trustcheck.domain.UserAction
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map

class ScanRepositoryImpl(private val dao: ScanDao) : ScanRepository {

    override suspend fun save(result: UrlAnalysisResult, targetType: TargetType, origin: ScanOrigin, sourceApp: String?, file: FileFacts?): Long =
        dao.insert(
            ScanEntity(
                targetType = targetType.name,
                normalizedUrl = result.normalizedUrl,
                displayHost = result.displayHost,
                registrableDomain = result.registrableDomain,
                finalUrl = result.finalUrl,
                classification = result.classification.name,
                riskScore = result.riskScore,
                indicators = StorageJson.encodeIndicators(result.indicators),
                sources = StorageJson.encodeSources(result.sources),
                origin = origin.name,
                sourceApp = sourceApp,
                userAction = UserAction.NONE.name,
                aiExplanation = null,
                fileInfo = file?.let { StorageJson.encodeFile(it) },
                timestamp = result.timestampMillis,
            ),
        )

    override suspend fun updateResult(id: Long, result: UrlAnalysisResult) = dao.updateResult(
        id = id,
        classification = result.classification.name,
        riskScore = result.riskScore,
        indicators = StorageJson.encodeIndicators(result.indicators),
        sources = StorageJson.encodeSources(result.sources),
        finalUrl = result.finalUrl,
        timestamp = result.timestampMillis,
    )

    override suspend fun get(id: Long): ScanRecord? = dao.get(id)?.toDomain()

    override fun observe(id: Long): Flow<ScanRecord?> = dao.observe(id).map { it?.toDomain() }

    override fun observeHistory(query: String, filter: Set<RiskClassification>): Flow<List<ScanRecord>> {
        val classes = (filter.ifEmpty { RiskClassification.entries.toSet() }).map { it.name }
        return dao.observeFiltered(query.trim(), classes).map { list -> list.map { it.toDomain() } }
    }

    override fun observeRecentAlerts(limit: Int): Flow<List<ScanRecord>> =
        dao.observeRecent(ALERT_CLASSES, limit).map { list -> list.map { it.toDomain() } }

    override fun observeStats(): Flow<ScanStats> = combine(
        dao.observeCount(),
        dao.observeCountIn(listOf(RiskClassification.SUSPICIOUS.name)),
        dao.observeCountIn(listOf(RiskClassification.CONFIRMED_MALICIOUS.name)),
    ) { total, suspicious, malicious -> ScanStats(total, suspicious, malicious) }

    override suspend fun findRecent(normalizedUrl: String, sinceMillis: Long): ScanRecord? =
        dao.findRecent(normalizedUrl, sinceMillis)?.toDomain()

    override suspend fun setUserAction(id: Long, action: UserAction) = dao.updateUserAction(id, action.name)

    override suspend fun delete(id: Long) = dao.delete(id)

    override suspend fun clearAll() = dao.clear()

    override suspend fun purgeOlderThan(cutoffMillis: Long): Int = dao.deleteOlderThan(cutoffMillis)

    companion object {
        val ALERT_CLASSES = listOf(RiskClassification.CONFIRMED_MALICIOUS.name, RiskClassification.SUSPICIOUS.name)
    }
}
