// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanDao {
    @Insert
    suspend fun insert(scan: ScanEntity): Long

    @Query("SELECT * FROM scans WHERE id = :id")
    fun observe(id: Long): Flow<ScanEntity?>

    @Query("SELECT * FROM scans WHERE id = :id")
    suspend fun get(id: Long): ScanEntity?

    @Query(
        """
        SELECT * FROM scans
        WHERE classification IN (:classifications)
          AND (:query = '' OR normalized_url LIKE '%' || :query || '%' OR display_host LIKE '%' || :query || '%' OR source_app LIKE '%' || :query || '%')
        ORDER BY timestamp DESC
        LIMIT :limit
        """,
    )
    fun observeFiltered(query: String, classifications: List<String>, limit: Int = 500): Flow<List<ScanEntity>>

    @Query("SELECT * FROM scans WHERE classification IN (:classifications) ORDER BY timestamp DESC LIMIT :limit")
    fun observeRecent(classifications: List<String>, limit: Int): Flow<List<ScanEntity>>

    @Query("SELECT COUNT(*) FROM scans")
    fun observeCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM scans WHERE classification IN (:classifications)")
    fun observeCountIn(classifications: List<String>): Flow<Int>

    @Query("SELECT * FROM scans WHERE normalized_url = :normalizedUrl AND timestamp >= :since ORDER BY timestamp DESC LIMIT 1")
    suspend fun findRecent(normalizedUrl: String, since: Long): ScanEntity?

    @Query(
        """
        UPDATE scans SET classification = :classification, risk_score = :riskScore, indicators = :indicators,
            sources = :sources, final_url = :finalUrl, timestamp = :timestamp
        WHERE id = :id
        """,
    )
    suspend fun updateResult(id: Long, classification: String, riskScore: Int, indicators: String, sources: String, finalUrl: String?, timestamp: Long)

    @Query("UPDATE scans SET user_action = :action WHERE id = :id")
    suspend fun updateUserAction(id: Long, action: String)

    @Query("UPDATE scans SET ai_explanation = :json WHERE id = :id")
    suspend fun updateAi(id: Long, json: String?)

    @Query("DELETE FROM scans WHERE id = :id")
    suspend fun delete(id: Long)

    @Query("DELETE FROM scans")
    suspend fun clear()

    @Query("DELETE FROM scans WHERE timestamp < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long): Int
}

@Dao
interface BlocklistDao {
    @Query("SELECT COUNT(*) FROM blocklist")
    suspend fun count(): Int

    @Query("SELECT * FROM blocklist WHERE domain IN (:domains) LIMIT 1")
    suspend fun firstMatch(domains: List<String>): BlocklistEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entries: List<BlocklistEntity>)

    @Query("DELETE FROM blocklist WHERE domain IN (:domains)")
    suspend fun remove(domains: List<String>)

    @Query("DELETE FROM blocklist")
    suspend fun clear()

    @Transaction
    suspend fun replaceAll(entries: List<BlocklistEntity>) {
        clear()
        entries.chunked(500).forEach { upsert(it) }
    }
}
