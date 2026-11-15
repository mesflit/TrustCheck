// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.database

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * One scan in the security history. Stores the privacy-reduced URL (no query/fragment), never
 * the surrounding message text.
 */
@Entity(
    tableName = "scans",
    indices = [Index("timestamp"), Index("classification"), Index("normalized_url")],
)
data class ScanEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "target_type") val targetType: String,
    @ColumnInfo(name = "normalized_url") val normalizedUrl: String?,
    @ColumnInfo(name = "display_host") val displayHost: String?,
    @ColumnInfo(name = "registrable_domain") val registrableDomain: String?,
    @ColumnInfo(name = "final_url") val finalUrl: String?,
    val classification: String,
    @ColumnInfo(name = "risk_score") val riskScore: Int,
    /** JSON array of {code, detail}. */
    val indicators: String,
    /** JSON array of {source, status, detail}. */
    val sources: String,
    val origin: String,
    @ColumnInfo(name = "source_app") val sourceApp: String?,
    @ColumnInfo(name = "user_action") val userAction: String,
    /** JSON AI explanation, or null. */
    @ColumnInfo(name = "ai_explanation") val aiExplanation: String?,
    val timestamp: Long,
)

/** Domain entries synced from the TrustCheck threat feed (never bundled or invented). */
@Entity(tableName = "blocklist")
data class BlocklistEntity(
    @PrimaryKey val domain: String,
    val category: String,
    val source: String,
    @ColumnInfo(name = "updated_at") val updatedAt: Long,
)
