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
    /** Unused since v2 (AI removed); kept so existing databases need no column drop. */
    @ColumnInfo(name = "ai_explanation") val aiExplanation: String?,
    /** JSON file metadata for FILE scans (added in schema v2). */
    @ColumnInfo(name = "file_info") val fileInfo: String? = null,
    val timestamp: Long,
)
