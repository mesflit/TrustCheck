// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(entities = [ScanEntity::class], version = 2, exportSchema = true)
abstract class TrustCheckDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao

    companion object {
        /** v2: file scanning adds a nullable file_info column; the threat list moved out of Room. */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE scans ADD COLUMN file_info TEXT")
                db.execSQL("DROP TABLE IF EXISTS blocklist")
            }
        }

        fun create(context: Context): TrustCheckDatabase =
            Room.databaseBuilder(context, TrustCheckDatabase::class.java, "trustcheck.db")
                .addMigrations(MIGRATION_1_2)
                .fallbackToDestructiveMigrationOnDowngrade(dropAllTables = true)
                .build()
    }
}
