// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [ScanEntity::class, BlocklistEntity::class], version = 1, exportSchema = true)
abstract class TrustCheckDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao
    abstract fun blocklistDao(): BlocklistDao

    companion object {
        fun create(context: Context): TrustCheckDatabase =
            Room.databaseBuilder(context, TrustCheckDatabase::class.java, "trustcheck.db")
                .fallbackToDestructiveMigrationOnDowngrade(dropAllTables = true)
                .build()
    }
}
