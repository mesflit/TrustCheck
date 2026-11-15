// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.mesflit.trustcheck.core.localization.AppLanguage
import com.mesflit.trustcheck.core.network.DailyQuota
import com.mesflit.trustcheck.domain.AppSettings
import com.mesflit.trustcheck.domain.SettingsRepository
import com.mesflit.trustcheck.domain.ThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException

private val Context.settingsStore: DataStore<Preferences> by preferencesDataStore(name = "trustcheck_settings")

class SettingsRepositoryImpl(context: Context) : SettingsRepository {
    private val store = context.applicationContext.settingsStore

    private object K {
        val onboarding = booleanPreferencesKey("onboarding_completed")
        val theme = stringPreferencesKey("theme")
        val language = stringPreferencesKey("language")
        val monitoring = booleanPreferencesKey("notification_monitoring")
        val alerts = booleanPreferencesKey("alerts_enabled")
        val cloudTi = booleanPreferencesKey("cloud_threat_intel")
        val cloudAi = booleanPreferencesKey("cloud_ai")
        val redirects = booleanPreferencesKey("resolve_redirects")
        val keepClean = booleanPreferencesKey("keep_clean_notification_scans")
        val retention = intPreferencesKey("retention_days")
        val diagnostics = booleanPreferencesKey("diagnostics")
        val sbKey = stringPreferencesKey("safe_browsing_key")
        val aiDay = longPreferencesKey("ai_quota_day")
        val aiUsed = intPreferencesKey("ai_quota_used")
        val bonusDay = longPreferencesKey("ai_bonus_day")
        val bonusAmount = intPreferencesKey("ai_bonus_amount")
        val totalScans = longPreferencesKey("total_scans")
        val backendToken = stringPreferencesKey("backend_token")
    }

    override val settings: Flow<AppSettings> = store.data
        .catch { e -> if (e is IOException) emit(androidx.datastore.preferences.core.emptyPreferences()) else throw e }
        .map { p ->
            read(p).copy(
                aiQuota = DailyQuota(p[K.aiDay] ?: 0, p[K.aiUsed] ?: 0),
                aiBonus = DailyQuota(p[K.bonusDay] ?: 0, p[K.bonusAmount] ?: 0),
                totalScans = p[K.totalScans] ?: 0,
            )
        }

    override suspend fun current(): AppSettings = settings.first()

    override suspend fun update(transform: (AppSettings) -> AppSettings) {
        store.edit { p ->
            val old = read(p)
            val n = transform(old)
            p[K.onboarding] = n.onboardingCompleted
            p[K.theme] = n.theme.name
            p[K.language] = n.language.tag
            p[K.monitoring] = n.notificationMonitoring
            p[K.alerts] = n.alertsEnabled
            p[K.cloudTi] = n.cloudThreatIntel
            p[K.cloudAi] = n.cloudAi
            p[K.redirects] = n.resolveRedirects
            p[K.keepClean] = n.keepCleanNotificationScans
            p[K.retention] = n.retentionDays
            p[K.diagnostics] = n.diagnostics
            p[K.sbKey] = n.safeBrowsingApiKey.trim()
        }
    }

    private fun read(p: Preferences) = AppSettings(
        onboardingCompleted = p[K.onboarding] ?: false,
        theme = enumValueOrNull<ThemeMode>(p[K.theme]) ?: ThemeMode.SYSTEM,
        language = AppLanguage.fromStoredTag(p[K.language]),
        notificationMonitoring = p[K.monitoring] ?: false,
        alertsEnabled = p[K.alerts] ?: true,
        cloudThreatIntel = p[K.cloudTi] ?: false,
        cloudAi = p[K.cloudAi] ?: false,
        resolveRedirects = p[K.redirects] ?: false,
        keepCleanNotificationScans = p[K.keepClean] ?: false,
        retentionDays = p[K.retention] ?: 30,
        diagnostics = p[K.diagnostics] ?: false,
        safeBrowsingApiKey = p[K.sbKey] ?: "",
    )

    override suspend fun setLanguage(language: AppLanguage) {
        store.edit { it[K.language] = language.tag }
    }

    override suspend fun incrementTotalScans(by: Int) {
        store.edit { it[K.totalScans] = (it[K.totalScans] ?: 0) + by }
    }

    override suspend fun consumeAiQuota(day: Long) {
        store.edit { p ->
            val q = DailyQuota(p[K.aiDay] ?: 0, p[K.aiUsed] ?: 0).consume(day)
            p[K.aiDay] = q.epochDay
            p[K.aiUsed] = q.used
        }
    }

    override suspend fun addAiBonus(day: Long, amount: Int) {
        store.edit { p ->
            val q = DailyQuota(p[K.bonusDay] ?: 0, p[K.bonusAmount] ?: 0).forDay(day)
            p[K.bonusDay] = day
            p[K.bonusAmount] = q.used + amount
        }
    }

    override suspend fun backendToken(): String? = store.data.first()[K.backendToken]

    override suspend fun setBackendToken(token: String?) {
        store.edit { if (token == null) it.remove(K.backendToken) else it[K.backendToken] = token }
    }
}
