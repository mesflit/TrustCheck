// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.localization

import android.content.Context
import android.content.res.Configuration
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.app.LocaleManagerCompat
import androidx.core.os.LocaleListCompat
import java.util.Locale

/**
 * Applies and resolves the app language.
 *
 * UI: AppCompat per-app locales (Android 13+ system API; AppCompat back-port with
 * autoStoreLocales below 13). Changing it recreates activities immediately.
 * Background (notifications, workers): [localizedContext] builds a context for the stored
 * language, because per-app locales are not guaranteed to be applied to non-activity contexts on
 * older Android versions.
 */
object LocaleController {

    fun apply(language: AppLanguage) {
        val list = if (language == AppLanguage.SYSTEM) LocaleListCompat.getEmptyLocaleList() else LocaleListCompat.forLanguageTags(language.tag)
        AppCompatDelegate.setApplicationLocales(list)
    }

    /** Language currently applied by AppCompat/the system per-app setting. */
    fun appliedLanguage(): AppLanguage {
        val list = AppCompatDelegate.getApplicationLocales()
        return if (list.isEmpty) AppLanguage.SYSTEM else AppLanguage.match(list[0]?.toLanguageTag()) ?: AppLanguage.SYSTEM
    }

    fun systemTags(context: Context): List<String> {
        val list = LocaleManagerCompat.getSystemLocales(context)
        return (0 until list.size()).mapNotNull { list[it]?.toLanguageTag() }
    }

    fun effective(context: Context, selected: AppLanguage): AppLanguage = AppLanguage.resolve(selected, systemTags(context))

    fun localizedContext(context: Context, selected: AppLanguage): Context {
        val lang = effective(context, selected)
        val config = Configuration(context.resources.configuration)
        config.setLocale(Locale.forLanguageTag(lang.tag))
        config.setLayoutDirection(Locale.forLanguageTag(lang.tag))
        return context.createConfigurationContext(config)
    }
}
