// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.localization

/** Languages shipped with TrustCheck. [SYSTEM] follows the device locale with English fallback. */
enum class AppLanguage(val tag: String, val nativeName: String, val isRtl: Boolean = false) {
    SYSTEM("", ""),
    ENGLISH("en", "English"),
    TURKISH("tr", "Türkçe"),
    GERMAN("de", "Deutsch"),
    SPANISH("es", "Español"),
    FRENCH("fr", "Français"),
    PORTUGUESE_BR("pt-BR", "Português (Brasil)"),
    ARABIC("ar", "العربية", isRtl = true),
    JAPANESE("ja", "日本語"),
    RUSSIAN("ru", "Русский"),
    ;

    companion object {
        val supported: List<AppLanguage> = entries.filter { it != SYSTEM }
        val DEFAULT = ENGLISH

        /** Exact tag, then language-only match (e.g. "pt-PT" → pt-BR, "de-AT" → de), else null. */
        fun match(tag: String?): AppLanguage? {
            if (tag.isNullOrBlank()) return null
            val norm = tag.replace('_', '-').trim()
            supported.firstOrNull { it.tag.equals(norm, ignoreCase = true) }?.let { return it }
            val lang = norm.substringBefore('-').lowercase()
            return supported.firstOrNull { it.tag.substringBefore('-').equals(lang, ignoreCase = true) }
        }

        /** Stored preference → enum. Unknown/blank values mean SYSTEM. */
        fun fromStoredTag(tag: String?): AppLanguage = if (tag.isNullOrBlank()) SYSTEM else match(tag) ?: SYSTEM

        /**
         * The language actually used for UI text and AI explanations.
         * [systemTags] are the device's preferred locales in priority order.
         */
        fun resolve(selected: AppLanguage, systemTags: List<String>): AppLanguage =
            if (selected != SYSTEM) selected else systemTags.firstNotNullOfOrNull { match(it) } ?: DEFAULT
    }
}
