package com.mesflit.trustcheck.core.localization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLanguageTest {
    @Test fun ninelanguagesSupported() {
        assertEquals(9, AppLanguage.supported.size)
        assertEquals(setOf("en", "tr", "de", "es", "fr", "pt-BR", "ar", "ja", "ru"), AppLanguage.supported.map { it.tag }.toSet())
    }

    @Test fun matchesExactAndLanguageOnly() {
        assertEquals(AppLanguage.PORTUGUESE_BR, AppLanguage.match("pt-BR"))
        assertEquals(AppLanguage.PORTUGUESE_BR, AppLanguage.match("pt_PT"))
        assertEquals(AppLanguage.GERMAN, AppLanguage.match("de-AT"))
        assertNull(AppLanguage.match("ko-KR"))
    }

    @Test fun fallsBackToEnglish() {
        assertEquals(AppLanguage.ENGLISH, AppLanguage.resolve(AppLanguage.SYSTEM, listOf("ko-KR", "zh-CN")))
        assertEquals(AppLanguage.ENGLISH, AppLanguage.resolve(AppLanguage.SYSTEM, emptyList()))
    }

    @Test fun systemUsesFirstSupportedDeviceLocale() {
        assertEquals(AppLanguage.TURKISH, AppLanguage.resolve(AppLanguage.SYSTEM, listOf("ko-KR", "tr-TR", "en-US")))
    }

    @Test fun explicitSelectionWins() {
        assertEquals(AppLanguage.JAPANESE, AppLanguage.resolve(AppLanguage.JAPANESE, listOf("tr-TR")))
    }

    @Test fun storedTagRoundTrip() {
        AppLanguage.entries.forEach { assertEquals(it, AppLanguage.fromStoredTag(it.tag)) }
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromStoredTag("xx"))
    }

    @Test fun onlyArabicIsRtl() {
        assertTrue(AppLanguage.ARABIC.isRtl)
        assertEquals(1, AppLanguage.entries.count { it.isRtl })
    }
}
