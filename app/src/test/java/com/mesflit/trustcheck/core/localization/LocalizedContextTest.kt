package com.mesflit.trustcheck.core.localization

import android.app.Application
import android.content.Context
import android.view.View
import androidx.test.core.app.ApplicationProvider
import com.mesflit.trustcheck.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Language switching for background contexts (notifications/workers) and English fallback. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class, qualifiers = "en-rUS")
class LocalizedContextTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test fun switchesLanguageForEachSupportedLocale() {
        val english = LocaleController.localizedContext(context, AppLanguage.ENGLISH).getString(R.string.alert_title_malicious)
        for (lang in AppLanguage.supported - AppLanguage.ENGLISH) {
            val text = LocaleController.localizedContext(context, lang).getString(R.string.alert_title_malicious)
            assertNotEquals("$lang should be translated", english, text)
        }
    }

    @Test fun arabicIsRightToLeft() {
        val ctx = LocaleController.localizedContext(context, AppLanguage.ARABIC)
        assertEquals(View.LAYOUT_DIRECTION_RTL, ctx.resources.configuration.layoutDirection)
    }

    @Test fun systemLanguageResolvesAgainstDeviceLocale() {
        assertEquals(AppLanguage.ENGLISH, LocaleController.effective(context, AppLanguage.SYSTEM))
    }

    @Test @Config(qualifiers = "ko-rKR")
    fun unsupportedDeviceLocaleFallsBackToEnglish() {
        val ctx = LocaleController.localizedContext(context, AppLanguage.SYSTEM)
        assertEquals("Dangerous link detected", ctx.getString(R.string.alert_title_malicious))
    }
}
