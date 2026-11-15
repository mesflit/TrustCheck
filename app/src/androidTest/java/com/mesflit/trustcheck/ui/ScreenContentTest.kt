package com.mesflit.trustcheck.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.TrustCheckTheme
import com.mesflit.trustcheck.core.localization.AppLanguage
import com.mesflit.trustcheck.core.security.UrlAnalysisEngine
import com.mesflit.trustcheck.domain.AppSettings
import com.mesflit.trustcheck.domain.ScanOutcome
import com.mesflit.trustcheck.feature.premium.PremiumContent
import com.mesflit.trustcheck.feature.scanner.ScannerContent
import com.mesflit.trustcheck.feature.scanner.ScannerState
import com.mesflit.trustcheck.feature.settings.SettingsContent
import com.mesflit.trustcheck.monetization.BillingStatus
import com.mesflit.trustcheck.monetization.Entitlement
import com.mesflit.trustcheck.monetization.EntitlementSource
import com.mesflit.trustcheck.monetization.EntitlementState
import com.mesflit.trustcheck.monetization.PlanOffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Stateless screen tests: no network, billing or ads involved. */
@RunWith(AndroidJUnit4::class)
class ScreenContentTest {
    @get:Rule val compose = createComposeRule()
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun scannerAcceptsInputAndShowsProgressAndResults() {
        var input = ""
        var scans = 0
        compose.setContent {
            TrustCheckTheme {
                ScannerContent(ScannerState(input = input), { input = it }, {}, {}, { scans++ }, {})
            }
        }
        compose.onNodeWithTag("scanner_input").performTextInput("https://paypa1.com")
        assertEquals("https://paypa1.com", input)
        compose.onNodeWithTag("scanner_scan").performClick()
        assertEquals(1, scans)
    }

    @Test fun scannerShowsProgressWhileScanning() {
        compose.setContent {
            TrustCheckTheme { ScannerContent(ScannerState(input = "x", scanning = true), {}, {}, {}, {}, {}) }
        }
        compose.onNodeWithTag("scanner_progress").assertIsDisplayed()
        compose.onNodeWithTag("scanner_scan").assertIsNotEnabled()
    }

    @Test fun scannerShowsLocalizedVerdict() {
        val result = UrlAnalysisEngine().analyzeLocally("https://paypa1.com/login")
        compose.setContent {
            TrustCheckTheme { ScannerContent(ScannerState(results = listOf(ScanOutcome(1, result))), {}, {}, {}, {}, {}) }
        }
        compose.onNodeWithText(ctx.getString(R.string.class_suspicious)).assertIsDisplayed()
    }

    @Test fun languageSelectorListsAllLanguagesAndReportsChoice() {
        var chosen: AppLanguage? = null
        compose.setContent {
            TrustCheckTheme {
                SettingsContent(
                    settings = AppSettings(), entitlement = Entitlement.FREE, notificationAccess = false,
                    postNotificationsGranted = true, backendConfigured = false, showAdPrivacy = false,
                    onUpdate = {}, onLanguage = { chosen = it }, onOpenAccessSettings = {}, onRequestPostNotifications = {},
                    onOpenBatterySettings = {}, onAdPrivacy = {}, onClearHistory = {}, onOpenPremium = {}, onOpenUrl = {},
                )
            }
        }
        compose.onNodeWithTag("settings").assertIsDisplayed()
        compose.onNodeWithTag("settings_language").performClick()
        AppLanguage.supported.forEach { compose.onNodeWithTag("lang_$it").assertExists() }
        compose.onNodeWithTag("lang_${AppLanguage.TURKISH}").performClick()
        assertEquals(AppLanguage.TURKISH, chosen)
    }

    @Test fun settingsShowsNotificationAccessState() {
        compose.setContent {
            TrustCheckTheme {
                SettingsContent(
                    settings = AppSettings(), entitlement = Entitlement.FREE, notificationAccess = false,
                    postNotificationsGranted = false, backendConfigured = false, showAdPrivacy = false,
                    onUpdate = {}, onLanguage = {}, onOpenAccessSettings = {}, onRequestPostNotifications = {},
                    onOpenBatterySettings = {}, onAdPrivacy = {}, onClearHistory = {}, onOpenPremium = {}, onOpenUrl = {},
                )
            }
        }
        compose.onNodeWithText(ctx.getString(R.string.settings_access_missing)).assertIsDisplayed()
        compose.onNodeWithText(ctx.getString(R.string.settings_post_notifications_missing)).assertExists()
    }

    @Test fun premiumShowsOnlyPlayProvidedPricesAndHonestStatus() {
        val plans = listOf(
            PlanOffer("annual", "t1", "₺999,99", "P1Y", null, null),
            PlanOffer("monthly", "t2", "₺129,99", "P1M", null, null),
        )
        var subscribed: PlanOffer? = null
        compose.setContent {
            TrustCheckTheme {
                PremiumContent(plans, Entitlement.FREE, BillingStatus.READY, null, {}, {}, { subscribed = it }, {}, {})
            }
        }
        compose.onNodeWithText(ctx.getString(R.string.premium_per_year, "₺999,99")).assertIsDisplayed()
        compose.onNodeWithTag("subscribe_monthly").performClick()
        assertEquals("monthly", subscribed?.basePlanId)
    }

    @Test fun premiumWithoutPlansSaysUnavailableInsteadOfInventingPrices() {
        compose.setContent { TrustCheckTheme { PremiumContent(emptyList(), Entitlement.FREE, BillingStatus.READY, null, {}, {}, {}, {}, {}) } }
        compose.onNodeWithTag("premium_unavailable").assertIsDisplayed()
    }

    @Test fun premiumPendingIsNotShownAsActive() {
        val pending = Entitlement(false, EntitlementState.PENDING, EntitlementSource.PLAY_CLIENT)
        compose.setContent { TrustCheckTheme { PremiumContent(emptyList(), pending, BillingStatus.READY, null, {}, {}, {}, {}, {}) } }
        compose.onNodeWithText(ctx.getString(R.string.premium_pending)).assertIsDisplayed()
        assertTrue(compose.onAllNodesWithTextCount(ctx.getString(R.string.premium_active)) == 0)
    }

    private fun androidx.compose.ui.test.junit4.ComposeContentTestRule.onAllNodesWithTextCount(text: String) =
        onAllNodes(androidx.compose.ui.test.hasText(text)).fetchSemanticsNodes().size
}

