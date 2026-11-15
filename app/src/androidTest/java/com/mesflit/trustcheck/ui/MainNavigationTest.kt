package com.mesflit.trustcheck.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.mesflit.trustcheck.MainActivity
import com.mesflit.trustcheck.TrustCheckApp
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainNavigationTest {
    @get:Rule val compose = createEmptyComposeRule()
    private var scenario: ActivityScenario<MainActivity>? = null

    @Before fun setUp() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as TrustCheckApp
        runBlocking { app.container.settings.update { it.copy(onboardingCompleted = true) } }
        scenario = ActivityScenario.launch(MainActivity::class.java)
    }

    @After fun tearDown() { scenario?.close() }

    @Test fun bottomNavigationReachesEveryTopLevelScreen() {
        compose.onNodeWithTag("dashboard").assertIsDisplayed()
        compose.onNodeWithTag("nav_scanner").performClick()
        compose.onNodeWithTag("scanner").assertIsDisplayed()
        compose.onNodeWithTag("nav_history").performClick()
        compose.onNodeWithTag("history").assertIsDisplayed()
        compose.onNodeWithTag("nav_settings").performClick()
        compose.onNodeWithTag("settings").assertIsDisplayed()
        compose.onNodeWithTag("nav_dashboard").performClick()
        compose.onNodeWithTag("dashboard").assertIsDisplayed()
    }
}
