// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.mesflit.trustcheck.AppContainer
import com.mesflit.trustcheck.MainActivity
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.TrustCheckTheme
import com.mesflit.trustcheck.feature.dashboard.DashboardScreen
import com.mesflit.trustcheck.feature.history.HistoryScreen
import com.mesflit.trustcheck.feature.onboarding.OnboardingScreen
import com.mesflit.trustcheck.feature.premium.PremiumScreen
import com.mesflit.trustcheck.feature.report.ReportScreen
import com.mesflit.trustcheck.feature.scanner.ScannerScreen
import com.mesflit.trustcheck.feature.settings.SettingsScreen
import kotlinx.coroutines.launch

val LocalAppContainer = staticCompositionLocalOf<AppContainer> { error("AppContainer not provided") }

@Composable
inline fun <reified VM : ViewModel> containerViewModel(key: String? = null, crossinline create: (AppContainer) -> VM): VM {
    val container = LocalAppContainer.current
    return viewModel(key = key, factory = viewModelFactory { initializer { create(container) } })
}

object Routes {
    const val DASHBOARD = "dashboard"
    const val SCANNER = "scanner"
    const val HISTORY = "history"
    const val SETTINGS = "settings"
    const val PREMIUM = "premium"
    const val REPORT = "report/{id}"
    fun report(id: Long) = "report/$id"
}

private data class TopLevel(val route: String, val label: Int, val icon: ImageVector, val tag: String)

private val topLevel = listOf(
    TopLevel(Routes.DASHBOARD, R.string.nav_dashboard, Icons.Filled.Shield, "nav_dashboard"),
    TopLevel(Routes.SCANNER, R.string.nav_scanner, Icons.Filled.Search, "nav_scanner"),
    TopLevel(Routes.HISTORY, R.string.nav_history, Icons.Filled.History, "nav_history"),
    TopLevel(Routes.SETTINGS, R.string.nav_settings, Icons.Filled.Settings, "nav_settings"),
)

@Composable
fun TrustCheckRoot(container: AppContainer, activity: MainActivity) {
    val settings by container.settings.settings.collectAsStateWithLifecycle(initialValue = null)
    val current = settings
    TrustCheckTheme(current?.theme ?: com.mesflit.trustcheck.domain.ThemeMode.SYSTEM) {
        CompositionLocalProvider(LocalAppContainer provides container) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                when {
                    current == null -> Box(Modifier.fillMaxSize())
                    !current.onboardingCompleted -> {
                        val scope = rememberCoroutineScope()
                        OnboardingScreen(onFinished = {
                            scope.launch {
                                container.settings.update { it.copy(onboardingCompleted = true) }
                                container.scheduler.schedulePeriodic(container.settings.current(), container.backend.isConfigured)
                                container.ads.gatherConsent(activity, container.billing.entitlement.value.isPremium)
                            }
                        })
                    }
                    else -> MainScaffold(container, activity)
                }
            }
        }
    }
}

@Composable
fun MainScaffold(container: AppContainer, activity: MainActivity, nav: NavHostController = rememberNavController()) {
    val backStack by nav.currentBackStackEntryAsState()
    val route = backStack?.destination?.route
    val pendingScan by container.pendingScan.collectAsStateWithLifecycle()
    val pendingReport by activity.pendingReportId.collectAsStateWithLifecycle()

    LaunchedEffect(pendingScan) {
        if (pendingScan != null && route != Routes.SCANNER) navigateTopLevel(nav, Routes.SCANNER)
    }
    LaunchedEffect(pendingReport) {
        pendingReport?.let { nav.navigate(Routes.report(it)); activity.pendingReportId.value = null }
    }

    Scaffold(
        bottomBar = {
            if (topLevel.any { it.route == route }) {
                NavigationBar {
                    topLevel.forEach { item ->
                        NavigationBarItem(
                            modifier = Modifier.testTag(item.tag),
                            selected = route == item.route,
                            onClick = { navigateTopLevel(nav, item.route) },
                            icon = { Icon(item.icon, contentDescription = null) },
                            label = { Text(stringResource(item.label)) },
                        )
                    }
                }
            }
        },
    ) { padding ->
        NavHost(nav, startDestination = Routes.DASHBOARD, modifier = Modifier.padding(padding)) {
            composable(Routes.DASHBOARD) {
                DashboardScreen(
                    onQuickScan = { text -> container.pendingScan.value = com.mesflit.trustcheck.PendingScan.Text(text, com.mesflit.trustcheck.domain.ScanOrigin.MANUAL) },
                    onOpenReport = { nav.navigate(Routes.report(it)) },
                    onOpenSettings = { navigateTopLevel(nav, Routes.SETTINGS) },
                    onOpenPremium = { nav.navigate(Routes.PREMIUM) },
                )
            }
            composable(Routes.SCANNER) { ScannerScreen(onOpenReport = { nav.navigate(Routes.report(it)) }) }
            composable(Routes.HISTORY) { HistoryScreen(onOpenReport = { nav.navigate(Routes.report(it)) }) }
            composable(Routes.SETTINGS) { SettingsScreen(activity = activity, onOpenPremium = { nav.navigate(Routes.PREMIUM) }) }
            composable(Routes.PREMIUM) { PremiumScreen(activity = activity, onBack = { nav.popBackStack() }) }
            composable(Routes.REPORT, arguments = listOf(navArgument("id") { type = NavType.LongType })) { entry ->
                ReportScreen(
                    id = entry.arguments?.getLong("id") ?: 0L,
                    activity = activity,
                    onBack = { nav.popBackStack() },
                    onOpenSettings = { navigateTopLevel(nav, Routes.SETTINGS) },
                )
            }
        }
    }
}

fun navigateTopLevel(nav: NavHostController, route: String) {
    nav.navigate(route) {
        popUpTo(nav.graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}
