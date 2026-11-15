// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.dashboard

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.WorkspacePremium
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.mesflit.trustcheck.AppContainer
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.EmptyState
import com.mesflit.trustcheck.core.design.LocalRiskColors
import com.mesflit.trustcheck.core.design.RiskBadge
import com.mesflit.trustcheck.core.design.SectionCard
import com.mesflit.trustcheck.core.design.StatTile
import com.mesflit.trustcheck.core.design.StatusDot
import com.mesflit.trustcheck.core.design.rememberDateTimeFormatter
import com.mesflit.trustcheck.domain.ScanRecord
import com.mesflit.trustcheck.domain.ScanStats
import com.mesflit.trustcheck.domain.TargetType
import com.mesflit.trustcheck.monetization.BannerAdSlot
import com.mesflit.trustcheck.monetization.Entitlement
import com.mesflit.trustcheck.ui.LocalAppContainer
import com.mesflit.trustcheck.ui.containerViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

data class DashboardState(
    val stats: ScanStats = ScanStats(0, 0, 0),
    val totalScans: Long = 0,
    val recentAlerts: List<ScanRecord> = emptyList(),
    val monitoringEnabled: Boolean = false,
    val cloudEnabled: Boolean = false,
    val entitlement: Entitlement = Entitlement.FREE,
)

class DashboardViewModel(c: AppContainer) : ViewModel() {
    val state: StateFlow<DashboardState> = combine(
        c.scans.observeStats(),
        c.scans.observeRecentAlerts(5),
        c.settings.settings,
        c.billing.entitlement,
    ) { stats, alerts, s, e ->
        DashboardState(stats, maxOf(s.totalScans, stats.total.toLong()), alerts, s.notificationMonitoring, s.cloudThreatIntel, e)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DashboardState())
}

fun hasNotificationAccess(context: Context): Boolean =
    NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)

@Composable
fun DashboardScreen(
    onQuickScan: (String) -> Unit,
    onOpenReport: (Long) -> Unit,
    onOpenSettings: () -> Unit,
    onOpenPremium: () -> Unit,
) {
    val vm = containerViewModel { DashboardViewModel(it) }
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var access by remember { mutableStateOf(hasNotificationAccess(context)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { access = hasNotificationAccess(context) }
    val container = LocalAppContainer.current

    DashboardContent(
        state = state,
        notificationAccess = access,
        onQuickScan = onQuickScan,
        onOpenReport = onOpenReport,
        onOpenSettings = onOpenSettings,
        onOpenPremium = onOpenPremium,
        adSlot = { BannerAdSlot(container.ads, state.entitlement) },
    )
}

@Composable
fun DashboardContent(
    state: DashboardState,
    notificationAccess: Boolean,
    onQuickScan: (String) -> Unit,
    onOpenReport: (Long) -> Unit,
    onOpenSettings: () -> Unit,
    onOpenPremium: () -> Unit,
    adSlot: @Composable () -> Unit = {},
) {
    val format = rememberDateTimeFormatter()
    val monitoringActive = state.monitoringEnabled && notificationAccess
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("dashboard"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
                if (!state.entitlement.isPremium) {
                    IconButton(onClick = onOpenPremium) {
                        Icon(Icons.Filled.WorkspacePremium, contentDescription = stringResource(R.string.premium_title), tint = MaterialTheme.colorScheme.secondary)
                    }
                }
            }
        }
        item {
            val good = monitoringActive
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        if (good) Icons.Filled.VerifiedUser else Icons.Filled.GppMaybe,
                        contentDescription = null,
                        tint = if (good) LocalRiskColors.current.noKnownThreat else LocalRiskColors.current.suspicious,
                        modifier = Modifier.size(36.dp),
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            stringResource(if (good) R.string.dashboard_protection_active else R.string.dashboard_protection_limited),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(stringResource(R.string.dashboard_protection_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                StatusLine(monitoringActive, stringResource(if (monitoringActive) R.string.dashboard_monitoring_on else R.string.dashboard_monitoring_off))
                StatusLine(state.cloudEnabled, stringResource(if (state.cloudEnabled) R.string.dashboard_cloud_on else R.string.dashboard_cloud_off))
                if (!monitoringActive) {
                    TextButton(onClick = onOpenSettings, modifier = Modifier.testTag("enable_monitoring")) { Text(stringResource(R.string.dashboard_enable_monitoring)) }
                }
            }
        }
        item { QuickScanCard(onQuickScan) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatTile(stringResource(R.string.dashboard_stat_scanned), state.totalScans.toString(), Modifier.weight(1f))
                StatTile(stringResource(R.string.dashboard_stat_suspicious), state.stats.suspicious.toString(), Modifier.weight(1f), LocalRiskColors.current.suspicious)
                StatTile(stringResource(R.string.dashboard_stat_malicious), state.stats.malicious.toString(), Modifier.weight(1f), LocalRiskColors.current.malicious)
            }
        }
        item { Text(stringResource(R.string.dashboard_recent_alerts), style = MaterialTheme.typography.titleMedium) }
        if (state.recentAlerts.isEmpty()) {
            item { EmptyState(stringResource(R.string.dashboard_no_alerts)) }
        } else {
            items(state.recentAlerts, key = { it.id }) { r -> ScanRow(r, format, onClick = { onOpenReport(r.id) }) }
        }
        item { adSlot() }
    }
}

@Composable
private fun StatusLine(on: Boolean, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        StatusDot(on)
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun QuickScanCard(onQuickScan: (String) -> Unit) {
    var text by rememberSaveable { mutableStateOf("") }
    SectionCard(title = stringResource(R.string.dashboard_quick_scan)) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            modifier = Modifier.fillMaxWidth().testTag("quick_scan_input"),
            placeholder = { Text(stringResource(R.string.scanner_input_hint)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go),
            keyboardActions = KeyboardActions(onGo = { if (text.isNotBlank()) onQuickScan(text.trim()) }),
        )
        Button(onClick = { onQuickScan(text.trim()) }, enabled = text.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.scanner_scan))
        }
    }
}

@Composable
fun ScanRow(r: ScanRecord, format: (Long) -> String, onClick: () -> Unit, trailing: @Composable () -> Unit = {}) {
    SectionCard(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    if (r.targetType == TargetType.TEXT) stringResource(R.string.scanner_text_message) else r.displayHost ?: r.normalizedUrl.orEmpty(),
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    listOfNotNull(format(r.timestamp), r.sourceApp).joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                )
            }
            RiskBadge(r.classification)
            trailing()
        }
    }
}
