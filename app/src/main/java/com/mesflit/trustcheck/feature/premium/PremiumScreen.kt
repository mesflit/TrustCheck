// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.premium

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mesflit.trustcheck.MainActivity
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.SectionCard
import com.mesflit.trustcheck.monetization.BillingEvent
import com.mesflit.trustcheck.monetization.BillingStatus
import com.mesflit.trustcheck.monetization.Entitlement
import com.mesflit.trustcheck.monetization.EntitlementSource
import com.mesflit.trustcheck.monetization.EntitlementState
import com.mesflit.trustcheck.monetization.PlanCatalog
import com.mesflit.trustcheck.monetization.PlanOffer
import com.mesflit.trustcheck.ui.LocalAppContainer

@Composable
fun PremiumScreen(activity: MainActivity, onBack: () -> Unit) {
    val billing = LocalAppContainer.current.billing
    val plans by billing.plans.collectAsStateWithLifecycle()
    val entitlement by billing.entitlement.collectAsStateWithLifecycle()
    val status by billing.status.collectAsStateWithLifecycle()
    val event by billing.events.collectAsStateWithLifecycle()
    val context = LocalContext.current
    LaunchedEffect(Unit) { billing.start() }
    PremiumContent(
        plans = plans,
        entitlement = entitlement,
        status = status,
        event = event,
        onEventShown = billing::consumeEvent,
        onBack = onBack,
        onSubscribe = { billing.launchPurchase(activity, it) },
        onRestore = billing::restore,
        onManage = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(billing.manageSubscriptionsUrl()))) },
    )
}

@Composable
fun PremiumContent(
    plans: List<PlanOffer>,
    entitlement: Entitlement,
    status: BillingStatus,
    event: BillingEvent?,
    onEventShown: () -> Unit,
    onBack: () -> Unit,
    onSubscribe: (PlanOffer) -> Unit,
    onRestore: () -> Unit,
    onManage: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    val eventText = event?.let { stringResource(eventMessage(it)) }
    LaunchedEffect(event) {
        if (eventText != null) { snackbar.showSnackbar(eventText); onEventShown() }
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.premium_title)) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.action_back)) } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp).testTag("premium"),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(stringResource(R.string.premium_subtitle), style = MaterialTheme.typography.bodyLarge)
            SectionCard {
                listOf(R.string.premium_feature_no_ads, R.string.premium_feature_ai, R.string.premium_feature_retention, R.string.premium_feature_support).forEach {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.secondary, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(10.dp))
                        Text(stringResource(it), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Text(stringResource(R.string.premium_free_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            // Status reflects exactly what Google Play / the verification server reported.
            if (entitlement.state != EntitlementState.NONE) {
                SectionCard {
                    Text(stringResource(stateLabel(entitlement.state)), style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("premium_state"))
                    if (entitlement.source == EntitlementSource.PLAY_CLIENT || entitlement.source == EntitlementSource.PLAY_CLIENT_PROVISIONAL) {
                        Text(stringResource(R.string.premium_unverified_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (entitlement.isPremium || entitlement.state == EntitlementState.ON_HOLD) {
                        OutlinedButton(onClick = onManage) { Text(stringResource(R.string.premium_manage)) }
                    }
                }
            }

            if (!entitlement.isPremium) {
                when {
                    status == BillingStatus.CONNECTING -> CircularProgressIndicator()
                    plans.isEmpty() -> SectionCard { Text(stringResource(R.string.premium_unavailable), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("premium_unavailable")) }
                    else -> plans.forEach { plan -> PlanCard(plan, onSubscribe) }
                }
                Text(stringResource(R.string.premium_terms), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            TextButton(onClick = onRestore, modifier = Modifier.testTag("premium_restore")) { Text(stringResource(R.string.premium_restore)) }
        }
    }
}

@Composable
private fun PlanCard(plan: PlanOffer, onSubscribe: (PlanOffer) -> Unit) {
    SectionCard {
        Text(
            stringResource(
                when (plan.period) {
                    PlanCatalog.Period.MONTHLY -> R.string.premium_monthly
                    PlanCatalog.Period.ANNUAL -> R.string.premium_annual
                    PlanCatalog.Period.OTHER -> R.string.premium_plan_other
                },
            ),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            when (plan.period) {
                PlanCatalog.Period.MONTHLY -> stringResource(R.string.premium_per_month, plan.formattedPrice)
                PlanCatalog.Period.ANNUAL -> stringResource(R.string.premium_per_year, plan.formattedPrice)
                PlanCatalog.Period.OTHER -> plan.formattedPrice
            },
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        plan.introFormattedPrice?.let { Text(stringResource(R.string.premium_intro, it), style = MaterialTheme.typography.bodySmall) }
        Button(onClick = { onSubscribe(plan) }, modifier = Modifier.fillMaxWidth().testTag("subscribe_${plan.basePlanId}")) {
            Text(stringResource(R.string.premium_subscribe))
        }
    }
}

private fun stateLabel(s: EntitlementState) = when (s) {
    EntitlementState.ACTIVE -> R.string.premium_active
    EntitlementState.GRACE_PERIOD -> R.string.premium_grace
    EntitlementState.PENDING -> R.string.premium_pending
    EntitlementState.ON_HOLD -> R.string.premium_on_hold
    EntitlementState.EXPIRED, EntitlementState.NONE -> R.string.premium_expired
}

private fun eventMessage(e: BillingEvent) = when (e) {
    BillingEvent.PurchaseCompleted -> R.string.premium_event_completed
    BillingEvent.PurchasePending -> R.string.premium_event_pending
    BillingEvent.Cancelled -> R.string.premium_event_cancelled
    BillingEvent.AlreadyOwned -> R.string.premium_event_owned
    BillingEvent.Restored -> R.string.premium_event_restored
    BillingEvent.NothingToRestore -> R.string.premium_event_nothing
    is BillingEvent.Error -> R.string.premium_event_error
}
