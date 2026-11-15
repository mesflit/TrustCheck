// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.report

import android.content.ActivityNotFoundException
import android.content.ComponentName
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
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Circle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.mesflit.trustcheck.AppContainer
import com.mesflit.trustcheck.MainActivity
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.LocalRiskColors
import com.mesflit.trustcheck.core.design.RiskBadge
import com.mesflit.trustcheck.core.design.RiskGauge
import com.mesflit.trustcheck.core.design.SectionCard
import com.mesflit.trustcheck.core.design.rememberDateTimeFormatter
import com.mesflit.trustcheck.core.localization.LocaleController
import com.mesflit.trustcheck.core.localization.SecurityStrings
import com.mesflit.trustcheck.core.network.DailyQuota
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.Severity
import com.mesflit.trustcheck.domain.AiRequest
import com.mesflit.trustcheck.domain.AiResult
import com.mesflit.trustcheck.domain.ScanRecord
import com.mesflit.trustcheck.domain.TargetType
import com.mesflit.trustcheck.domain.UserAction
import com.mesflit.trustcheck.monetization.PremiumPolicy
import com.mesflit.trustcheck.ui.containerViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class AiUiState { IDLE, LOADING, NOT_CONFIGURED, NO_CONSENT, QUOTA_EXCEEDED, RATE_LIMITED, ERROR }

data class ReportState(
    val loaded: Boolean = false,
    val record: ScanRecord? = null,
    val ai: AiUiState = AiUiState.IDLE,
    val aiRemaining: Int = 0,
    val backendConfigured: Boolean = false,
    val cloudAiConsent: Boolean = false,
    val messageAvailable: Boolean = false,
    val openableUrl: String? = null,
)

class ReportViewModel(private val c: AppContainer, private val id: Long) : ViewModel() {
    private val ai = MutableStateFlow(AiUiState.IDLE)

    val state: StateFlow<ReportState> = combine(
        c.scans.observe(id), c.settings.settings, ai,
    ) { record, s, aiState ->
        val day = DailyQuota.epochDay(System.currentTimeMillis())
        val limit = PremiumPolicy.DAILY_AI_EXPLANATIONS
        val session = c.session.get(id)
        ReportState(
            loaded = true,
            record = record,
            ai = aiState,
            aiRemaining = s.aiQuota.remaining(day, limit),
            backendConfigured = c.backend.isConfigured,
            cloudAiConsent = s.cloudAi,
            messageAvailable = session?.messageText != null,
            openableUrl = record?.takeIf { it.targetType == TargetType.URL }?.let { session?.originalInput?.takeIf { u -> u.startsWith("http", true) } ?: it.normalizedUrl },
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ReportState())

    fun explain(includeMessage: Boolean) {
        val record = state.value.record ?: return
        if (ai.value == AiUiState.LOADING) return
        viewModelScope.launch {
            val s = c.settings.current()
            val day = DailyQuota.epochDay(System.currentTimeMillis())
            val limit = PremiumPolicy.DAILY_AI_EXPLANATIONS
            if (!s.aiQuota.canUse(day, limit)) { ai.value = AiUiState.QUOTA_EXCEEDED; return@launch }
            ai.value = AiUiState.LOADING
            val language = LocaleController.effective(c.appContext, s.language).tag
            val request = AiRequest(
                url = record.normalizedUrl,
                text = if (includeMessage) c.session.get(id)?.messageText else null,
                localIndicators = record.indicators.map { it.indicator.name },
                localClassification = record.classification.name,
                language = language,
            )
            ai.value = when (val r = c.ai.explain(request)) {
                is AiResult.Success -> {
                    c.settings.consumeAiQuota(day)
                    c.scans.attachAi(id, r.explanation)
                    AiUiState.IDLE
                }
                AiResult.NotConfigured -> AiUiState.NOT_CONFIGURED
                AiResult.NoConsent -> AiUiState.NO_CONSENT
                AiResult.QuotaExceeded -> AiUiState.QUOTA_EXCEEDED
                AiResult.RateLimited -> AiUiState.RATE_LIMITED
                is AiResult.Error -> AiUiState.ERROR
            }
        }
    }

    fun enableAiConsent() = viewModelScope.launch { c.settings.update { it.copy(cloudAi = true) }; ai.value = AiUiState.IDLE }

    fun markOpened() = viewModelScope.launch { c.scans.setUserAction(id, UserAction.OPENED_ANYWAY) }

    fun delete(onDone: () -> Unit) = viewModelScope.launch { c.scans.delete(id); onDone() }

}

@Composable
fun ReportScreen(id: Long, activity: MainActivity, onBack: () -> Unit, onOpenSettings: () -> Unit) {
    val vm = containerViewModel(key = "report-$id") { ReportViewModel(it, id) }
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    ReportContent(
        state = state,
        onBack = onBack,
        onExplain = { include -> vm.explain(include) },
        onEnableAi = vm::enableAiConsent,
        onOpenSettings = onOpenSettings,
        onDelete = { vm.delete(onBack) },
        onOpenAnyway = { url ->
            vm.markOpened()
            val view = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)
            val chooser = Intent.createChooser(view, context.getString(R.string.report_open_anyway))
                .putExtra(Intent.EXTRA_EXCLUDE_COMPONENTS, arrayOf(ComponentName(context, MainActivity::class.java)))
            try { context.startActivity(chooser) } catch (_: ActivityNotFoundException) { }
        },
    )
}

@Composable
fun ReportContent(
    state: ReportState,
    onBack: () -> Unit,
    onExplain: (Boolean) -> Unit,
    onEnableAi: () -> Unit,
    onOpenSettings: () -> Unit,
    onDelete: () -> Unit,
    onOpenAnyway: (String) -> Unit,
) {
    var confirmOpen by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.report_title)) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.action_back)) } },
                actions = {
                    if (state.record != null) IconButton(onClick = onDelete) { Icon(Icons.Filled.Delete, stringResource(R.string.history_delete)) }
                },
            )
        },
    ) { padding ->
        val r = state.record
        if (r == null) {
            Column(Modifier.padding(padding).padding(16.dp)) {
                if (state.loaded) Text(stringResource(R.string.report_not_found)) else CircularProgressIndicator()
            }
            return@Scaffold
        }
        val format = rememberDateTimeFormatter()
        val riskColors = LocalRiskColors.current
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp).testTag("report"),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            // --- Verdict ---
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RiskGauge(r.riskScore, r.classification, size = 112.dp)
                    Spacer(Modifier.width(16.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        RiskBadge(r.classification)
                        Text(
                            if (r.targetType == TargetType.TEXT) stringResource(R.string.scanner_text_message) else r.displayHost ?: r.normalizedUrl.orEmpty(),
                            style = MaterialTheme.typography.titleMedium,
                        )
                    }
                }
                Text(stringResource(SecurityStrings.classificationDescription(r.classification)), style = MaterialTheme.typography.bodyMedium)
                r.finalUrl?.let { Text(stringResource(R.string.report_final_destination, it), style = MaterialTheme.typography.bodySmall) }
            }

            // --- Indicators ---
            SectionCard(title = stringResource(R.string.report_indicators)) {
                if (r.indicators.isEmpty()) Text(stringResource(R.string.report_no_indicators), style = MaterialTheme.typography.bodyMedium)
                r.indicators.forEach { d ->
                    val color = when (d.indicator.severity) {
                        Severity.CRITICAL, Severity.HIGH -> riskColors.malicious
                        Severity.MEDIUM -> riskColors.suspicious
                        else -> riskColors.unknown
                    }
                    Row {
                        Icon(Icons.Filled.Circle, contentDescription = null, tint = color, modifier = Modifier.padding(top = 6.dp).size(10.dp))
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(stringResource(SecurityStrings.indicatorTitle(d.indicator)), style = MaterialTheme.typography.titleSmall)
                            Text(stringResource(SecurityStrings.indicatorDescription(d.indicator)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            d.detail?.takeIf { it.isNotBlank() }?.let { Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        }
                    }
                }
            }

            // --- Recommendations ---
            SectionCard(title = stringResource(R.string.report_recommendations)) {
                SecurityStrings.recommendations(r.classification).forEach { res ->
                    Text("• " + stringResource(res), style = MaterialTheme.typography.bodyMedium)
                }
            }

            // --- AI explanation ---
            AiSection(state, onExplain, onEnableAi, onOpenSettings)

            // --- Sources ---
            SectionCard(title = stringResource(R.string.report_sources)) {
                r.sources.forEach { s ->
                    Row {
                        Text(stringResource(SecurityStrings.sourceName(s.source)), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        Text(stringResource(SecurityStrings.sourceStatus(s.status)), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Text(stringResource(R.string.report_scanned_at, format(r.timestamp)), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.report_origin, stringResource(SecurityStrings.origin(r.origin))), style = MaterialTheme.typography.bodySmall)
                r.sourceApp?.let { Text(stringResource(R.string.report_source_app, it), style = MaterialTheme.typography.bodySmall) }
                Text(stringResource(R.string.report_not_safe_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            // --- Actions ---
            state.openableUrl?.let { url ->
                OutlinedButton(onClick = { confirmOpen = true }, modifier = Modifier.fillMaxWidth().testTag("open_anyway")) {
                    Text(stringResource(R.string.report_open_anyway))
                }
                if (url == r.normalizedUrl) Text(stringResource(R.string.report_query_removed_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (confirmOpen && state.openableUrl != null) {
            val dangerous = r.classification == RiskClassification.CONFIRMED_MALICIOUS || r.classification == RiskClassification.SUSPICIOUS
            AlertDialog(
                onDismissRequest = { confirmOpen = false },
                title = { Text(stringResource(R.string.report_open_confirm_title)) },
                text = { Text(stringResource(if (dangerous) R.string.report_open_confirm_body_danger else R.string.report_open_confirm_body)) },
                confirmButton = {
                    TextButton(onClick = { confirmOpen = false; onOpenAnyway(state.openableUrl) }) { Text(stringResource(R.string.report_open_confirm_action)) }
                },
                dismissButton = { TextButton(onClick = { confirmOpen = false }) { Text(stringResource(R.string.common_cancel)) } },
            )
        }
    }
}

@Composable
private fun AiSection(
    state: ReportState,
    onExplain: (Boolean) -> Unit,
    onEnableAi: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    val r = state.record ?: return
    var includeMessage by remember { mutableStateOf(false) }
    SectionCard(title = stringResource(R.string.report_ai_title)) {
        val ai = r.ai
        if (ai != null) {
            Text(ai.summary, style = MaterialTheme.typography.bodyMedium)
            ai.notes.forEach { Text("• ${it.explanation}", style = MaterialTheme.typography.bodySmall) }
            if (ai.recommendations.isNotEmpty()) {
                ai.recommendations.forEach { Text("→ $it", style = MaterialTheme.typography.bodySmall) }
            }
            Text(stringResource(R.string.report_ai_model, ai.model), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(stringResource(R.string.report_ai_disclaimer), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            return@SectionCard
        }
        when {
            !state.backendConfigured -> Text(stringResource(R.string.report_ai_not_configured), style = MaterialTheme.typography.bodyMedium)
            !state.cloudAiConsent -> {
                Text(stringResource(R.string.report_ai_no_consent), style = MaterialTheme.typography.bodyMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onEnableAi) { Text(stringResource(R.string.report_ai_enable)) }
                    TextButton(onClick = onOpenSettings) { Text(stringResource(R.string.nav_settings)) }
                }
            }
            else -> {
                if (state.messageAvailable) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = includeMessage, onCheckedChange = { includeMessage = it })
                        Text(stringResource(R.string.report_ai_include_message), style = MaterialTheme.typography.bodySmall)
                    }
                }
                when (state.ai) {
                    AiUiState.LOADING -> Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.report_ai_loading))
                    }
                    AiUiState.QUOTA_EXCEEDED -> Text(stringResource(R.string.report_ai_quota_exceeded), style = MaterialTheme.typography.bodyMedium)
                    AiUiState.RATE_LIMITED -> Text(stringResource(R.string.report_ai_rate_limited), style = MaterialTheme.typography.bodyMedium)
                    AiUiState.ERROR, AiUiState.NOT_CONFIGURED, AiUiState.NO_CONSENT -> Text(stringResource(R.string.report_ai_error), style = MaterialTheme.typography.bodyMedium)
                    AiUiState.IDLE -> Unit
                }
                Button(
                    onClick = { onExplain(includeMessage) },
                    enabled = state.ai != AiUiState.LOADING && state.aiRemaining > 0,
                    modifier = Modifier.testTag("ai_explain"),
                ) {
                    Icon(Icons.Filled.AutoAwesome, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.report_ai_explain))
                }
                Text(stringResource(R.string.report_ai_remaining, state.aiRemaining), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
