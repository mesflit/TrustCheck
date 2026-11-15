// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.report

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.text.format.Formatter
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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Circle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.text.font.FontFamily
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
import com.mesflit.trustcheck.core.localization.SecurityStrings
import com.mesflit.trustcheck.core.security.FileFacts
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.Severity
import com.mesflit.trustcheck.domain.ScanRecord
import com.mesflit.trustcheck.domain.TargetType
import com.mesflit.trustcheck.domain.UserAction
import com.mesflit.trustcheck.ui.containerViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class ReportState(
    val loaded: Boolean = false,
    val record: ScanRecord? = null,
    val openableUrl: String? = null,
)

class ReportViewModel(private val c: AppContainer, private val id: Long) : ViewModel() {
    val state: StateFlow<ReportState> = c.scans.observe(id).map { record ->
        val session = c.session.get(id)
        ReportState(
            loaded = true,
            record = record,
            openableUrl = record?.takeIf { it.targetType == TargetType.URL }
                ?.let { session?.originalInput?.takeIf { u -> u.startsWith("http", true) } ?: it.normalizedUrl },
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ReportState())

    fun markOpened() = viewModelScope.launch { c.scans.setUserAction(id, UserAction.OPENED_ANYWAY) }

    fun delete(onDone: () -> Unit) = viewModelScope.launch { c.scans.delete(id); onDone() }
}

@Composable
fun ReportScreen(id: Long, onBack: () -> Unit) {
    val vm = containerViewModel(key = "report-$id") { ReportViewModel(it, id) }
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    fun openExternal(url: String, title: Int) {
        val view = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)
        val chooser = Intent.createChooser(view, context.getString(title))
            .putExtra(Intent.EXTRA_EXCLUDE_COMPONENTS, arrayOf(ComponentName(context, MainActivity::class.java)))
        try { context.startActivity(chooser) } catch (_: ActivityNotFoundException) { }
    }
    ReportContent(
        state = state,
        onBack = onBack,
        onDelete = { vm.delete(onBack) },
        onOpenAnyway = { url -> vm.markOpened(); openExternal(url, R.string.report_open_anyway) },
        // Only the SHA-256 hash leaves the device, and only when the user taps the button.
        onLookupHash = { sha -> openExternal("https://www.virustotal.com/gui/file/$sha", R.string.file_lookup_hash) },
    )
}

@Composable
fun ReportContent(
    state: ReportState,
    onBack: () -> Unit,
    onDelete: () -> Unit,
    onOpenAnyway: (String) -> Unit,
    onLookupHash: (String) -> Unit = {},
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
        val isFile = r.targetType == TargetType.FILE
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
                Text(
                    stringResource(if (isFile) SecurityStrings.fileClassificationDescription(r.classification) else SecurityStrings.classificationDescription(r.classification)),
                    style = MaterialTheme.typography.bodyMedium,
                )
                r.finalUrl?.let { Text(stringResource(R.string.report_final_destination, it), style = MaterialTheme.typography.bodySmall) }
            }

            // --- File details ---
            r.file?.let { FileSection(it, onLookupHash) }

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
                val recs = if (isFile) SecurityStrings.fileRecommendations(r.classification) else SecurityStrings.recommendations(r.classification)
                recs.forEach { res -> Text("• " + stringResource(res), style = MaterialTheme.typography.bodyMedium) }
            }

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
private fun FileSection(f: FileFacts, onLookupHash: (String) -> Unit) {
    val context = LocalContext.current
    SectionCard(title = stringResource(R.string.file_details)) {
        Text(stringResource(R.string.file_name, f.displayName), style = MaterialTheme.typography.bodyMedium)
        if (f.sizeBytes >= 0) Text(stringResource(R.string.file_size, Formatter.formatShortFileSize(context, f.sizeBytes)), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.file_type, f.kind.label), style = MaterialTheme.typography.bodyMedium)
        f.apk?.let { a ->
            a.appLabel?.let { Text(stringResource(R.string.file_app_name, it), style = MaterialTheme.typography.bodyMedium) }
            a.packageName?.let { Text(stringResource(R.string.file_package, it), style = MaterialTheme.typography.bodyMedium) }
            a.versionName?.let { Text(stringResource(R.string.file_version, it), style = MaterialTheme.typography.bodyMedium) }
            if (a.permissions.isNotEmpty()) {
                Text(stringResource(R.string.file_permissions, a.permissions.size), style = MaterialTheme.typography.titleSmall)
                Text(a.permissions.joinToString("\n") { it.substringAfterLast('.') }, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Text("SHA-256", style = MaterialTheme.typography.titleSmall)
        SelectionContainer { Text(f.sha256, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
        OutlinedButton(onClick = { onLookupHash(f.sha256) }, modifier = Modifier.testTag("lookup_hash")) {
            Text(stringResource(R.string.file_lookup_hash))
        }
        Text(stringResource(R.string.file_lookup_hash_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(stringResource(R.string.file_not_antivirus), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
