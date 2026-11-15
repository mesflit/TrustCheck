// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.scanner

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.mesflit.trustcheck.AppContainer
import com.mesflit.trustcheck.PendingScan
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.ScanSession
import com.mesflit.trustcheck.core.design.RiskBadge
import com.mesflit.trustcheck.core.design.SectionCard
import com.mesflit.trustcheck.core.localization.SecurityStrings
import com.mesflit.trustcheck.core.ocr.OcrTextExtractor
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.UrlExtractor
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.ScanOutcome
import com.mesflit.trustcheck.ui.containerViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class ScannerNotice { NONE, EMPTY_INPUT, OCR_NO_TEXT, OCR_FAILED, OFFLINE }

data class ScannerState(
    val input: String = "",
    val scanning: Boolean = false,
    val ocrRunning: Boolean = false,
    val results: List<ScanOutcome> = emptyList(),
    val textOnly: Boolean = false,
    val notice: ScannerNotice = ScannerNotice.NONE,
    /** One-shot navigation event: open this report (single-link scans). */
    val openReport: Long? = null,
)

class ScannerViewModel(private val c: AppContainer) : ViewModel() {
    private val _state = MutableStateFlow(ScannerState())
    val state: StateFlow<ScannerState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            c.pendingScan.collect { pending ->
                if (pending != null) {
                    c.pendingScan.value = null
                    handle(pending)
                }
            }
        }
    }

    fun onInput(text: String) = _state.update { it.copy(input = text, notice = ScannerNotice.NONE) }
    fun clear() = _state.update { ScannerState() }
    fun consumeNavigation() = _state.update { it.copy(openReport = null) }

    private fun handle(p: PendingScan) {
        when (p) {
            is PendingScan.Text -> { onInput(p.text); scan(p.origin) }
            is PendingScan.Image -> viewModelScope.launch {
                _state.update { ScannerState(ocrRunning = true) }
                when (val o = c.ocr.extract(p.uri)) {
                    is OcrTextExtractor.Outcome.Text -> { _state.update { it.copy(ocrRunning = false, input = o.value) }; scan(ScanOrigin.SHARE_IMAGE) }
                    OcrTextExtractor.Outcome.NoText -> _state.update { it.copy(ocrRunning = false, notice = ScannerNotice.OCR_NO_TEXT) }
                    is OcrTextExtractor.Outcome.Failed -> _state.update { it.copy(ocrRunning = false, notice = ScannerNotice.OCR_FAILED) }
                }
            }
        }
    }

    fun scan(origin: ScanOrigin = ScanOrigin.MANUAL) {
        val input = _state.value.input.trim()
        if (input.isEmpty()) { _state.update { it.copy(notice = ScannerNotice.EMPTY_INPUT) }; return }
        if (_state.value.scanning) return
        _state.update { it.copy(scanning = true, results = emptyList(), notice = ScannerNotice.NONE) }
        viewModelScope.launch {
            val online = c.connectivity.isOnline()
            val singleToken = !input.any { it.isWhitespace() }
            val outcome = if (singleToken && UrlExtractor.extract(input).size <= 1) {
                val r = c.scanCoordinator.scanUrl(input, origin)
                r.recordId?.let { c.session.put(it, ScanSession.Entry(input, null)) }
                listOf(r) to false
            } else {
                val t = c.scanCoordinator.scanText(input, origin)
                val urls = UrlExtractor.extract(input)
                t.items.forEachIndexed { i, item ->
                    item.recordId?.let { c.session.put(it, ScanSession.Entry(urls.getOrElse(i) { input }, input)) }
                }
                t.items to urls.isEmpty()
            }
            val settings = c.settings.current()
            _state.update {
                it.copy(
                    scanning = false,
                    results = outcome.first,
                    textOnly = outcome.second,
                    openReport = outcome.first.singleOrNull()?.takeIf { !outcome.second }?.recordId,
                    notice = if (!online && settings.cloudThreatIntel) ScannerNotice.OFFLINE else ScannerNotice.NONE,
                )
            }
        }
    }
}

@Composable
fun ScannerScreen(onOpenReport: (Long) -> Unit) {
    val vm = containerViewModel { ScannerViewModel(it) }
    val state by vm.state.collectAsStateWithLifecycle()
    val clipboard = LocalClipboardManager.current
    ScannerContent(
        state = state,
        onInput = vm::onInput,
        onPaste = { clipboard.getText()?.text?.let(vm::onInput) },
        onClear = vm::clear,
        onScan = { vm.scan() },
        onOpenReport = onOpenReport,
    )
    LaunchedEffect(state.openReport) {
        state.openReport?.let { vm.consumeNavigation(); onOpenReport(it) }
    }
}

@Composable
fun ScannerContent(
    state: ScannerState,
    onInput: (String) -> Unit,
    onPaste: () -> Unit,
    onClear: () -> Unit,
    onScan: () -> Unit,
    onOpenReport: (Long) -> Unit,
) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp).testTag("scanner"),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(stringResource(R.string.scanner_title), style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(
            value = state.input,
            onValueChange = onInput,
            modifier = Modifier.fillMaxWidth().testTag("scanner_input"),
            label = { Text(stringResource(R.string.scanner_input_label)) },
            placeholder = { Text(stringResource(R.string.scanner_input_hint)) },
            minLines = 3,
            maxLines = 8,
            enabled = !state.scanning && !state.ocrRunning,
            trailingIcon = {
                if (state.input.isNotEmpty()) {
                    IconButton(onClick = onClear) { Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.scanner_clear)) }
                }
            },
            isError = state.notice == ScannerNotice.EMPTY_INPUT,
            supportingText = { if (state.notice == ScannerNotice.EMPTY_INPUT) Text(stringResource(R.string.scanner_empty_input)) },
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton(onClick = onPaste, enabled = !state.scanning, modifier = Modifier.testTag("scanner_paste")) {
                Icon(Icons.Filled.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.scanner_paste))
            }
            Button(onClick = onScan, enabled = !state.scanning && !state.ocrRunning, modifier = Modifier.weight(1f).testTag("scanner_scan")) {
                if (state.scanning) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.scanner_scanning))
                } else {
                    Text(stringResource(R.string.scanner_scan))
                }
            }
        }
        if (state.scanning || state.ocrRunning) {
            LinearProgressIndicator(Modifier.fillMaxWidth().testTag("scanner_progress"))
            if (state.ocrRunning) Text(stringResource(R.string.scanner_ocr_running), style = MaterialTheme.typography.bodyMedium)
        }
        when (state.notice) {
            ScannerNotice.OCR_NO_TEXT -> Notice(stringResource(R.string.scanner_ocr_no_text))
            ScannerNotice.OCR_FAILED -> Notice(stringResource(R.string.scanner_ocr_failed))
            ScannerNotice.OFFLINE -> Notice(stringResource(R.string.scanner_offline_note))
            else -> Unit
        }
        if (state.results.isNotEmpty()) {
            Text(stringResource(R.string.scanner_results), style = MaterialTheme.typography.titleMedium)
            state.results.forEach { r -> ResultCard(r, onOpenReport) }
        }
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.report_not_safe_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun Notice(text: String) {
    SectionCard { Text(text, style = MaterialTheme.typography.bodyMedium) }
}

@Composable
private fun ResultCard(r: ScanOutcome, onOpenReport: (Long) -> Unit) {
    val res = r.result
    SectionCard(onClick = r.recordId?.let { id -> { onOpenReport(id) } }) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    res.displayHost ?: res.normalizedUrl ?: stringResource(if (res.normalizedUrl == null && res.input.isEmpty()) R.string.scanner_text_message else R.string.class_failed),
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(stringResource(SecurityStrings.classificationDescription(res.classification)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.width(8.dp))
            RiskBadge(res.classification)
        }
        if (r.recordId != null && res.classification != RiskClassification.ANALYSIS_FAILED) {
            Text(stringResource(R.string.scanner_view_report), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        }
    }
}
