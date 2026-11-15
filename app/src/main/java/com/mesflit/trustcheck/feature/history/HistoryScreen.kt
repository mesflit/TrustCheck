// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.history

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.mesflit.trustcheck.AppContainer
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.EmptyState
import com.mesflit.trustcheck.core.design.rememberDateTimeFormatter
import com.mesflit.trustcheck.core.localization.SecurityStrings
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.domain.ScanRecord
import com.mesflit.trustcheck.feature.dashboard.ScanRow
import com.mesflit.trustcheck.monetization.BannerAdSlot
import com.mesflit.trustcheck.ui.LocalAppContainer
import com.mesflit.trustcheck.ui.containerViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

@OptIn(ExperimentalCoroutinesApi::class, kotlinx.coroutines.FlowPreview::class)
class HistoryViewModel(private val c: AppContainer) : ViewModel() {
    val query = MutableStateFlow("")
    val filter = MutableStateFlow<Set<RiskClassification>>(emptySet())

    val items: StateFlow<List<ScanRecord>> = combine(query.debounce(200), filter) { q, f -> q to f }
        .flatMapLatest { (q, f) -> c.scans.observeHistory(q, f) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun toggle(cls: RiskClassification) { filter.value = if (cls in filter.value) filter.value - cls else filter.value + cls }
    fun delete(id: Long) = viewModelScope.launch { c.scans.delete(id) }
    fun clearAll() = viewModelScope.launch { c.scans.clearAll() }
}

@Composable
fun HistoryScreen(onOpenReport: (Long) -> Unit) {
    val vm = containerViewModel { HistoryViewModel(it) }
    val items by vm.items.collectAsStateWithLifecycle()
    val query by vm.query.collectAsStateWithLifecycle()
    val filter by vm.filter.collectAsStateWithLifecycle()
    val container = LocalAppContainer.current
    val entitlement by container.billing.entitlement.collectAsStateWithLifecycle()
    HistoryContent(
        items = items,
        query = query,
        filter = filter,
        onQuery = { vm.query.value = it },
        onToggle = vm::toggle,
        onOpenReport = onOpenReport,
        onDelete = { vm.delete(it) },
        onClearAll = { vm.clearAll() },
        adSlot = { BannerAdSlot(container.ads, entitlement) },
    )
}

@Composable
fun HistoryContent(
    items: List<ScanRecord>,
    query: String,
    filter: Set<RiskClassification>,
    onQuery: (String) -> Unit,
    onToggle: (RiskClassification) -> Unit,
    onOpenReport: (Long) -> Unit,
    onDelete: (Long) -> Unit,
    onClearAll: () -> Unit,
    adSlot: @Composable () -> Unit = {},
) {
    var confirmClear by remember { mutableStateOf(false) }
    val format = rememberDateTimeFormatter()
    LazyColumn(
        Modifier.fillMaxSize().testTag("history"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.history_title), style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
                IconButton(onClick = { confirmClear = true }, enabled = items.isNotEmpty()) {
                    Icon(Icons.Filled.DeleteSweep, contentDescription = stringResource(R.string.history_clear_all))
                }
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = onQuery,
                modifier = Modifier.fillMaxWidth().testTag("history_search"),
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                placeholder = { Text(stringResource(R.string.history_search)) },
                singleLine = true,
            )
        }
        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(RiskClassification.entries) { c ->
                    FilterChip(selected = c in filter, onClick = { onToggle(c) }, label = { Text(stringResource(SecurityStrings.classificationTitle(c))) })
                }
            }
        }
        if (items.isEmpty()) {
            item { EmptyState(stringResource(R.string.history_empty)) }
        } else {
            items(items, key = { it.id }) { r ->
                ScanRow(r, format, onClick = { onOpenReport(r.id) }) {
                    IconButton(onClick = { onDelete(r.id) }) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.history_delete)) }
                }
            }
        }
        item { adSlot() }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.history_clear_confirm_title)) },
            text = { Text(stringResource(R.string.history_clear_confirm_body)) },
            confirmButton = { TextButton(onClick = { confirmClear = false; onClearAll() }) { Text(stringResource(R.string.history_clear_confirm_action)) } },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
}
