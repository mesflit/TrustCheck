// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.settings

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.mesflit.trustcheck.AppContainer
import com.mesflit.trustcheck.BuildConfig
import com.mesflit.trustcheck.MainActivity
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.SectionCard
import com.mesflit.trustcheck.core.localization.AppLanguage
import com.mesflit.trustcheck.core.localization.LocaleController
import com.mesflit.trustcheck.domain.AppSettings
import com.mesflit.trustcheck.domain.ThemeMode
import com.mesflit.trustcheck.feature.dashboard.hasNotificationAccess
import com.mesflit.trustcheck.monetization.Entitlement
import com.mesflit.trustcheck.monetization.PremiumPolicy
import com.mesflit.trustcheck.ui.LocalAppContainer
import com.mesflit.trustcheck.ui.containerViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(private val c: AppContainer) : ViewModel() {
    val settings: StateFlow<AppSettings?> = c.settings.settings.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
    val backendConfigured = c.backend.isConfigured

    fun update(transform: (AppSettings) -> AppSettings) = viewModelScope.launch {
        c.settings.update(transform)
        val s = c.settings.current()
        c.scheduler.schedulePeriodic(s, c.backend.isConfigured)
        if (!s.cloudThreatIntel && !s.resolveRedirects) c.scheduler.cancelAllScans()
    }

    fun setLanguage(language: AppLanguage) = viewModelScope.launch {
        c.settings.setLanguage(language)
        c.notifier.ensureChannels(language)
        LocaleController.apply(language) // recreates the activity immediately
    }

    fun clearHistory() = viewModelScope.launch { c.scans.clearAll(); c.session.clear() }
}

@Composable
fun SettingsScreen(activity: MainActivity, onOpenPremium: () -> Unit) {
    val vm = containerViewModel { SettingsViewModel(it) }
    val s by vm.settings.collectAsStateWithLifecycle()
    val container = LocalAppContainer.current
    val entitlement by container.billing.entitlement.collectAsStateWithLifecycle()
    val privacyOptions by container.ads.privacyOptionsRequired.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var access by remember { mutableStateOf(hasNotificationAccess(context)) }
    var postGranted by remember { mutableStateOf(postNotificationsGranted(context)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        access = hasNotificationAccess(context)
        postGranted = postNotificationsGranted(context)
    }
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { postGranted = it }

    val current = s ?: return
    SettingsContent(
        settings = current,
        entitlement = entitlement,
        notificationAccess = access,
        postNotificationsGranted = postGranted,
        backendConfigured = vm.backendConfigured,
        showAdPrivacy = privacyOptions,
        onUpdate = { vm.update(it) },
        onLanguage = vm::setLanguage,
        onOpenAccessSettings = { context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) },
        onRequestPostNotifications = {
            if (Build.VERSION.SDK_INT >= 33) permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        },
        onOpenBatterySettings = { context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) },
        onAdPrivacy = { container.ads.showPrivacyOptions(activity) },
        onClearHistory = vm::clearHistory,
        onOpenPremium = onOpenPremium,
        onOpenUrl = { url -> context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) },
    )
}

fun postNotificationsGranted(context: android.content.Context): Boolean =
    Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

const val SOURCE_URL = "https://github.com/mesflit/TrustCheck"
const val PRIVACY_URL = "https://github.com/mesflit/TrustCheck/blob/main/docs/PRIVACY_POLICY.md"
const val LICENSE_URL = "https://www.gnu.org/licenses/gpl-3.0.html"

@Composable
fun SettingsContent(
    settings: AppSettings,
    entitlement: Entitlement,
    notificationAccess: Boolean,
    postNotificationsGranted: Boolean,
    backendConfigured: Boolean,
    showAdPrivacy: Boolean,
    onUpdate: ((AppSettings) -> AppSettings) -> Unit,
    onLanguage: (AppLanguage) -> Unit,
    onOpenAccessSettings: () -> Unit,
    onRequestPostNotifications: () -> Unit,
    onOpenBatterySettings: () -> Unit,
    onAdPrivacy: () -> Unit,
    onClearHistory: () -> Unit,
    onOpenPremium: () -> Unit,
    onOpenUrl: (String) -> Unit,
) {
    var dialog by rememberSaveable { mutableStateOf<String?>(null) }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp).testTag("settings"),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.headlineMedium)

        SectionCard(title = stringResource(R.string.settings_section_general)) {
            ClickRow(
                stringResource(R.string.settings_language),
                if (settings.language == AppLanguage.SYSTEM) stringResource(R.string.settings_language_system) else settings.language.nativeName,
                Modifier.testTag("settings_language"),
            ) { dialog = "language" }
            ClickRow(stringResource(R.string.settings_theme), stringResource(themeLabel(settings.theme))) { dialog = "theme" }
        }

        SectionCard(title = stringResource(R.string.settings_section_notifications)) {
            SwitchRow(stringResource(R.string.settings_monitoring), stringResource(R.string.settings_monitoring_desc), settings.notificationMonitoring, Modifier.testTag("settings_monitoring")) { v ->
                onUpdate { it.copy(notificationMonitoring = v) }
                if (v && !notificationAccess) onOpenAccessSettings()
            }
            Text(
                stringResource(if (notificationAccess) R.string.settings_access_granted else R.string.settings_access_missing),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TextButton(onClick = onOpenAccessSettings) { Text(stringResource(R.string.settings_open_access_settings)) }
            HorizontalDivider()
            SwitchRow(stringResource(R.string.settings_alerts), stringResource(R.string.settings_alerts_desc), settings.alertsEnabled) { v -> onUpdate { it.copy(alertsEnabled = v) } }
            if (!postNotificationsGranted) {
                Text(stringResource(R.string.settings_post_notifications_missing), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                TextButton(onClick = onRequestPostNotifications) { Text(stringResource(R.string.settings_grant)) }
            }
        }

        SectionCard(title = stringResource(R.string.settings_section_privacy)) {
            SwitchRow(stringResource(R.string.settings_cloud_ti), stringResource(R.string.settings_cloud_ti_desc), settings.cloudThreatIntel, Modifier.testTag("settings_cloud_ti")) { v -> onUpdate { it.copy(cloudThreatIntel = v) } }
            SwitchRow(stringResource(R.string.settings_cloud_ai), stringResource(R.string.settings_cloud_ai_desc), settings.cloudAi) { v -> onUpdate { it.copy(cloudAi = v) } }
            SwitchRow(stringResource(R.string.settings_redirects), stringResource(R.string.settings_redirects_desc), settings.resolveRedirects) { v -> onUpdate { it.copy(resolveRedirects = v) } }
            SwitchRow(stringResource(R.string.settings_keep_clean), stringResource(R.string.settings_keep_clean_desc), settings.keepCleanNotificationScans) { v -> onUpdate { it.copy(keepCleanNotificationScans = v) } }
            SwitchRow(stringResource(R.string.settings_diagnostics), stringResource(R.string.settings_diagnostics_desc), settings.diagnostics) { v -> onUpdate { it.copy(diagnostics = v) } }
            if (showAdPrivacy) TextButton(onClick = onAdPrivacy) { Text(stringResource(R.string.settings_ad_privacy)) }
            TextButton(onClick = { onOpenUrl(PRIVACY_URL) }) { Text(stringResource(R.string.settings_privacy_policy)) }
        }

        SectionCard(title = stringResource(R.string.settings_section_background)) {
            Text(stringResource(R.string.settings_background_desc), style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onOpenBatterySettings) { Text(stringResource(R.string.settings_battery_settings)) }
        }

        SectionCard(title = stringResource(R.string.settings_section_ai)) {
            Text(
                stringResource(if (backendConfigured) R.string.settings_backend_status_configured else R.string.settings_backend_status_missing),
                style = MaterialTheme.typography.bodySmall,
            )
            var key by rememberSaveable(settings.safeBrowsingApiKey) { mutableStateOf(settings.safeBrowsingApiKey) }
            Text(stringResource(R.string.settings_sb_key_desc), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedTextField(
                value = key,
                onValueChange = { key = it },
                label = { Text(stringResource(R.string.settings_sb_key)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            TextButton(onClick = { onUpdate { it.copy(safeBrowsingApiKey = key.trim()) } }, enabled = key.trim() != settings.safeBrowsingApiKey) {
                Text(stringResource(R.string.settings_save))
            }
        }

        SectionCard(title = stringResource(R.string.settings_section_data)) {
            ClickRow(stringResource(R.string.settings_retention), stringResource(R.string.settings_retention_days, settings.retentionDays)) { dialog = "retention" }
            TextButton(onClick = { dialog = "clear" }) { Text(stringResource(R.string.settings_clear_history), color = MaterialTheme.colorScheme.error) }
        }

        SectionCard(title = stringResource(R.string.settings_section_premium), onClick = onOpenPremium) {
            Text(stringResource(if (entitlement.isPremium) R.string.settings_premium_active else R.string.settings_premium_free), style = MaterialTheme.typography.bodyMedium)
        }

        SectionCard(title = stringResource(R.string.settings_section_about)) {
            Text(stringResource(R.string.settings_version, BuildConfig.VERSION_NAME), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(R.string.settings_developer), style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = { onOpenUrl(SOURCE_URL) }) { Text(stringResource(R.string.settings_source_code)) }
            TextButton(onClick = { onOpenUrl(LICENSE_URL) }) { Text(stringResource(R.string.settings_license)) }
        }
    }

    when (dialog) {
        "language" -> ChoiceDialog(
            title = stringResource(R.string.settings_language),
            options = AppLanguage.entries.toList(),
            selected = settings.language,
            label = { if (it == AppLanguage.SYSTEM) stringResource(R.string.settings_language_system) else it.nativeName },
            tagPrefix = "lang_",
            onSelect = { dialog = null; if (it != settings.language) onLanguage(it) },
            onDismiss = { dialog = null },
        )
        "theme" -> ChoiceDialog(
            title = stringResource(R.string.settings_theme),
            options = ThemeMode.entries.toList(),
            selected = settings.theme,
            label = { stringResource(themeLabel(it)) },
            onSelect = { t -> dialog = null; onUpdate { it.copy(theme = t) } },
            onDismiss = { dialog = null },
        )
        "retention" -> ChoiceDialog(
            title = stringResource(R.string.settings_retention),
            options = PremiumPolicy.retentionOptions(entitlement),
            selected = settings.retentionDays,
            label = { stringResource(R.string.settings_retention_days, it) },
            onSelect = { d -> dialog = null; onUpdate { it.copy(retentionDays = d) } },
            onDismiss = { dialog = null },
        )
        "clear" -> AlertDialog(
            onDismissRequest = { dialog = null },
            title = { Text(stringResource(R.string.history_clear_confirm_title)) },
            text = { Text(stringResource(R.string.history_clear_confirm_body)) },
            confirmButton = { TextButton(onClick = { dialog = null; onClearHistory() }) { Text(stringResource(R.string.history_clear_confirm_action)) } },
            dismissButton = { TextButton(onClick = { dialog = null }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
}

private fun themeLabel(t: ThemeMode) = when (t) {
    ThemeMode.SYSTEM -> R.string.theme_system
    ThemeMode.LIGHT -> R.string.theme_light
    ThemeMode.DARK -> R.string.theme_dark
}

@Composable
private fun ClickRow(title: String, value: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Row(modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun SwitchRow(title: String, description: String, checked: Boolean, modifier: Modifier = Modifier, onChange: (Boolean) -> Unit) {
    Row(modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun <T> ChoiceDialog(
    title: String,
    options: List<T>,
    selected: T,
    label: @Composable (T) -> String,
    onSelect: (T) -> Unit,
    onDismiss: () -> Unit,
    tagPrefix: String? = null,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                options.forEach { o ->
                    Row(
                        Modifier.fillMaxWidth()
                            .selectable(selected = o == selected, onClick = { onSelect(o) }, role = Role.RadioButton)
                            .padding(vertical = 10.dp)
                            .let { m -> if (tagPrefix != null) m.testTag(tagPrefix + o.toString()) else m },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = o == selected, onClick = null)
                        Spacer(Modifier.width(12.dp))
                        Text(label(o))
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) } },
    )
}
