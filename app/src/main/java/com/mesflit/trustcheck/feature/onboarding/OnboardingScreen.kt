// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.feature.onboarding

import android.Manifest
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Flag
import androidx.compose.material.icons.filled.Payments
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material.icons.filled.Translate
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.filled.VolunteerActivism
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.design.SectionCard
import com.mesflit.trustcheck.feature.dashboard.hasNotificationAccess
import com.mesflit.trustcheck.feature.settings.postNotificationsGranted
import com.mesflit.trustcheck.ui.LocalAppContainer
import kotlinx.coroutines.launch

private const val PAGES = 6

@Composable
fun OnboardingScreen(onFinished: () -> Unit) {
    val container = LocalAppContainer.current
    val settings by container.settings.settings.collectAsStateWithLifecycle(initialValue = null)
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var page by rememberSaveable { mutableIntStateOf(0) }
    var access by remember { mutableStateOf(hasNotificationAccess(context)) }
    var post by remember { mutableStateOf(postNotificationsGranted(context)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { access = hasNotificationAccess(context); post = postNotificationsGranted(context) }
    val postLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { post = it }

    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(20.dp).testTag("onboarding")) {
        LinearProgressIndicator(progress = { (page + 1) / PAGES.toFloat() }, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.size(20.dp))
        AnimatedContent(targetState = page, modifier = Modifier.weight(1f), label = "onboarding") { p ->
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                when (p) {
                    0 -> Page(Icons.Filled.Shield, R.string.onboarding_welcome_title, R.string.onboarding_welcome_body)
                    1 -> {
                        Text(stringResource(R.string.onboarding_features_title), style = MaterialTheme.typography.headlineSmall)
                        Text(stringResource(R.string.onboarding_features_body), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        FEATURES.forEach { (icon, title, body) -> FeatureRow(icon, title, body) }
                    }
                    2 -> Page(Icons.Filled.AutoAwesome, R.string.onboarding_how_title, R.string.onboarding_how_body)
                    3 -> {
                        Page(Icons.Filled.NotificationsActive, R.string.onboarding_perm_title, R.string.onboarding_perm_body)
                        PermissionCard(
                            title = stringResource(R.string.onboarding_perm_notif_access),
                            description = stringResource(R.string.onboarding_perm_notif_access_desc),
                            granted = access,
                            onGrant = {
                                scope.launch { container.settings.update { it.copy(notificationMonitoring = true) } }
                                context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                            },
                        )
                        if (Build.VERSION.SDK_INT >= 33) {
                            PermissionCard(
                                title = stringResource(R.string.onboarding_perm_post),
                                description = stringResource(R.string.onboarding_perm_post_desc),
                                granted = post,
                                onGrant = { postLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) },
                            )
                        }
                        Text(stringResource(R.string.onboarding_optional), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    4 -> {
                        Page(Icons.Filled.Security, R.string.onboarding_feed_title, R.string.onboarding_feed_body)
                        val s = settings
                        if (s != null) {
                            ToggleCard(stringResource(R.string.settings_feed), stringResource(R.string.settings_feed_desc), s.threatFeed) { v ->
                                scope.launch { container.settings.update { it.copy(threatFeed = v) } }
                            }
                        }
                        Text(stringResource(R.string.onboarding_optional), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    else -> Page(Icons.Filled.Lock, R.string.onboarding_data_title, R.string.onboarding_data_body)
                }
            }
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            if (page > 0) TextButton(onClick = { page-- }) { Text(stringResource(R.string.onboarding_back)) }
            Spacer(Modifier.weight(1f))
            if (page < PAGES - 1) {
                TextButton(onClick = { page = PAGES - 1 }, modifier = Modifier.testTag("onboarding_skip")) { Text(stringResource(R.string.onboarding_skip)) }
                Spacer(Modifier.width(8.dp))
                Button(onClick = { page++ }, modifier = Modifier.testTag("onboarding_next")) { Text(stringResource(R.string.onboarding_next)) }
            } else {
                Button(onClick = onFinished, modifier = Modifier.testTag("onboarding_finish")) { Text(stringResource(R.string.onboarding_finish)) }
            }
        }
    }
}

/** Every feature, explained on first launch. */
private val FEATURES: List<Triple<ImageVector, Int, Int>> = listOf(
    Triple(Icons.Filled.Link, R.string.feat_links_title, R.string.feat_links_desc),
    Triple(Icons.Filled.Sms, R.string.feat_messages_title, R.string.feat_messages_desc),
    Triple(Icons.Filled.NotificationsActive, R.string.feat_notifications_title, R.string.feat_notifications_desc),
    Triple(Icons.Filled.Share, R.string.feat_share_title, R.string.feat_share_desc),
    Triple(Icons.Filled.Image, R.string.feat_screenshots_title, R.string.feat_screenshots_desc),
    Triple(Icons.Filled.UploadFile, R.string.feat_files_title, R.string.feat_files_desc),
    Triple(Icons.Filled.QrCodeScanner, R.string.feat_qr_title, R.string.feat_qr_desc),
    Triple(Icons.Filled.Payments, R.string.feat_payment_title, R.string.feat_payment_desc),
    Triple(Icons.Filled.Security, R.string.feat_feed_title, R.string.feat_feed_desc),
    Triple(Icons.Filled.Assessment, R.string.feat_reports_title, R.string.feat_reports_desc),
    Triple(Icons.Filled.History, R.string.feat_history_title, R.string.feat_history_desc),
    Triple(Icons.Filled.Flag, R.string.feat_report_wrong_title, R.string.feat_report_wrong_desc),
    Triple(Icons.Filled.WifiOff, R.string.feat_offline_title, R.string.feat_offline_desc),
    Triple(Icons.Filled.Translate, R.string.feat_languages_title, R.string.feat_languages_desc),
    Triple(Icons.Filled.VolunteerActivism, R.string.feat_free_title, R.string.feat_free_desc),
)

@Composable
private fun FeatureRow(icon: ImageVector, title: Int, body: Int) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 2.dp).size(24.dp))
        Spacer(Modifier.width(14.dp))
        Column {
            Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
            Text(stringResource(body), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun Page(icon: ImageVector, title: Int, body: Int) {
    Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(48.dp))
    Text(stringResource(title), style = MaterialTheme.typography.headlineSmall)
    Text(stringResource(body), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun PermissionCard(title: String, description: String, granted: Boolean, onGrant: () -> Unit) {
    SectionCard(title = title) {
        Text(description, style = MaterialTheme.typography.bodyMedium)
        if (granted) {
            Text(stringResource(R.string.onboarding_granted), color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.labelLarge)
        } else {
            OutlinedButton(onClick = onGrant) { Text(stringResource(R.string.settings_grant)) }
        }
    }
}

@Composable
private fun ToggleCard(title: String, description: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked = checked, onCheckedChange = onChange)
        }
    }
}
