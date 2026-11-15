// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.IntentCompat
import androidx.lifecycle.lifecycleScope
import com.mesflit.trustcheck.core.localization.LocaleController
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.service.notification.AlertNotifier
import com.mesflit.trustcheck.ui.TrustCheckRoot
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private val container get() = (application as TrustCheckApp).container

    /** A report to open, e.g. from a tapped security alert. */
    val pendingReportId = MutableStateFlow<Long?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        container.billing.start()
        if (savedInstanceState == null) handleIntent(intent)

        lifecycleScope.launch {
            val s = container.settings.current()
            if (s.onboardingCompleted) container.ads.gatherConsent(this@MainActivity, container.billing.entitlement.value.isPremium)
        }

        setContent { TrustCheckRoot(container = container, activity = this) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        // Keep the stored language in sync if the user changed it in system per-app settings.
        lifecycleScope.launch {
            val applied = LocaleController.appliedLanguage()
            if (container.settings.current().language != applied) container.settings.setLanguage(applied)
        }
    }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        when (intent.action) {
            AlertNotifier.ACTION_OPEN_REPORT -> intent.getLongExtra(AlertNotifier.EXTRA_SCAN_ID, -1L).takeIf { it > 0 }?.let { pendingReportId.value = it }

            Intent.ACTION_SEND -> {
                val type = intent.type.orEmpty()
                if (type.startsWith("image/")) {
                    IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)?.let {
                        container.pendingScan.value = PendingScan.Image(it)
                    }
                } else {
                    val text = listOfNotNull(intent.getStringExtra(Intent.EXTRA_SUBJECT), intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString())
                        .joinToString("\n").trim()
                    if (text.isNotEmpty()) container.pendingScan.value = PendingScan.Text(text, ScanOrigin.SHARE_TEXT)
                }
            }

            Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()?.takeIf { it.isNotBlank() }?.let {
                container.pendingScan.value = PendingScan.Text(it, ScanOrigin.TEXT_SELECTION)
            }

            // "Open with TrustCheck": analyze only. The link is never opened automatically.
            Intent.ACTION_VIEW -> intent.dataString?.takeIf { it.startsWith("http", ignoreCase = true) }?.let {
                container.pendingScan.value = PendingScan.Text(it, ScanOrigin.LINK_OPEN)
            }
        }
    }
}
