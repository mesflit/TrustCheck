// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.monetization

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.google.android.gms.ads.AdRequest
import com.google.android.gms.ads.AdSize
import com.google.android.gms.ads.AdView
import com.mesflit.trustcheck.R

/**
 * Adaptive banner placed only at the bottom of the Dashboard and History lists, always under a
 * visible "Advertisement" label so it can never be mistaken for a security recommendation.
 * Renders nothing for Premium users, when consent does not allow ads, or when ads are not
 * configured for this build.
 */
@Composable
fun BannerAdSlot(ads: AdsManager, entitlement: Entitlement, modifier: Modifier = Modifier) {
    val canRequest by ads.canRequestAds.collectAsState()
    if (!PremiumPolicy.showAds(entitlement, ads.adsEnabledInBuild) || !canRequest) return

    val context = LocalContext.current
    val widthDp = LocalConfiguration.current.screenWidthDp
    val adView = remember(widthDp) {
        AdView(context).apply {
            adUnitId = ads.bannerUnitId
            setAdSize(AdSize.getCurrentOrientationAnchoredAdaptiveBannerAdSize(context, widthDp))
            loadAd(AdRequest.Builder().build())
        }
    }
    DisposableEffect(adView) { onDispose { adView.destroy() } }

    Column(modifier.fillMaxWidth().padding(top = 8.dp)) {
        Text(
            stringResource(R.string.ad_label),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 4.dp, bottom = 4.dp),
        )
        AndroidView(factory = { adView }, modifier = Modifier.fillMaxWidth())
    }
}
