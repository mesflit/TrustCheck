// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.monetization

import android.app.Activity
import android.content.Context
import com.google.android.gms.ads.AdError
import com.google.android.gms.ads.AdRequest
import com.google.android.gms.ads.FullScreenContentCallback
import com.google.android.gms.ads.LoadAdError
import com.google.android.gms.ads.MobileAds
import com.google.android.gms.ads.rewarded.RewardedAd
import com.google.android.gms.ads.rewarded.RewardedAdLoadCallback
import com.google.android.ump.ConsentInformation
import com.google.android.ump.ConsentRequestParameters
import com.google.android.ump.UserMessagingPlatform
import com.mesflit.trustcheck.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AdMob + Google User Messaging Platform.
 *
 * Policy enforced in code and UI:
 *  - Ads are requested only after UMP says consent allows it (GDPR/US state regulations).
 *  - No ads for Premium users, no ads in scanner/report/alert screens, never during a scan.
 *  - Debug builds use Google's public test ad units; production IDs are injected at build time.
 */
class AdsManager(context: Context) {
    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val consent: ConsentInformation = UserMessagingPlatform.getConsentInformation(appContext)
    private val sdkStarted = AtomicBoolean(false)

    val adsEnabledInBuild: Boolean = BuildConfig.ADS_ENABLED && BuildConfig.ADMOB_BANNER_ID.isNotBlank()
    val bannerUnitId: String = BuildConfig.ADMOB_BANNER_ID
    private val rewardedUnitId: String = BuildConfig.ADMOB_REWARDED_ID

    private val _canRequestAds = MutableStateFlow(false)
    val canRequestAds: StateFlow<Boolean> = _canRequestAds.asStateFlow()

    private val _privacyOptionsRequired = MutableStateFlow(false)
    val privacyOptionsRequired: StateFlow<Boolean> = _privacyOptionsRequired.asStateFlow()

    private val _rewardedReady = MutableStateFlow(false)
    val rewardedReady: StateFlow<Boolean> = _rewardedReady.asStateFlow()
    private var rewardedAd: RewardedAd? = null

    /** Call from the main activity's onCreate. Shows the consent form only if required. */
    fun gatherConsent(activity: Activity, isPremium: Boolean) {
        if (!adsEnabledInBuild || isPremium) return
        val params = ConsentRequestParameters.Builder().setTagForUnderAgeOfConsent(false).build()
        consent.requestConsentInfoUpdate(
            activity,
            params,
            {
                UserMessagingPlatform.loadAndShowConsentFormIfRequired(activity) { _ ->
                    updateState()
                    if (consent.canRequestAds()) startSdk()
                }
            },
            { _ -> updateState() },
        )
        // Consent from a previous session can be used immediately.
        updateState()
        if (consent.canRequestAds()) startSdk()
    }

    private fun updateState() {
        _canRequestAds.value = consent.canRequestAds()
        _privacyOptionsRequired.value =
            consent.privacyOptionsRequirementStatus == ConsentInformation.PrivacyOptionsRequirementStatus.REQUIRED
    }

    private fun startSdk() {
        if (!sdkStarted.compareAndSet(false, true)) return
        scope.launch(Dispatchers.IO) {
            MobileAds.initialize(appContext) {}
        }
    }

    fun showPrivacyOptions(activity: Activity) {
        UserMessagingPlatform.showPrivacyOptionsForm(activity) { _ -> updateState() }
    }

    /** Optional rewarded ad: user-initiated only, grants extra AI explanations for today. */
    fun loadRewarded() {
        if (!adsEnabledInBuild || !_canRequestAds.value || rewardedUnitId.isBlank() || rewardedAd != null) return
        RewardedAd.load(appContext, rewardedUnitId, AdRequest.Builder().build(), object : RewardedAdLoadCallback() {
            override fun onAdLoaded(ad: RewardedAd) {
                rewardedAd = ad
                _rewardedReady.value = true
            }

            override fun onAdFailedToLoad(error: LoadAdError) {
                rewardedAd = null
                _rewardedReady.value = false
            }
        })
    }

    fun showRewarded(activity: Activity, onReward: () -> Unit) {
        val ad = rewardedAd ?: return
        ad.fullScreenContentCallback = object : FullScreenContentCallback() {
            override fun onAdDismissedFullScreenContent() {
                rewardedAd = null
                _rewardedReady.value = false
            }

            override fun onAdFailedToShowFullScreenContent(error: AdError) {
                rewardedAd = null
                _rewardedReady.value = false
            }
        }
        ad.show(activity) { onReward() }
    }
}
