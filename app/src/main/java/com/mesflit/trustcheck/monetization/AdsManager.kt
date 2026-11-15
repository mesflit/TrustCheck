// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.monetization

import android.app.Activity
import android.content.Context
import com.google.android.gms.ads.MobileAds
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
/** What happened to ads on this device, shown in Settings so missing ads can be diagnosed. */
data class AdStatus(val kind: Kind, val code: Int? = null) {
    enum class Kind { NOT_CONFIGURED, PREMIUM, WAITING_FOR_CONSENT, CONSENT_ERROR, LOADING, SHOWING, NO_FILL, ERROR }
}

class AdsManager(context: Context) {
    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val consent: ConsentInformation = UserMessagingPlatform.getConsentInformation(appContext)
    private val sdkStarted = AtomicBoolean(false)

    val adsEnabledInBuild: Boolean = BuildConfig.ADS_ENABLED && BuildConfig.ADMOB_BANNER_ID.isNotBlank()
    val bannerUnitId: String = BuildConfig.ADMOB_BANNER_ID

    private val _canRequestAds = MutableStateFlow(false)
    val canRequestAds: StateFlow<Boolean> = _canRequestAds.asStateFlow()

    private val _status = MutableStateFlow(AdStatus(if (adsEnabledInBuild) AdStatus.Kind.WAITING_FOR_CONSENT else AdStatus.Kind.NOT_CONFIGURED))
    val status: StateFlow<AdStatus> = _status.asStateFlow()

    /** Called by the banner after each load attempt (AdMob error codes: 3 = no ad available). */
    fun reportLoad(errorCode: Int?) {
        _status.value = when (errorCode) {
            null -> AdStatus(AdStatus.Kind.SHOWING)
            3 -> AdStatus(AdStatus.Kind.NO_FILL, 3)
            else -> AdStatus(AdStatus.Kind.ERROR, errorCode)
        }
    }

    fun reportLoading() { if (_status.value.kind != AdStatus.Kind.SHOWING) _status.value = AdStatus(AdStatus.Kind.LOADING) }

    private val _privacyOptionsRequired = MutableStateFlow(false)
    val privacyOptionsRequired: StateFlow<Boolean> = _privacyOptionsRequired.asStateFlow()

    /** Call from the main activity's onCreate. Shows the consent form only if required. */
    fun gatherConsent(activity: Activity, isPremium: Boolean) {
        if (!adsEnabledInBuild) return
        if (isPremium) { _status.value = AdStatus(AdStatus.Kind.PREMIUM); return }
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
            { error -> updateState(); if (!consent.canRequestAds()) _status.value = AdStatus(AdStatus.Kind.CONSENT_ERROR, error.errorCode) },
        )
        // Consent from a previous session can be used immediately.
        updateState()
        if (consent.canRequestAds()) startSdk()
    }

    private fun updateState() {
        _canRequestAds.value = consent.canRequestAds()
        if (consent.canRequestAds() && _status.value.kind == AdStatus.Kind.WAITING_FOR_CONSENT) _status.value = AdStatus(AdStatus.Kind.LOADING)
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
}
