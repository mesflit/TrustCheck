// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.monetization

import android.app.Activity
import android.content.Context
import com.android.billingclient.api.AcknowledgePurchaseParams
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.PendingPurchasesParams
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.PurchasesUpdatedListener
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams
import com.android.billingclient.api.acknowledgePurchase
import com.android.billingclient.api.queryProductDetails
import com.android.billingclient.api.queryPurchasesAsync
import com.mesflit.trustcheck.core.network.ApiResult
import com.mesflit.trustcheck.core.network.BackendClient
import com.mesflit.trustcheck.core.network.dto.BillingVerifyRequest
import com.mesflit.trustcheck.core.network.dto.BillingVerifyResponse
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

enum class BillingStatus { DISCONNECTED, CONNECTING, READY, UNAVAILABLE, ERROR }

sealed interface BillingEvent {
    data object PurchaseCompleted : BillingEvent
    data object PurchasePending : BillingEvent
    data object Cancelled : BillingEvent
    data object AlreadyOwned : BillingEvent
    data object NothingToRestore : BillingEvent
    data object Restored : BillingEvent
    data class Error(val code: Int) : BillingEvent
}

/**
 * Google Play Billing integration. Entitlement is recomputed from Play on every connection and
 * after every purchase; it is never read from a stored flag. When TrustCheck-Backend is
 * configured, each purchase token is verified server-side (Google Play Developer API) and that
 * answer is authoritative.
 */
class BillingManager(
    context: Context,
    private val backend: BackendClient,
) : PurchasesUpdatedListener {

    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _status = MutableStateFlow(BillingStatus.DISCONNECTED)
    val status: StateFlow<BillingStatus> = _status.asStateFlow()

    private val _entitlement = MutableStateFlow(Entitlement.FREE)
    val entitlement: StateFlow<Entitlement> = _entitlement.asStateFlow()

    private val _plans = MutableStateFlow<List<PlanOffer>>(emptyList())
    val plans: StateFlow<List<PlanOffer>> = _plans.asStateFlow()

    private val _events = MutableStateFlow<BillingEvent?>(null)
    val events: StateFlow<BillingEvent?> = _events.asStateFlow()

    private var productDetails: ProductDetails? = null

    private val client: BillingClient = BillingClient.newBuilder(appContext)
        .setListener(this)
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
        .build()

    fun consumeEvent() { _events.value = null }

    fun start() {
        if (client.isReady || _status.value == BillingStatus.CONNECTING) return
        _status.value = BillingStatus.CONNECTING
        client.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    _status.value = BillingStatus.READY
                    scope.launch {
                        loadPlans()
                        refreshEntitlement()
                    }
                } else {
                    _status.value = if (result.responseCode == BillingClient.BillingResponseCode.BILLING_UNAVAILABLE) BillingStatus.UNAVAILABLE else BillingStatus.ERROR
                }
            }

            override fun onBillingServiceDisconnected() {
                _status.value = BillingStatus.DISCONNECTED
            }
        })
    }

    private suspend fun loadPlans() {
        val params = QueryProductDetailsParams.newBuilder()
            .setProductList(
                listOf(
                    QueryProductDetailsParams.Product.newBuilder()
                        .setProductId(PlanCatalog.PREMIUM_PRODUCT_ID)
                        .setProductType(BillingClient.ProductType.SUBS)
                        .build(),
                ),
            ).build()
        val result = client.queryProductDetails(params)
        val details = result.productDetailsList?.firstOrNull() ?: run { _plans.value = emptyList(); return }
        productDetails = details
        _plans.value = details.subscriptionOfferDetails.orEmpty()
            // One entry per base plan: prefer the offer with an intro phase, else the base offer.
            .groupBy { it.basePlanId }
            .mapNotNull { (basePlan, offers) ->
                val offer = offers.firstOrNull { it.pricingPhases.pricingPhaseList.size > 1 } ?: offers.first()
                val phases = offer.pricingPhases.pricingPhaseList
                val recurring = phases.lastOrNull() ?: return@mapNotNull null
                val intro = phases.takeIf { it.size > 1 }?.first()
                PlanOffer(
                    basePlanId = basePlan,
                    offerToken = offer.offerToken,
                    formattedPrice = recurring.formattedPrice,
                    billingPeriod = recurring.billingPeriod,
                    introFormattedPrice = intro?.formattedPrice,
                    introBillingPeriod = intro?.billingPeriod,
                )
            }
            .sortedBy { PlanCatalog.sortKey(it.basePlanId) }
    }

    fun launchPurchase(activity: Activity, plan: PlanOffer): Boolean {
        val details = productDetails ?: return false
        val params = BillingFlowParams.newBuilder()
            .setProductDetailsParamsList(
                listOf(
                    BillingFlowParams.ProductDetailsParams.newBuilder()
                        .setProductDetails(details)
                        .setOfferToken(plan.offerToken)
                        .build(),
                ),
            ).build()
        return client.launchBillingFlow(activity, params).responseCode == BillingClient.BillingResponseCode.OK
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: MutableList<Purchase>?) {
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> scope.launch {
                val list = purchases.orEmpty()
                refreshEntitlement(list)
                _events.value = if (list.any { it.purchaseState == Purchase.PurchaseState.PENDING }) BillingEvent.PurchasePending else BillingEvent.PurchaseCompleted
            }
            BillingClient.BillingResponseCode.USER_CANCELED -> _events.value = BillingEvent.Cancelled
            BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED -> {
                _events.value = BillingEvent.AlreadyOwned
                scope.launch { refreshEntitlement() }
            }
            else -> _events.value = BillingEvent.Error(result.responseCode)
        }
    }

    /** "Restore purchases": re-queries Google Play for active subscriptions on this account. */
    fun restore() {
        scope.launch {
            if (!client.isReady) { start(); return@launch }
            val e = refreshEntitlement()
            _events.value = if (e.isPremium) BillingEvent.Restored else BillingEvent.NothingToRestore
        }
    }

    private suspend fun refreshEntitlement(updated: List<Purchase>? = null): Entitlement {
        val purchases = updated ?: client.queryPurchasesAsync(
            QueryPurchasesParams.newBuilder().setProductType(BillingClient.ProductType.SUBS).build(),
        ).purchasesList
        val snapshots = purchases.map { it.toSnapshot() }
        val verification = snapshots.filter { it.state == PurchaseState.PURCHASED }.associate { it.purchaseToken to verify(it) }
        val entitlement = EntitlementResolver.resolve(snapshots, PlanCatalog.premiumProductIds) { verification[it.purchaseToken] ?: VerificationResult.NotConfigured }
        _entitlement.value = entitlement

        // Acknowledge within 3 days or Google refunds automatically. Only when the purchase is
        // valid (server-verified active, or no backend configured).
        purchases.filter { it.purchaseState == Purchase.PurchaseState.PURCHASED && !it.isAcknowledged }.forEach { p ->
            val v = verification[p.purchaseToken]
            val ok = v is VerificationResult.Verified && v.active || v == VerificationResult.NotConfigured
            if (ok) {
                client.acknowledgePurchase(AcknowledgePurchaseParams.newBuilder().setPurchaseToken(p.purchaseToken).build())
            }
        }
        return entitlement
    }

    private suspend fun verify(p: PurchaseSnapshot): VerificationResult {
        if (!backend.isConfigured) return VerificationResult.NotConfigured
        val productId = p.productIds.firstOrNull { it in PlanCatalog.premiumProductIds } ?: return VerificationResult.Failed("unknown_product")
        return when (val r = backend.post(
            "v1/billing/verify",
            BillingVerifyRequest(appContext.packageName, productId, p.purchaseToken),
            BillingVerifyRequest.serializer(),
            BillingVerifyResponse.serializer(),
        )) {
            is ApiResult.Ok -> VerificationResult.Verified(r.value.active, r.value.inGracePeriod, r.value.onHold, r.value.expiryTimeMillis)
            ApiResult.NotConfigured -> VerificationResult.NotConfigured
            ApiResult.RateLimited -> VerificationResult.Failed("rate_limited")
            is ApiResult.HttpError -> VerificationResult.Failed("http_${r.code}")
            is ApiResult.NetworkError -> VerificationResult.Failed(r.message)
        }
    }

    private fun Purchase.toSnapshot() = PurchaseSnapshot(
        productIds = products,
        purchaseToken = purchaseToken,
        state = when (purchaseState) {
            Purchase.PurchaseState.PURCHASED -> PurchaseState.PURCHASED
            Purchase.PurchaseState.PENDING -> PurchaseState.PENDING
            else -> PurchaseState.UNSPECIFIED
        },
        acknowledged = isAcknowledged,
        autoRenewing = isAutoRenewing,
    )

    /** Opens Google Play's subscription management page for this app. */
    fun manageSubscriptionsUrl(): String =
        "https://play.google.com/store/account/subscriptions?sku=${PlanCatalog.PREMIUM_PRODUCT_ID}&package=${appContext.packageName}"
}
