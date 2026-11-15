// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.monetization

/** Platform-independent view of a Play purchase (mapped from BillingClient's Purchase). */
data class PurchaseSnapshot(
    val productIds: List<String>,
    val purchaseToken: String,
    val state: PurchaseState,
    val acknowledged: Boolean,
    val autoRenewing: Boolean,
)

enum class PurchaseState { PURCHASED, PENDING, UNSPECIFIED }

/** Server-side verification outcome from TrustCheck-Backend (Google Play Developer API). */
sealed interface VerificationResult {
    data class Verified(
        val active: Boolean,
        val inGracePeriod: Boolean,
        val onHold: Boolean,
        val expiryTimeMillis: Long?,
    ) : VerificationResult

    /** Backend not configured — only the Play client's report is available. */
    data object NotConfigured : VerificationResult

    /** Backend configured but unreachable or errored. */
    data class Failed(val reason: String) : VerificationResult
}

enum class EntitlementSource {
    NONE,
    /** Verified by the backend against the Google Play Developer API. Authoritative. */
    SERVER_VERIFIED,
    /** Reported by the on-device Play Billing library; no server verification configured. */
    PLAY_CLIENT,
    /** Backend unreachable right now; temporarily trusting the Play client until it answers. */
    PLAY_CLIENT_PROVISIONAL,
}

enum class EntitlementState { NONE, ACTIVE, GRACE_PERIOD, PENDING, ON_HOLD, EXPIRED }

data class Entitlement(
    val isPremium: Boolean,
    val state: EntitlementState,
    val source: EntitlementSource,
    val expiryTimeMillis: Long? = null,
) {
    companion object {
        val FREE = Entitlement(false, EntitlementState.NONE, EntitlementSource.NONE)
    }
}

/**
 * Pure entitlement logic. Premium is derived only from current Play purchases (re-queried on
 * every start) and, when available, server verification. A locally stored "premium" flag is
 * never an input.
 */
object EntitlementResolver {

    fun resolve(
        purchases: List<PurchaseSnapshot>,
        premiumProductIds: Set<String>,
        verify: (PurchaseSnapshot) -> VerificationResult,
    ): Entitlement {
        val relevant = purchases.filter { p -> p.productIds.any { it in premiumProductIds } }
        if (relevant.isEmpty()) return Entitlement.FREE

        val purchased = relevant.filter { it.state == PurchaseState.PURCHASED }
        if (purchased.isEmpty()) {
            return if (relevant.any { it.state == PurchaseState.PENDING }) {
                Entitlement(false, EntitlementState.PENDING, EntitlementSource.PLAY_CLIENT)
            } else {
                Entitlement.FREE
            }
        }

        var best: Entitlement = Entitlement(false, EntitlementState.EXPIRED, EntitlementSource.SERVER_VERIFIED)
        for (p in purchased) {
            val e = when (val v = verify(p)) {
                is VerificationResult.Verified -> when {
                    v.active && v.inGracePeriod -> Entitlement(true, EntitlementState.GRACE_PERIOD, EntitlementSource.SERVER_VERIFIED, v.expiryTimeMillis)
                    v.active -> Entitlement(true, EntitlementState.ACTIVE, EntitlementSource.SERVER_VERIFIED, v.expiryTimeMillis)
                    v.onHold -> Entitlement(false, EntitlementState.ON_HOLD, EntitlementSource.SERVER_VERIFIED, v.expiryTimeMillis)
                    else -> Entitlement(false, EntitlementState.EXPIRED, EntitlementSource.SERVER_VERIFIED, v.expiryTimeMillis)
                }
                VerificationResult.NotConfigured -> Entitlement(true, EntitlementState.ACTIVE, EntitlementSource.PLAY_CLIENT)
                is VerificationResult.Failed -> Entitlement(true, EntitlementState.ACTIVE, EntitlementSource.PLAY_CLIENT_PROVISIONAL)
            }
            if (rank(e) > rank(best)) best = e
        }
        return best
    }

    private fun rank(e: Entitlement): Int = when {
        e.isPremium && e.source == EntitlementSource.SERVER_VERIFIED -> 4
        e.isPremium -> 3
        e.state == EntitlementState.ON_HOLD -> 2
        e.state == EntitlementState.PENDING -> 1
        else -> 0
    }
}

/**
 * What Premium changes: **only advertising**. Every feature — protection, file scanning,
 * history retention — is identical for free and Premium users.
 */
object PremiumPolicy {
    val RETENTION_OPTIONS_DAYS = listOf(7, 30, 90, 365)

    fun showAds(e: Entitlement, adsEnabledInBuild: Boolean) = adsEnabledInBuild && !e.isPremium
}
