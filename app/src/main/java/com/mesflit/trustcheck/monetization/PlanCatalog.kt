// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.monetization

/**
 * Google Play product configuration. Prices are NOT defined here: they come from Play Console
 * (suggested launch prices: monthly USD 3.99, annual USD 29.99) and are displayed exactly as
 * returned by ProductDetails, localized by Google Play.
 */
object PlanCatalog {
    /** Subscription product ID in Play Console. */
    const val PREMIUM_PRODUCT_ID = "trustcheck_premium"

    /** Base plan IDs configured under the subscription. */
    const val BASE_PLAN_MONTHLY = "monthly"
    const val BASE_PLAN_ANNUAL = "annual"

    val premiumProductIds: Set<String> = setOf(PREMIUM_PRODUCT_ID)

    enum class Period { MONTHLY, ANNUAL, OTHER }

    fun periodFor(basePlanId: String): Period = when (basePlanId) {
        BASE_PLAN_MONTHLY -> Period.MONTHLY
        BASE_PLAN_ANNUAL -> Period.ANNUAL
        else -> Period.OTHER
    }

    /** Display order: annual first (best value), then monthly, then anything else Play returns. */
    fun sortKey(basePlanId: String): Int = when (periodFor(basePlanId)) {
        Period.ANNUAL -> 0
        Period.MONTHLY -> 1
        Period.OTHER -> 2
    }
}

/** A purchasable offer as reported by Google Play. [formattedPrice] is Play's localized string. */
data class PlanOffer(
    val basePlanId: String,
    val offerToken: String,
    val formattedPrice: String,
    /** ISO-8601 billing period from Play, e.g. P1M, P1Y. */
    val billingPeriod: String,
    /** Present when the offer starts with a free trial or intro price, as Play reports it. */
    val introFormattedPrice: String?,
    val introBillingPeriod: String?,
) {
    val period: PlanCatalog.Period get() = PlanCatalog.periodFor(basePlanId)
}
