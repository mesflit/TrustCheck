package com.mesflit.trustcheck.monetization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EntitlementResolverTest {
    private val ids = setOf("trustcheck_premium")
    private fun purchase(state: PurchaseState, product: String = "trustcheck_premium") =
        PurchaseSnapshot(listOf(product), "token-$state", state, acknowledged = true, autoRenewing = true)

    @Test fun noPurchasesIsFree() {
        assertEquals(Entitlement.FREE, EntitlementResolver.resolve(emptyList(), ids) { error("unused") })
    }

    @Test fun unrelatedProductIsFree() {
        assertFalse(EntitlementResolver.resolve(listOf(purchase(PurchaseState.PURCHASED, "other")), ids) { VerificationResult.NotConfigured }.isPremium)
    }

    @Test fun pendingIsNotPremium() {
        val e = EntitlementResolver.resolve(listOf(purchase(PurchaseState.PENDING)), ids) { error("pending must not be verified") }
        assertFalse(e.isPremium)
        assertEquals(EntitlementState.PENDING, e.state)
    }

    @Test fun serverVerifiedActive() {
        val e = EntitlementResolver.resolve(listOf(purchase(PurchaseState.PURCHASED)), ids) { VerificationResult.Verified(true, false, false, 123L) }
        assertTrue(e.isPremium)
        assertEquals(EntitlementSource.SERVER_VERIFIED, e.source)
        assertEquals(123L, e.expiryTimeMillis)
    }

    @Test fun gracePeriodKeepsPremium() {
        val e = EntitlementResolver.resolve(listOf(purchase(PurchaseState.PURCHASED)), ids) { VerificationResult.Verified(true, true, false, null) }
        assertTrue(e.isPremium)
        assertEquals(EntitlementState.GRACE_PERIOD, e.state)
    }

    @Test fun serverOverridesClientWhenInactive() {
        val e = EntitlementResolver.resolve(listOf(purchase(PurchaseState.PURCHASED)), ids) { VerificationResult.Verified(false, false, true, null) }
        assertFalse(e.isPremium)
        assertEquals(EntitlementState.ON_HOLD, e.state)
    }

    @Test fun noBackendTrustsPlayClientAndLabelsIt() {
        val e = EntitlementResolver.resolve(listOf(purchase(PurchaseState.PURCHASED)), ids) { VerificationResult.NotConfigured }
        assertTrue(e.isPremium)
        assertEquals(EntitlementSource.PLAY_CLIENT, e.source)
    }

    @Test fun backendFailureIsProvisional() {
        val e = EntitlementResolver.resolve(listOf(purchase(PurchaseState.PURCHASED)), ids) { VerificationResult.Failed("timeout") }
        assertTrue(e.isPremium)
        assertEquals(EntitlementSource.PLAY_CLIENT_PROVISIONAL, e.source)
    }

    @Test fun policy() {
        val premium = Entitlement(true, EntitlementState.ACTIVE, EntitlementSource.SERVER_VERIFIED)
        assertFalse(PremiumPolicy.showAds(premium, adsEnabledInBuild = true))
        assertTrue(PremiumPolicy.showAds(Entitlement.FREE, adsEnabledInBuild = true))
        assertFalse(PremiumPolicy.showAds(Entitlement.FREE, adsEnabledInBuild = false))
        assertTrue(PremiumPolicy.dailyAiLimit(premium) > PremiumPolicy.dailyAiLimit(Entitlement.FREE))
    }
}
