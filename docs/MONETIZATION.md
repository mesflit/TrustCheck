# Monetization setup

## Google AdMob

**What is integrated**: Google Mobile Ads SDK, UMP consent (`AdsManager.gatherConsent` runs after
onboarding), adaptive banners (`BannerAdSlot`) at the bottom of the Dashboard and History lists
only, an optional user-initiated rewarded ad (+3 AI explanations per day), and an “Ad privacy
choices” entry in Settings when UMP requires it.

**Placement rules enforced in code**: no ads in scanner, report, onboarding, premium or alert
UI; none while scanning; none for Premium users (`PremiumPolicy.showAds`); every banner is
labelled “Advertisement”.

| Build | App ID | Ad units | Ads shown |
|---|---|---|---|
| debug | Google test app ID | Google test units | test ads |
| release without secrets | Google test app ID (only so the SDK doesn’t crash) | none | **disabled** |
| release with `ADMOB_APP_ID` + `ADMOB_BANNER_ID` | production | production | yes (after consent) |

Production setup:
1. Create the app and ad units (Banner, Rewarded) in AdMob.
2. Publish a GDPR / US-states consent message in **AdMob → Privacy & messaging**.
3. Add `ADMOB_APP_ID`, `ADMOB_BANNER_ID`, `ADMOB_REWARDED_ID` as GitHub secrets (or
   `trustcheck.admob*` Gradle properties locally). **Never commit production IDs** — CI fails if it finds one.
4. Add `app-ads.txt` to your developer website.
5. Never click your own production ads; use test devices.

## Google Play Billing

**What is integrated** (`BillingManager`, Billing Library 7): product details and localized
prices from Play, purchase flow, pending purchases, restore (`queryPurchasesAsync`),
acknowledgement, grace period / account hold (through server verification), and a “Manage
subscription” deep link.

Play Console configuration:
1. Monetize → Subscriptions → create product **`trustcheck_premium`**.
2. Add base plans **`monthly`** (auto-renewing, P1M, suggested USD 3.99) and **`annual`** (P1Y,
   suggested USD 29.99). Optional offers (e.g. free trial) appear automatically as intro prices.
3. Enable a grace period and account hold in the subscription settings.
4. Add license testers for testing.

Prices are never hardcoded. The UI shows exactly what Play returns, and if no product details
are available it says subscriptions are unavailable.

### Verification

With the backend configured, each purchase token is verified through `POST /v1/billing/verify`
(Google Play Developer API, `subscriptionsv2`). The server result is authoritative. Without a
backend, the app relies on the Play Billing library’s on-device result and labels it as such.
If the backend is temporarily unreachable, the user keeps Premium provisionally.
Configure Real-time Developer Notifications (Pub/Sub) on the backend to track renewals,
cancellations and revocations.

### What Premium unlocks

No ads, 100 AI explanations per day instead of 5, and up to 365 days of history retention.
**All essential protection is identical for free users.**
