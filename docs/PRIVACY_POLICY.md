# TrustCheck Privacy Policy (draft)

*Draft for review by the developer and, ideally, a legal professional before publication.
Last updated: 2026-11-15.*

TrustCheck (“the app”) is developed by Mesflit. This policy explains what data the app processes
and why. The app’s source code is public (GPL-3.0-only), so every statement here can be checked.

## 1. Data processed on your device

| Data | Purpose | Stored? |
|---|---|---|
| Links you paste, share or open with TrustCheck | Security analysis | The privacy-reduced link (scheme, host, path; **no query string, fragment or credentials**), result and timestamp are kept in local history |
| Text you share or select | Finding links and scam phrases | **Not stored.** Kept in memory for the current session only |
| Screenshots you share | On-device text recognition (ML Kit) | **Not stored and never uploaded** |
| Files you scan | On-device inspection: type, size, SHA-256, app permissions, links inside | File name, size, type, SHA-256 and (for apps) package name and permissions are kept in history. **File contents are never stored or uploaded** |
| Notification text (only if you grant Notification Access and enable monitoring) | Finding links in incoming messages | **Never stored, logged or uploaded.** Only the privacy-reduced link and source app name are kept, and by default only when a warning was found |
| Settings, AI usage counter | App functionality | Local only |

Local data is excluded from cloud backups and device transfer. You can delete individual entries
or all history, and choose a retention period (7–365 days).

## 2. Data sent off the device

| Feature | What is sent | Recipient |
|---|---|---|
| Daily threat list (default **on**, can be turned off) | Nothing about you: the app *downloads* a public list once a day. GitHub sees your IP address, as for any download | GitHub (github.com and its download servers) |
| Online lookup with your own Safe Browsing key (default **off**) | Privacy-reduced links | Google Safe Browsing |
| Reveal short-link destinations (default **off**) | A `HEAD` request to the link-shortening service (your IP address is visible to it) | The shortener |
| "Look up on VirusTotal" button (only when you tap it) | The file's SHA-256 fingerprint, opened in your browser | VirusTotal (Google) |

Files you scan are inspected on the device and are never uploaded. TrustCheck does not run its
own server in the default build.

## 3. Advertising (free version)

The free version shows Google AdMob banner ads outside security screens. Google may process
device identifiers (advertising ID), IP address and usage data to serve and measure ads, as
described in Google’s policies (https://policies.google.com/technologies/ads). Where required
(e.g. EEA, UK, certain US states) your consent is requested through Google’s User Messaging
Platform, and you can change it any time under **Settings → Ad privacy choices**. Premium
subscribers see no ads.

## 4. Purchases

Subscriptions are processed by Google Play. The app receives a purchase token, which may be sent
to the TrustCheck backend to verify the subscription with Google. The developer does not receive
your payment details.

## 5. What the app does not do

No selling of personal data. No accessibility-service monitoring. No reading of SMS databases.
No VPN traffic inspection. No contact, location or microphone access.

## 6. Children

The app is not directed at children under 13 (or the age required in your country).

## 7. Your rights

Under GDPR/KVKK and similar laws you have rights over your personal data. TrustCheck keeps your
data on your device, where you can view and delete it at any time.

## 8. Contact

Mesflit — via https://github.com/mesflit/TrustCheck (Security → “Report a vulnerability” for
private matters). *Add a contact email address before publishing.*

## 9. Changes

Material changes will be announced in the release notes and in the app.
