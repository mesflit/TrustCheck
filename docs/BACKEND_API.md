# TrustCheck-Backend API contract

The backend is **optional and not used by the default (zero-cost) build** and lives in the private repository `mesflit/TrustCheck-Backend`.
The client works fully offline without it. This document is the contract the Android client
implements (`core/network`). No backend code is in this public repository.

Base URL: injected at build time (`trustcheck.backendBaseUrl` / `TRUSTCHECK_BACKEND_URL`).
**HTTPS only.** The client refuses non-HTTPS base URLs.

## Responsibilities

Threat-intelligence aggregation (use
**commercial-use** sources such as Google Web Risk; the free Safe Browsing API is non-commercial),
rate limiting and abuse prevention, Play subscription verification, and optional sync later.

## Requirements

- TLS everywhere; HSTS.
- Validate every input (URL length ≤ 2048, max 10 URLs per lookup, text ≤ 4000 chars, language in the supported list).
- Per-install and per-IP rate limits; return `429` when exceeded.
- Store **no** message text and no full URLs in logs. Keep minimal, short-lived metrics.
- Never return a verdict the upstream provider did not give (`unknown` when unsure).
- Recommended: require a Play Integrity token on `/v1/auth/install` for production.

## Authentication

`POST /v1/auth/install` → `{ "installId": "<random uuid>", "platform": "android", "appVersion"?, "osVersion"? }`
→ `200 { "token": "<opaque>", "expiresAt"?: <ms> }`

All other endpoints require `Authorization: Bearer <token>`. On `401` the client discards the
token and registers again once.

## Endpoints

### `POST /v1/threat/lookup`
Request: `{ "urls": ["https://host/path", ...] }` (privacy-reduced: no query, fragment or userinfo)
Response: `{ "results": [ { "url", "verdict": "malicious"|"clean"|"unknown", "threatTypes": [], "source": "web_risk" } ] }`

Only `"clean"` counts as an answer. `"unknown"` means the lookup was inconclusive and the client
shows **Unknown**.

### `GET /v1/blocklist?since=<version>` (unused: the app now uses the GitHub-hosted threat list)
Response: `{ "version", "full": bool, "added": [{ "domain", "category", "source" }], "removed": ["domain"] }`
Synced at most daily, on network and when the battery is not low, and only with cloud consent.

### `POST /v1/billing/verify`
Request: `{ "packageName", "productId", "purchaseToken" }`
Server calls `purchases.subscriptionsv2.get` (Google Play Developer API) and acknowledges if needed.
Response: `{ "active", "state", "inGracePeriod", "onHold", "expiryTimeMillis"?, "acknowledged" }`
The server answer is authoritative over the client’s view.

## Errors

`400` invalid input · `401` token invalid or expired · `429` rate limited · `5xx` upstream
failure. The client maps all errors to “unavailable” states and never to a verdict.
