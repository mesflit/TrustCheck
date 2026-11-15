# Detection logic

All weights live in `core/security/Models.kt` (`Indicator`). The risk score is the sum of local
indicator weights, capped at 100 (lure-word hits count up to 3×). Reputation matches are
reported separately and force **Confirmed malicious** (score ≥ 95).

## Classification rules (`RiskScorer.classify`)

1. Any reputation source (daily threat list, Safe Browsing, optional backend) returns **MATCH** → `CONFIRMED_MALICIOUS`.
2. Local score ≥ **40** → `SUSPICIOUS`.
3. At least one reputation source answered **NO_MATCH** → `NO_KNOWN_THREAT`.
4. Otherwise → `UNKNOWN`. Offline, unconfigured, timed-out or errored lookups are never treated as clean.

Unparseable input → `ANALYSIS_FAILED`.

## Indicators

| Indicator | Weight | Notes |
|---|---|---|
| Dangerous scheme (`javascript:`, `data:`, `vbscript:`, `file:`, `intent:`) | 70 | |
| Homograph of brand | 55 | Non-Latin look-alikes mapping exactly to a brand |
| Look-alike brand | 50 | leetspeak, hyphenation, `rn→m`, one-edit typos (brands ≥ 6 chars, same first letter), brand on abused TLD |
| Obfuscated IP | 45 | decimal/hex/octal forms |
| Mixed script / brand in subdomain | 40 | Latin + Cyrillic/Greek/Armenian in one label; CJK mixes allowed |
| User-info `@` trick / whole-script confusable / brand in label | 35 | |
| IP host / executable download | 30 | |
| Embedded URL parameter, shortener, non-standard port, redirect chain ≥ 5, credential/urgency/prize/payment phrases | 15–25 | |
| Suspicious TLD | 12 | Weak signal on its own |
| HTTP, excessive encoding/subdomains, sensitive parameter, redirect to other domain | 10 | |
| Lure words, many hyphens | 8 | |
| Punycode, private network, long URL | 5 | Informational |

## Files

Files have no reputation source, so their verdict is **Suspicious** (score ≥ 40) or **Unknown**
(no warning signs — never "safe"). Links found inside a file are analyzed and saved as their own
reports; a dangerous one adds *Contains a dangerous link* to the file.

| Indicator | Weight |
|---|---|
| APK named after a brand it does not belong to | 50 |
| Double extension (`invoice.pdf.apk`), contains a dangerous link | 40 |
| APK accessibility service | 35 |
| Disguised type (content ≠ name), APK SMS access, banking-trojan pattern (SMS + accessibility/overlay) | 30 |
| Macro document, APK device admin | 25 |
| App/program, script | 20 |
| APK overlay, installs apps, reads notifications | 15 |
| APK signed with the public Android debug key | 10 |

Type detection uses magic bytes (ZIP/APK/Office, PDF, PE, ELF, DEX, images, text). APK facts come
from `PackageManager.getPackageArchiveInfo` on a private temporary copy that is deleted
immediately; the APK is never installed. PDFs: first 3 pages rendered and OCR'd on-device.

## Threat list

Daily list built by `scripts/build_threat_feed.py`. On the device each domain is stored as the
first 64 bits of its SHA-256 in a sorted file and looked up by binary search (host and every
parent domain). A list older than 10 days is treated as unavailable, so outdated data never
produces "No known threat detected".

## Known limitations

- Registrable domains use a compact multi-label suffix list plus common shared-hosting suffixes,
  not the full Public Suffix List. Rare suffixes may be grouped incorrectly.
- The brand list covers frequently impersonated global, Turkish, Brazilian, Spanish, French,
  German, Russian, Japanese and Gulf brands; new targets need contributions.
- Phrase detection is keyword-based; the optional AI layer gives deeper text analysis.
- OCR uses ML Kit’s Latin model: URLs are recognized in any UI language, but non-Latin phrases in images are not.
- Redirect resolution sends a `HEAD` request to the shortener (revealing your IP to it), so it is off by default.
