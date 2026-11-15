// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/**
 * Final verdict categories. These are deliberately conservative:
 * nothing in TrustCheck ever claims a URL is "safe".
 */
enum class RiskClassification {
    /** A trusted threat-intelligence source (or synced blocklist) lists this URL/domain. */
    CONFIRMED_MALICIOUS,

    /** Local heuristics (or AI) found strong warning signs. Not confirmed by threat intel. */
    SUSPICIOUS,

    /** At least one threat-intelligence source was consulted and returned no match. */
    NO_KNOWN_THREAT,

    /** No reputation source could be consulted and no strong local warning signs were found. */
    UNKNOWN,

    /** The input could not be analyzed (unparseable, unsupported, internal error). */
    ANALYSIS_FAILED,
}

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

/**
 * Every signal TrustCheck can report. [weight] is the contribution to the 0–100 risk score.
 * Weights are heuristic and documented in docs/DETECTION.md.
 */
enum class Indicator(val weight: Int) {
    DANGEROUS_SCHEME(70),
    USERINFO_IN_URL(35),
    IP_ADDRESS_HOST(30),
    OBFUSCATED_IP_HOST(45),
    PRIVATE_NETWORK_HOST(5),
    PUNYCODE_DOMAIN(5),
    MIXED_SCRIPT_DOMAIN(40),
    WHOLE_SCRIPT_CONFUSABLE(35),
    HOMOGRAPH_OF_BRAND(55),
    LOOKALIKE_BRAND(50),
    BRAND_IN_SUBDOMAIN(40),
    BRAND_IN_DOMAIN_LABEL(35),
    URL_SHORTENER(15),
    INSECURE_HTTP(10),
    NON_STANDARD_PORT(15),
    EXCESSIVE_SUBDOMAINS(10),
    LONG_URL(5),
    SUSPICIOUS_TLD(12),
    SUSPICIOUS_KEYWORDS(8),
    EXCESSIVE_ENCODING(10),
    EMBEDDED_URL_PARAMETER(15),
    SENSITIVE_DATA_IN_URL(10),
    EXECUTABLE_DOWNLOAD(30),
    MANY_HYPHENS(8),
    REDIRECTS_TO_OTHER_DOMAIN(10),
    REDIRECT_CHAIN_TOO_LONG(15),

    // Text (message) indicators
    URGENCY_LANGUAGE(15),
    CREDENTIAL_REQUEST(25),
    PRIZE_OR_MONEY_LURE(15),
    PAYMENT_OR_FEE_REQUEST(15),

    // Files
    DOUBLE_EXTENSION(40),
    EXTENSION_MISMATCH(30),
    EXECUTABLE_FILE(20),
    SCRIPT_FILE(20),
    MACRO_DOCUMENT(25),
    FILE_CONTAINS_DANGEROUS_LINK(40),

    // Android app packages (APK)
    APK_SMS_ACCESS(30),
    APK_ACCESSIBILITY_SERVICE(35),
    APK_DEVICE_ADMIN(25),
    APK_SCREEN_OVERLAY(15),
    APK_INSTALLS_APPS(15),
    APK_NOTIFICATION_ACCESS(15),
    APK_BANKING_TROJAN_PATTERN(30),
    APK_BRAND_IMPERSONATION(50),
    APK_DEBUG_SIGNED(10),

    // Reputation
    BLOCKLIST_MATCH(100),
    THREAT_INTEL_MATCH(100),
    ;

    val severity: Severity
        get() = when {
            weight >= 60 -> Severity.CRITICAL
            weight >= 35 -> Severity.HIGH
            weight >= 15 -> Severity.MEDIUM
            weight >= 8 -> Severity.LOW
            else -> Severity.INFO
        }
}

/** An indicator plus optional machine-readable detail (e.g. the impersonated brand). Never localized here. */
data class DetectedIndicator(val indicator: Indicator, val detail: String? = null)

enum class AnalysisSource {
    LOCAL_HEURISTICS,
    LOCAL_BLOCKLIST,
    TRUSTCHECK_BACKEND,
    GOOGLE_SAFE_BROWSING,
    REDIRECT_RESOLVER,
    ON_DEVICE_OCR,
    FILE_INSPECTION,
}

enum class SourceStatus { MATCH, NO_MATCH, UNAVAILABLE, ERROR, SKIPPED }

data class SourceResult(
    val source: AnalysisSource,
    val status: SourceStatus,
    /** Threat types for MATCH (e.g. SOCIAL_ENGINEERING), or an error/skip reason code. */
    val detail: String? = null,
)

data class UrlAnalysisResult(
    val input: String,
    /** Privacy-reduced key: scheme://host[:port]/path — query and fragment removed. */
    val normalizedUrl: String?,
    val displayHost: String?,
    val registrableDomain: String?,
    val finalUrl: String?,
    val indicators: List<DetectedIndicator>,
    val riskScore: Int,
    val classification: RiskClassification,
    val sources: List<SourceResult>,
    val timestampMillis: Long,
) {
    val threatIntelConsulted: Boolean
        get() = sources.any { it.source.isReputation && (it.status == SourceStatus.MATCH || it.status == SourceStatus.NO_MATCH) }

    companion object {
        fun failed(input: String, now: Long, reason: String) = UrlAnalysisResult(
            input = input,
            normalizedUrl = null,
            displayHost = null,
            registrableDomain = null,
            finalUrl = null,
            indicators = emptyList(),
            riskScore = 0,
            classification = RiskClassification.ANALYSIS_FAILED,
            sources = listOf(SourceResult(AnalysisSource.LOCAL_HEURISTICS, SourceStatus.ERROR, reason)),
            timestampMillis = now,
        )
    }
}

val AnalysisSource.isReputation: Boolean
    get() = this == AnalysisSource.LOCAL_BLOCKLIST ||
        this == AnalysisSource.TRUSTCHECK_BACKEND ||
        this == AnalysisSource.GOOGLE_SAFE_BROWSING
