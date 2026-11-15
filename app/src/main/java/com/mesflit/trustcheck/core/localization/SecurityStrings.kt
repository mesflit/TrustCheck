// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.localization

import androidx.annotation.StringRes
import com.mesflit.trustcheck.R
import com.mesflit.trustcheck.core.security.AnalysisSource
import com.mesflit.trustcheck.core.security.Indicator
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.SourceStatus
import com.mesflit.trustcheck.domain.ScanOrigin

/** Maps engine enums to localized resources, so reports and notifications are fully translated. */
object SecurityStrings {

    @StringRes fun classificationTitle(c: RiskClassification): Int = when (c) {
        RiskClassification.CONFIRMED_MALICIOUS -> R.string.class_malicious
        RiskClassification.SUSPICIOUS -> R.string.class_suspicious
        RiskClassification.NO_KNOWN_THREAT -> R.string.class_no_known_threat
        RiskClassification.UNKNOWN -> R.string.class_unknown
        RiskClassification.ANALYSIS_FAILED -> R.string.class_failed
    }

    @StringRes fun classificationDescription(c: RiskClassification): Int = when (c) {
        RiskClassification.CONFIRMED_MALICIOUS -> R.string.class_malicious_desc
        RiskClassification.SUSPICIOUS -> R.string.class_suspicious_desc
        RiskClassification.NO_KNOWN_THREAT -> R.string.class_no_known_threat_desc
        RiskClassification.UNKNOWN -> R.string.class_unknown_desc
        RiskClassification.ANALYSIS_FAILED -> R.string.class_failed_desc
    }

    /** Recommended actions per classification. */
    fun recommendations(c: RiskClassification): List<Int> = when (c) {
        RiskClassification.CONFIRMED_MALICIOUS -> listOf(R.string.rec_do_not_open, R.string.rec_do_not_enter_data, R.string.rec_delete_message, R.string.rec_if_entered_change_password)
        RiskClassification.SUSPICIOUS -> listOf(R.string.rec_do_not_open, R.string.rec_verify_official_channel, R.string.rec_do_not_enter_data)
        RiskClassification.NO_KNOWN_THREAT -> listOf(R.string.rec_still_careful, R.string.rec_verify_official_channel)
        RiskClassification.UNKNOWN -> listOf(R.string.rec_unknown_enable_cloud, R.string.rec_verify_official_channel, R.string.rec_still_careful)
        RiskClassification.ANALYSIS_FAILED -> listOf(R.string.rec_failed_check_input)
    }

    @StringRes fun indicatorTitle(i: Indicator): Int = when (i) {
        Indicator.DANGEROUS_SCHEME -> R.string.ind_dangerous_scheme
        Indicator.USERINFO_IN_URL -> R.string.ind_userinfo
        Indicator.IP_ADDRESS_HOST -> R.string.ind_ip_host
        Indicator.OBFUSCATED_IP_HOST -> R.string.ind_obfuscated_ip
        Indicator.PRIVATE_NETWORK_HOST -> R.string.ind_private_host
        Indicator.PUNYCODE_DOMAIN -> R.string.ind_punycode
        Indicator.MIXED_SCRIPT_DOMAIN -> R.string.ind_mixed_script
        Indicator.WHOLE_SCRIPT_CONFUSABLE -> R.string.ind_whole_script
        Indicator.HOMOGRAPH_OF_BRAND -> R.string.ind_homograph_brand
        Indicator.LOOKALIKE_BRAND -> R.string.ind_lookalike
        Indicator.BRAND_IN_SUBDOMAIN -> R.string.ind_brand_subdomain
        Indicator.BRAND_IN_DOMAIN_LABEL -> R.string.ind_brand_label
        Indicator.URL_SHORTENER -> R.string.ind_shortener
        Indicator.INSECURE_HTTP -> R.string.ind_http
        Indicator.NON_STANDARD_PORT -> R.string.ind_port
        Indicator.EXCESSIVE_SUBDOMAINS -> R.string.ind_subdomains
        Indicator.LONG_URL -> R.string.ind_long_url
        Indicator.SUSPICIOUS_TLD -> R.string.ind_tld
        Indicator.SUSPICIOUS_KEYWORDS -> R.string.ind_keywords
        Indicator.EXCESSIVE_ENCODING -> R.string.ind_encoding
        Indicator.EMBEDDED_URL_PARAMETER -> R.string.ind_embedded_url
        Indicator.SENSITIVE_DATA_IN_URL -> R.string.ind_sensitive_param
        Indicator.EXECUTABLE_DOWNLOAD -> R.string.ind_executable
        Indicator.MANY_HYPHENS -> R.string.ind_hyphens
        Indicator.REDIRECTS_TO_OTHER_DOMAIN -> R.string.ind_redirect_other
        Indicator.REDIRECT_CHAIN_TOO_LONG -> R.string.ind_redirect_long
        Indicator.URGENCY_LANGUAGE -> R.string.ind_urgency
        Indicator.CREDENTIAL_REQUEST -> R.string.ind_credentials
        Indicator.PRIZE_OR_MONEY_LURE -> R.string.ind_prize
        Indicator.PAYMENT_OR_FEE_REQUEST -> R.string.ind_payment
        Indicator.BLOCKLIST_MATCH -> R.string.ind_blocklist
        Indicator.THREAT_INTEL_MATCH -> R.string.ind_threat_intel
    }

    @StringRes fun indicatorDescription(i: Indicator): Int = when (i) {
        Indicator.DANGEROUS_SCHEME -> R.string.ind_dangerous_scheme_desc
        Indicator.USERINFO_IN_URL -> R.string.ind_userinfo_desc
        Indicator.IP_ADDRESS_HOST -> R.string.ind_ip_host_desc
        Indicator.OBFUSCATED_IP_HOST -> R.string.ind_obfuscated_ip_desc
        Indicator.PRIVATE_NETWORK_HOST -> R.string.ind_private_host_desc
        Indicator.PUNYCODE_DOMAIN -> R.string.ind_punycode_desc
        Indicator.MIXED_SCRIPT_DOMAIN -> R.string.ind_mixed_script_desc
        Indicator.WHOLE_SCRIPT_CONFUSABLE -> R.string.ind_whole_script_desc
        Indicator.HOMOGRAPH_OF_BRAND -> R.string.ind_homograph_brand_desc
        Indicator.LOOKALIKE_BRAND -> R.string.ind_lookalike_desc
        Indicator.BRAND_IN_SUBDOMAIN -> R.string.ind_brand_subdomain_desc
        Indicator.BRAND_IN_DOMAIN_LABEL -> R.string.ind_brand_label_desc
        Indicator.URL_SHORTENER -> R.string.ind_shortener_desc
        Indicator.INSECURE_HTTP -> R.string.ind_http_desc
        Indicator.NON_STANDARD_PORT -> R.string.ind_port_desc
        Indicator.EXCESSIVE_SUBDOMAINS -> R.string.ind_subdomains_desc
        Indicator.LONG_URL -> R.string.ind_long_url_desc
        Indicator.SUSPICIOUS_TLD -> R.string.ind_tld_desc
        Indicator.SUSPICIOUS_KEYWORDS -> R.string.ind_keywords_desc
        Indicator.EXCESSIVE_ENCODING -> R.string.ind_encoding_desc
        Indicator.EMBEDDED_URL_PARAMETER -> R.string.ind_embedded_url_desc
        Indicator.SENSITIVE_DATA_IN_URL -> R.string.ind_sensitive_param_desc
        Indicator.EXECUTABLE_DOWNLOAD -> R.string.ind_executable_desc
        Indicator.MANY_HYPHENS -> R.string.ind_hyphens_desc
        Indicator.REDIRECTS_TO_OTHER_DOMAIN -> R.string.ind_redirect_other_desc
        Indicator.REDIRECT_CHAIN_TOO_LONG -> R.string.ind_redirect_long_desc
        Indicator.URGENCY_LANGUAGE -> R.string.ind_urgency_desc
        Indicator.CREDENTIAL_REQUEST -> R.string.ind_credentials_desc
        Indicator.PRIZE_OR_MONEY_LURE -> R.string.ind_prize_desc
        Indicator.PAYMENT_OR_FEE_REQUEST -> R.string.ind_payment_desc
        Indicator.BLOCKLIST_MATCH -> R.string.ind_blocklist_desc
        Indicator.THREAT_INTEL_MATCH -> R.string.ind_threat_intel_desc
    }

    @StringRes fun sourceName(s: AnalysisSource): Int = when (s) {
        AnalysisSource.LOCAL_HEURISTICS -> R.string.src_local
        AnalysisSource.LOCAL_BLOCKLIST -> R.string.src_blocklist
        AnalysisSource.TRUSTCHECK_BACKEND -> R.string.src_backend
        AnalysisSource.GOOGLE_SAFE_BROWSING -> R.string.src_safe_browsing
        AnalysisSource.REDIRECT_RESOLVER -> R.string.src_redirects
        AnalysisSource.CLOUD_AI -> R.string.src_ai
        AnalysisSource.ON_DEVICE_OCR -> R.string.src_ocr
    }

    @StringRes fun sourceStatus(s: SourceStatus): Int = when (s) {
        SourceStatus.MATCH -> R.string.status_match
        SourceStatus.NO_MATCH -> R.string.status_no_match
        SourceStatus.UNAVAILABLE -> R.string.status_unavailable
        SourceStatus.ERROR -> R.string.status_error
        SourceStatus.SKIPPED -> R.string.status_skipped
    }

    @StringRes fun origin(o: ScanOrigin): Int = when (o) {
        ScanOrigin.MANUAL -> R.string.origin_manual
        ScanOrigin.SHARE_TEXT -> R.string.origin_share
        ScanOrigin.SHARE_IMAGE -> R.string.origin_image
        ScanOrigin.LINK_OPEN -> R.string.origin_link
        ScanOrigin.TEXT_SELECTION -> R.string.origin_selection
        ScanOrigin.NOTIFICATION -> R.string.origin_notification
    }
}
