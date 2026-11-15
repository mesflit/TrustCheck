// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull

/** A reputation source (threat intelligence). Implementations must never fabricate verdicts. */
interface ThreatIntelProvider {
    val source: AnalysisSource

    /** False when not configured (no backend URL / no key) or not consented. */
    suspend fun isAvailable(): Boolean

    /**
     * Looks up privacy-reduced URL keys. Returns one [SourceResult] for the whole batch:
     * MATCH with threat types if any URL is listed, NO_MATCH if the service answered with no
     * listing, ERROR/UNAVAILABLE otherwise. Must throw nothing except CancellationException.
     */
    suspend fun lookup(urlKeys: List<String>): SourceResult
}

/** Locally cached blocklist synced from a trusted feed (never bundled with invented entries). */
interface LocalBlocklist {
    suspend fun isEmpty(): Boolean
    /** Returns the matched entry's category/source, or null. */
    suspend fun match(hostAndParents: List<String>): String?
}

/** Resolves redirect chains for URL shorteners without downloading or rendering content. */
interface RedirectResolver {
    /** Returns the chain of Location URLs (excluding the start), or null if not resolvable. */
    suspend fun resolve(url: String, maxHops: Int): List<String>?
}

data class AnalysisOptions(
    val allowNetwork: Boolean,
    val resolveRedirects: Boolean,
    val lookupTimeoutMillis: Long = 15_000,
)

class UrlAnalysisEngine(
    private val threatIntel: List<ThreatIntelProvider> = emptyList(),
    private val blocklist: LocalBlocklist? = null,
    private val redirectResolver: RedirectResolver? = null,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    suspend fun analyze(input: String, options: AnalysisOptions): UrlAnalysisResult {
        val now = clock()
        return try {
            analyzeInternal(input, options, now)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            UrlAnalysisResult.failed(input, now, "internal_error")
        }
    }

    /** Local-only analysis: fast and offline. Used for instant notification screening. */
    fun analyzeLocally(input: String): UrlAnalysisResult {
        val now = clock()
        return when (val outcome = UrlNormalizer.parse(input)) {
            is ParseOutcome.Failure -> UrlAnalysisResult.failed(input, now, outcome.reason)
            is ParseOutcome.DangerousScheme -> dangerous(input, outcome.scheme, now)
            is ParseOutcome.Success -> {
                val indicators = HeuristicAnalyzer.analyze(outcome.url)
                build(input, outcome.url, null, indicators, listOf(SourceResult(AnalysisSource.LOCAL_HEURISTICS, SourceStatus.NO_MATCH)), now)
            }
        }
    }

    private suspend fun analyzeInternal(input: String, options: AnalysisOptions, now: Long): UrlAnalysisResult {
        val url = when (val outcome = UrlNormalizer.parse(input)) {
            is ParseOutcome.Failure -> return UrlAnalysisResult.failed(input, now, outcome.reason)
            is ParseOutcome.DangerousScheme -> return dangerous(input, outcome.scheme, now)
            is ParseOutcome.Success -> outcome.url
        }
        val indicators = HeuristicAnalyzer.analyze(url).toMutableList()
        val sources = mutableListOf(SourceResult(AnalysisSource.LOCAL_HEURISTICS, if (indicators.isEmpty()) SourceStatus.NO_MATCH else SourceStatus.MATCH))

        // Optional redirect resolution for shorteners (HEAD only, never renders content).
        var finalUrl: ParsedUrl? = null
        if (options.allowNetwork && options.resolveRedirects && redirectResolver != null && HeuristicAnalyzer.isShortener(url)) {
            val chain = withTimeoutOrNull(options.lookupTimeoutMillis) { redirectResolver.resolve(url.analysisUrl, MAX_HOPS) }
            if (chain == null) {
                sources += SourceResult(AnalysisSource.REDIRECT_RESOLVER, SourceStatus.ERROR, "unresolved")
            } else {
                sources += SourceResult(AnalysisSource.REDIRECT_RESOLVER, SourceStatus.NO_MATCH, chain.size.toString())
                if (chain.size >= MAX_HOPS) indicators += DetectedIndicator(Indicator.REDIRECT_CHAIN_TOO_LONG, chain.size.toString())
                val last = chain.lastOrNull()?.let { (UrlNormalizer.parse(it) as? ParseOutcome.Success)?.url }
                if (last != null) {
                    finalUrl = last
                    val startReg = DomainUtils.registrableDomain(url.asciiHost)
                    val endReg = DomainUtils.registrableDomain(last.asciiHost)
                    if (startReg != endReg) indicators += DetectedIndicator(Indicator.REDIRECTS_TO_OTHER_DOMAIN, last.unicodeHost)
                    HeuristicAnalyzer.analyze(last)
                        .filter { it.indicator != Indicator.URL_SHORTENER }
                        .forEach { d -> if (indicators.none { it.indicator == d.indicator }) indicators += d }
                }
            }
        }

        val keys = listOfNotNull(url.lookupKey, finalUrl?.lookupKey).distinct()
        val hosts = (DomainUtils.hostAndParents(url.asciiHost) + (finalUrl?.let { DomainUtils.hostAndParents(it.asciiHost) } ?: emptyList())).distinct()

        // Synced local blocklist (offline).
        if (blocklist != null && !blocklist.isEmpty()) {
            val hit = blocklist.match(hosts)
            if (hit != null) {
                indicators += DetectedIndicator(Indicator.BLOCKLIST_MATCH, hit)
                sources += SourceResult(AnalysisSource.LOCAL_BLOCKLIST, SourceStatus.MATCH, hit)
            } else {
                sources += SourceResult(AnalysisSource.LOCAL_BLOCKLIST, SourceStatus.NO_MATCH)
            }
        }

        // Cloud threat intelligence.
        for (provider in threatIntel) {
            if (!options.allowNetwork) {
                sources += SourceResult(provider.source, SourceStatus.SKIPPED, "offline")
                continue
            }
            if (!provider.isAvailable()) {
                sources += SourceResult(provider.source, SourceStatus.UNAVAILABLE, "not_configured")
                continue
            }
            val r = withTimeoutOrNull(options.lookupTimeoutMillis) { provider.lookup(keys) }
                ?: SourceResult(provider.source, SourceStatus.ERROR, "timeout")
            sources += r
            if (r.status == SourceStatus.MATCH) indicators += DetectedIndicator(Indicator.THREAT_INTEL_MATCH, r.detail)
        }

        return build(input, url, finalUrl, indicators, sources, now)
    }

    private fun build(
        input: String,
        url: ParsedUrl,
        finalUrl: ParsedUrl?,
        indicators: List<DetectedIndicator>,
        sources: List<SourceResult>,
        now: Long,
    ): UrlAnalysisResult {
        val local = indicators.filter { it.indicator != Indicator.THREAT_INTEL_MATCH && it.indicator != Indicator.BLOCKLIST_MATCH }
        val score = RiskScorer.score(local)
        val classification = RiskScorer.classify(score, sources)
        return UrlAnalysisResult(
            input = input,
            normalizedUrl = url.lookupKey,
            displayHost = url.unicodeHost,
            registrableDomain = DomainUtils.registrableDomain(url.asciiHost),
            finalUrl = finalUrl?.lookupKey,
            indicators = indicators.sortedByDescending { it.indicator.weight },
            riskScore = RiskScorer.finalScore(score, classification),
            classification = classification,
            sources = sources,
            timestampMillis = now,
        )
    }

    private fun dangerous(input: String, scheme: String, now: Long): UrlAnalysisResult {
        val indicators = listOf(DetectedIndicator(Indicator.DANGEROUS_SCHEME, scheme))
        val score = RiskScorer.score(indicators)
        val sources = listOf(SourceResult(AnalysisSource.LOCAL_HEURISTICS, SourceStatus.MATCH))
        return UrlAnalysisResult(
            input = input, normalizedUrl = "$scheme:", displayHost = null, registrableDomain = null, finalUrl = null,
            indicators = indicators, riskScore = score, classification = RiskScorer.classify(score, sources),
            sources = sources, timestampMillis = now,
        )
    }

    companion object {
        const val MAX_HOPS = 5
    }
}
