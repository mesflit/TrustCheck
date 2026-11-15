package com.mesflit.trustcheck.core.security

import java.net.URLEncoder

/**
 * Builds a prefilled GitHub issue link for "this result is wrong" reports.
 *
 * Privacy: only the query-free link (defanged so it is not clickable), or a file's SHA-256 and type,
 * plus the verdict, indicator codes, sources and app version are included. Message text, file names,
 * indicator details and anything else from the user's content are never added. Nothing is sent
 * automatically: the user sees the issue form in the browser and decides whether to submit it.
 */
object DetectionReport {
    enum class Kind(val label: String) { FALSE_ALARM("False alarm"), MISSED_THREAT("Missed threat") }

    const val NEW_ISSUE_URL = "https://github.com/mesflit/TrustCheck/issues/new"
    const val TEMPLATE = "detection_report.yml"

    data class Input(
        val kind: Kind,
        val targetType: String,
        /** Query-free URL (lookup key) for links and messages; null if none. */
        val url: String?,
        val fileSha256: String? = null,
        val fileType: String? = null,
        val classification: RiskClassification,
        val score: Int,
        val indicators: List<Indicator>,
        val sources: List<SourceResult>,
        val appVersion: String,
    )

    /** "https://evil.example/login" → "hxxps://evil[.]example/login" so the link is not clickable on GitHub. */
    fun defang(url: String): String =
        url.replaceFirst(Regex("^http", RegexOption.IGNORE_CASE), "hxxp").replace(".", "[.]")

    fun target(i: Input): String = when {
        i.fileSha256 != null -> "SHA-256 ${i.fileSha256}" + (i.fileType?.let { " ($it)" } ?: "")
        i.url != null -> defang(stripQuery(i.url))
        else -> "(no link)"
    }

    fun issueUrl(i: Input): String {
        val fields = linkedMapOf(
            "template" to TEMPLATE,
            "title" to "[${i.kind.label}] ${target(i).take(120)}",
            "kind" to i.kind.label,
            "target" to target(i),
            "verdict" to "${i.classification.name} (score ${i.score})",
            "indicators" to i.indicators.joinToString(", ") { it.name }.ifEmpty { "none" },
            "sources" to i.sources.joinToString(", ") { "${it.source.name}=${it.status.name}" }.ifEmpty { "none" },
            "version" to i.appVersion,
        )
        return NEW_ISSUE_URL + "?" + fields.entries.joinToString("&") { (k, v) -> "$k=${enc(v)}" }
    }

    private fun stripQuery(url: String) = url.substringBefore('#').substringBefore('?')
    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
}
