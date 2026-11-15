// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

/** File type detected from content ("magic bytes"), independent of the file name. */
enum class FileKind(val label: String) {
    APK("APK"), ZIP("ZIP"), OOXML("Office"), PDF("PDF"), WINDOWS_EXE("EXE"), ELF("ELF"), DEX("DEX"),
    IMAGE("Image"), TEXT("Text"), HTML("HTML"), SCRIPT("Script"), UNKNOWN("?"),
}

/** Facts read from an Android package without installing it. */
data class ApkFacts(
    val packageName: String?,
    val appLabel: String?,
    val versionName: String?,
    val permissions: List<String>,
    /** True if the APK declares an AccessibilityService. */
    val hasAccessibilityService: Boolean,
    /** True if the APK declares a NotificationListenerService. */
    val hasNotificationListener: Boolean,
    /** True if the APK declares a device-admin receiver. */
    val hasDeviceAdmin: Boolean,
    /** True if signed with the public Android debug certificate. */
    val debugSigned: Boolean,
)

/** Everything TrustCheck records about a scanned file. The content itself is never stored. */
data class FileFacts(
    val displayName: String,
    val sizeBytes: Long,
    val declaredMime: String?,
    val kind: FileKind,
    val sha256: String,
    val apk: ApkFacts? = null,
)

/**
 * Offline file heuristics: disguised types, double extensions, executables, scripts, macro
 * documents and risky Android app permissions. TrustCheck does not claim to be an antivirus:
 * it reports warning signs and shows the SHA-256 so the user can look the file up elsewhere.
 */
object FileInspector {

    private val executableExt = setOf("apk", "xapk", "apks", "apkm", "exe", "msi", "scr", "com", "pif", "dll", "jar", "dex", "elf", "bin", "dmg", "pkg", "app", "deb", "rpm")
    private val scriptExt = setOf("js", "jse", "vbs", "vbe", "wsf", "wsh", "bat", "cmd", "ps1", "psm1", "hta", "lnk", "sh", "py", "reg", "scf", "url")
    private val macroExt = setOf("docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm")
    private val decoyExt = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip", "rar", "csv", "rtf", "odt", "heic", "webp")
    val TEXT_EXT = setOf("txt", "html", "htm", "csv", "json", "xml", "eml", "md", "log", "rtf", "vcf", "ics", "svg")

    private val smsPermissions = setOf(
        "android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_MMS", "android.permission.RECEIVE_WAP_PUSH",
    )

    fun extensionOf(name: String): String = name.substringAfterLast('/').substringAfterLast('.', "").lowercase()

    /** Detects the real type from the first bytes (and, for ZIPs, from entry names supplied by the caller). */
    fun detectKind(header: ByteArray, name: String, zipEntryNames: Collection<String> = emptyList()): FileKind {
        fun starts(vararg b: Int) = header.size >= b.size && b.indices.all { header[it].toInt() and 0xFF == b[it] }
        val ext = extensionOf(name)
        return when {
            starts(0x50, 0x4B, 0x03, 0x04) || starts(0x50, 0x4B, 0x05, 0x06) -> when {
                zipEntryNames.any { it == "AndroidManifest.xml" } || zipEntryNames.any { it == "classes.dex" } -> FileKind.APK
                zipEntryNames.any { it == "[Content_Types].xml" } -> FileKind.OOXML
                zipEntryNames.isEmpty() && ext in setOf("apk", "xapk", "apks", "apkm") -> FileKind.APK
                zipEntryNames.isEmpty() && ext in setOf("docx", "xlsx", "pptx", "docm", "xlsm", "pptm") -> FileKind.OOXML
                else -> FileKind.ZIP
            }
            starts(0x25, 0x50, 0x44, 0x46) -> FileKind.PDF                       // %PDF
            starts(0x4D, 0x5A) -> FileKind.WINDOWS_EXE                            // MZ
            starts(0x7F, 0x45, 0x4C, 0x46) -> FileKind.ELF
            starts(0x64, 0x65, 0x78, 0x0A) -> FileKind.DEX                        // dex\n
            starts(0xFF, 0xD8, 0xFF) || starts(0x89, 0x50, 0x4E, 0x47) || starts(0x47, 0x49, 0x46, 0x38) ||
                (starts(0x52, 0x49, 0x46, 0x46) && header.size >= 12 && String(header, 8, 4, Charsets.US_ASCII) == "WEBP") -> FileKind.IMAGE
            ext in scriptExt -> FileKind.SCRIPT
            looksLikeText(header) -> if (ext in setOf("html", "htm") || headerText(header).contains("<html", ignoreCase = true)) FileKind.HTML else FileKind.TEXT
            else -> FileKind.UNKNOWN
        }
    }

    private fun headerText(h: ByteArray) = String(h, Charsets.UTF_8)

    private fun looksLikeText(h: ByteArray): Boolean {
        if (h.isEmpty()) return false
        val control = h.count { val b = it.toInt() and 0xFF; b < 0x09 || (b in 0x0E..0x1F) }
        return control == 0
    }

    fun analyze(facts: FileFacts): List<DetectedIndicator> {
        val out = mutableListOf<DetectedIndicator>()
        val name = facts.displayName.trim()
        val ext = extensionOf(name)
        val stem = name.substringBeforeLast('.', name)
        val innerExt = extensionOf(stem)
        val executableKind = facts.kind in setOf(FileKind.APK, FileKind.WINDOWS_EXE, FileKind.ELF, FileKind.DEX)

        // "invoice.pdf.apk", "photo.jpg   .exe"
        if ((ext in executableExt || ext in scriptExt) && innerExt in decoyExt) {
            out += DetectedIndicator(Indicator.DOUBLE_EXTENSION, name.takeLast(40))
        }
        // An app or program pretending to be a document/photo (wrong or missing extension).
        if (executableKind && ext !in executableExt) {
            out += DetectedIndicator(Indicator.EXTENSION_MISMATCH, "${facts.kind.label} ≠ .${ext.ifEmpty { "?" }}")
        }
        if (executableKind || ext in executableExt) out += DetectedIndicator(Indicator.EXECUTABLE_FILE, facts.kind.label)
        if (facts.kind == FileKind.SCRIPT || ext in scriptExt) out += DetectedIndicator(Indicator.SCRIPT_FILE, ext)
        if (ext in macroExt) out += DetectedIndicator(Indicator.MACRO_DOCUMENT, ext)

        facts.apk?.let { out += analyzeApk(it) }
        return out.distinctBy { it.indicator }
    }

    fun analyzeApk(apk: ApkFacts): List<DetectedIndicator> {
        val out = mutableListOf<DetectedIndicator>()
        val perms = apk.permissions.toSet()
        val sms = perms.intersect(smsPermissions)
        if (sms.isNotEmpty()) out += DetectedIndicator(Indicator.APK_SMS_ACCESS, sms.joinToString(",") { it.substringAfterLast('.') })
        if (apk.hasAccessibilityService) out += DetectedIndicator(Indicator.APK_ACCESSIBILITY_SERVICE)
        if (apk.hasDeviceAdmin || "android.permission.BIND_DEVICE_ADMIN" in perms) out += DetectedIndicator(Indicator.APK_DEVICE_ADMIN)
        val overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms
        if (overlay) out += DetectedIndicator(Indicator.APK_SCREEN_OVERLAY)
        if ("android.permission.REQUEST_INSTALL_PACKAGES" in perms) out += DetectedIndicator(Indicator.APK_INSTALLS_APPS)
        if (apk.hasNotificationListener) out += DetectedIndicator(Indicator.APK_NOTIFICATION_ACCESS)
        // Classic banking-trojan combination: read SMS codes + control/cover the screen.
        if (sms.isNotEmpty() && (apk.hasAccessibilityService || overlay)) out += DetectedIndicator(Indicator.APK_BANKING_TROJAN_PATTERN)
        if (apk.debugSigned) out += DetectedIndicator(Indicator.APK_DEBUG_SIGNED)
        brandImpersonation(apk)?.let { out += DetectedIndicator(Indicator.APK_BRAND_IMPERSONATION, it) }
        return out
    }

    /**
     * An app named after a well-known brand whose package name has nothing to do with that brand,
     * e.g. label "Garanti BBVA Mobil" with package "com.update.service". Returns the brand keyword.
     */
    fun brandImpersonation(apk: ApkFacts): String? {
        val label = apk.appLabel?.lowercase()?.replace(Regex("[^\\p{L}\\p{N}]"), "") ?: return null
        val pkg = apk.packageName?.lowercase() ?: return null
        val pkgFlat = pkg.replace(".", "").replace("_", "")
        val matched = BrandCatalog.brands.filter { b -> b.keyword.length >= 4 && label.contains(b.keyword) }
        if (matched.isEmpty()) return null
        // Legitimate if the package belongs to ANY brand named in the label (e.g. "Garanti BBVA" → com.garanti.*).
        val owners = matched.flatMap { b -> b.officialDomains.map { it.substringBefore('.').replace("-", "") } + b.keyword }
        if (owners.any { pkgFlat.contains(it) }) return null
        return matched.maxBy { it.keyword.length }.keyword
    }

    /** Builds a local-only result for a file (no reputation source exists for files). */
    fun result(facts: FileFacts, indicators: List<DetectedIndicator>, now: Long): UrlAnalysisResult {
        val score = RiskScorer.score(indicators)
        val sources = listOf(SourceResult(AnalysisSource.FILE_INSPECTION, if (indicators.isEmpty()) SourceStatus.NO_MATCH else SourceStatus.MATCH))
        return UrlAnalysisResult(
            input = facts.displayName,
            normalizedUrl = null,
            displayHost = facts.displayName,
            registrableDomain = null,
            finalUrl = null,
            indicators = indicators.sortedByDescending { it.indicator.weight },
            riskScore = score,
            classification = RiskScorer.classify(score, sources),
            sources = sources,
            timestampMillis = now,
        )
    }

    /** Namespace/schema hosts found inside Office and SVG files that are not real links. */
    val NON_LINK_HOSTS = setOf(
        "schemas.openxmlformats.org", "schemas.microsoft.com", "purl.org", "www.w3.org", "w3.org",
        "ns.adobe.com", "schema.org", "openoffice.org", "www.openoffice.org", "dublincore.org", "xmlns.com",
    )
}
