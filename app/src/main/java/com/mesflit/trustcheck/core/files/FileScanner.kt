// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.files

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import com.mesflit.trustcheck.core.ocr.OcrTextExtractor
import com.mesflit.trustcheck.core.security.ApkFacts
import com.mesflit.trustcheck.core.security.FileFacts
import com.mesflit.trustcheck.core.security.FileInspector
import com.mesflit.trustcheck.core.security.FileKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipInputStream

/**
 * Reads a user-selected or shared file **on the device only**: real type, SHA-256, APK facts,
 * and (for documents, PDFs and images) text to look for links. Nothing is uploaded, the file is
 * never opened or executed, and extracted text lives only in memory.
 */
class FileScanner(private val context: Context, private val ocr: OcrTextExtractor) {

    sealed interface Outcome {
        /** [text] is in-memory only; callers must not persist it. */
        data class Success(val facts: FileFacts, val text: String?) : Outcome
        data class Failed(val reason: String) : Outcome
    }

    suspend fun inspect(uri: Uri): Outcome = withContext(Dispatchers.IO) {
        try {
            inspectInternal(uri)
        } catch (e: SecurityException) {
            Outcome.Failed("no_permission")
        } catch (e: IOException) {
            Outcome.Failed("io")
        } catch (e: OutOfMemoryError) {
            Outcome.Failed("too_large")
        }
    }

    private suspend fun inspectInternal(uri: Uri): Outcome {
        val resolver = context.contentResolver
        var name = uri.lastPathSegment?.substringAfterLast('/') ?: "file"
        var size = -1L
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                c.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 }?.let { i -> c.getString(i)?.let { name = it } }
                c.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 && !c.isNull(it) }?.let { i -> size = c.getLong(i) }
            }
        }
        val mime = resolver.getType(uri)

        // Pass 1: header + SHA-256 (streamed, any size).
        val digest = MessageDigest.getInstance("SHA-256")
        val header = ByteArray(HEADER_BYTES)
        var headerLen = 0
        var total = 0L
        open(uri).use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (headerLen < HEADER_BYTES) {
                    val take = minOf(n, HEADER_BYTES - headerLen)
                    System.arraycopy(buf, 0, header, headerLen, take)
                    headerLen += take
                }
                digest.update(buf, 0, n)
                total += n
            }
        }
        if (size < 0) size = total
        val head = header.copyOf(headerLen)
        val sha256 = digest.digest().joinToString("") { "%02x".format(it) }

        // Pass 2 (ZIP only): entry names, plus XML text of Office files for link extraction.
        val isZip = headerLen >= 4 && head[0] == 0x50.toByte() && head[1] == 0x4B.toByte()
        val entryNames = mutableListOf<String>()
        val officeText = StringBuilder()
        if (isZip) {
            ZipInputStream(open(uri)).use { zip ->
                while (entryNames.size < MAX_ZIP_ENTRIES) {
                    val e = zip.nextEntry ?: break
                    entryNames += e.name
                    val lower = e.name.lowercase()
                    if ((lower.endsWith(".xml") || lower.endsWith(".rels")) && officeText.length < MAX_TEXT_CHARS && !lower.startsWith("androidmanifest")) {
                        officeText.append(readLimited(zip, MAX_TEXT_CHARS - officeText.length)).append('\n')
                    }
                }
            }
        }

        val kind = FileInspector.detectKind(head, name, entryNames)
        val apk = if (kind == FileKind.APK && size in 1..MAX_APK_BYTES) readApk(uri) else null
        val facts = FileFacts(name, size, mime, kind, sha256, apk)

        val text: String? = when (kind) {
            FileKind.TEXT, FileKind.HTML -> if (size <= MAX_TEXT_BYTES) open(uri).use { readLimited(it, MAX_TEXT_CHARS) } else null
            FileKind.OOXML -> officeText.toString().replace(Regex("<[^>]+>"), " ")
            FileKind.PDF -> pdfText(uri)
            FileKind.IMAGE -> (ocr.extract(uri) as? OcrTextExtractor.Outcome.Text)?.value
            else -> null
        }
        return Outcome.Success(facts, text?.takeIf { it.isNotBlank() })
    }

    private fun open(uri: Uri): InputStream =
        context.contentResolver.openInputStream(uri) ?: throw IOException("cannot open")

    private fun readLimited(input: InputStream, maxChars: Int): String {
        val bytes = ByteArray(maxChars.coerceAtLeast(0))
        var read = 0
        while (read < bytes.size) {
            val n = input.read(bytes, read, bytes.size - read)
            if (n < 0) break
            read += n
        }
        return String(bytes, 0, read, Charsets.UTF_8)
    }

    /** Renders the first pages and runs on-device OCR (works for scanned and text PDFs). */
    private suspend fun pdfText(uri: Uri): String? {
        val pfd = context.contentResolver.openFileDescriptor(uri, "r") ?: return null
        val sb = StringBuilder()
        pfd.use {
            val renderer = try { PdfRenderer(it) } catch (e: Exception) { return null } // encrypted/corrupt
            renderer.use { r ->
                for (i in 0 until minOf(r.pageCount, MAX_PDF_PAGES)) {
                    r.openPage(i).use { page ->
                        val scale = PDF_RENDER_WIDTH.toFloat() / page.width.coerceAtLeast(1)
                        val bmp = Bitmap.createBitmap(PDF_RENDER_WIDTH, (page.height * scale).toInt().coerceIn(1, 4000), Bitmap.Config.ARGB_8888)
                        bmp.eraseColor(Color.WHITE)
                        page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        (ocr.extract(bmp) as? OcrTextExtractor.Outcome.Text)?.let { t -> sb.append(t.value).append('\n') }
                        bmp.recycle()
                    }
                }
            }
        }
        return sb.toString()
    }

    /** Reads manifest facts from an APK copy in the app's private cache. The APK is never installed. */
    private fun readApk(uri: Uri): ApkFacts? {
        val tmp = File(context.cacheDir, "scan-${System.nanoTime()}.apk")
        return try {
            open(uri).use { input -> tmp.outputStream().use { input.copyTo(it) } }
            val pm = context.packageManager
            @Suppress("DEPRECATION")
            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
                (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)
            val info: PackageInfo = (
                if (Build.VERSION.SDK_INT >= 33) pm.getPackageArchiveInfo(tmp.path, PackageManager.PackageInfoFlags.of(flags.toLong()))
                else @Suppress("DEPRECATION") pm.getPackageArchiveInfo(tmp.path, flags)
                ) ?: return null
            val label = info.applicationInfo?.let { ai ->
                ai.sourceDir = tmp.path
                ai.publicSourceDir = tmp.path
                runCatching { pm.getApplicationLabel(ai).toString() }.getOrNull()
            }
            val services = info.services.orEmpty()
            val receivers = info.receivers.orEmpty()
            ApkFacts(
                packageName = info.packageName,
                appLabel = label,
                versionName = info.versionName,
                permissions = info.requestedPermissions?.toList().orEmpty(),
                hasAccessibilityService = services.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" },
                hasNotificationListener = services.any { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" },
                hasDeviceAdmin = receivers.any { it.permission == "android.permission.BIND_DEVICE_ADMIN" },
                debugSigned = isDebugSigned(info),
            )
        } catch (e: Exception) {
            null
        } finally {
            tmp.delete()
        }
    }

    private fun isDebugSigned(info: PackageInfo): Boolean {
        @Suppress("DEPRECATION")
        val sigs = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        val cf = CertificateFactory.getInstance("X.509")
        return sigs.orEmpty().any { s ->
            runCatching { (cf.generateCertificate(s.toByteArray().inputStream()) as X509Certificate).subjectX500Principal.name.contains("CN=Android Debug") }
                .getOrDefault(false)
        }
    }

    companion object {
        private const val HEADER_BYTES = 64
        private const val MAX_ZIP_ENTRIES = 5_000
        private const val MAX_TEXT_CHARS = 2_000_000
        private const val MAX_TEXT_BYTES = 5L * 1024 * 1024
        private const val MAX_APK_BYTES = 300L * 1024 * 1024
        private const val MAX_PDF_PAGES = 3
        private const val PDF_RENDER_WIDTH = 1240
    }
}
