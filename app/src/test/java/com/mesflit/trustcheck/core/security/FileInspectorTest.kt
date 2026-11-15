package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FileInspectorTest {
    private val zip = byteArrayOf(0x50, 0x4B, 0x03, 0x04, 0, 0)
    private val pdf = "%PDF-1.7".toByteArray()
    private val exe = byteArrayOf(0x4D, 0x5A, 0, 0)

    private fun facts(name: String, kind: FileKind, apk: ApkFacts? = null) = FileFacts(name, 1000, null, kind, "00", apk)
    private fun codes(f: FileFacts) = FileInspector.analyze(f).map { it.indicator }.toSet()
    private fun apk(perms: List<String> = emptyList(), label: String? = "App", pkg: String? = "com.example.app", a11y: Boolean = false) =
        ApkFacts(pkg, label, "1.0", perms, a11y, hasNotificationListener = false, hasDeviceAdmin = false, debugSigned = false)

    @Test fun detectsKindsFromContentNotName() {
        assertEquals(FileKind.APK, FileInspector.detectKind(zip, "photo.jpg", listOf("AndroidManifest.xml", "classes.dex")))
        assertEquals(FileKind.OOXML, FileInspector.detectKind(zip, "a.docx", listOf("[Content_Types].xml", "word/document.xml")))
        assertEquals(FileKind.ZIP, FileInspector.detectKind(zip, "a.zip", listOf("readme.txt")))
        assertEquals(FileKind.PDF, FileInspector.detectKind(pdf, "invoice.pdf"))
        assertEquals(FileKind.WINDOWS_EXE, FileInspector.detectKind(exe, "invoice.pdf"))
        assertEquals(FileKind.TEXT, FileInspector.detectKind("hello https://x.com".toByteArray(), "notes.txt"))
        assertEquals(FileKind.HTML, FileInspector.detectKind("<html><body>".toByteArray(), "page.htm"))
        assertEquals(FileKind.SCRIPT, FileInspector.detectKind("var a=1".toByteArray(), "run.js"))
    }

    @Test fun doubleExtensionAndDisguisedExecutable() {
        assertTrue(Indicator.DOUBLE_EXTENSION in codes(facts("fatura.pdf.apk", FileKind.APK)))
        val disguised = codes(facts("kargo_takip.pdf", FileKind.APK))
        assertTrue(Indicator.EXTENSION_MISMATCH in disguised)
        assertTrue(Indicator.EXECUTABLE_FILE in disguised)
        assertTrue(Indicator.EXTENSION_MISMATCH in codes(facts("photo.jpg", FileKind.WINDOWS_EXE)))
    }

    @Test fun ordinaryFilesAreClean() {
        assertTrue(codes(facts("report.pdf", FileKind.PDF)).isEmpty())
        assertTrue(codes(facts("holiday.jpg", FileKind.IMAGE)).isEmpty())
        assertEquals(setOf(Indicator.EXECUTABLE_FILE), codes(facts("TrustCheck-v0.1.0.apk", FileKind.APK, apk())))
    }

    @Test fun scriptsAndMacros() {
        assertTrue(Indicator.SCRIPT_FILE in codes(facts("odeme.js", FileKind.SCRIPT)))
        assertTrue(Indicator.MACRO_DOCUMENT in codes(facts("fatura.xlsm", FileKind.OOXML)))
    }

    @Test fun bankingTrojanPatternIsSuspicious() {
        val f = facts("guncelleme.apk", FileKind.APK, apk(listOf("android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"), a11y = true))
        val ind = FileInspector.analyze(f)
        val c = ind.map { it.indicator }.toSet()
        assertTrue(Indicator.APK_SMS_ACCESS in c)
        assertTrue(Indicator.APK_ACCESSIBILITY_SERVICE in c)
        assertTrue(Indicator.APK_BANKING_TROJAN_PATTERN in c)
        assertEquals(RiskClassification.SUSPICIOUS, FileInspector.result(f, ind, 0).classification)
    }

    @Test fun brandImpersonationInAppName() {
        assertEquals("garantibbva", FileInspector.brandImpersonation(apk(label = "Garanti BBVA Mobil", pkg = "com.update.service")))
        assertNull(FileInspector.brandImpersonation(apk(label = "Garanti BBVA Mobil", pkg = "com.garanti.cepsubesi")))
        assertNull(FileInspector.brandImpersonation(apk(label = "WhatsApp", pkg = "com.whatsapp")))
        assertEquals("whatsapp", FileInspector.brandImpersonation(apk(label = "WhatsApp Gold", pkg = "net.gold.chat")))
    }

    @Test fun fileResultIsNeverReportedAsSafe() {
        val f = facts("report.pdf", FileKind.PDF)
        val r = FileInspector.result(f, emptyList(), 0)
        assertEquals(RiskClassification.UNKNOWN, r.classification)
        assertFalse(r.threatIntelConsulted)
    }
}
