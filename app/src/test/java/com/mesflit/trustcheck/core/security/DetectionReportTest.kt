package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLDecoder

class DetectionReportTest {
    private fun input(url: String? = "https://paypa1-login.example.com/verify?token=secret#x") = DetectionReport.Input(
        kind = DetectionReport.Kind.MISSED_THREAT,
        targetType = "URL",
        url = url,
        classification = RiskClassification.NO_KNOWN_THREAT,
        score = 12,
        indicators = listOf(Indicator.LOOKALIKE_BRAND),
        sources = listOf(SourceResult(AnalysisSource.LOCAL_HEURISTICS, SourceStatus.entries.first())),
        appVersion = "0.1.0",
    )

    @Test fun defangsLinks() {
        assertEquals("hxxps://evil[.]example[.]com/a", DetectionReport.defang("https://evil.example.com/a"))
    }

    @Test fun neverIncludesQueryOrFragment() {
        val decoded = URLDecoder.decode(DetectionReport.issueUrl(input()), "UTF-8")
        assertFalse(decoded.contains("secret"))
        assertFalse(decoded.contains("#x"))
        assertTrue(decoded.contains("hxxps://paypa1-login[.]example[.]com/verify"))
        assertTrue(decoded.contains("template=detection_report.yml"))
        assertTrue(decoded.contains("LOOKALIKE_BRAND"))
        assertTrue(decoded.contains("NO_KNOWN_THREAT (score 12)"))
    }

    @Test fun filesUseHashOnly() {
        val i = input(url = null).copy(fileSha256 = "ab".repeat(32), fileType = "APK")
        assertEquals("SHA-256 ${"ab".repeat(32)} (APK)", DetectionReport.target(i))
    }

    @Test fun spacesAreEncodedAsPercent20() {
        assertFalse(DetectionReport.issueUrl(input()).contains("+"))
    }
}
