package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PaymentDetailsAnalyzerTest {
    private fun codes(t: String, home: String? = "TR") = PaymentDetailsAnalyzer.analyze(t, home).map { it.indicator }.toSet()

    // Valid example IBANs from public ISO 13616 / bank documentation samples.
    private val validDe = "DE89 3704 0044 0532 0130 00"
    private val validGb = "GB29 NWBK 6016 1331 9268 19"

    @Test fun ibanChecksum() {
        assertTrue(PaymentDetailsAnalyzer.isValidIban(validDe))
        assertTrue(PaymentDetailsAnalyzer.isValidIban(validGb))
        assertFalse(PaymentDetailsAnalyzer.isValidIban("DE89 3704 0044 0532 0130 01"))
    }

    @Test fun foreignAndInvalidIban() {
        assertTrue(Indicator.FOREIGN_IBAN in codes("Ödemeyi şu hesaba yapın: $validDe"))
        assertTrue(Indicator.INVALID_IBAN in codes("IBAN: DE89 3704 0044 0532 0130 01"))
        assertFalse(Indicator.FOREIGN_IBAN in codes("Please pay to $validDe", home = "DE"))
    }

    @Test fun ibanIsMasked() {
        val d = PaymentDetailsAnalyzer.analyze("pay $validGb", "TR").single { it.indicator == Indicator.FOREIGN_IBAN }.detail!!
        assertEquals("GB29 •••• 6819", d)
        assertFalse(d.contains("NWBK6016"))
    }

    @Test fun premiumAndInternationalNetworkNumbers() {
        assertTrue(Indicator.PREMIUM_RATE_NUMBER in codes("Ödülünüz için hemen arayın: 0900 123 45 67"))
        assertTrue(Indicator.PREMIUM_RATE_NUMBER in codes("Call +44 909 876 5432 now"))
        assertTrue(Indicator.PREMIUM_RATE_NUMBER in codes("Rufen Sie 0900 1234567 an", home = "DE"))
        assertTrue(Indicator.INTERNATIONAL_NETWORK_NUMBER in codes("Missed call from +882 1234 5678"))
    }

    @Test fun foreignNumbersOnlyInInternationalFormat() {
        assertTrue(Indicator.FOREIGN_PHONE_NUMBER in codes("WhatsApp: +44 7700 900123"))
        assertTrue(codes("Beni ara: +90 532 123 45 67").isEmpty())
        assertTrue(codes("Beni ara: 0532 123 45 67").isEmpty())
        assertTrue(codes("Call me +44 7700 900123", home = null).isEmpty())
    }

    @Test fun ignoresDatesAmountsAndLinks() {
        assertTrue(codes("Toplam 1.250.000 TL, tarih 15.11.2026").isEmpty())
        assertTrue(codes("https://example.com/track/09001234567").isEmpty())
        assertTrue(codes("Sipariş no: 12345").isEmpty())
    }

    @Test fun cryptoAddresses() {
        // Well-known public example addresses (Bitcoin genesis address, EIP-55 example)
        assertTrue(Indicator.CRYPTO_ADDRESS in codes("Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        assertTrue(Indicator.CRYPTO_ADDRESS in codes("USDT: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))
        assertTrue(Indicator.CRYPTO_ADDRESS in codes("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"))
        // Same shape but broken checksum → not reported
        assertFalse(Indicator.CRYPTO_ADDRESS in codes("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"))
    }

    @Test fun combinedScamMessageIsSuspicious() {
        val text = "Tebrikler! Ödülünüzü almak için gümrük ücretini $validGb hesabına yatırın veya 0900 123 45 67'yi arayın."
        val ind = ScamTextAnalyzer.analyze(text, "TR")
        assertEquals(RiskClassification.SUSPICIOUS, ResultMerger.textOnly(ind, 0).classification)
    }
}
