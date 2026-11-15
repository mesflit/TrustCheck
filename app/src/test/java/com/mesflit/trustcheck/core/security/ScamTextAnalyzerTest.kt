package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertTrue
import org.junit.Test

class ScamTextAnalyzerTest {
    private fun codes(t: String) = ScamTextAnalyzer.analyze(t).map { it.indicator }.toSet()

    @Test fun multilingualPhrases() {
        assertTrue(Indicator.PAYMENT_OR_FEE_REQUEST in codes("Kargonuz bekliyor, gümrük ücreti ödemeniz gerekiyor"))
        assertTrue(Indicator.URGENCY_LANGUAGE in codes("Ihr Konto wird gesperrt – handeln Sie sofort"))
        assertTrue(Indicator.PRIZE_OR_MONEY_LURE in codes("¡Felicidades! Has ganado un premio"))
        assertTrue(Indicator.CREDENTIAL_REQUEST in codes("Введите код подтверждения"))
        assertTrue(Indicator.CREDENTIAL_REQUEST in codes("認証コードを入力してください"))
        assertTrue(Indicator.URGENCY_LANGUAGE in codes("عاجل: سيتم تعليق حسابك"))
        assertTrue(Indicator.PRIZE_OR_MONEY_LURE in codes("Parabéns, você ganhou um sorteio"))
        assertTrue(Indicator.CREDENTIAL_REQUEST in codes("Vérifiez votre compte immédiatement"))
    }

    @Test fun turkishDottedCapitalI() {
        assertTrue(Indicator.URGENCY_LANGUAGE in codes("SON UYARI: HESABINIZ ASKIYA ALINACAK"))
    }

    @Test fun shortTokensNeedWordBoundaries() {
        assertTrue(codes("The shotput event is tomorrow").isEmpty())
        assertTrue(Indicator.CREDENTIAL_REQUEST in codes("Send me the OTP please"))
    }

    @Test fun benignMessages() {
        assertTrue(codes("Hey, are we still meeting for lunch?").isEmpty())
    }
}
