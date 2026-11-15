// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.security

import java.util.Locale

/**
 * Lightweight, multilingual scam-message phrase detection for shared text.
 * It is a coarse signal; the optional cloud AI layer provides deeper analysis.
 * Notification content is never retained — only the resulting indicator codes are.
 */
object ScamTextAnalyzer {

    private val groups: Map<Indicator, List<String>> = mapOf(
        Indicator.URGENCY_LANGUAGE to listOf(
            // en
            "urgent", "immediately", "within 24 hours", "account will be suspended", "act now", "final notice", "last warning", "expires today",
            // tr
            "acil", "hemen", "24 saat içinde", "hesabınız askıya", "son uyarı", "derhal",
            // de
            "dringend", "sofort", "innerhalb von 24 stunden", "konto wird gesperrt", "letzte mahnung",
            // es
            "urgente", "inmediatamente", "en 24 horas", "cuenta será suspendida", "último aviso",
            // fr
            "immédiatement", "sous 24 heures", "compte sera suspendu", "dernier avertissement",
            // pt
            "imediatamente", "em 24 horas", "conta será bloqueada", "último aviso", "bloqueio",
            // ar
            "عاجل", "فورا", "خلال 24 ساعة", "سيتم تعليق حسابك", "تحذير أخير",
            // ja
            "至急", "緊急", "24時間以内", "アカウントが停止", "直ちに",
            // ru
            "срочно", "немедленно", "в течение 24 часов", "аккаунт будет заблокирован", "последнее предупреждение",
        ),
        Indicator.CREDENTIAL_REQUEST to listOf(
            "verify your account", "confirm your password", "enter your pin", "verification code", "one-time code", "otp", "login details", "update your payment",
            "şifrenizi", "doğrulama kodu", "kart bilgilerinizi", "tek kullanımlık", "hesabınızı doğrulayın",
            "passwort bestätigen", "bestätigungscode", "konto verifizieren", "zugangsdaten",
            "verifique su cuenta", "código de verificación", "contraseña", "datos bancarios",
            "vérifiez votre compte", "code de vérification", "mot de passe", "coordonnées bancaires",
            "verifique sua conta", "código de verificação", "senha", "dados do cartão",
            "رمز التحقق", "كلمة المرور", "تحديث بياناتك", "أدخل الرمز",
            "認証コード", "パスワード", "暗証番号", "本人確認",
            "код подтверждения", "пароль", "подтвердите аккаунт", "данные карты",
        ),
        Indicator.PRIZE_OR_MONEY_LURE to listOf(
            "you have won", "you've won", "congratulations", "claim your prize", "free gift", "lottery", "cash reward", "investment opportunity", "guaranteed profit",
            "kazandınız", "tebrikler", "hediye", "çekiliş", "ödül",
            "gewonnen", "herzlichen glückwunsch", "gewinnspiel", "geschenk",
            "has ganado", "felicidades", "premio", "regalo", "lotería",
            "vous avez gagné", "félicitations", "cadeau", "loterie",
            "você ganhou", "parabéns", "prêmio", "presente", "sorteio",
            "لقد ربحت", "مبروك", "جائزة", "هدية",
            "当選", "おめでとう", "賞金", "プレゼント",
            "вы выиграли", "поздравляем", "приз", "подарок", "лотерея",
        ),
        Indicator.PAYMENT_OR_FEE_REQUEST to listOf(
            "customs fee", "delivery fee", "shipping fee", "pay now", "outstanding payment", "unpaid", "gift card", "crypto", "bitcoin", "wire transfer",
            "gümrük ücreti", "kargo ücreti", "ödeme yapın", "borcunuz", "hediye kartı",
            "zollgebühr", "versandgebühr", "jetzt bezahlen", "offene zahlung",
            "tasa de aduana", "gastos de envío", "pague ahora", "pago pendiente",
            "frais de douane", "frais de livraison", "payez maintenant", "paiement en attente",
            "taxa alfandegária", "taxa de entrega", "pague agora", "pagamento pendente",
            "رسوم جمركية", "رسوم التوصيل", "ادفع الآن",
            "関税", "配送料", "未払い", "今すぐ支払",
            "таможенный сбор", "оплата доставки", "оплатите сейчас", "задолженность",
        ),
    )

    fun analyze(text: String): List<DetectedIndicator> {
        if (text.isBlank()) return emptyList()
        val t = fold(text.take(UrlExtractor.MAX_INPUT_CHARS))
        return groups.mapNotNull { (indicator, phrases) ->
            val hits = phrases.filter { p -> matches(t, fold(p)) }
            if (hits.isEmpty()) null else DetectedIndicator(indicator, hits.size.toString())
        }
    }

    /**
     * Case folding that is stable for Turkish: "I"/"İ"/"ı"/"i" all fold to "i", so
     * "HESABINIZ" matches "hesabınız" regardless of the device locale.
     */
    internal fun fold(s: String): String =
        s.lowercase(Locale.ROOT).replace("i̇", "i").replace('ı', 'i')

    private fun matches(text: String, phrase: String): Boolean {
        // Short ASCII tokens (e.g. "otp", "acil") need word boundaries to avoid substring hits.
        return if (phrase.length <= 5 && phrase.all { it.code < 128 }) {
            Regex("(?<![\\p{L}\\p{N}])${Regex.escape(phrase)}(?![\\p{L}\\p{N}])").containsMatchIn(text)
        } else {
            text.contains(phrase)
        }
    }
}
