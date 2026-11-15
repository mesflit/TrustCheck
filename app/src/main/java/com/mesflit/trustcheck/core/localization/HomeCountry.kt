// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.localization

import android.content.Context
import android.telephony.TelephonyManager
import java.util.Locale

/**
 * The user's home country (ISO 3166 alpha-2), used only on the device to recognize foreign
 * phone numbers and IBANs. SIM country first, then network country, then the region setting.
 * Needs no permission and is never sent anywhere.
 */
object HomeCountry {
    fun detect(context: Context): String? {
        val tm = context.getSystemService(TelephonyManager::class.java)
        val candidates = listOfNotNull(tm?.simCountryIso, tm?.networkCountryIso, Locale.getDefault().country)
        return candidates.map { it.trim().uppercase(Locale.ROOT) }.firstOrNull { it.length == 2 && it.all(Char::isLetter) }
    }
}
