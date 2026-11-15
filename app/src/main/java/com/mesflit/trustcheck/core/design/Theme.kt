// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.design

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.domain.ThemeMode

// Deep navy base with blue → purple accents.
private val Navy950 = Color(0xFF070B1A)
private val Navy900 = Color(0xFF0B1226)
private val Navy850 = Color(0xFF111A33)
private val Navy800 = Color(0xFF182341)
private val Navy700 = Color(0xFF243256)
private val Blue400 = Color(0xFF6E9BFF)
private val Blue600 = Color(0xFF3563E9)
private val Purple300 = Color(0xFFB9A3FF)
private val Purple600 = Color(0xFF6B4CE0)
private val Slate100 = Color(0xFFE7ECF7)
private val Slate300 = Color(0xFFAAB4CC)
private val Slate600 = Color(0xFF4C5672)

private val DarkColors = darkColorScheme(
    primary = Blue400,
    onPrimary = Navy950,
    primaryContainer = Color(0xFF1C2E66),
    onPrimaryContainer = Color(0xFFDCE5FF),
    secondary = Purple300,
    onSecondary = Navy950,
    secondaryContainer = Color(0xFF2E2563),
    onSecondaryContainer = Color(0xFFE9E2FF),
    tertiary = Color(0xFF7FD3C6),
    background = Navy950,
    onBackground = Slate100,
    surface = Navy900,
    onSurface = Slate100,
    surfaceVariant = Navy800,
    onSurfaceVariant = Slate300,
    surfaceContainerLowest = Navy950,
    surfaceContainerLow = Navy900,
    surfaceContainer = Navy850,
    surfaceContainerHigh = Navy800,
    surfaceContainerHighest = Navy700,
    outline = Color(0xFF3A4668),
    outlineVariant = Color(0xFF26304D),
    error = Color(0xFFFF8A8A),
    onError = Navy950,
)

private val LightColors = lightColorScheme(
    primary = Blue600,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDCE5FF),
    onPrimaryContainer = Color(0xFF0B1F5C),
    secondary = Purple600,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE9E2FF),
    onSecondaryContainer = Color(0xFF23145E),
    tertiary = Color(0xFF00796B),
    background = Color(0xFFF6F8FD),
    onBackground = Color(0xFF0E1530),
    surface = Color.White,
    onSurface = Color(0xFF0E1530),
    surfaceVariant = Color(0xFFE9EDF7),
    onSurfaceVariant = Slate600,
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF8FAFE),
    surfaceContainer = Color(0xFFF1F4FB),
    surfaceContainerHigh = Color(0xFFEBEFF8),
    surfaceContainerHighest = Color(0xFFE4E9F5),
    outline = Color(0xFFB7C0D6),
    outlineVariant = Color(0xFFD9DFEC),
    error = Color(0xFFC62828),
)

/** Semantic risk colors with accessible contrast on both themes. */
@Immutable
data class RiskColors(
    val malicious: Color,
    val suspicious: Color,
    val noKnownThreat: Color,
    val unknown: Color,
    val failed: Color,
    val onRisk: Color,
) {
    fun of(c: RiskClassification): Color = when (c) {
        RiskClassification.CONFIRMED_MALICIOUS -> malicious
        RiskClassification.SUSPICIOUS -> suspicious
        RiskClassification.NO_KNOWN_THREAT -> noKnownThreat
        RiskClassification.UNKNOWN -> unknown
        RiskClassification.ANALYSIS_FAILED -> failed
    }
}

private val DarkRisk = RiskColors(
    malicious = Color(0xFFFF6B6B), suspicious = Color(0xFFFFB84D), noKnownThreat = Color(0xFF5FD39A),
    unknown = Color(0xFF9AA6C4), failed = Color(0xFF8C96B0), onRisk = Navy950,
)
private val LightRisk = RiskColors(
    malicious = Color(0xFFC62828), suspicious = Color(0xFFB45F00), noKnownThreat = Color(0xFF1B7F4B),
    unknown = Color(0xFF55607A), failed = Color(0xFF6B7280), onRisk = Color.White,
)

val LocalRiskColors = staticCompositionLocalOf { DarkRisk }

private val AppTypography = Typography().let { t ->
    t.copy(
        headlineMedium = t.headlineMedium.copy(fontWeight = FontWeight.SemiBold, letterSpacing = (-0.2).sp),
        headlineSmall = t.headlineSmall.copy(fontWeight = FontWeight.SemiBold),
        titleLarge = t.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = t.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelLarge = t.labelLarge.copy(fontWeight = FontWeight.SemiBold),
    )
}

val NumberStyle = TextStyle(fontSize = 28.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp)

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

@Composable
fun TrustCheckTheme(mode: ThemeMode = ThemeMode.SYSTEM, content: @Composable () -> Unit) {
    val dark = when (mode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.DARK -> true
        ThemeMode.LIGHT -> false
    }
    val colors: ColorScheme = if (dark) DarkColors else LightColors
    androidx.compose.runtime.CompositionLocalProvider(LocalRiskColors provides if (dark) DarkRisk else LightRisk) {
        MaterialTheme(colorScheme = colors, typography = AppTypography, shapes = AppShapes, content = content)
    }
}
