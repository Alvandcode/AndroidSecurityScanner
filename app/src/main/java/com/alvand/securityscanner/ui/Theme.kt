package com.alvand.securityscanner.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Soft blue-purple color scheme matching the clean security scanner design.
private val LightScheme = lightColorScheme(
    primary = Color(0xFF6B7CFF), onPrimary = Color.White,
    secondary = Color(0xFF9B8AFB), onSecondary = Color.White,
    background = Color(0xFFEDF0FA), onBackground = Color(0xFF1A1D2E),
    surface = Color.White, onSurface = Color(0xFF2D3142),
    surfaceVariant = Color(0xFFF0F2FA), onSurfaceVariant = Color(0xFF6B7280),
    outline = Color(0xFFE0E4EF),
    tertiary = Color(0xFF8B9CF7)
)
private val DarkScheme = darkColorScheme(
    primary = Color(0xFF9FA8DA), onPrimary = Color(0xFF0F1420),
    secondary = Color(0xFF7E9BFF), onSecondary = Color(0xFF0F1420),
    background = Color(0xFF0B1020), onBackground = Color(0xFFE9EDF6),
    surface = Color(0xFF182036), onSurface = Color(0xFFE9EDF6),
    surfaceVariant = Color(0xFF232E4D), onSurfaceVariant = Color(0xFFC3CCE0),
    outline = Color(0xFF4A5878),
    error = Color(0xFFFF8A80), onError = Color(0xFF1A0000),
    tertiary = Color(0xFF7E9BFF)
)

// Verdict glow colors (shared by apps + files).
val GlowDanger = Color(0xFFFF5252)
val GlowWarn = Color(0xFFFFC107)
val GlowSafe = Color(0xFF4CAF50)

// Design accent colors
val AccentBlue = Color(0xFF6B7CFF)
val AccentPurple = Color(0xFF9B8AFB)
val AccentPink = Color(0xFFE08BD4)
val RingBlue = Color(0xFF7B8CFF)
val RingPink = Color(0xFFE08BD4)
val TextPrimary = Color(0xFF1A1D2E)
val TextSecondary = Color(0xFF6B7280)
val CardShadow = Color(0xFFD0D5E8)

@Composable
fun AppTheme(theme: String, content: @Composable () -> Unit) {
    val dark = when (theme) {
        "light" -> false
        "dark" -> true
        else -> isSystemInDarkTheme()
    }
    MaterialTheme(colorScheme = if (dark) DarkScheme else LightScheme, content = content)
}
