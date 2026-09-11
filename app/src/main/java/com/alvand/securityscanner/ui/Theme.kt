package com.alvand.securityscanner.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Explicit on-colors everywhere: default Material3 dynamic tones made body text
// near-black on our translucent cards in dark mode (unreadable). These are fixed.
private val LightScheme = lightColorScheme(
    primary = Color(0xFF5B7CFF), onPrimary = Color.White,
    secondary = Color(0xFF9B8AFB), onSecondary = Color.White,
    background = Color(0xFFF3F4FA), onBackground = Color(0xFF1A1D2E),
    surface = Color.White, onSurface = Color(0xFF1A1D2E),
    surfaceVariant = Color(0xFFECEFF7), onSurfaceVariant = Color(0xFF5A6072),
    outline = Color(0xFFD9DEEB)
)
private val DarkScheme = darkColorScheme(
    primary = Color(0xFF9FA8DA), onPrimary = Color(0xFF0F1420),
    secondary = Color(0xFF7E9BFF), onSecondary = Color(0xFF0F1420),
    background = Color(0xFF0B1020), onBackground = Color(0xFFE9EDF6),
    surface = Color(0xFF182036), onSurface = Color(0xFFE9EDF6),
    surfaceVariant = Color(0xFF232E4D), onSurfaceVariant = Color(0xFFC3CCE0),
    outline = Color(0xFF4A5878),
    error = Color(0xFFFF8A80), onError = Color(0xFF1A0000)
)

// Verdict glow colors (shared by apps + files).
val GlowDanger = Color(0xFFFF5252)
val GlowWarn = Color(0xFFFFC107)
val GlowSafe = Color(0xFF4CAF50)

@Composable
fun AppTheme(theme: String, content: @Composable () -> Unit) {
    val dark = when (theme) {
        "light" -> false
        "dark" -> true
        else -> isSystemInDarkTheme()
    }
    MaterialTheme(colorScheme = if (dark) DarkScheme else LightScheme, content = content)
}
