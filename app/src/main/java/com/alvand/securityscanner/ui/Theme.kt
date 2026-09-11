package com.alvand.securityscanner.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightScheme = lightColorScheme(
    primary = Color(0xFF3F51B5), secondary = Color(0xFF5C6BC0),
    background = Color(0xFFF0F2F5), surface = Color.White
)
private val DarkScheme = darkColorScheme(
    primary = Color(0xFF9FA8DA), secondary = Color(0xFF5C6BC0),
    background = Color(0xFF0F1420), surface = Color(0xFF1A2233)
)

@Composable
fun AppTheme(theme: String, content: @Composable () -> Unit) {
    val dark = when (theme) {
        "light" -> false
        "dark" -> true
        else -> isSystemInDarkTheme()
    }
    MaterialTheme(colorScheme = if (dark) DarkScheme else LightScheme, content = content)
}
