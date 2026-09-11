package com.alvand.securityscanner.ui

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

// Glassmorphism card: translucent + gradient border. Real blur only on API 31+.
@Composable
fun GlassCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(24.dp)
    var m = Modifier
        .clip(shape)
        .background(Color.White.copy(alpha = 0.12f))
        .border(1.dp, Brush.linearGradient(listOf(Color.White.copy(0.35f), Color.White.copy(0.08f))), shape)
        .padding(16.dp)
    if (Build.VERSION.SDK_INT >= 31) m = m.blur(0.dp) // container blur handled by bg gradient; per-card blur optional
    Column(modifier = modifier.then(m), content = content)
}

@Composable
fun GlassBackground(isDark: Boolean, content: @Composable () -> Unit) {
    val bg = if (isDark) {
        Brush.verticalGradient(listOf(Color(0xFF0F1420), Color(0xFF1B2340), Color(0xFF2A1B4A)))
    } else {
        Brush.verticalGradient(listOf(Color(0xFFE8EAF6), Color(0xFFF0F2F5), Color(0xFFE1BEE7)))
    }
    Box(Modifier.fillMaxSize().background(bg)) { content() }
}
