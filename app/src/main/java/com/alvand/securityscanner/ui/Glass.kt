package com.alvand.securityscanner.ui

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

// Liquid-glass card: gradient body + light-catching border.
// Text color is forced to onSurface: without this, body text turned near-black
// on our translucent cards in dark mode (unreadable).
@Composable
fun GlassCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(26.dp)
    Column(
        modifier = modifier
            .shadow(6.dp, shape, clip = false)
            .clip(shape)
            .background(
                Brush.verticalGradient(
                    listOf(
                        Color.White.copy(alpha = 0.16f),
                        Color.White.copy(alpha = 0.05f)
                    )
                )
            )
            .border(
                1.dp,
                Brush.linearGradient(
                    listOf(
                        Color.White.copy(alpha = 0.50f),
                        Color.White.copy(alpha = 0.10f),
                        Color.White.copy(alpha = 0.32f)
                    )
                ),
                shape
            )
            .padding(16.dp)
    ) {
        CompositionLocalProvider(LocalContentColor provides MaterialTheme.colorScheme.onSurface) {
            content()
        }
    }
}

@Composable
fun GlassBackground(isDark: Boolean, content: @Composable () -> Unit) {
    val bg = if (isDark) {
        Brush.verticalGradient(listOf(Color(0xFF0B1020), Color(0xFF16224A), Color(0xFF2A1B4A)))
    } else {
        Brush.verticalGradient(listOf(Color(0xFFE8EAF6), Color(0xFFF2F4FA), Color(0xFFD8E4FA)))
    }
    Box(Modifier.fillMaxSize().background(bg)) {
        // Liquid light blobs (real blur on API 31+, plain translucent otherwise).
        if (Build.VERSION.SDK_INT >= 31) {
            Box(
                Modifier.size(280.dp).offset(x = (-80).dp, y = (-60).dp).blur(70.dp)
                    .background(Color(0xFF3D5AFE).copy(alpha = 0.30f), CircleShape)
            )
            Box(
                Modifier.size(320.dp).align(Alignment.BottomEnd).offset(x = 90.dp, y = 80.dp).blur(80.dp)
                    .background(Color(0xFF00E5FF).copy(alpha = 0.20f), CircleShape)
            )
        }
        content()
    }
}
