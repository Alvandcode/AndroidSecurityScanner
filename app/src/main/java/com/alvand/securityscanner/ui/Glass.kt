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
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.unit.dp

// Clean white card with subtle shadow matching the minimal security scanner design.
@Composable
fun GlassCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(24.dp)
    val light = MaterialTheme.colorScheme.background.luminance() > 0.5f
    val body: Brush = if (light) {
        Brush.verticalGradient(listOf(Color.White, Color(0xFFFBFCFF)))
    } else {
        Brush.verticalGradient(
            listOf(Color.White.copy(alpha = 0.16f), Color.White.copy(alpha = 0.05f))
        )
    }
    val edge: Brush = if (light) {
        Brush.linearGradient(listOf(Color(0xFFE8ECF4), Color.White, Color(0xFFE8ECF4)))
    } else {
        Brush.linearGradient(
            listOf(
                Color.White.copy(alpha = 0.50f),
                Color.White.copy(alpha = 0.10f),
                Color.White.copy(alpha = 0.32f)
            )
        )
    }
    Column(
        modifier = modifier
            .shadow(if (light) 6.dp else 8.dp, shape, clip = false, ambientColor = Color(0xFFD0D5E8))
            .clip(shape)
            .background(body)
            .border(1.dp, edge, shape)
            .padding(18.dp)
    ) {
        CompositionLocalProvider(LocalContentColor provides MaterialTheme.colorScheme.onSurface) {
            content()
        }
    }
}

// Soft lavender-blue gradient background matching the clean design.
@Composable
fun GlassBackground(isDark: Boolean, content: @Composable () -> Unit) {
    val bg = if (isDark) {
        Brush.verticalGradient(listOf(Color(0xFF0B1020), Color(0xFF16224A), Color(0xFF2A1B4A)))
    } else {
        Brush.verticalGradient(listOf(Color(0xFFE8ECF8), Color(0xFFF0F3FC), Color(0xFFDDE4F6)))
    }
    Box(Modifier.fillMaxSize().background(bg)) {
        if (Build.VERSION.SDK_INT >= 31) {
            Box(
                Modifier.size(300.dp).offset(x = (-60).dp, y = (-40).dp).blur(80.dp)
                    .background(Color(0xFF7B8CFF).copy(alpha = 0.18f), CircleShape)
            )
            Box(
                Modifier.size(350.dp).align(Alignment.BottomEnd).offset(x = 60.dp, y = 60.dp).blur(90.dp)
                    .background(Color(0xFFB8A4F8).copy(alpha = 0.14f), CircleShape)
            )
        }
        content()
    }
}
