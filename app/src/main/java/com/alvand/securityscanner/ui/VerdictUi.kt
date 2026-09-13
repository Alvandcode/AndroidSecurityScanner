package com.alvand.securityscanner.ui

import android.util.LruCache
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Card with a colored neon edge: red = infected, yellow = suspicious,
 * green = healthy. Suspicious cards gently breathe (pulse) so warnings
 * catch the eye without being aggressive.
 */
@Composable
fun GlowCard(
    glow: Color,
    pulse: Boolean = false,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    val shape = RoundedCornerShape(22.dp)
    val alpha: Float = if (pulse) {
        val t = rememberInfiniteTransition(label = "glow")
        t.animateFloat(
            initialValue = 0.25f,
            targetValue = 0.65f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1600, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "glowAlpha"
        ).value
    } else {
        0.45f
    }
    val edge = Brush.linearGradient(
        listOf(
            glow.copy(alpha = alpha),
            glow.copy(alpha = alpha * 0.15f),
            glow.copy(alpha = alpha)
        )
    )
    Column(
        modifier = modifier
            .shadow(
                elevation = 8.dp, shape = shape, clip = false,
                ambientColor = glow.copy(alpha = 0.20f),
                spotColor = glow.copy(alpha = 0.20f)
            )
            .clip(shape)
            .background(
                Brush.verticalGradient(
                    listOf(
                        Color.White,
                        Color(0xFFFBFCFF)
                    )
                )
            )
            .border(1.2.dp, edge, shape)
            .padding(14.dp),
        content = content
    )
}

@Composable
fun CategoryHeader(text: String, dot: Color, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.padding(horizontal = 4.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(8.dp).background(dot, androidx.compose.foundation.shape.CircleShape))
        Spacer(Modifier.width(8.dp))
        Text(
            text, fontWeight = FontWeight.SemiBold, fontSize = 14.sp,
            color = TextPrimary
        )
    }
}

private object AppIconCache {
    private const val MAX = 120
    private val cache = LruCache<String, androidx.compose.ui.graphics.ImageBitmap>(MAX)
    fun get(pkg: String): androidx.compose.ui.graphics.ImageBitmap? = synchronized(this) { cache.get(pkg) }
    fun put(pkg: String, bmp: androidx.compose.ui.graphics.ImageBitmap) = synchronized(this) { cache.put(pkg, bmp) }
}

/** Real launcher icon of an installed app, cached in memory. Falls back to 🤖. */
@Composable
fun AppIcon(packageName: String, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    var bmp by remember(packageName) { mutableStateOf(AppIconCache.get(packageName)) }
    LaunchedEffect(packageName) {
        if (bmp != null) return@LaunchedEffect
        withContext(Dispatchers.IO) {
            try {
                val d = ctx.packageManager.getApplicationIcon(packageName)
                val w = d.intrinsicWidth.coerceIn(1, 512)
                val h = d.intrinsicHeight.coerceIn(1, 512)
                val raw = android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.ARGB_8888)
                val c = android.graphics.Canvas(raw)
                d.setBounds(0, 0, w, h)
                d.draw(c)
                val sized = if (w > 192 || h > 192) {
                    android.graphics.Bitmap.createScaledBitmap(raw, 192, 192, true)
                } else raw
                val img = sized.asImageBitmap()
                AppIconCache.put(packageName, img)
                bmp = img
            } catch (_: Exception) { }
        }
    }
    val img = bmp
    if (img != null) {
        Image(img, contentDescription = null, modifier = modifier.clip(RoundedCornerShape(14.dp)))
    } else {
        Icon(Icons.Default.Android, contentDescription = null, modifier = modifier, tint = MaterialTheme.colorScheme.primary)
    }
}

/** Generic file glyph (APK = box, otherwise = document). */
@Composable
fun FileGlyph(isApk: Boolean, modifier: Modifier = Modifier) {
    Icon(
        if (isApk) Icons.Default.Archive else Icons.Default.InsertDriveFile,
        contentDescription = null, modifier = modifier,
        tint = MaterialTheme.colorScheme.secondary
    )
}
