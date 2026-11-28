package com.alvand.securityscanner

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.alvand.securityscanner.data.PrefsKeys
import com.alvand.securityscanner.scanner.AppFinding
import com.alvand.securityscanner.scanner.AppScanner
import com.alvand.securityscanner.scanner.Verdict
import com.alvand.securityscanner.ui.AppTheme
import com.alvand.securityscanner.ui.GlassBackground
import com.alvand.securityscanner.ui.GlassCard
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun HomeScreen(vm: ScanViewModel, onScan: () -> Unit, onSettings: () -> Unit, onHistory: () -> Unit) {
    val ctx = LocalContext.current
    var selected by remember { mutableStateOf<AppFinding?>(null) }
    var webOpen by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val notifLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { }
    val realtime by ctx.dataStore.data.map { it[PrefsKeys.REALTIME] != false }.collectAsState(true)
    val lastScan by ctx.dataStore.data.map { it[PrefsKeys.LAST_SCAN] }.collectAsState(null)
    val notifOn = if (Build.VERSION.SDK_INT >= 33) {
        ctx.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
    } else true
    fun askNotif() {
        if (Build.VERSION.SDK_INT >= 33 && !notifOn) {
            try { notifLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS) } catch (_: Exception) { }
        }
    }
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onSettings) {
                    Icon(Icons.Default.Menu, contentDescription = null, tint = com.alvand.securityscanner.ui.TextPrimary(), modifier = Modifier.size(26.dp))
                }
                IconButton(onClick = onHistory) {
                    Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(26.dp))
                }
            }
        }
        item {
            Text(stringResource(R.string.app_name), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(stringResource(R.string.app_tagline), fontSize = 14.sp, color = com.alvand.securityscanner.ui.TextSecondary())
        }
        item {
            val shown = vm.unifiedScore.value ?: vm.deviceScore.value
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                ScoreRing(shown)
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Default.AccessTime, contentDescription = null,
                        modifier = Modifier.size(14.dp), tint = com.alvand.securityscanner.ui.TextSecondary()
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        "${stringResource(R.string.last_scan)}: ${lastScan ?: stringResource(R.string.never)}",
                        fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary()
                    )
                }
            }
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                        shape = CircleShape,
                        modifier = Modifier.size(44.dp)
                    ) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Icon(
                                Icons.Default.VerifiedUser, contentDescription = null,
                                tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(24.dp)
                            )
                        }
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.quick_scan), fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = com.alvand.securityscanner.ui.TextPrimary())
                        Text(
                            stringResource(R.string.quick_desc), fontSize = 12.sp,
                            color = com.alvand.securityscanner.ui.TextSecondary()
                        )
                    }
                    Surface(
                        onClick = { askNotif(); vm.scan(ctx, false) },
                        color = com.alvand.securityscanner.ui.AccentBlue,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.size(44.dp)
                    ) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Icon(Icons.Default.ArrowForward, contentDescription = null, tint = Color.White, modifier = Modifier.size(20.dp))
                        }
                    }
                }
                if (vm.scanning.value && !vm.unifiedScanning.value) {
                    Spacer(Modifier.height(10.dp))
                    LinearProgressIndicator(
                        progress = { vm.progress.value },
                        modifier = Modifier.fillMaxWidth().height(4.dp),
                        color = com.alvand.securityscanner.ui.AccentBlue,
                        trackColor = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.12f)
                    )
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MiniScanCard(
                    Modifier.weight(1f), Icons.Default.GpsFixed,
                    stringResource(R.string.full_scan), stringResource(R.string.full_desc)
                ) { askNotif(); vm.scanAll(ctx, false); onScan() }
                MiniScanCard(
                    Modifier.weight(1f), Icons.Default.Apps,
                    stringResource(R.string.app_scan), stringResource(R.string.app_desc)
                ) { askNotif(); vm.scan(ctx, true) }
                MiniScanCard(
                    Modifier.weight(1f), Icons.Default.Language,
                    stringResource(R.string.web_scan), stringResource(R.string.web_desc)
                ) { webOpen = true }
            }
        }
        item {
            Text(
                stringResource(R.string.protection), fontSize = 16.sp, fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(start = 4.dp), color = com.alvand.securityscanner.ui.TextPrimary()
            )
        }
        item {
            GlassCard(Modifier.fillMaxWidth()) {
                ProtRow(
                    Icons.Default.VerifiedUser,
                    stringResource(R.string.realtime),
                    if (realtime) stringResource(R.string.scan_on) else stringResource(R.string.scan_off)
                ) {
                    Switch(
                        checked = realtime,
                        onCheckedChange = { on ->
                            scope.launch { ctx.dataStore.edit { it[PrefsKeys.REALTIME] = on } }
                        },
                        colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = com.alvand.securityscanner.ui.AccentBlue)
                    )
                }
                HorizontalDivider(Modifier.padding(vertical = 6.dp), color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.08f))
                ProtRow(Icons.Default.Wifi, stringResource(R.string.wifi_sec), stringResource(R.string.wifi_desc)) {
                    IconButton(onClick = {
                        try { ctx.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS)) } catch (_: Exception) { }
                    }) {
                        Icon(Icons.Default.ChevronRight, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary())
                    }
                }
                HorizontalDivider(Modifier.padding(vertical = 6.dp), color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.08f))
                ProtRow(Icons.Default.Storage, stringResource(R.string.database), stringResource(R.string.db_desc)) {
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Default.Refresh, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary())
                    }
                }
                HorizontalDivider(Modifier.padding(vertical = 6.dp), color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.08f))
                ProtRow(
                    Icons.Default.Notifications,
                    stringResource(R.string.notif_title),
                    if (notifOn) stringResource(R.string.notif_on) else stringResource(R.string.notif_off)
                ) {
                    IconButton(onClick = { if (!notifOn) askNotif() else {
                        try {
                            if (Build.VERSION.SDK_INT >= 26) {
                                ctx.startActivity(
                                    Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                        .putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
                                )
                            } else {
                                ctx.startActivity(
                                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${ctx.packageName}"))
                                )
                            }
                        } catch (_: Exception) { }
                    } }) {
                        Icon(Icons.Default.ChevronRight, contentDescription = null, tint = com.alvand.securityscanner.ui.TextSecondary())
                    }
                }
            }
        }
        // Device health (root / ADB / developer options) — only after a scan ran.
        val health = vm.health.value
        if (health != null) {
            item {
                GlassCard(Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.HealthAndSafety, contentDescription = null,
                            tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(22.dp)
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            stringResource(R.string.device_health), fontSize = 15.sp,
                            fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary()
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    val healthLines = buildList {
                        if (health.isProbablyRooted) add(stringResource(R.string.health_root))
                        if (health.adbEnabled == true) add(stringResource(R.string.health_adb))
                        if (health.devOptionsEnabled == true) add(stringResource(R.string.health_dev))
                    }
                    if (healthLines.isEmpty()) {
                        Text(stringResource(R.string.health_ok), fontSize = 13.sp, color = com.alvand.securityscanner.ui.GlowSafe)
                    } else {
                        healthLines.forEach {
                            Text("⚠ $it", fontSize = 13.sp, color = com.alvand.securityscanner.ui.GlowWarn)
                        }
                    }
                }
            }
        }
        val danger = vm.findings.value.filter { it.verdict == Verdict.DANGEROUS }
        val review = vm.findings.value.filter { it.verdict == Verdict.REVIEW }
        val safe = vm.findings.value.filter { it.verdict == Verdict.SAFE }
        if (danger.isNotEmpty()) {
            item {
                com.alvand.securityscanner.ui.CategoryHeader(
                    "${stringResource(R.string.dangerous)}: ${danger.size}",
                    com.alvand.securityscanner.ui.GlowDanger
                )
            }
            items(danger.take(50), key = { it.packageName }) { f ->
                AppRow(f, com.alvand.securityscanner.ui.GlowDanger, false) { selected = f }
            }
        }
        if (review.isNotEmpty()) {
            item {
                com.alvand.securityscanner.ui.CategoryHeader(
                    "${stringResource(R.string.review_needed)}: ${review.size}",
                    com.alvand.securityscanner.ui.GlowWarn
                )
            }
            items(review.take(50), key = { it.packageName }) { f ->
                AppRow(f, com.alvand.securityscanner.ui.GlowWarn, true) { selected = f }
            }
        }
        if (safe.isNotEmpty() && !danger.isNotEmpty() && !review.isNotEmpty()) {
            item {
                com.alvand.securityscanner.ui.CategoryHeader(
                    "${stringResource(R.string.safe)}: ${safe.size}",
                    com.alvand.securityscanner.ui.GlowSafe
                )
            }
            items(safe.take(30), key = { it.packageName }) { f ->
                AppRow(f, com.alvand.securityscanner.ui.GlowSafe, false) { selected = f }
            }
        }
    }
    selected?.let { com.alvand.securityscanner.ui.DetailsDialog(it) { selected = null } }
    if (webOpen) WebScanDialog { webOpen = false }
}

@Composable
fun AppRow(
    f: AppFinding,
    glow: androidx.compose.ui.graphics.Color,
    pulse: Boolean,
    onDetails: () -> Unit
) {
    val c = LocalContext.current
    com.alvand.securityscanner.ui.GlowCard(glow = glow, pulse = pulse, modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            com.alvand.securityscanner.ui.AppIcon(f.packageName, Modifier.size(44.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(f.appName, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = com.alvand.securityscanner.ui.TextPrimary())
                Text(f.packageName, fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary())
                Text("${f.score}/100 • " + verdictText(f.verdict) + (if (f.unknownSource) " • " + stringResource(R.string.unknown_source) else ""),
                    fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
                if (f.riskyPermissions.isNotEmpty())
                    Text("${stringResource(R.string.risky_permissions)}: ${f.riskyPermissions.size}", fontSize = 11.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            }
            Column {
                Surface(
                    onClick = onDetails,
                    color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(stringResource(R.string.details), modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp), fontSize = 12.sp, color = com.alvand.securityscanner.ui.AccentBlue, fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = {
                    try { c.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.packageName}"))) } catch (_: Exception) { }
                }) { Text(stringResource(R.string.uninstall), fontSize = 11.sp) }
            }
        }
    }
}

@Composable
fun ScoreRing(score: Int?) {
    val s = (score ?: 0).coerceIn(0, 100)
    val frac = s / 100f
    val ring: Brush
    val label: String
    val sub: String
    when {
        // No scan yet: neutral gray, honest "not scanned" — never "safe".
        score == null -> {
            ring = Brush.sweepGradient(listOf(
                MaterialTheme.colorScheme.onBackground.copy(alpha = 0.35f),
                MaterialTheme.colorScheme.onBackground.copy(alpha = 0.18f),
                MaterialTheme.colorScheme.onBackground.copy(alpha = 0.35f)))
            label = stringResource(R.string.not_scanned)
            sub = stringResource(R.string.not_scanned_sub)
        }
        s >= 80 -> {
            ring = Brush.sweepGradient(listOf(com.alvand.securityscanner.ui.RingBlue, com.alvand.securityscanner.ui.RingPink, com.alvand.securityscanner.ui.RingBlue))
            label = stringResource(R.string.safe)
            sub = stringResource(R.string.no_threats)
        }
        s >= 50 -> {
            ring = Brush.sweepGradient(listOf(Color(0xFFFFB300), Color(0xFFFF7043), Color(0xFFFFB300)))
            label = stringResource(R.string.review_needed)
            sub = stringResource(R.string.suspicious)
        }
        else -> {
            ring = Brush.sweepGradient(listOf(Color(0xFFFF5252), Color(0xFFD81B60), Color(0xFFFF5252)))
            label = stringResource(R.string.dangerous)
            sub = stringResource(R.string.infected)
        }
    }
    Box(Modifier.size(230.dp), contentAlignment = Alignment.Center) {
        // Hoisted out of Canvas: DrawScope is not a composable context.
        val ringTrack = MaterialTheme.colorScheme.onBackground
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 14.dp.toPx()
            val padding = 4.dp.toPx()
            drawArc(
                ringTrack.copy(alpha = if (score == null) 0.30f else 0.15f), 0f, 360f, false,
                style = Stroke(stroke, cap = StrokeCap.Round),
                topLeft = Offset(padding, padding),
                size = Size(size.width - padding * 2f, size.height - padding * 2f)
            )
            if (frac > 0f) drawArc(
                ring, -90f, 360f * frac, false,
                style = Stroke(stroke, cap = StrokeCap.Round),
                topLeft = Offset(padding, padding),
                size = Size(size.width - padding * 2f, size.height - padding * 2f)
            )
            val inset = 32.dp.toPx()
            drawArc(
                ringTrack.copy(alpha = 0.25f), 0f, 360f, false,
                style = Stroke(1.5.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4f, 6f), 0f)),
                alpha = 0.4f,
                topLeft = Offset(inset, inset),
                size = Size(size.width - inset * 2f, size.height - inset * 2f)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Surface(
                color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                shape = CircleShape,
                modifier = Modifier.size(48.dp)
            ) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(28.dp))
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(label, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary(), fontWeight = FontWeight.Medium)
            Text(
                if (score == null) "--%" else "$s%",
                fontSize = 42.sp, fontWeight = FontWeight.Bold,
                color = com.alvand.securityscanner.ui.TextPrimary()
            )
            Text(sub, fontSize = 12.sp, color = com.alvand.securityscanner.ui.AccentBlue, fontWeight = FontWeight.Medium)
        }
    }
}

@Composable
fun MiniScanCard(mod: Modifier, icon: ImageVector, title: String, desc: String, onClick: () -> Unit) {
    Surface(
        modifier = mod.clickable(onClick = onClick),
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(20.dp),
        shadowElevation = 4.dp
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp, horizontal = 8.dp)
        ) {
            Surface(
                color = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.1f),
                shape = CircleShape,
                modifier = Modifier.size(42.dp)
            ) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(22.dp))
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(title, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(desc, fontSize = 10.sp, color = com.alvand.securityscanner.ui.TextSecondary())
        }
    }
}

@Composable
fun ProtRow(icon: ImageVector, title: String, sub: String, action: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(24.dp))
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(sub, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
        }
        action()
    }
}

@Composable
fun Radar(active: Boolean) {
    val sweep = if (active) {
        rememberInfiniteTransition(label = "radar").animateFloat(
            initialValue = 0f, targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 2600, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "sweep"
        ).value
    } else 0f
    // Hoisted out of Canvas: DrawScope is not a composable context.
    val ringColor = MaterialTheme.colorScheme.onBackground
    Box(Modifier.size(260.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val cx = size.width / 2f
            val cy = size.height / 2f
            val r = minOf(cx, cy)
            for (f in listOf(0.34f, 0.56f, 0.78f, 1f)) {
                drawCircle(ringColor, r * f, style = Stroke(1.5.dp.toPx()), alpha = 0.35f)
            }
            if (active) {
                rotate(sweep) {
                    drawArc(
                        brush = Brush.sweepGradient(
                            0f to Color.Transparent,
                            0.22f to com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.5f),
                            0.26f to Color.Transparent,
                            center = Offset(cx, cy)
                        ),
                        startAngle = 0f, sweepAngle = 360f, useCenter = true,
                        topLeft = Offset(cx - r, cy - r),
                        size = Size(r * 2f, r * 2f)
                    )
                }
            }
        }
        OrbitChip(Modifier.align(Alignment.TopCenter).offset(y = (-14).dp), Icons.Default.BugReport)
        OrbitChip(Modifier.align(Alignment.CenterEnd).offset(x = 14.dp), Icons.Default.Wifi)
        OrbitChip(Modifier.align(Alignment.CenterStart).offset(x = (-14).dp), Icons.Default.Lock)
        OrbitChip(Modifier.align(Alignment.BottomCenter).offset(y = 14.dp), Icons.Default.Description)
        Surface(
            color = MaterialTheme.colorScheme.surface, shape = CircleShape,
            shadowElevation = 8.dp, modifier = Modifier.size(110.dp)
        ) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(52.dp))
                Icon(
                    Icons.Default.Search, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue,
                    modifier = Modifier.size(22.dp).align(Alignment.BottomEnd).offset(x = (-22).dp, y = (-22).dp)
                )
            }
        }
    }
}

@Composable
fun OrbitChip(mod: Modifier, icon: ImageVector) {
    Surface(color = MaterialTheme.colorScheme.surface, shape = CircleShape, shadowElevation = 4.dp, modifier = mod.size(40.dp)) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Icon(icon, contentDescription = null, tint = com.alvand.securityscanner.ui.AccentBlue, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
fun ScanStat(value: String, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary())
        Text(label, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
    }
}

@Composable
fun verdictText(v: Verdict) = when (v) {
    Verdict.SAFE -> stringResource(R.string.safe)
    Verdict.REVIEW -> stringResource(R.string.review_needed)
    Verdict.DANGEROUS -> stringResource(R.string.dangerous)
}

