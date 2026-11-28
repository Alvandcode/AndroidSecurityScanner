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

private const val TG_CHANNEL = "https://t.me/a_c_official"
private const val TON_ADDR = "UQCB9rzvwmq0FJDaBkHVdBgbfZPb06FWdKco3woAHH6AXuUt"


@Composable
fun SettingsScreen(theme: String, lang: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val clip = LocalClipboardManager.current
    val pkg = ctx.packageName
    val verName = try {
        if (Build.VERSION.SDK_INT >= 33) {
            ctx.packageManager.getPackageInfo(pkg, android.content.pm.PackageManager.PackageInfoFlags.of(0)).versionName
        } else {
            @Suppress("DEPRECATION") ctx.packageManager.getPackageInfo(pkg, 0).versionName
        }
    } catch (_: Exception) { "؟" }
    val verCode = try {
        if (Build.VERSION.SDK_INT >= 28) {
            if (Build.VERSION.SDK_INT >= 33) {
                ctx.packageManager.getPackageInfo(pkg, android.content.pm.PackageManager.PackageInfoFlags.of(0)).longVersionCode.toString()
            } else {
                @Suppress("DEPRECATION") ctx.packageManager.getPackageInfo(pkg, 0).longVersionCode.toString()
            }
        } else ""
    } catch (_: Exception) { "" }
    val cloud by ctx.dataStore.data.map { it[PrefsKeys.CLOUD] == true }.collectAsState(false)
    val vtKey by ctx.dataStore.data.map { it[PrefsKeys.VT_KEY] ?: "" }.collectAsState("")
    val sched by ctx.dataStore.data.map { it[PrefsKeys.SCHED] == true }.collectAsState(false)
    val catalogOn by ctx.dataStore.data.map { it[PrefsKeys.CATALOG] != false }.collectAsState(true)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(stringResource(R.string.settings), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = com.alvand.securityscanner.ui.TextPrimary())
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.theme), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("system" to stringResource(R.string.theme_system), "light" to stringResource(R.string.theme_light), "dark" to stringResource(R.string.theme_dark)).forEach { (v, t) ->
                    FilterChip(
                        selected = theme == v,
                        onClick = { scope.launch { ctx.dataStore.edit { it[PrefsKeys.THEME] = v }; (ctx as? MainActivity)?.recreate() } },
                        label = { Text(t) },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.12f), selectedLabelColor = com.alvand.securityscanner.ui.AccentBlue)
                    )
                }
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.language), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("system" to stringResource(R.string.lang_system), "en" to stringResource(R.string.lang_en), "fa" to stringResource(R.string.lang_fa)).forEach { (v, t) ->
                    FilterChip(
                        selected = lang == v,
                        onClick = {
                            scope.launch {
                                ctx.dataStore.edit { it[PrefsKeys.LANG] = v }
                                ctx.getSharedPreferences("events", Context.MODE_PRIVATE).edit().putString("ui_lang", v).apply()
                                if (Build.VERSION.SDK_INT >= 33) {
                                    // applicationLocales triggers its own recreation;
                                    // calling recreate() too would double-recreate.
                                    val lm = ctx.getSystemService(android.app.LocaleManager::class.java)
                                    lm?.applicationLocales = if (v == "system") android.os.LocaleList.forLanguageTags("") else android.os.LocaleList.forLanguageTags(v)
                                } else {
                                    (ctx as? MainActivity)?.recreate()
                                }
                            }
                        },
                        label = { Text(t) },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = com.alvand.securityscanner.ui.AccentBlue.copy(alpha = 0.12f), selectedLabelColor = com.alvand.securityscanner.ui.AccentBlue)
                    )
                }
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.catalog_title), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(stringResource(R.string.catalog_desc), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            Spacer(Modifier.height(4.dp))
            Switch(
                checked = catalogOn,
                onCheckedChange = { on ->
                    scope.launch { ctx.dataStore.edit { it[PrefsKeys.CATALOG] = on } }
                },
                colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = com.alvand.securityscanner.ui.AccentBlue)
            )
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.scheduled_scan), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(stringResource(R.string.scheduled_desc), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            Spacer(Modifier.height(4.dp))
            Switch(
                checked = sched,
                onCheckedChange = { on ->
                    scope.launch {
                        ctx.dataStore.edit { it[PrefsKeys.SCHED] = on }
                        if (on) com.alvand.securityscanner.scanner.ScanWorker.schedule(ctx)
                        else com.alvand.securityscanner.scanner.ScanWorker.cancel(ctx)
                    }
                },
                colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = com.alvand.securityscanner.ui.AccentBlue)
            )
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.cloud_lookup), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(stringResource(R.string.cloud_desc), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            Spacer(Modifier.height(4.dp))
            Switch(
                checked = cloud,
                onCheckedChange = { on ->
                    scope.launch {
                        ctx.dataStore.edit {
                            it[PrefsKeys.CLOUD] = on
                            if (!on) it.remove(PrefsKeys.VT_KEY)
                        }
                    }
                },
                colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = com.alvand.securityscanner.ui.AccentBlue)
            )
            if (cloud) {
                Spacer(Modifier.height(4.dp))
                var keyInput by remember(vtKey) { mutableStateOf(vtKey) }
                OutlinedTextField(
                    value = keyInput,
                    onValueChange = { keyInput = it },
                    label = { Text(stringResource(R.string.vt_api_key)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(4.dp))
                Surface(
                    onClick = {
                        val v = keyInput.trim()
                        scope.launch { ctx.dataStore.edit { it[PrefsKeys.VT_KEY] = v } }
                    },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    color = com.alvand.securityscanner.ui.AccentBlue,
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(stringResource(R.string.save), color = Color.White, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text("${stringResource(R.string.version)}: $verName ($verCode)", color = com.alvand.securityscanner.ui.TextPrimary())
            Text("com.alvand.securityscanner", fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.about), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Spacer(Modifier.height(8.dp))
            val appIcon = remember(ctx) {
                try {
                    val d = ctx.packageManager.getApplicationIcon(ctx.packageName)
                    val w = d.intrinsicWidth.coerceAtLeast(1).coerceAtMost(512)
                    val h = d.intrinsicHeight.coerceAtLeast(1).coerceAtMost(512)
                    val bmp = android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.ARGB_8888)
                    val c = android.graphics.Canvas(bmp)
                    d.setBounds(0, 0, w, h); d.draw(c)
                    bmp
                } catch (_: Exception) { null }
            }
            if (appIcon != null) {
                Image(
                    appIcon.asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.size(72.dp)
                )
            } else {
                Image(
                    painterResource(R.drawable.ic_logo_placeholder),
                    contentDescription = null,
                    modifier = Modifier.size(72.dp)
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.developed_by), fontSize = 13.sp, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(stringResource(R.string.copyright), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            Spacer(Modifier.height(8.dp))
            Surface(
                onClick = {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/Alvandcode")))
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                color = com.alvand.securityscanner.ui.AccentBlue,
                shape = RoundedCornerShape(14.dp)
            ) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(stringResource(R.string.contact_dev), color = Color.White, fontWeight = FontWeight.SemiBold)
                }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = {
                try { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(TG_CHANNEL))) } catch (_: Exception) { }
            }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.telegram_channel))
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.donate_title), fontWeight = FontWeight.SemiBold, color = com.alvand.securityscanner.ui.TextPrimary())
            Text(stringResource(R.string.donate_desc), fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextSecondary())
            Spacer(Modifier.height(6.dp))
            SelectionContainer {
                Text(TON_ADDR, fontSize = 12.sp, color = com.alvand.securityscanner.ui.TextPrimary())
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Surface(
                    onClick = { clip.setText(AnnotatedString(TON_ADDR)) },
                    modifier = Modifier.weight(1f).height(44.dp),
                    color = com.alvand.securityscanner.ui.AccentBlue,
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(stringResource(R.string.donate_copy), color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                    }
                }
                OutlinedButton(onClick = {
                    try {
                        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("ton://transfer/$TON_ADDR")))
                    } catch (_: Exception) {
                        try { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://tonviewer.io/$TON_ADDR"))) } catch (_: Exception) { }
                    }
                }, modifier = Modifier.weight(1f).height(44.dp)) {
                    Text(stringResource(R.string.donate_open))
                }
            }
        }
        Text(
            stringResource(R.string.copyright),
            fontSize = 11.sp,
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            color = com.alvand.securityscanner.ui.TextSecondary()
        )
    }
}

