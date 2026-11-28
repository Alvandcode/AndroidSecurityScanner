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

val Context.dataStore by preferencesDataStore("settings")


class MainActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(applyLocale(newBase))
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val ctx = LocalContext.current
            val theme by ctx.dataStore.data.map { it[PrefsKeys.THEME] ?: "system" }.collectAsState("system")
            val lang by ctx.dataStore.data.map { it[PrefsKeys.LANG] ?: "system" }.collectAsState("system")
            AppTheme(theme) {
                GlassBackground(androidx.compose.foundation.isSystemInDarkTheme() || theme == "dark") {
                    MainTabs(theme, lang)
                }
            }
        }
    }

    companion object {
        fun applyLocale(c: Context): Context {
            // FIX: never runBlocking(DataStore) on the main thread (ANR).
            // Language is mirrored to SharedPreferences "events/ui_lang" on every
            // change in Settings, so attachBaseContext stays synchronous.
            val lang = try {
                c.getSharedPreferences("events", MODE_PRIVATE).getString("ui_lang", "system")
            } catch (_: Exception) { "system" }
            if (lang == null || lang == "system") return c
            val locale = Locale(if (lang == "fa") "fa" else "en")
            Locale.setDefault(locale)
            val cfg = c.resources.configuration
            cfg.setLocale(locale)
            cfg.setLayoutDirection(locale)
            return c.createConfigurationContext(cfg)
        }
    }
}

@Composable
fun MainTabs(theme: String, lang: String) {
    var tab by remember { mutableIntStateOf(0) }
    val vm: ScanViewModel = viewModel()
    val ctx0 = LocalContext.current
    LaunchedEffect(Unit) {
        try {
            val saved = ctx0.dataStore.data.map { it[PrefsKeys.FILE_TREE] }.firstOrNull()
            if (!saved.isNullOrBlank()) vm.setTreeUri(saved)
        } catch (_: Exception) { }
    }
    Scaffold(
        containerColor = androidx.compose.ui.graphics.Color.Transparent,
        bottomBar = {
            Surface(
                color = MaterialTheme.colorScheme.surface,
                shadowElevation = 16.dp,
                shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
            ) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    BottomTab(
                        selected = tab == 0, icon = Icons.Default.Home,
                        label = stringResource(R.string.dashboard), onClick = { tab = 0 }
                    )
                    BottomTab(
                        selected = tab == 1, icon = Icons.Default.Folder,
                        label = stringResource(R.string.files), onClick = { tab = 1 }
                    )
                    Box(contentAlignment = Alignment.Center) {
                        FloatingActionButton(
                            onClick = { tab = 2; vm.scanAll(ctx0) },
                            containerColor = com.alvand.securityscanner.ui.AccentBlue,
                            contentColor = Color.White,
                            shape = CircleShape,
                            modifier = Modifier.size(62.dp).offset(y = (-8).dp),
                            elevation = FloatingActionButtonDefaults.elevation(8.dp)
                        ) {
                            Icon(Icons.Default.GpsFixed, contentDescription = null, modifier = Modifier.size(28.dp))
                        }
                    }
                    BottomTab(
                        selected = tab == 3, icon = Icons.Default.History,
                        label = stringResource(R.string.history), onClick = { tab = 3 }
                    )
                    BottomTab(
                        selected = tab == 4, icon = Icons.Default.Settings,
                        label = stringResource(R.string.settings), onClick = { tab = 4 }
                    )
                }
            }
        }
    ) { pad ->
        Box(Modifier.padding(pad)) {
            when (tab) {
                0 -> HomeScreen(vm, onScan = { tab = 2 }, onSettings = { tab = 4 }, onHistory = { tab = 3 })
                1 -> FilesScreen(vm)
                2 -> ScanScreen(vm, onBack = { tab = 0 })
                3 -> HistoryList(vm)
                4 -> SettingsScreen(theme, lang)
                else -> HomeScreen(vm, onScan = { tab = 2 }, onSettings = { tab = 4 }, onHistory = { tab = 3 })
            }
        }
    }
}

@Composable
fun BottomTab(
    selected: Boolean,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit
) {
    val tint = if (selected) com.alvand.securityscanner.ui.AccentBlue else MaterialTheme.colorScheme.onSurfaceVariant
    Column(
        Modifier.clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(26.dp))
        Spacer(Modifier.height(2.dp))
        Text(label, fontSize = 11.sp, color = tint, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
    }
}

