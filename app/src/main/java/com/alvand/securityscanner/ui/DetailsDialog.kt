package com.alvand.securityscanner.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ThumbDown
import androidx.compose.material.icons.filled.ThumbUp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.alvand.securityscanner.R
import com.alvand.securityscanner.dataStore
import com.alvand.securityscanner.data.PrefsKeys
import com.alvand.securityscanner.scanner.AppFinding
import com.alvand.securityscanner.scanner.ApkDetails
import com.alvand.securityscanner.scanner.loadApkDetails
import com.alvand.securityscanner.scanner.lookupVirusTotal
import com.alvand.securityscanner.scanner.parseVtVerdict
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * App details, verdict-first: NO verbose explanations or per-engine lists —
 * a positive/negative percentage gauge plus counts of clean vs flagged scan
 * results (like a sentiment gauge: big green % / big red %, split bar).
 */
@Composable
fun DetailsDialog(f: AppFinding, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val clip = LocalClipboardManager.current
    var det by remember { mutableStateOf<ApkDetails?>(null) }
    var vt by remember { mutableStateOf<String?>(null) }
    var checking by remember { mutableStateOf(false) }
    val cloud by ctx.dataStore.data.map { it[PrefsKeys.CLOUD] == true }.collectAsState(false)
    val vtKey by ctx.dataStore.data.map { it[PrefsKeys.VT_KEY] ?: "" }.collectAsState("")

    LaunchedEffect(f.packageName) { det = loadApkDetails(ctx, f.packageName) }

    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(f.appName, fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(f.packageName, fontSize = 11.sp, color = TextSecondary())

                // ---- Positive/Negative gauge (no explanations, just numbers) ----
                VerdictGauge(positive = f.score)

                // Counts of positive/negative scan results (Idol Catalog engines).
                if (f.catalogStatus != null && (f.catalogEnginesClean > 0 || f.catalogEnginesIssues > 0)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.ThumbUp, contentDescription = null,
                            tint = GlowSafe, modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            "${stringResource(R.string.engines_clean)}: ${f.catalogEnginesClean}",
                            fontSize = 13.sp, color = GlowSafe, fontWeight = FontWeight.SemiBold
                        )
                        Spacer(Modifier.width(14.dp))
                        Icon(
                            Icons.Default.ThumbDown, contentDescription = null,
                            tint = GlowDanger, modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            "${stringResource(R.string.engines_issues)}: ${f.catalogEnginesIssues}",
                            fontSize = 13.sp, color = GlowDanger, fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                // VirusTotal counts only (e.g. "منفی: 3 از 92").
                if (vt != null) {
                    val vtp = parseVtVerdict(vt)
                    if (vtp != null) {
                        val (flagged, total) = vtp
                        Text(
                            "VirusTotal — ${stringResource(R.string.negative)}: $flagged / $total",
                            fontSize = 13.sp,
                            color = if (flagged > 0) GlowDanger else GlowSafe
                        )
                    } else {
                        Text("VirusTotal: $vt", fontSize = 12.sp, color = TextSecondary())
                    }
                }

                // Compact facts (one line each, no explanation paragraphs).
                val installerFriendly = com.alvand.securityscanner.scanner.RiskEngine.installerLabel(f.installer)
                Text("${stringResource(R.string.installer)}: $installerFriendly", fontSize = 12.sp)
                val target = det?.targetSdk
                if (target != null && target < 29 && !f.isSystemApp) {
                    Text(stringResource(R.string.target_sdk_old_warn), fontSize = 11.sp, color = GlowWarn)
                }
                Text("${stringResource(R.string.signatures)}: ${det?.signers ?: "…"}", fontSize = 12.sp)
                if (f.riskyPermissions.isNotEmpty()) {
                    Text(
                        "${stringResource(R.string.risky_permissions)}: ${f.riskyPermissions.size}",
                        fontSize = 12.sp, color = GlowWarn
                    )
                }
                SelectionContainer {
                    Text("${stringResource(R.string.sha256)}:\n${det?.sha256 ?: "…"}", fontSize = 11.sp)
                }
                if (cloud && vtKey.isNotBlank()) {
                    Button(
                        onClick = {
                            val sha = det?.sha256 ?: return@Button
                            scope.launch {
                                checking = true
                                vt = lookupVirusTotal(sha, vtKey) ?: "error/offline"
                                checking = false
                            }
                        },
                        enabled = !checking && det?.sha256 != null
                    ) { Text(if (checking) "…" else stringResource(R.string.check_online)) }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                clip.setText(AnnotatedString(det?.sha256 ?: f.packageName))
            }) { Text(stringResource(R.string.copy)) }
        },
        dismissButton = {
            TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
        }
    )
}

/**
 * Sentiment-style gauge: two big chips (red % negative, green % positive)
 * over a green/red split bar. Mirrors the neon dashboard reference.
 */
@Composable
fun VerdictGauge(positive: Int) {
    val pos = positive.coerceIn(0, 100)
    val neg = 100 - pos
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            GaugeChip(
                Modifier.weight(1f), color = GlowDanger,
                icon = { Icon(Icons.Default.ThumbDown, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp)) },
                value = "$neg%", label = stringResource(R.string.negative)
            )
            GaugeChip(
                Modifier.weight(1f), color = GlowSafe,
                icon = { Icon(Icons.Default.ThumbUp, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp)) },
                value = "$pos%", label = stringResource(R.string.positive)
            )
        }
        // Split bar
        Row(
            Modifier
                .fillMaxWidth()
                .height(10.dp)
                .clip(RoundedCornerShape(5.dp))
        ) {
            Box(
                Modifier
                    .weight(pos.coerceAtLeast(0.01f))
                    .fillMaxHeight()
                    .background(GlowDanger)
            )
            Box(
                Modifier
                    .weight(neg.coerceAtLeast(0.01f))
                    .fillMaxHeight()
                    .background(GlowSafe)
            )
        }
    }
}

@Composable
private fun GaugeChip(
    modifier: Modifier,
    color: Color,
    icon: @Composable () -> Unit,
    value: String,
    label: String
) {
    Row(
        modifier
            .clip(RoundedCornerShape(14.dp))
            .background(color.copy(alpha = 0.14f))
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(26.dp)
                .background(color, CircleShape),
            contentAlignment = Alignment.Center
        ) { icon() }
        Spacer(Modifier.width(8.dp))
        Text(value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = color)
        Spacer(Modifier.width(6.dp))
        Text(label, fontSize = 12.sp, color = TextSecondary())
    }
}
