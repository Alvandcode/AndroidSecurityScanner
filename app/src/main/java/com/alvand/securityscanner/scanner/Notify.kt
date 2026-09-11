package com.alvand.securityscanner.scanner

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.alvand.securityscanner.MainActivity
import com.alvand.securityscanner.R

private const val CH = "scan_events"

fun ensureChannel(ctx: Context) {
    if (Build.VERSION.SDK_INT < 26) return
    val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
    if (nm.getNotificationChannel(CH) == null) {
        nm.createNotificationChannel(
            NotificationChannel(CH, "Scan events", NotificationManager.IMPORTANCE_DEFAULT)
        )
    }
}

private fun openIntent(ctx: Context): PendingIntent {
    val i = Intent(ctx, MainActivity::class.java).apply { flags = Intent.FLAG_ACTIVITY_SINGLE_TOP }
    return PendingIntent.getActivity(ctx, 0, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
}

fun hasNotifPermission(ctx: Context): Boolean {
    if (Build.VERSION.SDK_INT < 33) return true
    return ctx.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
}

fun notifyScanFinished(ctx: Context, score: Int, threats: Int) {
    // Caller decides when to call; Worker only calls on threats>0.
    // Still guard the runtime permission so we never crash on Android 13+.
    if (!hasNotifPermission(ctx)) return
    ensureChannel(ctx)
    val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
    val title = ctx.getString(R.string.device_score) + ": $score/100"
    val text = ctx.getString(R.string.threats) + ": $threats"
    nm.notify(
        1001,
        NotificationCompat.Builder(ctx, CH)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title).setContentText(text)
            .setContentIntent(openIntent(ctx)).setAutoCancel(true).build()
    )
}

fun notifyNewApp(ctx: Context, pkg: String) {
    if (!hasNotifPermission(ctx)) return
    ensureChannel(ctx)
    val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
    nm.notify(
        1002,
        NotificationCompat.Builder(ctx, CH)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(pkg)
            .setContentText(ctx.getString(R.string.tap_to_scan))
            .setContentIntent(openIntent(ctx)).setAutoCancel(true).build()
    )
}

fun notifyVerdict(ctx: Context, f: AppFinding) {
    if (!hasNotifPermission(ctx)) return
    ensureChannel(ctx)
    val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
    val verdict = when (f.verdict) {
        Verdict.DANGEROUS -> ctx.getString(R.string.dangerous)
        Verdict.REVIEW -> ctx.getString(R.string.review_needed)
        else -> ctx.getString(R.string.safe)
    }
    nm.notify(
        1003,
        NotificationCompat.Builder(ctx, CH)
            .setSmallIcon(
                if (f.verdict == Verdict.SAFE) android.R.drawable.ic_dialog_info
                else android.R.drawable.ic_dialog_alert
            )
            .setContentTitle("${f.appName} — $verdict (${f.score}/100)")
            .setContentText(f.packageName)
            .setContentIntent(openIntent(ctx)).setAutoCancel(true).build()
    )
}
