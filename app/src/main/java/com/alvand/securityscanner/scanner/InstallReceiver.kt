package com.alvand.securityscanner.scanner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.alvand.securityscanner.data.PrefsKeys
import com.alvand.securityscanner.dataStore
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map

/**
 * Install-time + boot handling. No shell, no root: uses PackageManager only.
 *
 * The heavy work (scanOne + notification) is moved into WorkManager
 * (InstallScanWorker) instead of a bare CoroutineScope inside onReceive:
 * goAsync receivers have ~10s budget, a worker survives process death
 * and gets its own background budget. Each package gets its own uniquely
 * named work, so bursts of installs are all processed.
 */
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> {
                // Reschedule daily scan after reboot if the user enabled it.
                val pending = goAsync()
                ContextCompat.getMainExecutor(context).execute {
                    // Small read; keep off the broadcast main path with a worker instead.
                    WorkManager.getInstance(context).enqueue(
                        OneTimeWorkRequestBuilder<BootRescheduleWorker>().build()
                    )
                    pending.finish()
                }
            }
            Intent.ACTION_PACKAGE_ADDED, Intent.ACTION_PACKAGE_REPLACED -> {
                // Skip our own updates to avoid self-spam.
                val pkg = intent.data?.schemeSpecificPart ?: return
                if (pkg == context.packageName) return
                if (intent.action == Intent.ACTION_PACKAGE_REPLACED) return // updates are less urgent
                val wm = WorkManager.getInstance(context)
                wm.enqueueUniqueWork(
                    "install_scan_$pkg",
                    ExistingWorkPolicy.REPLACE,
                    OneTimeWorkRequestBuilder<InstallScanWorker>()
                        .setInputData(workDataOf(InstallScanWorker.KEY_PACKAGE to pkg))
                        .build()
                )
            }
        }
    }
}

/** Reschedules the daily scan if the user has it enabled. Runs off the receiver. */
class BootRescheduleWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result = try {
        val enabled = applicationContext.dataStore.data
            .map { it[PrefsKeys.SCHED] == true }
            .firstOrNull() == true
        if (enabled) ScanWorker.schedule(applicationContext)
        Result.success()
    } catch (_: Exception) {
        Result.success() // not worth retrying a reschedule
    }
}

/** Real verdict for a newly installed app; notifies only when realtime is on. */
class InstallScanWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result {
        val pkg = inputData.getString(KEY_PACKAGE) ?: return Result.success()
        val ctx = applicationContext
        return try {
            val realtimeOn = ctx.dataStore.data
                .map { it[PrefsKeys.REALTIME] != false } // default ON
                .firstOrNull() ?: true
            if (!realtimeOn) return Result.success()
            val catalog = CatalogReputation.fetch()
            val finding = AppScanner(ctx).scanOne(pkg, catalog)
            when {
                finding == null -> notifyNewApp(ctx, pkg)
                finding.verdict != Verdict.SAFE -> notifyVerdict(ctx, finding)
                else -> notifyNewApp(ctx, pkg)
            }
            Result.success()
        } catch (_: Exception) {
            // Best-effort: a silent fallback ping is better than nothing.
            try { notifyNewApp(ctx, pkg) } catch (_: Exception) { }
            Result.success()
        }
    }

    companion object { const val KEY_PACKAGE = "pkg" }
}
