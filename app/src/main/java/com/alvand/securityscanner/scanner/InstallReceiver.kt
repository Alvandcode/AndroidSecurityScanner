package com.alvand.securityscanner.scanner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.alvand.securityscanner.data.PrefsKeys
import com.alvand.securityscanner.dataStore
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

// Install-time + boot handling. No shell, no root: uses PackageManager only.
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        // Reschedule daily scan after reboot if the user enabled it.
        if (action == Intent.ACTION_BOOT_COMPLETED) {
            val pending = goAsync()
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    val enabled = context.dataStore.data
                        .map { it[PrefsKeys.SCHED] == true }
                        .firstOrNull() == true
                    if (enabled) ScanWorker.schedule(context)
                } catch (_: Exception) { } finally { pending.finish() }
            }
            return
        }
        if (action != Intent.ACTION_PACKAGE_ADDED && action != Intent.ACTION_PACKAGE_REPLACED) return
        // REPLACED (update) is less urgent than ADDED; still record it.
        val isUpdate = action == Intent.ACTION_PACKAGE_REPLACED
        // Skip our own updates to avoid self-spam.
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == context.packageName) return
        try {
            context.getSharedPreferences("events", Context.MODE_PRIVATE)
                .edit().putString("last_installed", pkg).apply()
        } catch (_: Exception) { }
        if (isUpdate) return
        // Real verdict for the new app (off the main thread).
        val pending = goAsync()
        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            try {
                val finding = AppScanner(context.applicationContext).scanOne(pkg)
                if (finding != null && finding.verdict != Verdict.SAFE) {
                    notifyVerdict(context, finding)
                } else {
                    notifyNewApp(context, pkg)
                }
            } catch (_: Exception) {
                try { notifyNewApp(context, pkg) } catch (_: Exception) { }
            } finally { pending.finish() }
        }
    }
}
