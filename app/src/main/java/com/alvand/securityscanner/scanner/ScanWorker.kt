package com.alvand.securityscanner.scanner

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.work.*
import com.alvand.securityscanner.data.HistoryDb
import com.alvand.securityscanner.data.PrefsKeys
import com.alvand.securityscanner.dataStore
import kotlinx.coroutines.flow.firstOrNull
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit

class ScanWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result {
        return try {
            val findings = AppScanner(applicationContext).scanAll(includeSystem = false)
            val score = RiskEngine.deviceScore(findings)
            val threats = findings.count { it.verdict == Verdict.DANGEROUS }
            val top = findings.filter { it.verdict != Verdict.SAFE }.take(15)
                .joinToString(";") { "${it.packageName}:${it.score}" }.take(2000)
            val db = HistoryDb.get(applicationContext)
            db.dao().insert(
                com.alvand.securityscanner.data.ScanRecord(
                    timestamp = System.currentTimeMillis(),
                    deviceScore = score, appsScanned = findings.size,
                    threats = threats, summary = top
                )
            )
            db.dao().trim()
            applicationContext.dataStore.edit {
                it[PrefsKeys.LAST_SCORE] = score.toString()
                it[PrefsKeys.LAST_SCAN] = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
            }
            if (threats > 0) notifyScanFinished(applicationContext, score, threats)
            Result.success()
        } catch (_: Exception) {
            Result.retry()
        }
    }

    companion object {
        private const val TAG = "scheduled_scan"
        fun schedule(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<ScanWorker>(24, TimeUnit.HOURS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiresBatteryNotLow(true)
                        .build()
                )
                .addTag(TAG).build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(TAG, ExistingPeriodicWorkPolicy.UPDATE, req)
        }
        fun cancel(ctx: Context) = WorkManager.getInstance(ctx).cancelUniqueWork(TAG)
    }
}
