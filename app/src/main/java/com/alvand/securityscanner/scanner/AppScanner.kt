package com.alvand.securityscanner.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class AppScanner(private val context: Context) {

    data class Progress(val done: Int, val total: Int)

    suspend fun scanAll(
        includeSystem: Boolean = false,
        onProgress: (Progress) -> Unit = {}
    ): List<AppFinding> = withContext(Dispatchers.Default) {
        val pm = context.packageManager
        val pkgs: List<PackageInfo> = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        val out = mutableListOf<AppFinding>()
        pkgs.forEachIndexed { i, pkg ->
            val ai = pkg.applicationInfo ?: return@forEachIndexed
            val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem && !includeSystem) { onProgress(Progress(i + 1, pkgs.size)); return@forEachIndexed }

            val perms: List<String> = pkg.requestedPermissions?.toList() ?: emptyList()
            val installer: String? = try {
                if (Build.VERSION.SDK_INT >= 30) {
                    pm.getInstallSourceInfo(pkg.packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(pkg.packageName)
                }
            } catch (_: Exception) { null }

            val trustedInstallers = RiskEngine.trustedInstallers
            val unknownSource = installer == null || installer !in trustedInstallers

            val debuggable = (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val targetSdk = ai.targetSdkVersion
            val (score, verdict, reasons) = RiskEngine.score(perms, unknownSource, debuggable, isSystem, targetSdk)

            val risky = perms.map { it.substringAfterLast('.') }
                .distinct()
                .mapNotNull { short ->
                    RiskEngine.weights[short]?.let {
                        RiskyPermission(short, it, faDesc(short), enDesc(short))
                    }
                }

            out.add(
                AppFinding(
                    packageName = pkg.packageName,
                    appName = pm.getApplicationLabel(ai)?.toString() ?: pkg.packageName,
                    versionName = pkg.versionName,
                    installer = installer,
                    isSystemApp = isSystem,
                    isDebuggable = debuggable,
                    riskyPermissions = risky,
                    unknownSource = unknownSource && !isSystem,
                    score = score,
                    verdict = verdict,
                    reasons = reasons
                )
            )
            onProgress(Progress(i + 1, pkgs.size))
        }
        out.sortedBy { it.score }
    }

    /** Lightweight single-package scan for install-time alerts. */
    suspend fun scanOne(packageName: String): AppFinding? = withContext(Dispatchers.Default) {
        try {
            val pm = context.packageManager
            val pkg: PackageInfo = if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }
            val ai = pkg.applicationInfo ?: return@withContext null
            val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            val perms: List<String> = pkg.requestedPermissions?.toList() ?: emptyList()
            val installer: String? = try {
                if (Build.VERSION.SDK_INT >= 30) {
                    pm.getInstallSourceInfo(packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(packageName)
                }
            } catch (_: Exception) { null }
            val unknownSource = installer == null || installer !in RiskEngine.trustedInstallers
            val debuggable = (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val (score, verdict, reasons) = RiskEngine.score(
                perms, unknownSource, debuggable, isSystem, ai.targetSdkVersion
            )
            val risky = perms.map { it.substringAfterLast('.') }.distinct()
                .mapNotNull { short ->
                    RiskEngine.weights[short]?.let {
                        RiskyPermission(short, it, faDesc(short), enDesc(short))
                    }
                }
            AppFinding(
                packageName = pkg.packageName ?: packageName,
                appName = pm.getApplicationLabel(ai)?.toString() ?: packageName,
                versionName = pkg.versionName,
                installer = installer,
                isSystemApp = isSystem,
                isDebuggable = debuggable,
                riskyPermissions = risky,
                unknownSource = unknownSource && !isSystem,
                score = score,
                verdict = verdict,
                reasons = reasons
            )
        } catch (_: Exception) { null }
    }

    private fun faDesc(p: String) = when (p) {
        "SEND_SMS" -> "ارسال پیامک"
        "READ_SMS", "RECEIVE_SMS" -> "خواندن پیامک"
        "BIND_ACCESSIBILITY_SERVICE" -> "دسترسی دسترس‌پذیری (حساس)"
        "BIND_DEVICE_ADMIN" -> "مدیریت دستگاه"
        "REQUEST_INSTALL_PACKAGES" -> "نصب بسته‌ها"
        "SYSTEM_ALERT_WINDOW" -> "نمایش روی سایر برنامه‌ها"
        "CAMERA" -> "دوربین"
        "RECORD_AUDIO" -> "ضبط صدا"
        "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION" -> "موقعیت مکانی"
        else -> p
    }

    private fun enDesc(p: String) = p.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() }
}
