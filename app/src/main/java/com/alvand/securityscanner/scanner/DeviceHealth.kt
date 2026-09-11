package com.alvand.securityscanner.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File

/**
 * Device-level health signals. No root required, read-only.
 * Replaces the old Python script's `ps/ss/settings put` approach which
 * does not work on non-rooted Android 11+ and falsely promised auto-fix.
 */
data class DeviceHealth(
    val isProbablyRooted: Boolean,
    val rootReasons: List<String>,
    val adbEnabled: Boolean?,
    val devOptionsEnabled: Boolean?,
    val issues: List<String>
)

private val knownRootPackages = setOf(
    "com.topjohnwu.magisk", "com.topjohnwu.magiskhide",
    "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine"
)

private val suPaths = listOf(
    "/system/bin/su", "/system/xbin/su",
    "/sbin/su", "/data/local/xbin/su",
    "/data/local/bin/su", "/system/sd/xbin/su"
)

fun checkDeviceHealth(ctx: Context): DeviceHealth {
    val rootReasons = mutableListOf<String>()
    val pm = ctx.packageManager

    // 1. Known root-manager apps (via PackageManager, no shell needed)
    for (pkg in knownRootPackages) {
        try {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkg, 0)
            rootReasons.add("ROOT_PKG:$pkg")
            break
        } catch (_: PackageManager.NameNotFoundException) { }
    }
    // 2. su binary present (file check only, no exec)
    if (suPaths.any { try { File(it).exists() } catch (_: Exception) { false } }) {
        rootReasons.add("SU_BINARY")
    }
    // 3. test-keys build (emulator/custom ROM)
    if (Build.TAGS?.contains("test-keys") == true) {
        rootReasons.add("TEST_KEYS_BUILD")
    }

    // 4. Security settings (READ is allowed without special permission;
    // WRITE would need WRITE_SECURE_SETTINGS which normal apps don't have,
    // so we only report + deep-link the user to Settings).
    var adb: Boolean? = null
    var dev: Boolean? = null
    try {
        adb = Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    } catch (_: Exception) { }
    try {
        dev = Settings.Global.getInt(
            ctx.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) == 1
    } catch (_: Exception) { }

    val issues = mutableListOf<String>()
    if (rootReasons.isNotEmpty()) issues.add("ROOT_DETECTED")
    if (adb == true) issues.add("ADB_ENABLED")
    if (dev == true) issues.add("DEV_OPTIONS_ENABLED")

    return DeviceHealth(
        isProbablyRooted = rootReasons.isNotEmpty(),
        rootReasons = rootReasons,
        adbEnabled = adb,
        devOptionsEnabled = dev,
        issues = issues
    )
}
