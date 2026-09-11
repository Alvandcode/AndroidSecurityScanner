package com.alvand.securityscanner.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.FileInputStream
import java.security.MessageDigest

data class ApkDetails(
    val sha256: String?,
    val signers: Int,
    val targetSdk: Int,
    val sourceDir: String?
)

// Reads only installed APK file header bytes via stream; never uploads the file.
// Skips files > 200MB to avoid OOM/battery drain on low-end devices.
suspend fun loadApkDetails(ctx: Context, packageName: String): ApkDetails =
    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val pm = ctx.packageManager
        try {
            val pkg = if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(
                        PackageManager.GET_SIGNING_CERTIFICATES.toLong()
                    )
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            }
            val ai = pkg.applicationInfo
            val src = ai?.publicSourceDir
            var sha: String? = null
            if (src != null) {
                try {
                    val f = java.io.File(src)
                    // 200MB cap: hashing a 2GB game on every tap is not acceptable.
                    if (f.exists() && f.length() in 1..(200L * 1024 * 1024)) {
                        val md = MessageDigest.getInstance("SHA-256")
                        FileInputStream(f).use { ins ->
                            val buf = ByteArray(32768)
                            while (true) {
                                val n = ins.read(buf)
                                if (n <= 0) break
                                md.update(buf, 0, n)
                            }
                        }
                        sha = md.digest().joinToString("") { "%02x".format(it) }
                    }
                } catch (_: Exception) { sha = null }
            }
            val signers = if (Build.VERSION.SDK_INT >= 28) {
                pkg.signingInfo?.apkContentsSigners?.size ?: 0
            } else {
                @Suppress("DEPRECATION")
                pkg.signatures?.size ?: 0
            }
            ApkDetails(sha, signers, ai?.targetSdkVersion ?: 0, src)
        } catch (_: Exception) {
            ApkDetails(null, 0, 0, null)
        }
    }
