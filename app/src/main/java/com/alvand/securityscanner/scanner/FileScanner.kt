package com.alvand.securityscanner.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import kotlin.coroutines.coroutineContext

/**
 * File-system scan WITHOUT root.
 *
 * Honest scope: on Android 10+ an ordinary app can only see:
 *  - its own app-specific dirs (no permission needed)
 *  - media via MediaStore (with READ_MEDIA_*), and
 *  - whatever folder the USER explicitly grants via SAF (OpenDocumentTree).
 * System dirs (/data, other apps' private dirs) are NOT visible — and any
 * tool claiming otherwise without root/MDM is lying.
 *
 * This scanner walks the user-granted tree, hashes files (cap 150MB),
 * parses sideloaded APKs via PackageManager.getPackageArchiveInfo (no apktool),
 * and reports SAFE / REVIEW (مشکوک) / DANGEROUS (آلوده) with reasons.
 * The user decides what to do (delete/share/uninstall) — we never auto-delete.
 */

enum class FileVerdict { SAFE, REVIEW, DANGEROUS }

data class FileFinding(
    val displayName: String,
    val uriString: String,
    val mime: String?,
    val size: Long,
    val sha256: String?,
    val verdict: FileVerdict,
    val reasons: List<String>,
    val isApk: Boolean,
    val apkPackage: String?,
    val score: Int // 0..100, 100 = safe (same scale as apps)
)

data class FileScanProgress(val done: Int, val total: Int, val currentName: String)
data class FileScanResult(
    val files: List<FileFinding>,
    val truncated: Boolean
) {
    val safe: Int get() = files.count { it.verdict == FileVerdict.SAFE }
    val review: Int get() = files.count { it.verdict == FileVerdict.REVIEW }
    val dangerous: Int get() = files.count { it.verdict == FileVerdict.DANGEROUS }
}

private const val MAX_FILES = 2000
private const val MAX_DEPTH = 6
private const val MAX_HASH_BYTES = 150L * 1024 * 1024
private const val MAX_APK_COPY_BYTES = 120L * 1024 * 1024

private val apkExts = setOf("apk", "apks", "xapk")
private val execExts = setOf("sh", "bin", "exe", "msi", "bat", "cmd", "dex", "so", "jar", "py", "js")
private val suspiciousNameKeys = listOf(
    "spy", "hack", "crack", "keylog", "stealth", "trojan",
    "free_", "_free", "modded", "premium_unlocked", "smsforward", "callrecord"
)

object FileScanner {

    suspend fun scanTree(
        ctx: Context,
        treeUri: Uri,
        onProgress: (FileScanProgress) -> Unit = {}
    ): FileScanResult = withContext(Dispatchers.IO) {
        val out = mutableListOf<FileFinding>()
        var truncated = false

        val root = try {
            DocumentFile.fromTreeUri(ctx, treeUri)
        } catch (_: Exception) { null } ?: return@withContext FileScanResult(emptyList(), true)

        // Flatten with BFS + depth cap (DFS recursion can overflow on weird trees).
        val queue: ArrayDeque<Pair<DocumentFile, Int>> = ArrayDeque()
        queue.add(root to 0)
        val flat: ArrayList<DocumentFile> = ArrayList()

        while (queue.isNotEmpty() && flat.size < MAX_FILES) {
            if (!coroutineContext.isActive) break
            val (dir, depth) = queue.removeFirst()
            val children: Array<DocumentFile> = try {
                dir.listFiles()
            } catch (_: Exception) { emptyArray() }
            for (c in children) {
                if (flat.size + queue.size >= MAX_FILES) { truncated = true; break }
                try {
                    if (c.isDirectory && depth < MAX_DEPTH) {
                        queue.add(c to depth + 1)
                    } else if (c.isFile) {
                        flat.add(c)
                    }
                } catch (_: Exception) { }
            }
            if (truncated) break
        }
        if (flat.size >= MAX_FILES) truncated = true

        for ((i, doc) in flat.withIndex()) {
            ensureActive() // Stop button cancels promptly (throws CancellationException)
            val name = try { doc.name ?: "?" } catch (_: Exception) { "?" }
            try { onProgress(FileScanProgress(i + 1, flat.size, name)) } catch (_: Exception) { }
            try {
                out.add(analyzeOne(ctx, doc))
            } catch (_: Exception) {
                out.add(
                    FileFinding(name, doc.uri.toString(), null, -1, null, FileVerdict.SAFE, emptyList(), false, null, 100)
                )
            }
        }
        // Most dangerous first, same ordering as app list.
        FileScanResult(out.sortedBy { it.score }, truncated)
    }

    private suspend fun analyzeOne(ctx: Context, doc: DocumentFile): FileFinding {
        val uri = doc.uri
        val name = try { doc.name ?: "unknown" } catch (_: Exception) { "unknown" }
        val size = try { doc.length() } catch (_: Exception) { -1L }
        val mime = try { doc.type } catch (_: Exception) { null }
        val lower = name.lowercase()
        val ext = lower.substringAfterLast('.', "")
        val isApk = ext in apkExts

        var deduction = 0
        val reasons = mutableListOf<String>()

        // --- Generic file heuristics (extension / name / size) ---
        if (!isApk && ext in execExts) {
            deduction += 12; reasons.add("EXECUTABLE_EXT")
        }
        // Double extension trick: invoice.pdf.apk / photo.jpg.exe
        val parts = lower.split('.')
        if (parts.size >= 3) {
            val inner = parts[parts.size - 2]
            if (inner in setOf("pdf", "jpg", "jpeg", "png", "mp4", "mp3", "doc", "docx", "xls", "zip") && (isApk || ext in execExts)) {
                deduction += 15; reasons.add("DOUBLE_EXTENSION")
            }
        }
        if (name.startsWith(".")) { deduction += 4; reasons.add("HIDDEN_FILE") }
        if (suspiciousNameKeys.any { lower.contains(it) }) { deduction += 8; reasons.add("SUSPICIOUS_NAME") }
        if (size >= 0 && isApk) {
            if (size < 50L * 1024) { deduction += 8; reasons.add("APK_TOO_SMALL") }
            if (size > 500L * 1024 * 1024) { deduction += 6; reasons.add("APK_HUGE") }
        }

        // --- Hash (bounded) ---
        val sha = hashUri(ctx, uri, MAX_HASH_BYTES)
        if (sha != null && KnownBadHashes.contains(sha.lowercase())) {
            deduction += 60; reasons.add("KNOWN_MALWARE_HASH")
        }

        // --- APK deep parse via PackageManager (no apktool, no root) ---
        var apkPkg: String? = null
        if (isApk && size in 1..MAX_APK_COPY_BYTES) {
            val parsed = parseApkCopy(ctx, uri)
            if (parsed != null) {
                apkPkg = parsed.packageName
                val (ascore, averdict, areasons) = RiskEngine.score(
                    perms = parsed.perms,
                    unknownSource = true, // a loose file has no trusted installer
                    isDebuggable = parsed.debuggable,
                    isSystemApp = false,
                    targetSdk = parsed.targetSdk
                )
                // Merge: APK permission risk dominates file risk.
                val apkDeduction = 100 - ascore
                deduction += apkDeduction
                reasons.addAll(areasons.map { "APK:$it" })
                if (averdict == Verdict.DANGEROUS) reasons.add("APK_DANGEROUS_PERMS")
            } else {
                // Unparsable APK = corrupted or deliberately malformed.
                deduction += 10; reasons.add("APK_UNPARSABLE")
            }
        } else if (isApk && size > MAX_APK_COPY_BYTES) {
            reasons.add("APK_TOO_BIG_TO_PARSE")
        }

        val score = (100 - deduction).coerceIn(0, 100)
        val verdict = when {
            score >= 80 -> FileVerdict.SAFE
            score >= 50 -> FileVerdict.REVIEW
            else -> FileVerdict.DANGEROUS
        }
        return FileFinding(
            displayName = name, uriString = uri.toString(), mime = mime,
            size = size, sha256 = sha, verdict = verdict, reasons = reasons,
            isApk = isApk, apkPackage = apkPkg, score = score
        )
    }

    private fun hashUri(ctx: Context, uri: Uri, cap: Long): String? {
        return try {
            val cr = ctx.contentResolver
            cr.openInputStream(uri)?.use { ins ->
                val md = MessageDigest.getInstance("SHA-256")
                val buf = ByteArray(32768)
                var total = 0L
                while (true) {
                    val n = ins.read(buf)
                    if (n <= 0) break
                    total += n
                    if (total > cap) return null // too big: skip hash, don't OOM
                    md.update(buf, 0, n)
                }
                md.digest().joinToString("") { "%02x".format(it) }
            }
        } catch (_: Exception) { null }
    }

    private data class ParsedApk(
        val packageName: String, val perms: List<String>,
        val debuggable: Boolean, val targetSdk: Int
    )

    private fun parseApkCopy(ctx: Context, uri: Uri): ParsedApk? {
        var tmp: File? = null
        return try {
            val cr = ctx.contentResolver
            tmp = File.createTempFile("scan_", ".apk", ctx.cacheDir)
            cr.openInputStream(uri)?.use { ins ->
                tmp.outputStream().use { out ->
                    val buf = ByteArray(32768)
                    var total = 0L
                    while (true) {
                        val n = ins.read(buf)
                        if (n <= 0) break
                        total += n
                        if (total > MAX_APK_COPY_BYTES) return null
                        out.write(buf, 0, n)
                    }
                }
            } ?: return null
            val pm = ctx.packageManager
            val info = if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageArchiveInfo(
                    tmp.absolutePath,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageArchiveInfo(tmp.absolutePath, PackageManager.GET_PERMISSIONS)
            } ?: return null
            val ai = info.applicationInfo
            ParsedApk(
                packageName = info.packageName ?: "?",
                perms = info.requestedPermissions?.toList() ?: emptyList(),
                debuggable = ai != null && (ai.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                targetSdk = ai?.targetSdkVersion ?: 0
            )
        } catch (_: Exception) { null } finally {
            try { tmp?.delete() } catch (_: Exception) { }
        }
    }

    /** Delete a previously found file via its SAF uri. Returns true if gone. */
    fun deleteByUri(ctx: Context, uriString: String): Boolean {
        return try {
            val uri = Uri.parse(uriString)
            val doc = DocumentFile.fromSingleUri(ctx, uri)
                ?: return false
            // fromSingleUri.delete() respects the persisted tree permission.
            doc.delete()
        } catch (_: Exception) { false }
    }

    fun displaySize(bytes: Long): String {
        if (bytes < 0) return "?"
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(java.util.Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(java.util.Locale.US, "%.1f MB", mb)
        return String.format(java.util.Locale.US, "%.2f GB", mb / 1024.0)
    }
}

/**
 * Local known-bad SHA-256 set. Ships empty; OTA/cloud can fill it later.
 * (Deliberately NOT hardcoding the old Python script's empty-file hash.)
 */
object KnownBadHashes {
    val hashes: Set<String> = emptySet()
    fun contains(sha: String): Boolean = hashes.contains(sha)
}

/** Persisted SAF tree helpers. */
fun takePersistableTree(ctx: Context, uri: Uri) {
    try {
        val flags = android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or
                android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        ctx.contentResolver.takePersistableUriPermission(uri, flags)
    } catch (_: Exception) {
        // Read-only trees (some providers) throw on WRITE take; retry read-only.
        try {
            ctx.contentResolver.takePersistableUriPermission(
                uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: Exception) { }
    }
}

fun hasPersistedTree(ctx: Context, uri: Uri): Boolean {
    return try {
        ctx.contentResolver.persistedUriPermissions.any { it.uri == uri && it.isReadPermission }
    } catch (_: Exception) { false }
}
