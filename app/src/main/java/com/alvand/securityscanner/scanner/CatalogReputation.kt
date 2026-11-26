package com.alvand.securityscanner.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Idol Store Catalog reputation engine.
 *
 * Source: https://github.com/Alvandcode/idol-store-catalog
 * The catalog CI runs ClamAV + OSV-Scanner + YARA + Semgrep + Gitleaks +
 * binary inspection on each app's source archive and release assets, then
 * publishes `security-results.json` at the raw URL below.
 *
 * Privacy: this is a READ-ONLY public JSON download. Nothing is uploaded,
 * no device identifier is sent, and no VirusTotal quota is consumed.
 *
 * Honest semantics (same as the catalog itself):
 *  - SAFE / LOW_RISK  = configured scanners completed and found nothing
 *  - WARNING          = needs human review (vulns / suspicious patterns)
 *  - DANGEROUS        = malware with credible evidence
 *  - INCOMPLETE / SCAN_ERROR / NOT_SCANNED = NOT a clean result — we must
 *    never treat them as "safe".
 */
data class CatalogApp(
    val id: String,                 // applicationId (e.g. com.idol.store)
    val name: String,
    val status: String,             // one of APP_STATUSES
    val riskLevel: String,
    val releaseVersion: String,
    val githubRepository: String,
    val detections: List<String>,
    val warnings: List<String>
)

data class CatalogAsset(
    val name: String,
    val status: String,             // one of ASSET_STATUSES
    val sha256: String?,
    val appStatus: String? = null   // overall_status of the app the asset belongs to
)

data class CatalogData(
    val generatedAt: String,
    val scannerVersion: String,
    val apps: Map<String, CatalogApp>,          // key: lowercase package id
    val assets: Map<String, CatalogAsset>       // key: lowercase sha256
) {
    fun appFor(packageName: String): CatalogApp? = apps[packageName.lowercase()]
    fun assetFor(sha256: String): CatalogAsset? = assets[sha256.lowercase()]
}

object CatalogStatus {
    const val SAFE = "SAFE"
    const val LOW_RISK = "LOW_RISK"
    const val WARNING = "WARNING"
    const val DANGEROUS = "DANGEROUS"
    const val INCOMPLETE = "INCOMPLETE"
    const val NOT_SCANNED = "NOT_SCANNED"
    const val SCAN_ERROR = "SCAN_ERROR"

    // Asset-level
    const val A_NO_DETECTION = "no_detection"
    const val A_MALWARE = "malware_detected"
    const val A_SUSPICIOUS = "suspicious_content"
}

object CatalogReputation {
    const val RESULTS_URL =
        "https://raw.githubusercontent.com/Alvandcode/idol-store-catalog/main/security-results.json"
    private const val HTTP_TIMEOUT = 15_000

    // In-memory TTL cache: avoid re-downloading on every scan.
    private const val TTL_MS = 6L * 60 * 60 * 1000   // 6 hours
    @Volatile private var cached: CatalogData? = null
    @Volatile private var cachedAt = 0L
    private val mutex = Mutex()

    /** Returns cached data if fresh; forces a refresh when [force] is set. */
    suspend fun fetch(force: Boolean = false): CatalogData? = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        if (!force) {
            cached?.let { if (now - cachedAt < TTL_MS) return@withContext it }
        }
        mutex.withLock {
            // Double-check inside the lock.
            cached?.let { if (System.currentTimeMillis() - cachedAt < TTL_MS) return@withContext it }
            val data = downloadAndParse()
            if (data != null) {
                cached = data
                cachedAt = System.currentTimeMillis()
                // Feed the local known-bad set so file scans benefit even
                // when callers don't thread CatalogData through.
                KnownBadHashes.replaceAll(data.assets.entries
                    .filter { it.value.status == CatalogStatus.A_MALWARE }
                    .map { it.key.lowercase() })
            }
            data
        }
    }

    fun cachedOrNull(): CatalogData? = cached

    private fun downloadAndParse(): CatalogData? {
        return try {
            val c = (URL(RESULTS_URL).openConnection() as HttpsURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = HTTP_TIMEOUT
                readTimeout = HTTP_TIMEOUT
                setRequestProperty("Accept", "application/json")
            }
            if (c.responseCode != 200) return null
            val body = c.inputStream.bufferedReader().readText()
            parse(body)
        } catch (_: Exception) {
            null
        }
    }

    /** Visible for tests. */
    fun parse(body: String): CatalogData {
        val root = JSONObject(body)
        val results = root.optJSONArray("results") ?: org.json.JSONArray()
        val apps = mutableMapOf<String, CatalogApp>()
        val assets = mutableMapOf<String, CatalogAsset>()
        for (i in 0 until results.length()) {
            val r = results.optJSONObject(i) ?: continue
            val id = r.optString("id", "")
            if (id.isBlank()) continue
            val status = r.optString("overall_status", CatalogStatus.NOT_SCANNED)
            val detections = mutableListOf<String>()
            r.optJSONArray("detections")?.let { arr ->
                for (j in 0 until arr.length()) {
                    val d = arr.optJSONObject(j)
                    detections.add(
                        d?.optString("signature", null) ?: (arr.optString(j).take(120))
                    )
                }
            }
            val warnings = mutableListOf<String>()
            r.optJSONArray("warnings")?.let { arr ->
                for (j in 0 until arr.length()) {
                    val w = arr.optJSONObject(j)
                    warnings.add(
                        w?.optString("message", null) ?: (arr.optString(j).take(120))
                    )
                }
            }
            apps[id.lowercase()] = CatalogApp(
                id = id,
                name = r.optString("name", id),
                status = status,
                riskLevel = r.optString("risk_level", "unknown"),
                releaseVersion = r.optString("release_version", ""),
                githubRepository = r.optString("github_repository", ""),
                detections = detections,
                warnings = warnings
            )
            val assetArr = r.optJSONArray("scanned_assets") ?: continue
            for (j in 0 until assetArr.length()) {
                val a = assetArr.optJSONObject(j) ?: continue
                val sha = a.optString("sha256", "")
                if (sha.length != 64) continue   // only hashed assets are usable
                assets[sha.lowercase()] = CatalogAsset(
                    name = a.optString("name", ""),
                    status = a.optString("status", "download_or_scan_error"),
                    sha256 = sha.lowercase(),
                    appStatus = status
                )
            }
        }
        return CatalogData(
            generatedAt = root.optString("generatedAt", ""),
            scannerVersion = root.optString("scannerVersion", ""),
            apps = apps,
            assets = assets
        )
    }
}
