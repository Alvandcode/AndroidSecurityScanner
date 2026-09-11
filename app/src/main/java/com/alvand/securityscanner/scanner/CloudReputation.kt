package com.alvand.securityscanner.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import javax.net.ssl.HttpsURLConnection

// Opt-in cloud reputation: sends ONLY the SHA-256 hex (never the APK).
// VirusTotal v3 file lookup. Returns e.g. "3/92 malicious" or null on error/offline.
// 404 = unknown hash (not an error), 401 = bad key, 429 = quota.
suspend fun lookupVirusTotal(sha256: String, apiKey: String): String? =
    lookupVirusTotalCached(sha256, apiKey)

/**
 * Cached + rate-limited wrapper.
 * Free VT keys: ~4 req/min, ~500/day. Without a limiter a 50-file scan
 * burns the whole quota in seconds and gets 429 for the rest of the day.
 */
suspend fun lookupVirusTotalCached(sha256: String, apiKey: String): String? =
    withContext(Dispatchers.IO) {
        if (sha256.length != 64 || !sha256.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return@withContext null
        if (apiKey.isBlank()) return@withContext null
        VtCache.get(sha256)?.let { return@withContext it }
        // Min 16s between network calls (4/min free tier). Cache hits bypass the wait.
        VtRateLimiter.waitForSlot()
        val res = lookupVirusTotalNetwork(sha256, apiKey.trim())
        if (res != null) VtCache.put(sha256, res)
        res
    }

private suspend fun lookupVirusTotalNetwork(sha256: String, apiKey: String): String? =
    withContext(Dispatchers.IO) {
        try {
            val url = URL("https://www.virustotal.com/api/v3/files/$sha256")
            val c = (url.openConnection() as HttpsURLConnection).apply {
                requestMethod = "GET"
                // Never log the key. Key goes only in this header over HTTPS.
                setRequestProperty("x-apikey", apiKey)
                setRequestProperty("User-Agent", "AlvandSecurityScanner/1.4.0")
                setRequestProperty("Accept", "application/json")
                connectTimeout = 15000
                readTimeout = 15000
            }
            when (c.responseCode) {
                200 -> {
                    val body = c.inputStream.bufferedReader().readText()
                    parseVtStats(body)
                }
                404 -> "unknown (not in VirusTotal)"
                401 -> "invalid API key (401)"
                429 -> "quota exceeded (429)"
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

/** Returns (flagged, total) or null if the text is not a VT verdict. */
fun parseVtVerdict(text: String?): Pair<Int, Int>? {
    if (text == null) return null
    // "3/92 flagged (malicious=2, suspicious=1)"
    val m = Regex("(\\d+)\\s*/\\s*(\\d+)\\s+flagged").find(text) ?: return null
    val flagged = m.groupValues[1].toIntOrNull() ?: return null
    val total = m.groupValues[2].toIntOrNull() ?: return null
    return flagged to total
}

private object VtCache {
    private const val MAX = 200
    private val map = object : LinkedHashMap<String, String>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>): Boolean = size > MAX
    }
    @Synchronized fun get(sha: String): String? = map[sha.lowercase()]
    @Synchronized fun put(sha: String, res: String) { map[sha.lowercase()] = res }
}

private object VtRateLimiter {
    // Free tier: 4 lookups / minute. Keep 16s gap between NETWORK calls.
    private const val GAP_MS = 16_000L
    private var lastCall = 0L
    suspend fun waitForSlot() {
        val now = System.currentTimeMillis()
        val wait = GAP_MS - (now - lastCall)
        if (wait > 0) {
            try { kotlinx.coroutines.delay(wait) } catch (_: Exception) { }
        }
        lastCall = System.currentTimeMillis()
    }
}

internal fun parseVtStats(body: String): String? {
    return try {
        // Minimal org.json parsing (framework built-in, no new dependency).
        // Path: data.attributes.last_analysis_stats.{malicious,suspicious,harmless,undetected,...}
        val root = org.json.JSONObject(body)
        val stats = root.getJSONObject("data")
            .getJSONObject("attributes")
            .getJSONObject("last_analysis_stats")
        val mal = stats.optInt("malicious", -1)
        val susp = stats.optInt("suspicious", 0)
        if (mal < 0) return "found"
        var total = 0
        val keys = stats.keys()
        while (keys.hasNext()) {
            total += stats.optInt(keys.next(), 0)
        }
        val flag = mal + susp
        "$flag/$total flagged (malicious=$mal, suspicious=$susp)"
    } catch (_: Exception) {
        // Fallback for unexpected schema: try legacy regex once.
        val mal = Regex("\"malicious\"\\s*:\\s*(\\d+)").find(body)?.groupValues?.get(1)
        if (mal != null) "$mal/? malicious" else "found"
    }
}
