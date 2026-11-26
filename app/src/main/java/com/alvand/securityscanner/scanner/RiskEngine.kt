package com.alvand.securityscanner.scanner

// Phase-1 risk model: weighted, explainable, no silent negative overflow.
data class AppFinding(
    val packageName: String,
    val appName: String,
    val versionName: String?,
    val installer: String?,
    val isSystemApp: Boolean,
    val isDebuggable: Boolean,
    val riskyPermissions: List<RiskyPermission>,
    val unknownSource: Boolean,
    val score: Int, // 0..100, 100 = safe
    val verdict: Verdict,
    val reasons: List<String>,
    val catalogStatus: String? = null   // Idol Catalog overall_status, null = not in catalog
)

enum class Verdict { SAFE, REVIEW, DANGEROUS }

data class RiskyPermission(val name: String, val weight: Int, val descriptionFa: String, val descriptionEn: String)

object RiskEngine {
    // Weights tuned: combos matter more than single perms.
    // NOTE: single well-known apps (camera, maps) legitimately hold these;
    // unknown installer + combos is what pushes verdict to DANGEROUS.
    val weights = mapOf(
        "SEND_SMS" to 18, "RECEIVE_SMS" to 12, "READ_SMS" to 12,
        "BIND_ACCESSIBILITY_SERVICE" to 20, "BIND_DEVICE_ADMIN" to 20,
        "REQUEST_INSTALL_PACKAGES" to 15, "SYSTEM_ALERT_WINDOW" to 10,
        "READ_CONTACTS" to 6, "WRITE_CONTACTS" to 7,
        "READ_CALL_LOG" to 10, "WRITE_CALL_LOG" to 10, "CALL_PHONE" to 10,
        "READ_PHONE_STATE" to 6, "READ_PHONE_NUMBERS" to 8,
        "ACCESS_FINE_LOCATION" to 8, "ACCESS_COARSE_LOCATION" to 4,
        "ACCESS_BACKGROUND_LOCATION" to 14,
        "CAMERA" to 5, "RECORD_AUDIO" to 10,
        "READ_EXTERNAL_STORAGE" to 2, "WRITE_EXTERNAL_STORAGE" to 2,
        "READ_MEDIA_IMAGES" to 2, "READ_MEDIA_VIDEO" to 2, "READ_MEDIA_AUDIO" to 2,
        "POST_NOTIFICATIONS" to 1
    )

    // Play + OEM + popular IR stores. Anything else => UNKNOWN_INSTALLER.
    val trustedInstallers = setOf(
        "com.android.vending", // Play
        "com.google.android.packageinstaller", "com.android.packageinstaller",
        "com.samsung.android.packageinstaller", "com.miui.packageinstaller",
        "com.huawei.appmarket", "com.amazon.venezia",
        "com.farsitel.bazaar", // Bazaar
        "ir.mservices.market" // Myket
    )

    fun installerLabel(installer: String?): String = when (installer) {
        "com.android.vending" -> "Play Store"
        "com.farsitel.bazaar" -> "Bazaar"
        "ir.mservices.market" -> "Myket"
        "com.samsung.android.packageinstaller", "com.miui.packageinstaller",
        "com.huawei.appmarket", "com.amazon.venezia" -> "OEM/Store"
        "com.google.android.packageinstaller", "com.android.packageinstaller" -> "System installer"
        null -> "Unknown"
        else -> installer
    }

    fun score(
        perms: List<String>,
        unknownSource: Boolean,
        isDebuggable: Boolean,
        isSystemApp: Boolean,
        targetSdk: Int = 0
    ): Triple<Int, Verdict, List<String>> {
        var deduction = 0
        val reasons = mutableListOf<String>()
        val short = perms.map { it.substringAfterLast('.') }.toSet()

        short.forEach { p ->
            weights[p]?.let {
                deduction += it
                reasons.add(p)
            }
        }
        // Combo bonuses: these patterns are far more suspicious together.
        if (short.contains("SEND_SMS") && short.contains("READ_CONTACTS")) {
            deduction += 10; reasons.add("COMBO_SMS_CONTACTS")
        }
        if (short.contains("BIND_ACCESSIBILITY_SERVICE") && (short.contains("SYSTEM_ALERT_WINDOW") || short.contains("RECORD_AUDIO"))) {
            deduction += 12; reasons.add("COMBO_ACCESSIBILITY_OVERLAY")
        }
        if (short.contains("REQUEST_INSTALL_PACKAGES") && short.contains("ACCESS_FINE_LOCATION")) {
            deduction += 6; reasons.add("COMBO_INSTALLER_LOCATION")
        }
        // Outdated targetSdk = missing runtime-permission / sandbox hardening.
        if (!isSystemApp && targetSdk > 0) {
            when {
                targetSdk < 26 -> { deduction += 12; reasons.add("TARGET_SDK_ANCIENT") }
                targetSdk < 29 -> { deduction += 8; reasons.add("TARGET_SDK_OLD") }
                targetSdk < 31 -> { deduction += 4; reasons.add("TARGET_SDK_OUTDATED") }
            }
        }
        if (unknownSource && !isSystemApp) { deduction += 12; reasons.add("UNKNOWN_INSTALLER") }
        if (isDebuggable) { deduction += 15; reasons.add("DEBUGGABLE") }

        val score = (100 - deduction).coerceIn(0, 100)
        val verdict = when {
            score >= 80 -> Verdict.SAFE
            score >= 50 -> Verdict.REVIEW
            else -> Verdict.DANGEROUS
        }
        return Triple(score, verdict, reasons)
    }

    /**
     * Device score must NOT be a plain average: one banker-trojan among
     * 200 safe apps would still show 99/100. Weight by severity and
     * cap by the worst app so a single DANGEROUS app is always visible.
     * The review penalty is capped so a device full of system apps that
     * merely hold broad permissions can never drag the score to 0.
     */
    fun deviceScore(findings: List<AppFinding>): Int {
        if (findings.isEmpty()) return 100
        val dangerous = findings.count { it.verdict == Verdict.DANGEROUS }
        val review = findings.count { it.verdict == Verdict.REVIEW }
        val worst = findings.minOf { it.score }
        val penalty = (dangerous * 12 + review * 3).coerceAtMost(65)
        return minOf(100 - penalty, worst + 15).coerceIn(0, 100)
    }

    /** Same scale for files: 100 = all healthy. Empty folder = 100 (nothing to judge). */
    fun fileScore(files: List<FileFinding>): Int {
        if (files.isEmpty()) return 100
        val dangerous = files.count { it.verdict == FileVerdict.DANGEROUS }
        val review = files.count { it.verdict == FileVerdict.REVIEW }
        val worst = files.minOf { it.score }
        val penalty = (dangerous * 12 + review * 3).coerceAtMost(65)
        return minOf(100 - penalty, worst + 15).coerceIn(0, 100)
    }

    /**
     * Unified score for «اسکن همه»: min(appScore, fileScore).
     * A single infected file or app must drag the whole device score down —
     * averaging would hide it.
     */
    fun unifiedScore(appScore: Int, fileScore: Int, hasFiles: Boolean): Int {
        return if (hasFiles) minOf(appScore, fileScore).coerceIn(0, 100)
        else appScore.coerceIn(0, 100)
    }

    /**
     * Merge Idol Catalog status into an app verdict. Catalog evidence
     * TRUSTED over local heuristics: ClamAV/YARA detections are real
     * engine results, not name guesses.
     *  - DANGEROUS  → verdict forced DANGEROUS (never downgraded)
     *  - WARNING    → extra deduction, verdict at least REVIEW
     *  - SAFE / LOW_RISK → kept (never silently upgraded past REVIEW;
     *    local combos like accessibility+overlay still stand)
     *  - INCOMPLETE / SCAN_ERROR / NOT_SCANNED → no score change
     *    (an unfinished scan must never read as "clean" nor as "bad").
     */
    fun applyCatalog(
        score: Int,
        verdict: Verdict,
        reasons: List<String>,
        catalogStatus: String?
    ): Triple<Int, Verdict, List<String>> {
        if (catalogStatus == null) return Triple(score, verdict, reasons)
        val out = reasons.toMutableList()
        return when (catalogStatus) {
            CatalogStatus.DANGEROUS -> {
                out.add("CATALOG_DANGEROUS")
                Triple(minOf(score, 30), Verdict.DANGEROUS, out)
            }
            CatalogStatus.WARNING -> {
                out.add("CATALOG_WARNING")
                val s = (score - 10).coerceIn(0, 100)
                val v = if (verdict == Verdict.SAFE) Verdict.REVIEW else verdict
                Triple(s, v, out)
            }
            else -> Triple(score, verdict, reasons)
        }
    }

    /**
     * Merge catalog asset evidence into a file verdict.
     *  - hash flagged malware_detected → DANGEROUS, capped score
     *  - hash scanned clean on a SAFE/LOW_RISK app → name-based suspicion
     *    (SUSPICIOUS_NAME / double extension) alone cannot hold it at REVIEW.
     */
    fun applyCatalogToFile(
        score: Int,
        verdict: FileVerdict,
        reasons: List<String>,
        asset: CatalogAsset?,
        appStatus: String?
    ): Triple<Int, FileVerdict, List<String>> {
        if (asset == null) return Triple(score, verdict, reasons)
        val out = reasons.toMutableList()
        return when {
            asset.status == CatalogStatus.A_MALWARE -> {
                out.add("CATALOG_MALWARE_HASH")
                Triple(minOf(score, 20), FileVerdict.DANGEROUS, out)
            }
            asset.status == CatalogStatus.A_SUSPICIOUS -> {
                out.add("CATALOG_SUSPICIOUS")
                val v = if (verdict == FileVerdict.SAFE) FileVerdict.REVIEW else verdict
                Triple((score - 10).coerceIn(0, 100), v, out)
            }
            asset.status == CatalogStatus.A_NO_DETECTION &&
                    (appStatus == CatalogStatus.SAFE || appStatus == CatalogStatus.LOW_RISK) -> {
                out.add("CATALOG_KNOWN_GOOD")
                val v = if (verdict == FileVerdict.REVIEW) FileVerdict.SAFE else verdict
                Triple(maxOf(score, 90), v, out)
            }
            else -> Triple(score, verdict, reasons)
        }
    }
}
