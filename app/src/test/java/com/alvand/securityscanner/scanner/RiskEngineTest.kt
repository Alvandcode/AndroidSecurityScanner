package com.alvand.securityscanner.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the risk model. These encode the documented rules:
 * weights, combo bonuses, verdict thresholds, device/file score caps and
 * the catalog merge rules (DANGEROUS never downgraded, inconclusive
 * statuses never change a score).
 */
class RiskEngineTest {

    private fun finding(
        score: Int,
        verdict: Verdict
    ) = AppFinding(
        packageName = "pkg$score", appName = "App", versionName = null,
        installer = null, isSystemApp = false, isDebuggable = false,
        riskyPermissions = emptyList(), unknownSource = false,
        score = score, verdict = verdict, reasons = emptyList()
    )

    private fun fileFinding(score: Int, verdict: FileVerdict) = FileFinding(
        displayName = "f$score", uriString = "uri://$score", mime = null,
        size = 0, sha256 = null, verdict = verdict, reasons = emptyList(),
        isApk = false, apkPackage = null, score = score
    )

    // ---- RiskEngine.score -------------------------------------------------

    @Test
    fun `clean app with no permissions from trusted installer is SAFE`() {
        val (score, verdict, reasons) = RiskEngine.score(
            perms = emptyList(), unknownSource = false,
            isDebuggable = false, isSystemApp = false, targetSdk = 35
        )
        assertEquals(100, score)
        assertEquals(Verdict.SAFE, verdict)
        assertTrue(reasons.isEmpty())
    }

    @Test
    fun `single dangerous permission deducts its weight`() {
        val (score, _, reasons) = RiskEngine.score(
            listOf("android.permission.SEND_SMS"), false, false, false, 35
        )
        assertEquals(100 - 18, score)
        assertTrue(reasons.contains("SEND_SMS"))
    }

    @Test
    fun `unknown installer and debuggable flag deduct`() {
        val (_, _, reasons) = RiskEngine.score(
            emptyList(), unknownSource = true, isDebuggable = true,
            isSystemApp = false, targetSdk = 35
        )
        assertTrue(reasons.contains("UNKNOWN_INSTALLER"))
        assertTrue(reasons.contains("DEBUGGABLE"))
    }

    @Test
    fun `combo sms plus contacts adds bonus`() {
        val (_, _, alone) = RiskEngine.score(
            listOf("a.SEND_SMS"), false, false, false, 35
        )
        val (_, _, combo) = RiskEngine.score(
            listOf("a.SEND_SMS", "b.READ_CONTACTS"), false, false, false, 35
        )
        assertTrue(combo.contains("COMBO_SMS_CONTACTS"))
        assertEquals(
            alone.size + 2, combo.size // + READ_CONTACTS + combo bonus
        )
    }

    @Test
    fun `old target sdk deducts`() {
        val (_, _, reasons) = RiskEngine.score(
            emptyList(), false, false, false, 23
        )
        assertTrue(reasons.contains("TARGET_SDK_ANCIENT"))
    }

    @Test
    fun `system app is never penalized for old targetSdk`() {
        val (_, _, reasons) = RiskEngine.score(
            emptyList(), false, false, isSystemApp = true, targetSdk = 23
        )
        assertTrue(reasons.none { it.startsWith("TARGET_SDK") })
    }

    @Test
    fun `score never leaves the 0 to 100 range`() {
        // Extreme case: every risky permission + combos + debuggable + unknown.
        val all = RiskEngine.weights.keys.map { "x.$it" }
        val (score, _, _) = RiskEngine.score(all, true, true, false, 21)
        assertTrue(score in 0..100)
    }

    @Test
    fun `verdict thresholds are 80 and 50`() {
        assertEquals(Verdict.SAFE, RiskEngine.score(emptyList(), false, false, false, 35).second)
        // 100 - 18 (SEND_SMS) = 82 -> SAFE
        assertEquals(Verdict.SAFE, RiskEngine.score(listOf("x.SEND_SMS"), false, false, false, 35).second)
        // 100 - 20 (BIND_ACCESSIBILITY) = 80 -> SAFE boundary
        assertEquals(Verdict.SAFE, RiskEngine.score(listOf("x.BIND_ACCESSIBILITY_SERVICE"), false, false, false, 35).second)
        // 100 - 20 - 10 (overlay combo bonus) = 70 -> REVIEW
        assertEquals(Verdict.REVIEW, RiskEngine.score(
            listOf("x.BIND_ACCESSIBILITY_SERVICE", "x.SYSTEM_ALERT_WINDOW"),
            false, false, false, 35
        ).second)
        // 100 - 18 - 12 - 10 (combo) = 60... use bigger stack: 3 heavy perms
        assertEquals(Verdict.DANGEROUS, RiskEngine.score(
            listOf("x.SEND_SMS", "x.BIND_DEVICE_ADMIN", "x.ACCESS_BACKGROUND_LOCATION"),
            true, true, false, 21
        ).second)
    }

    // ---- deviceScore -------------------------------------------------------

    @Test
    fun `empty findings score 100`() {
        assertEquals(100, RiskEngine.deviceScore(emptyList()))
    }

    @Test
    fun `one dangerous app drags the score below 80`() {
        val apps = List(50) { finding(100, Verdict.SAFE) } + finding(0, Verdict.DANGEROUS)
        assertTrue(RiskEngine.deviceScore(apps) < 80)
    }

    @Test
    fun `review penalty is capped`() {
        // 50 REVIEW apps would be -150 without the cap; score must stay >= 100-65.
        val apps = List(50) { finding(75, Verdict.REVIEW) }
        val s = RiskEngine.deviceScore(apps)
        assertTrue("got $s", s >= 100 - 65)
        assertTrue(s <= 100)
    }

    @Test
    fun `all safe devices score 100`() {
        val apps = List(200) { finding(100, Verdict.SAFE) }
        assertEquals(100, RiskEngine.deviceScore(apps))
    }

    // ---- fileScore ---------------------------------------------------------

    @Test
    fun `fileScore mirrors deviceScore caps`() {
        val files = List(50) { fileFinding(75, FileVerdict.REVIEW) }
        assertTrue(RiskEngine.fileScore(files) >= 100 - 65)
    }

    // ---- unifiedScore ------------------------------------------------------

    @Test
    fun `unified takes the minimum when files present`() {
        assertEquals(40, RiskEngine.unifiedScore(90, 40, hasFiles = true))
        assertEquals(90, RiskEngine.unifiedScore(90, 40, hasFiles = false))
    }

    // ---- Catalog merge -----------------------------------------------------

    @Test
    fun `catalog DANGEROUS forces verdict and caps score`() {
        val (score, verdict, reasons) = RiskEngine.applyCatalog(
            95, Verdict.SAFE, emptyList(), CatalogStatus.DANGEROUS
        )
        assertEquals(30, score)
        assertEquals(Verdict.DANGEROUS, verdict)
        assertTrue(reasons.contains("CATALOG_DANGEROUS"))
    }

    @Test
    fun `catalog DANGEROUS never upgrades a locally dangerous score`() {
        val (score, verdict, _) = RiskEngine.applyCatalog(
            10, Verdict.DANGEROUS, listOf("DEBUGGABLE"), CatalogStatus.DANGEROUS
        )
        assertEquals(10, score)
        assertEquals(Verdict.DANGEROUS, verdict)
    }

    @Test
    fun `catalog WARNING downgrades SAFE to REVIEW`() {
        val (score, verdict, reasons) = RiskEngine.applyCatalog(
            95, Verdict.SAFE, emptyList(), CatalogStatus.WARNING
        )
        assertEquals(85, score)
        assertEquals(Verdict.REVIEW, verdict)
        assertTrue(reasons.contains("CATALOG_WARNING"))
    }

    @Test
    fun `catalog WARNING never upgrades a DANGEROUS verdict`() {
        val (_, verdict, _) = RiskEngine.applyCatalog(
            20, Verdict.DANGEROUS, emptyList(), CatalogStatus.WARNING
        )
        assertEquals(Verdict.DANGEROUS, verdict)
    }

    @Test
    fun `inconclusive catalog statuses change nothing`() {
        for (status in listOf(CatalogStatus.INCOMPLETE, CatalogStatus.NOT_SCANNED, CatalogStatus.SCAN_ERROR)) {
            val r = RiskEngine.applyCatalog(77, Verdict.REVIEW, emptyList(), status)
            assertEquals(77, r.first)
            assertEquals(Verdict.REVIEW, r.second)
        }
        // null = not in catalog at all
        val r = RiskEngine.applyCatalog(77, Verdict.REVIEW, emptyList(), null)
        assertEquals(77, r.first)
    }

    @Test
    fun `file catalog malware hash forces DANGEROUS`() {
        val asset = CatalogAsset(name = "x.apk", status = CatalogStatus.A_MALWARE, sha256 = "a".repeat(64))
        val (score, verdict, reasons) = RiskEngine.applyCatalogToFile(
            90, FileVerdict.SAFE, emptyList(), asset, CatalogStatus.SAFE
        )
        assertEquals(20, score)
        assertEquals(FileVerdict.DANGEROUS, verdict)
        assertTrue(reasons.contains("CATALOG_MALWARE_HASH"))
    }

    @Test
    fun `clean catalog hash rescues a name-flagged REVIEW file`() {
        val asset = CatalogAsset(name = "x.apk", status = CatalogStatus.A_NO_DETECTION, sha256 = "a".repeat(64))
        val (score, verdict, reasons) = RiskEngine.applyCatalogToFile(
            60, FileVerdict.REVIEW, listOf("SUSPICIOUS_NAME"), asset, CatalogStatus.SAFE
        )
        assertEquals(90, score)
        assertEquals(FileVerdict.SAFE, verdict)
        assertTrue(reasons.contains("CATALOG_KNOWN_GOOD"))
    }

    @Test
    fun `clean catalog hash never overrides a DANGEROUS file`() {
        val asset = CatalogAsset(name = "x.apk", status = CatalogStatus.A_NO_DETECTION, sha256 = "a".repeat(64))
        val (score, verdict, _) = RiskEngine.applyCatalogToFile(
            30, FileVerdict.DANGEROUS, listOf("APK_DANGEROUS_PERMS"), asset, CatalogStatus.SAFE
        )
        assertEquals(30, score)
        assertEquals(FileVerdict.DANGEROUS, verdict)
    }

    // ---- Catalog JSON parsing ----------------------------------------------

    @Test
    fun `parse minimal security-results json`() {
        val json = """
        {
          "schemaVersion": 2, "scanner": "Idol Security Scanner",
          "scannerVersion": "2.0.0", "generatedAt": "2026-01-01T00:00:00+00:00",
          "policy": {}, "results": [
            {
              "id": "com.example.app", "name": "Example",
              "github_repository": "https://github.com/x/y",
              "overall_status": "DANGEROUS", "risk_level": "high",
              "release_version": "v1.0",
              "detections": [], "warnings": [],
              "scanned_assets": [
                {"name": "app.apk", "status": "malware_detected", "sha256": "${"a".repeat(64)}"}
              ]
            }
          ], "summary": {}
        }
        """.trimIndent()
        val data = CatalogReputation.parse(json)
        val app = data.appFor("COM.EXAMPLE.APP") // lookup is case-insensitive
        assertEquals(CatalogStatus.DANGEROUS, app?.status)
        val asset = data.assetFor("a".repeat(64))
        assertEquals(CatalogStatus.A_MALWARE, asset?.status)
        assertEquals(CatalogStatus.DANGEROUS, asset?.appStatus)
    }

    @Test
    fun `parse ignores assets without usable hash`() {
        val json = """
        {
          "results": [
            {"id": "com.a", "overall_status": "SAFE",
             "scanned_assets": [{"name": "x.apk", "status": "download_or_scan_error", "sha256": null}]}
          ]
        }
        """.trimIndent()
        val data = CatalogReputation.parse(json)
        assertEquals(1, data.apps.size)
        assertEquals(0, data.assets.size)
    }

    @Test
    fun `parse handles missing results array`() {
        val data = CatalogReputation.parse("{}")
        assertEquals(0, data.apps.size)
        assertEquals(0, data.assets.size)
    }

    @Test
    fun `parse reads yara-shaped detections (rule + description)`() {
        val json = """
        {
          "results": [
            {"id": "com.a", "overall_status": "WARNING",
             "detections": [
               {"tool": "yara", "rule": "Suspicious_Socket", "severity": "high",
                "description": "raw socket usage"}
             ]}
          ]
        }
        """.trimIndent()
        val app = CatalogReputation.parse(json).appFor("com.a")
        assertEquals("Suspicious_Socket — raw socket usage", app?.detections?.first())
    }

    @Test
    fun `parse reads clamav signature detections`() {
        val json = """
        {
          "results": [
            {"id": "com.a", "overall_status": "DANGEROUS",
             "detections": [{"tool": "clamav", "signature": "Trojan.Android.Foo"}]}
          ]
        }
        """.trimIndent()
        val app = CatalogReputation.parse(json).appFor("com.a")
        assertEquals("Trojan.Android.Foo", app?.detections?.first())
    }

    @Test
    fun `parse skips empty detection labels`() {
        val json = """
        {
          "results": [
            {"id": "com.a", "overall_status": "WARNING",
             "detections": [{"tool": "yara", "severity": "low"}, "plain hit"]}
          ]
        }
        """.trimIndent()
        val app = CatalogReputation.parse(json).appFor("com.a")
        assertEquals(listOf("plain hit"), app?.detections)
    }
}
