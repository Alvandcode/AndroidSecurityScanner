# AndroidSecurityScanner — Phase 7 (v1.6.0, versionCode 8)

## Prerequisites
- Android Studio Hedgehog or later.
- JDK 17 (Gradle toolchain / `jvmTarget 17`).
- Android SDK 35 (`compileSdk/targetSdk 35`, `minSdk 23`).
- No root required — scanning uses PackageManager, SAF, and MediaStore only.

## Install (end users)
1. Download the APK from Releases. If Releases is empty, use Actions > Build Debug APK and download the `app-debug-apk` artifact.
2. On the device, allow installs from unknown sources (Unknown Sources / Install unknown apps) for your browser or file manager.
3. Install the APK. `applicationId` is fixed as `com.alvand.securityscanner`, so updates install over the previous version (no uninstall needed) as long as the signing key is the same and `versionCode` is incremented.

## New in Phase-5
- **Android 6..17:** `minSdk 23`, `target/compile 35` (forward-compatible).
  Every API-gated call guarded (`InstallSource` 30+, `PackageInfoFlags` 33+,
  `LocaleManager` 33+, channels 26+, SAF 21+). No `WRITE_SECURE_SETTINGS` fantasy.
- **VirusTotal wired end-to-end (opt-in, OFF by default):**
  SHA-256 only, never file content. LRU cache (200) + 16s rate limiter for the
  4-req/min free tier. Scan All auto-checks top-3 dangerous FILES; every threat
  row (app details + file list) has its own Check button. 401/404/429 surfaced.
  Get a key: virustotal.com > Sign up > API key > Settings > enable.
- **«اسکن همه» + single score:** Dashboard + Files both have ◉ Scan All.
  Apps (0-50%) + files (50-100%) with live stage text. Score = `min(appScore,
  fileScore)` so one infected item drags the device score down (no hiding by
  averaging). History stores one row with both app + file top lists.

## New in Phase-4: file scan without root (honest scope)
- **Files tab:** user picks a folder via SAF (e.g. Download). We walk max 2000 files /
  depth 6, hash (cap 150MB), parse loose APKs via `getPackageArchiveInfo` (no apktool).
- **Report:** سالم (SAFE) / مشکوک (REVIEW) / آلوده (DANGEROUS) counts + searchable list.
  User taps a row to Open / Delete — we never auto-delete.
- Heuristics: double-extension, executable ext, hidden, suspicious name, too-small/huge
  APK, unparsable APK, known-hash, plus full APK permission risk merged in.
- Limits shown in UI: without root, system + other apps' private dirs are NOT visible.
  SAF grant + MediaStore only. Truncation notice after 2000 files.
- History stores `filesScanned/fileThreats/fileSummary` (Room v2, destructive fallback).

## Fixed in Phase-3 (all Python-script flaws ported properly)
- **No shell/root hacks:** everything via PackageManager + Settings read-only.
  Old `ps/ss/settings put/apktool` approach removed — it fails on Android 11+ without root.
- **Honest risk model:** threat-weighted `RiskEngine.deviceScore()` (was plain average
  that hid a single trojan among 200 safe apps). Outdated `targetSdk` penalty added.
- **Trusted installers fixed:** Play + Samsung/Xiaomi/Huawei + Bazaar + Myket
  (was only 3 hardcoded). Friendly installer labels in UI.
- **Privacy fixed:** `allowBackup=false` + `data_extraction_rules` (history holds
  package list). VT key wiped when opt-in disabled. Reports never on `/sdcard`.
- **INTERNET permission added:** VirusTotal lookup was silently failing without it.
  VT parser fixed for v3 `last_analysis_stats` + 401/404/429 states. SHA-256 format validated.
- **Notifications fixed:** runtime-permission guard, only notify on threats,
  install receiver does real `scanOne()` verdict instead of generic ping.
- **Reboot-safe:** `BOOT_COMPLETED` reschedules daily WorkManager scan.
- **UI fixed:** search + only-threats filter + system-apps toggle + App-Info button,
  locale switch without `runBlocking` ANR, version shown from PackageManager.
- **Perf guards:** SHA-256 skips files >200MB, 32KB buffer, single-app scan for installs.
- **SDK 35:** `compileSdk/targetSdk 35` for Play Nov-2025 requirement.

## New in Phase-2
- **Persistent history (Room):** last 50 scans survive restarts, shown in History tab.
- **APK details dialog:** per-app SHA-256 (computed on-device, file never uploaded),
  signer count, target SDK, installer source, copy button.
- **Install alerts:** notification on every new install (tap to open + scan).
  On Android 13+ the app asks for POST_NOTIFICATIONS once.
- **Scheduled daily scan (WorkManager):** every 24h on battery-ok, notifies only on threats.
  Toggle in Settings.
- **Online reputation (opt-in, OFF by default):** VirusTotal file lookup by SHA-256 only.
  Enable in Settings + paste API key. Nothing is sent unless you enable it.

## Getting a VirusTotal key (free)
virustotal.com > Sign up > API key > paste in Settings > enable lookup.

## Update path (GitHub web)
Upload changed files, commit, Actions > Build Debug APK > download artifact.
versionCode 8 (v1.6.0) installs OVER previous versions (same applicationId + same debug.keystore).

## What was built
Native Kotlin + Compose app, `applicationId=com.alvand.securityscanner`, versionCode=8 / versionName=1.6.0.
- Dashboard with glassmorphism cards, device score 0..100, scan progress
- Real scanner via PackageManager (no root): permissions analysis + installer source + debuggable flag + combo rules
- History (last score/date + full list), Settings (dark/light/system, FA/EN/system)
- Install receiver hook for PACKAGE_ADDED/REPLACED

## Install-over requirement (no uninstall needed)
1. `applicationId` is fixed in `app/build.gradle.kts` — NEVER change it.
2. Every release: increment `versionCode` by +1, bump `versionName` (e.g. 1.0.1, 1.1.0).
3. Sign ALL releases with the SAME keystore. Create once:
   ```
   keytool -genkey -v -keystore keystore/release.keystore -alias alvand -keyalg RSA -keysize 2048 -validity 10000
   ```
   Then uncomment `signingConfigs.release` in `app/build.gradle.kts` and set passwords via env vars.
   Losing the key = users must uninstall. Debug builds install over debug, release over release.

## Icon (your logo)
You said you will send the logo. Current icon is a placeholder:
`app/src/main/res/drawable/ic_logo_placeholder.xml`
To replace: keep the SAME file name, paste your vector/SVG content into it, or drop
`ic_launcher.png` (192px) into `mipmap-xxxhdpi` folders and keep `mipmap-anydpi-v26/ic_launcher.xml`.
Send the logo and I will wire it in.

## UI: glassmorphism + themes + languages
- `ui/Glass.kt`: GlassCard + GlassBackground (translucent + gradient border). On API 31+ blur available.
- `ui/Theme.kt`: Material3 light/dark, `theme` pref (system|light|dark) in DataStore.
- `values/strings.xml` (en) + `values-fa/strings.xml` (fa), RTL supported. Language pref (system|en|fa) uses per-app locales on Android 13+ and recreates activity.

## Build from source
Prerequisites: Android Studio Hedgehog+, JDK 17, Android SDK 35 (see Prerequisites above).
1. Open folder `AndroidSecurityScanner` in Android Studio and let Gradle sync.
2. Build the debug APK:
   ```
   ./gradlew assembleDebug
   ```
3. APK output: `app/build/outputs/apk/debug/app-debug.apk` — install over previous version, no uninstall (same `applicationId=com.alvand.securityscanner` + same signing key, higher `versionCode`).

## Next (Phase-2 hooks ready)
- `InstallReceiver` currently stores last installed pkg; wire to foreground rescan + notification.
- Add cloud reputation (SHA256 only) + signature OTA + Room history.
