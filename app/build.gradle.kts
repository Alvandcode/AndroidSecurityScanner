plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.alvand.securityscanner"
    compileSdk = 35

    defaultConfig {
        // IMPORTANT: never change this once published, otherwise Android
        // treats it as a different app and forces uninstall.
        applicationId = "com.alvand.securityscanner"
        // Android 6 (API 23) .. Android 17: minSdk 23, target 35 (forward-compatible).
        // All API-gated calls are guarded with Build.VERSION checks.
        minSdk = 23
        targetSdk = 35
        // Increment versionCode on every release, keep versionName human-readable.
        // Install-over works only if applicationId + signing key are identical
        // and new versionCode > old versionCode.
        versionCode = 8
        versionName = "1.6.0"
        vectorDrawables { useSupportLibrary = true }
    }

    signingConfigs {
        // Fixed debug key for install-over from GitHub Actions.
        // After running gen-debug-keystore workflow once, place the
        // downloaded debug.keystore at repo root (next to settings.gradle.kts).
        // All CI builds then share one signature -> updates install over old version.
        getByName("debug") {
            val fixed = rootProject.file("debug.keystore")
            if (fixed.exists()) {
                storeFile = fixed
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
        // For Play release later: create ONE keystore, keep it forever,
        // and add a signingConfigs.create("release") block here.
    }

    buildTypes {
        debug {
            applicationIdSuffix = null // keep same id so debug also installs over debug
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Uncomment once keystore exists:
            // signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures { compose = true }

    packaging { resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" } }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.5")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
