// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

/** Reads a build setting from a Gradle property first, then an environment variable. */
fun setting(property: String, env: String): String? =
    (findProperty(property) as String?)?.takeIf { it.isNotBlank() }
        ?: System.getenv(env)?.takeIf { it.isNotBlank() }

// Google's official, public AdMob *test* identifiers. Safe to commit; they never pay out.
val admobTestAppId = "ca-app-pub-3940256099942544~3347511713"
val admobTestBannerId = "ca-app-pub-3940256099942544/9214589741"
val admobTestRewardedId = "ca-app-pub-3940256099942544/5224354917"

val prodAdmobAppId = setting("trustcheck.admobAppId", "ADMOB_APP_ID")
val prodAdmobBannerId = setting("trustcheck.admobBannerId", "ADMOB_BANNER_ID")
val prodAdmobRewardedId = setting("trustcheck.admobRewardedId", "ADMOB_REWARDED_ID")
val backendBaseUrl = setting("trustcheck.backendBaseUrl", "TRUSTCHECK_BACKEND_URL") ?: ""

val keystoreFile = setting("trustcheck.keystoreFile", "TRUSTCHECK_KEYSTORE_FILE")
val keystorePassword = setting("trustcheck.keystorePassword", "ANDROID_KEYSTORE_PASSWORD")
val keyAlias = setting("trustcheck.keyAlias", "ANDROID_KEY_ALIAS")
val keyPassword = setting("trustcheck.keyPassword", "ANDROID_KEY_PASSWORD")
val hasSigning = listOf(keystoreFile, keystorePassword, keyAlias, keyPassword).all { it != null } &&
    file(keystoreFile!!).exists()

android {
    namespace = "com.mesflit.trustcheck"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.mesflit.trustcheck"
        minSdk = 26
        targetSdk = 36
        versionCode = setting("trustcheck.versionCode", "TRUSTCHECK_VERSION_CODE")?.toInt() ?: 1
        versionName = setting("trustcheck.versionName", "TRUSTCHECK_VERSION_NAME") ?: "0.1.0-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = true }

        buildConfigField("String", "BACKEND_BASE_URL", "\"$backendBaseUrl\"")
    }

    androidResources {
        // Generates the per-app language list (android:localeConfig) from res/values-* folders.
        generateLocaleConfig = true
    }

    signingConfigs {
        if (hasSigning) {
            create("release") {
                storeFile = file(keystoreFile!!)
                storePassword = keystorePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            manifestPlaceholders["admobAppId"] = admobTestAppId
            buildConfigField("boolean", "ADS_ENABLED", "true")
            buildConfigField("boolean", "ADS_TEST_MODE", "true")
            buildConfigField("String", "ADMOB_BANNER_ID", "\"$admobTestBannerId\"")
            buildConfigField("String", "ADMOB_REWARDED_ID", "\"$admobTestRewardedId\"")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (hasSigning) signingConfig = signingConfigs.getByName("release")

            // Production ads are only enabled when real AdMob IDs are supplied at build time.
            // Without them the release build ships with ads disabled (the test app ID is only
            // present so the SDK's manifest check does not crash; no ad requests are made).
            val prodAds = prodAdmobAppId != null && prodAdmobBannerId != null
            manifestPlaceholders["admobAppId"] = prodAdmobAppId ?: admobTestAppId
            buildConfigField("boolean", "ADS_ENABLED", prodAds.toString())
            buildConfigField("boolean", "ADS_TEST_MODE", "false")
            buildConfigField("String", "ADMOB_BANNER_ID", "\"${prodAdmobBannerId ?: ""}\"")
            buildConfigField("String", "ADMOB_REWARDED_ID", "\"${prodAdmobRewardedId ?: ""}\"")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.foundation.layout.ExperimentalLayoutApi",
        )
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
        unitTests.all { it.systemProperty("trustcheck.resDir", file("src/main/res").absolutePath) }
    }
    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "META-INF/LICENSE*", "META-INF/NOTICE*")
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.navigation.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.datastore.preferences)

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.play.services)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)

    implementation(libs.play.services.ads)
    implementation(libs.google.ump)
    implementation(libs.billing.ktx)
    implementation(libs.mlkit.text.recognition)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.room.testing)
    testImplementation(libs.androidx.work.testing)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
