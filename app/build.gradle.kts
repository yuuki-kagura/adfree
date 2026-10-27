// Build integration for the native core.
//
// Layout:
//   rust/                  Rust crate (cdylib) built with cargo-ndk for every ABI
//   app/src/main/jniLibs/   destination of the produced .so files (gitignored)
//   app/src/main/kotlin/..  uniffi generated Kotlin bindings (committed)
//
// Usage:
//   ./gradlew :app:assembleDebug            # builds the .so for all ABIs
//   ./gradlew :app:generateUniffiBindings   # refreshes the Kotlin bindings
//   ./gradlew :app:assembleDebug -PskipNative # Kotlin only, for fast UI iteration

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.secrets)
}

// Where cargo puts its build artifacts. Kept outside the project directory so
// `git status` stays clean and incremental rebuilds survive `./gradlew clean`.
android {
    namespace = "git.shin.adfree"
    compileSdk { version = release(36) { minorApiLevel = 1 } }

    defaultConfig {
        applicationId = "git.shin.adfree"
        minSdk = 24
        targetSdk = 36
        // semantic-release bumps these in gradle.properties before building.
        versionCode = project.property("versionCode").toString().toInt()
        versionName = project.property("versionName").toString()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Keep the shipped APK lean: one .so per ABI, and the emulator ABI is
        // only built for the debug variant.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    signingConfigs {
        // Release signing reads everything from the environment, so no secret is
        // committed. CI decodes KEYSTORE_CONTENT to KEYSTORE_PATH and exports
        // KEYSTORE_*; local builds can use KEYSTORE_PATH / STORE_PASSWORD /
        // KEY_PASSWORD directly.
        val keystorePath = System.getenv("KEYSTORE_PATH")
        if (!keystorePath.isNullOrBlank() && file(keystorePath).exists()) {
            val storePass = System.getenv("STORE_PASSWORD")?.takeUnless { it.isBlank() }
                ?: System.getenv("KEYSTORE_PASSWORD")?.takeUnless { it.isBlank() }
            create("release") {
                storeFile = file(keystorePath)
                storePassword = storePass
                keyAlias = System.getenv("KEY_ALIAS")?.takeUnless { it.isBlank() }
                    ?: System.getenv("KEYSTORE_ALIAS")?.takeUnless { it.isBlank() }
                    ?: "git.shin.adfree"
                keyPassword = System.getenv("KEY_PASSWORD")?.takeUnless { it.isBlank() }
                    ?: storePass
            }
        }
        // Debug signing comes from the Android SDK's well known debug key.
        val debugKeystore = listOf(
            file("${System.getenv("HOME")}/.android/debug.keystore"),
            file("${rootProject.layout.buildDirectory.get().asFile}/debug.keystore"),
        ).firstOrNull { it.exists() }
        if (debugKeystore != null) {
            create("debugConfig") {
                storeFile = debugKeystore
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
    }

    // A fresh CI runner has no ~/.android/debug.keystore yet; AGP's built-in
    // debug config creates it on demand.
    val debugSigning = signingConfigs.findByName("debugConfig")
        ?: signingConfigs.getByName("debug")

    buildTypes {
        release {
            isCrunchPngs = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.findByName("release") ?: debugSigning
        }
        debug {
            signingConfig = debugSigning
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        jniLibs {
            // The core is already stripped by cargo; keep Android from
            // duplicating the work on every build.
            keepDebugSymbols += "**/libadfree_core.so"
        }
    }

    testOptions { unitTests { isIncludeAndroidResources = true } }
    dependenciesInfo {
        includeInApk = false
        includeInBundle = true
    }
}

secrets {
    propertiesFileName = ".env"
    defaultPropertiesFileName = ".env.example"
    ignoreList.add("FIREBASE_APPCHECK_DEBUG_TOKEN")
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.logging.interceptor)
    implementation(libs.okhttp)

    // uniffi's Kotlin bindings use JNA to call into the native library.
    implementation(libs.jna) {
        artifact { type = "aar" }
    }

    testImplementation(libs.androidx.compose.ui.test.junit4)
    testImplementation(libs.androidx.core)
    testImplementation(libs.androidx.junit)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.runner)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}

// ---------------------------------------------------------------- native build
//
// rust/ is the source of truth. `cargo-ndk` builds one cdylib per ABI into
// app/src/main/jniLibs/<abi>/, which AGP then packages into the APK.
//
//   ./gradlew :app:assembleDebug            build everything
//   ./gradlew :app:verifyBindings           regenerate the uniffi Kotlin bindings
//   ./gradlew :app:assembleDebug -PskipNative Kotlin-only, for fast UI iteration

val abis = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

val rustTargetDir: String = (project.findProperty("rustTargetDir") as String?)
    ?: System.getenv("ADFREE_RUST_TARGET_DIR")
    ?: rootProject.layout.buildDirectory.dir("rust-target").get().asFile.absolutePath

val skipNative: Boolean = (project.findProperty("skipNative") as String?)
    // Gradle hands a bare `-PskipNative` an empty string, which `.toBoolean()`
    // reads as false; "present and not false" matches what the flag promises.
    ?.let { it.lowercase() != "false" }
    ?: false

val ndkDir: String = sequenceOf(
    project.findProperty("ndkDir") as String?,
    System.getenv("ANDROID_NDK_HOME"),
    System.getenv("NDK_HOME"),
    "${System.getenv("ANDROID_HOME")}/ndk/27.3.13750724",
    "${System.getenv("HOME")}/Android/Sdk/ndk/27.3.13750724",
    "/opt/android-sdk/ndk/27.3.13750724",
    "${System.getenv("HOME")}/android-sdk/ndk/28.2.13676358",
    "${System.getenv("HOME")}/Android/Sdk/ndk/27.3.13750724",
).firstOrNull { it != null && file(it).isDirectory } ?: ""

val jniLibsDir: Directory = layout.projectDirectory.dir("src/main/jniLibs")

val buildRust = tasks.register("buildRust") {
    group = "adfree"
    description = "Builds the Rust core for every supported ABI"
    val generated = jniLibsDir
    // Không bao giờ coi là up-to-date: cargo-ndk tự cache incremental, còn nếu
    // task bị skip thì APK sẽ đóng gói .so cũ và uniffi sẽ mismatch kiểu dữ liệu.
    outputs.upToDateWhen { skipNative }
    doLast {
        if (skipNative) {
            logger.lifecycle("ADFREE: -PskipNative set, native core not rebuilt")
            return@doLast
        }
        if (ndkDir.isEmpty()) {
            logger.warn("ADFREE: no Android NDK found (looked in ANDROID_NDK_HOME/NDK_HOME/SDK). The app will build without libadfree_core.so.")
            return@doLast
        }
        val rustDir = File(rootProject.projectDir, "rust")
        for (abi in abis) {
            // ProcessBuilder instead of Gradle's exec helpers: this runs at
            // execution time and needs no provider gymnastics.
            val process = ProcessBuilder(
                "cargo", "ndk",
                "-t", abi,
                "-o", generated.asFile.absolutePath,
                "build", "--lib", "--release",
            )
                .directory(rustDir)
                .redirectErrorStream(true)
                .apply {
                    environment()["ANDROID_NDK_HOME"] = ndkDir
                    environment()["CARGO_TARGET_DIR"] = rustTargetDir
                }
                .start()
            val output = process.inputStream.bufferedReader().readText()
            val exit = process.waitFor()
            if (exit != 0) {
                val message = "ADFREE: cargo-ndk failed for $abi\n$output"
                if (abi == "x86") {
                    // 32-bit x86 emulators are dead; never fail a build on them.
                    logger.warn(message)
                    continue
                }
                logger.error(message)
                throw GradleException("ADFREE: cargo-ndk failed for $abi")
            }
        }
    }
}

/** Refreshes the committed uniffi bindings after a Rust interface change. */
val verifyBindings = tasks.register("verifyBindings") {
    group = "adfree"
    description = "Regenerates the uniffi Kotlin bindings from libadfree_core.so"
    // uniffi appends the Kotlin package path itself, so hand it the parent.
    val outDir = layout.projectDirectory.dir("src/main/kotlin")
    doLast {
        if (ndkDir.isEmpty()) throw GradleException("ADFREE: ANDROID_NDK_HOME is required")
        val lib = File("$rustTargetDir/aarch64-linux-android/release/libadfree_core.so")
        if (!lib.exists()) {
            throw GradleException("ADFREE: ${lib.absolutePath} not found - run :app:buildRust first")
        }
        val result = providers.exec {
            workingDir(rootProject.layout.projectDirectory.dir("rust"))
            commandLine(
                "uniffi-bindgen", "generate",
                "--library", lib.absolutePath,
                "--language", "kotlin",
                "--out-dir", outDir.asFile.absolutePath,
                "--config", rootProject.layout.projectDirectory.dir("rust/uniffi.toml").asFile.absolutePath,
            )
        }.result.get()
        if (result.exitValue != 0) throw GradleException("ADFREE: uniffi-bindgen failed")
    }
}

// Any Kotlin compile needs the native library to exist.
tasks.matching { it.name.startsWith("compile") && it.name.endsWith("Kotlin") }.configureEach {
    if (!skipNative) dependsOn(buildRust)
}
