// The Android-free domain shared by :app and :desktop: uniffi bindings,
// models, OTA rules, the UI layer (Compose compileOnly — the host module
// supplies the runtime), platform interfaces, and the string tables.

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.jetbrains.compose)
    alias(libs.plugins.kotlin.compose)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    compileOnly(libs.jna)

    // Compose is compiled against the desktop artifacts (same androidx.*
    // packages as the Android AARs at the matching 1.8.2 version); each host
    // module brings its own runtime copy.
    compileOnly(compose.runtime)
    compileOnly(compose.foundation)
    compileOnly(compose.ui)
    compileOnly(compose.runtimeSaveable)
    compileOnly(compose.animation)
    compileOnly(compose.material3)
    compileOnly(compose.materialIconsExtended)

    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit)
    testImplementation(compose.runtime)
}
