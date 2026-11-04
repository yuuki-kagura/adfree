// Android-free domain code: models, the uniffi core bindings and the OTA
// version rules. Everything here compiles against a plain JVM so a Linux
// desktop consumer (:desktop) can use the same code the app ships.
//
// JNA is compileOnly: the runtime library comes from whoever hosts the module
// (the jna AAR in :app, the jna jar in :desktop), which also avoids shipping
// the same classes twice into the APK.

plugins {
    alias(libs.plugins.kotlin.jvm)
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
    testImplementation(libs.junit)
}
