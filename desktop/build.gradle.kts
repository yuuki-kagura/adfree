// Linux desktop consumer of :shared: the console engine probe and a Compose
// for desktop window that renders real core results.

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.jetbrains.compose)
    alias(libs.plugins.kotlin.compose)
    application
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass = "git.shin.adfree.desktop.MainKt"
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED")
}

dependencies {
    implementation(project(":shared"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    runtimeOnly(libs.jna)

    testImplementation(libs.junit)
    testImplementation(compose.desktop.uiTestJUnit4)
    testImplementation(compose.desktop.currentOs)
    testImplementation(compose.materialIconsExtended)
}

// The console probe stays the default run target; the UI window is separate.
val runUi by tasks.registering(JavaExec::class) {
    group = "application"
    description = "Launch the Compose desktop window"
    mainClass = "git.shin.adfree.desktop.DesktopAppKt"
    classpath = sourceSets["main"].runtimeClasspath
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

// The full AdFree UI (shared screens + desktop seams) in one window.
val runApp by tasks.registering(JavaExec::class) {
    group = "application"
    description = "Launch the full AdFree desktop app"
    mainClass = "git.shin.adfree.desktop.AdFreeDesktopKt"
    classpath = sourceSets["main"].runtimeClasspath
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
