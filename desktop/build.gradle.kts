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
    // The host asks libc whether this process may mark its own sockets — that
    // is what decides whether the redirect layout can be installed at all.
    implementation(libs.jna)
    // AWT's tray is XEmbed: on a Wayland session KDE owns the tray through
    // xembedsniproxy, which shows the icon but delivers no clicks, so the
    // Compose tray menu is unreachable. Talking StatusNotifierItem to the
    // session bus is what KDE actually listens to.
    implementation(libs.dbus.java.core)
    implementation(libs.dbus.java.native.unixsocket)

    testImplementation(libs.junit)
    // dbus-java reports a failed send through SLF4J only, and without a provider
    // the reason a signal never left the bus is lost.
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.17")
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
