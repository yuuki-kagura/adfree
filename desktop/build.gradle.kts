// Linux desktop consumer of :shared: the console engine probe and a Compose
// for desktop window that renders real core results.

import org.jetbrains.compose.desktop.application.dsl.TargetFormat

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
    implementation(project(":shared"))
    // The native-messaging protocol AdGuard's browser extension speaks is
    // JSON; the bridge parses and builds it with the same library the rest of
    // the app uses.
    implementation(libs.kotlinx.serialization.json)
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

// ── Linux packaging ────────────────────────────────────────────────────────
// A deb and an rpm are what an Ubuntu, Fedora or Arch user installs, and each
// carries its own runtime. The filtering core is a native library the JVM
// loads, so it travels inside the application jar as a resource and is written
// out on first run (`findCoreLibrary`). It goes in the jar rather than through
// jpackage's `--app-content` because that path is decided while the project is
// configured and fails silently when a file is staged a moment too late: the
// package built, shipped, and could not filter.
val coreLibrary = rootProject.layout.projectDirectory.file("rust/target/release/libadfree_core.so")

val stageCoreLibrary by tasks.registering(Copy::class) {
    description = "Puts the Rust core into the app jar, where every package carries it"
    from(coreLibrary)
    into(layout.buildDirectory.dir("coreResources"))
    rename { "libadfree_core.so" }
}

sourceSets["main"].resources.srcDir(layout.buildDirectory.dir("coreResources"))
tasks.named("processResources") { dependsOn(stageCoreLibrary) }

compose.desktop {
    application {
        mainClass = "git.shin.adfree.desktop.AdFreeDesktopKt"
        // The core registers native upcalls; without this flag every one of
        // them is a warning on a JDK that has started enforcing it.
        jvmArgs += listOf("--enable-native-access=ALL-UNNAMED")

        nativeDistributions {
            // `versionName` is what the release tags carry; jpackage takes only
            // digits and dots, so the phone build's version name is what both
            // halves of the release are named after.
            val releaseVersion = (rootProject.findProperty("versionName") as? String)
                ?.takeUnless { it.isBlank() } ?: "1.0.0"
            packageName = "adfree"
            packageVersion = releaseVersion.substringBefore("-")
            description = "System-wide ad blocking: a transparent proxy, a DNS server and a TLS bridge."
            vendor = "Tachibana Shin"
            copyright = "© Tachibana Shin"
            targetFormats(TargetFormat.Deb, TargetFormat.Rpm)
            linux {
                iconFile.set(project.file("src/main/resources/icon/adfree.png"))
                menuGroup = "Network"
                appCategory = "Network"
                debMaintainer = "Tachibana Shin <tachibana-shin@users.noreply.github.com>"
                rpmLicenseType = "Apache-2.0"
                debPackageVersion = releaseVersion
            }
        }
    }
}

// A package without the core is a window that cannot filter, and every step on
// the way treats that as normal, so the build says so instead.
tasks.matching {
    it.name in setOf(
        "createDistributable",
        "createReleaseDistributable",
        "packageDistributionForCurrentOS",
        "packageReleaseDistributionForCurrentOS",
        "packageDeb",
        "packageReleaseDeb",
        "packageRpm",
        "packageReleaseRpm",
    )
}.configureEach {
    doFirst {
        if (!coreLibrary.asFile.isFile) {
            throw GradleException(
                "no ${coreLibrary.asFile.path} to package; run `cargo build --release --lib` in rust/ first",
            )
        }
    }
}