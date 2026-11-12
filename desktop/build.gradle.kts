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
// The core is a shared object on Unix and a DLL on Windows; everything that
// looks it up — this file, `findCoreLibrary`, the loader inside the core — has
// to agree on which, so the name is derived once.
val isWindowsHost = System.getProperty("os.name").orEmpty().lowercase().startsWith("windows")
val coreLibraryName = if (isWindowsHost) "adfree_core.dll" else "libadfree_core.so"
val coreLibrary: File = listOf(
    "rust/target/release/$coreLibraryName",
    // A GNU-targeted build on Windows lands here instead of `target/release`.
    "rust/target/x86_64-pc-windows-gnu/release/$coreLibraryName",
).map { rootProject.layout.projectDirectory.file(it).asFile }.firstOrNull { it.isFile }
    ?: rootProject.layout.projectDirectory.file("rust/target/release/$coreLibraryName").asFile

val stageCoreLibrary by tasks.registering(Copy::class) {
    description = "Puts the Rust core into the app jar, where every package carries it"
    from(coreLibrary)
    into(layout.buildDirectory.dir("coreResources"))
    rename { coreLibraryName }
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
            // One format per family: a deb/rpm for Linux distributions, an MSI
            // for Windows. jpackage only builds for the host it runs on, so the
            // list is chosen there rather than filtered afterwards.
            if (isWindowsHost) {
                targetFormats(TargetFormat.Msi)
                windows {
                    // Stable across releases: MSI upgrades match on this, and a
                    // new one turns an upgrade into a second installed copy.
                    upgradeUuid = "8f2b1c74-4a5e-4c1b-9f39-2d0a7b6c1e55"
                    menuGroup = "AdFree"
                    shortcut = true
                    // Consoles: the app needs no window of its own, and a
                    // package that asks for one opens a black box at logon.
                    console = false
                    // The driver and the certificate store are machine-wide and
                    // need the administrator token, which a per-user MSI cannot
                    // grant. Installing for all users matches what the app
                    // itself must already be.
                    perUserInstall = false
                }
            } else {
                targetFormats(TargetFormat.Deb, TargetFormat.Rpm)
            }
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
        "packageMsi",
        "packageReleaseMsi",
    )
}.configureEach {
    doFirst {
        if (!coreLibrary.isFile) {
            throw GradleException(
                "no ${coreLibrary.path} to package; run `cargo build --release --lib` in rust/ first",
            )
        }
    }
}

// An MSI that cannot find WinDivert is an app that starts and cannot filter. The
// files travel in the jar (``WinDivertFiles``), so the check is that the jar's
// resources are there before packaging, not that they are staged beside it.
tasks.matching { it.name.startsWith("package") && it.name.contains("Msi") }.configureEach {
    doFirst {
        val resource = project.file("src/main/resources/windivert/x64/WinDivert.dll")
        if (isWindowsHost && !resource.isFile) {
            throw GradleException("missing ${resource.path}; the MSI would ship without the driver")
        }
    }
}