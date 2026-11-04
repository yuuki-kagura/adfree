// Linux desktop consumer of :shared. Today it is a console proof that the
// Android-free domain runs on the host JVM; a Compose-for-desktop UI is the
// next step once more of :app moves over.

plugins {
    alias(libs.plugins.kotlin.jvm)
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
}

dependencies {
    implementation(project(":shared"))
    runtimeOnly(libs.jna)
}
