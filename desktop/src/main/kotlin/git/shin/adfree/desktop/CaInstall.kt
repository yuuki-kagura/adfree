package git.shin.adfree.desktop

import git.shin.adfree.core.coreInstallCaPem
import java.io.File
import kotlin.system.exitProcess

/**
 * The one job of this process: put the filtering CA into the system trust
 * store, then leave. [DesktopPrivileges] starts it as a short-lived root unit
 * through polkit, which is the desktop answer to the consent a phone gets from
 * `su` — the app asks, the system's own dialog answers, no terminal involved.
 *
 * It is deliberately not a smaller copy of the app. No container, no database,
 * no listeners: a process running as root that opened the signed-in user's
 * files would leave rows the app cannot write afterwards. It reads one PEM the
 * app exported, and the core decides where that PEM goes and which command
 * rehashes the store (`rust/src/trust.rs`), so the answer about this distro's
 * layout exists in exactly one place.
 *
 * Exit status is the whole report: zero means the certificate reads back from
 * the store, anything else says what the system said.
 */
fun main(args: Array<String>) {
    val pem = File(args.firstOrNull().orEmpty())
    if (!pem.isFile) {
        System.err.println("adfree-ca-install: no certificate at ${pem.path}")
        exitProcess(2)
    }
    // The unit has no working directory of this app's, so the core is named
    // rather than found: ADFREE_CORE_LIB is set by the caller.
    val library = findCoreLibrary()
    if (library == null) {
        System.err.println("adfree-ca-install: libadfree_core.so not found")
        exitProcess(2)
    }
    System.setProperty("uniffi.component.adfree.libraryOverride", library.absolutePath)
    val result = runCatching { coreInstallCaPem(pem.readText()) }.getOrElse { failure ->
        System.err.println("adfree-ca-install: ${failure.message ?: failure.javaClass.simpleName}")
        exitProcess(1)
    }
    if (!result.installed) {
        System.err.println("adfree-ca-install: ${result.detailCode} ${result.detail}".trimEnd())
        exitProcess(1)
    }
}
