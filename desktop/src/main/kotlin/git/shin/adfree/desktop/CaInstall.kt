package git.shin.adfree.desktop

import git.shin.adfree.core.coreInstallCaPem
import java.io.File
import kotlin.system.exitProcess

/**
 * The one job of this process: put the filtering CA into the system trust
 * store, then leave. [DesktopPrivileges] starts it as root through polkit,
 * which is the desktop answer to the consent a phone gets from `su` — the app
 * asks, the system's own dialog answers, no terminal involved.
 *
 * It is deliberately not a smaller copy of the app. No container, no database,
 * no listeners: a process running as root that opened the signed-in user's
 * files would leave rows the app cannot write afterwards. It reads one PEM the
 * app exported, and the core decides where that PEM goes and which command
 * rehashes the store (`rust/src/trust.rs`), so the answer about this distro's
 * layout exists in exactly one place.
 *
 * Both paths come from the caller because the elevation hands this process an
 * environment of its own: nothing here may depend on where the app was started
 * from, and a helper that searched for its core would find root's guess instead
 * of the one the app is running.
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
    val library = File(args.getOrNull(1).orEmpty())
    if (!library.isFile) {
        System.err.println("adfree-ca-install: no core library at ${library.path}")
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
