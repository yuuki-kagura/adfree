package git.shin.adfree.desktop

import java.io.File
import kotlin.system.exitProcess

/**
 * The one job of this process: write the fixed protection unit and the polkit
 * rule that lets the signed-in user start it, then leave. [DesktopPrivileges]
 * starts it as root through polkit, once per machine.
 *
 * It is deliberately not the app with a different uid and not a general
 * installer: it copies two files it is given to two paths it is told, reloads
 * systemd and enables or removes the unit. Nothing else, because anything else
 * would be a root shell behind a dialog.
 *
 * Arguments: `install <unitSource> <unitPath> <polkitSource> <polkitPath> [enable]`
 * or `remove <unitPath> <polkitPath>`.
 *
 * Exit status is the whole report; stderr carries the detail.
 */
fun main(args: Array<String>) {
    val mode = args.firstOrNull().orEmpty()
    when (mode) {
        "install" -> install(args)
        "remove" -> remove(args)
        else -> fail("adfree-setup: expected install or remove, got '$mode'")
    }
}

private fun install(args: Array<String>) {
    val unitSource = File(args.getOrNull(1).orEmpty())
    val unitPath = args.getOrNull(2).orEmpty()
    val polkitSource = File(args.getOrNull(3).orEmpty())
    val polkitPath = args.getOrNull(4).orEmpty()
    val enable = args.getOrNull(5) == "enable"
    if (unitPath.isBlank() || polkitPath.isBlank()) fail("adfree-setup: no destination given")
    for (source in listOf(unitSource, polkitSource)) {
        if (!source.isFile) fail("adfree-setup: no file at ${source.path}")
    }
    // Readable by everyone: the unit holds no secret, and a unit the user cannot
    // read is a unit they have to take root's word for.
    copy(unitSource, File(unitPath), readableByAll = true)
    // polkitd is not root: the rules directory is `root:polkitd 0750`, and a
    // rule it cannot open is a rule polkitd reports as "Error loading script"
    // and then ignores — a password prompt that comes back for no visible
    // reason.
    copy(polkitSource, File(polkitPath), readableByAll = true)
    step("systemctl", "daemon-reload")
    if (enable) step("systemctl", "enable", File(unitPath).name)
    println("adfree-setup: installed ${File(unitPath).name}")
}

private fun remove(args: Array<String>) {
    val unitPath = args.getOrNull(1).orEmpty()
    val polkitPath = args.getOrNull(2).orEmpty()
    if (unitPath.isNotBlank()) {
        val unit = File(unitPath)
        if (unit.isFile) {
            step("systemctl", "disable", unit.name)
            if (!unit.delete()) fail("adfree-setup: could not remove ${unit.path}")
        }
    }
    if (polkitPath.isNotBlank()) File(polkitPath).delete()
    step("systemctl", "daemon-reload")
    println("adfree-setup: removed")
}

/**
 * A copy that refuses to follow a symlink or to leave a file the user can edit:
 * the unit this writes is what the polkit rule lets them start, so a writable
 * unit would be a writable root command line.
 */
private fun copy(source: File, target: File, readableByAll: Boolean) {
    target.parentFile?.mkdirs()
    target.delete()
    source.copyTo(target, overwrite = true)
    target.setReadable(false, false)
    target.setReadable(true, true)
    if (readableByAll && !target.setReadable(true, false)) {
        fail("adfree-setup: could not make ${target.path} readable by polkitd")
    }
    target.setWritable(true, true)
    target.setWritable(false, false)
    target.setExecutable(false, false)
}

private fun step(vararg argv: String) {
    val process = runCatching { ProcessBuilder(*argv).redirectErrorStream(true).start() }
        .getOrElse { failure -> fail("adfree-setup: ${argv.first()} did not run: ${failure.message}") }
    val output = process.inputStream.bufferedReader().readText().trim()
    if (process.waitFor() != 0) fail("adfree-setup: ${argv.joinToString(" ")} said: ${output.ifBlank { "exit $process" }}")
    if (output.isNotEmpty()) System.err.println("adfree-setup: $output")
}

private fun fail(reason: String): Nothing {
    System.err.println(reason)
    exitProcess(1)
}
