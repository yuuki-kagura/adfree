package git.shin.adfree.desktop

import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException

/**
 * The one window that owns this machine's engine.
 *
 * Two instances are not two filters: the instance holding the ports answers
 * every redirected query, and a second one that fails to bind leaves the
 * first one's traffic pointed at a port it no longer holds. So the lock is
 * taken before the core is even started, and held for the life of the
 * process.
 *
 * It is also the hand-over switch. Filtering on a desktop needs
 * `CAP_NET_ADMIN`, which only the privileged unit has, so an unprivileged
 * window that is asked to protect the machine starts that unit and leaves —
 * and the unit runs this same `main`, which reads this same lock. Whoever
 * asks for the hand-over therefore has to let go *first*, before the ask:
 * holding it while asking is two processes waiting for each other, and the
 * unit gives up after ten seconds and exits. The window then stays up
 * saying "protected" over a proxy that was never raised, which is exactly
 * what a user reported: no password prompt, no filtering, and a score of
 * 20 % with an empty log.
 */
class InstanceLock(private val dataRoot: File) {

    private var channel: FileChannel? = null

    /** Takes the lock, waiting [timeoutMs] for the process being replaced. */
    fun acquire(timeoutMs: Long = 10_000): Boolean {
        val held = channel ?: try {
            dataRoot.mkdirs()
            FileChannel.open(
                File(dataRoot, "adfree.lock").toPath(),
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE,
            )
        } catch (e: Exception) {
            // A directory that cannot hold a lock file is not a reason to lose
            // the window; it is the same window that would have said so.
            System.err.println("[desktop] no instance lock: ${e.message}")
            return true
        }
        channel = held
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val lock = try {
                held.tryLock()
            } catch (_: OverlappingFileLockException) {
                null
            }
            if (lock != null) return true
            Thread.sleep(250)
        }
        held.close()
        channel = null
        return false
    }

    /**
     * Lets go, so the privileged instance this process is about to ask for can
     * take over. Only meaningful on the way out: nothing here re-reads state
     * from a lock it no longer holds.
     */
    fun release() {
        try {
            channel?.close()
        } catch (_: Exception) {
            // Already gone is the state it was wanted in.
        }
        channel = null
    }
}
