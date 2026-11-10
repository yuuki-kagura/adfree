package git.shin.adfree.desktop

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * One window owns the engine. The privileged unit is a second `main` that takes
 * the same lock, so the hand-over only works when the asking window lets go
 * first — the state this file guards.
 */
class InstanceLockTest {

    private fun scratch(): File =
        File.createTempFile("adfree-lock-", "").let { it.delete(); it.mkdirs(); it }

    @Test
    fun aSecondWindowCannotHoldTheSameEngine() {
        val directory = scratch()
        val first = InstanceLock(directory)
        val second = InstanceLock(directory)
        try {
            assertTrue("the first window takes the engine", first.acquire(500))
            assertFalse("the second must not start a second engine", second.acquire(300))
        } finally {
            first.release()
            second.release()
        }
    }

    @Test
    fun lettingGoHandsTheEngineToTheInstanceThatWaits() {
        val directory = scratch()
        val window = InstanceLock(directory)
        val unit = InstanceLock(directory)
        try {
            assertTrue(window.acquire(500))
            // The hand-over: release before asking the unit to start.
            window.release()
            assertTrue("the unit takes the engine the window released", unit.acquire(1_000))
        } finally {
            window.release()
            unit.release()
        }
    }

    /**
     * A refusal has to put the window back where it was: a failed ask that left
     * the lock released would let the next window start a second engine.
     */
    @Test
    fun aWindowCanTakeBackWhatItReleased() {
        val directory = scratch()
        val lock = InstanceLock(directory)
        try {
            assertTrue(lock.acquire(500))
            lock.release()
            assertTrue("the refused ask takes the engine back", lock.acquire(500))
        } finally {
            lock.release()
        }
    }
}
