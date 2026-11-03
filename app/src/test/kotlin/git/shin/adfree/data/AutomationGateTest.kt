package git.shin.adfree.data

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The gate decides what an exported receiver is allowed to do, so its refusal
 * cases matter more than its happy path: a broadcast from any installed app
 * must not be able to switch protection off before the user opts in.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class AutomationGateTest {

    private fun gate(): AutomationGate = AutomationGate(ApplicationProvider.getApplicationContext())

    @Test
    fun `external control is off on a fresh install and carries no usable token`() {
        val gate = gate()
        val state = gate.state.value
        assertFalse(state.enabled)
        // A token is minted for the Settings row, but nothing is authorised yet.
        // 16 random bytes, hex: long enough that guessing is not a strategy.
        assertEquals(32, state.token.length)
        assertTrue(state.token.all { it in 'a'..'f' || it in '0'..'9' })
        assertFalse(gate.authorize(state.token))
    }

    @Test
    fun `the token survives a restart instead of being reissued`() {
        val first = gate().state.value.token
        assertEquals(first, gate().state.value.token)
    }

    @Test
    fun `an enabled gate accepts only the exact token`() {
        val gate = gate()
        val token = gate.state.value.token
        gate.setEnabled(true)
        assertTrue(gate.authorize(token))
        assertFalse(gate.authorize(null))
        assertFalse(gate.authorize(""))
        assertFalse(gate.authorize("  "))
        assertFalse(gate.authorize(token.drop(1)))
        assertFalse(gate.authorize(token.uppercase()))
    }

    @Test
    fun `turning the gate off stops every broadcast again`() {
        val gate = gate()
        val token = gate.state.value.token
        gate.setEnabled(true)
        gate.setEnabled(false)
        assertFalse(gate.authorize(token))
    }

    @Test
    fun `rotating retires the old token and closes the switch`() {
        val gate = gate()
        val old = gate.state.value.token
        gate.setEnabled(true)

        val fresh = gate.rotateToken()

        assertNotEquals(old, fresh)
        assertEquals(fresh, gate.state.value.token)
        // Deliberately off: the user has to re-enable it knowing the new value.
        assertFalse(gate.state.value.enabled)
        assertFalse(gate.authorize(old))

        gate.setEnabled(true)
        assertTrue(gate.authorize(fresh))
    }
}
