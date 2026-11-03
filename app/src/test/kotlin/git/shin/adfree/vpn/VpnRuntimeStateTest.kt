package git.shin.adfree.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnRuntimeStateTest {

    @Test
    fun `a paused tunnel reads as paused, an inactive one never does`() {
        assertEquals(VpnUiState.OFF, vpnUiState(active = false, paused = false))
        assertEquals(VpnUiState.OFF, vpnUiState(active = false, paused = true))
        assertEquals(VpnUiState.ON, vpnUiState(active = true, paused = false))
        assertEquals(VpnUiState.PAUSED, vpnUiState(active = true, paused = true))
    }

    @Test
    fun `the notification toggles pause and resume`() {
        assertEquals(VpnActions.PAUSE, vpnToggleAction(paused = false))
        assertEquals(VpnActions.RESUME, vpnToggleAction(paused = true))
    }

    @Test
    fun `stopping from the notification is distinct from a reconfigure stop`() {
        // ACTION_STOP_VPN must not touch the remembered switch: restarting the
        // tunnel relies on it staying on.
        assertNotEquals(VpnActions.STOP, VpnActions.DISABLE)
        assertEquals("com.adfree.DISABLE_PROTECTION", VpnActions.DISABLE)
        assertEquals("com.adfree.STOP_VPN", VpnActions.STOP)
    }

    @Test
    fun `only a tunnel the user did not stop is reported as dropped`() {
        // A revoke or a system kill: the switch still expects protection and
        // the tunnel was up when the service went down.
        assertTrue(shouldReportDroppedProtection(wasRunning = true, protectionExpected = true))
        // Both disable paths clear the switch before the service dies, so the
        // user is not told about a stop they asked for.
        assertFalse(shouldReportDroppedProtection(wasRunning = true, protectionExpected = false))
        // A reconfigure keeps the switch on but takes the tunnel down first, so
        // the alert would fire on every restart if the tunnel alone decided it.
        assertFalse(shouldReportDroppedProtection(wasRunning = false, protectionExpected = true))
        assertFalse(shouldReportDroppedProtection(wasRunning = false, protectionExpected = false))
    }
}
