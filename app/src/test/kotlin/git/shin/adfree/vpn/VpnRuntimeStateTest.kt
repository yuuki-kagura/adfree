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

    /**
     * An always-on VPN is restarted by the platform, so the same loss is already
     * on its way back. Saying "protection stopped" about it would be a lie the
     * shade tells for a few seconds.
     */
    @Test
    fun `an always-on tunnel is not announced as dropped`() {
        assertFalse(
            shouldReportDroppedProtection(
                wasRunning = true,
                protectionExpected = true,
                systemKeepsVpn = true,
            ),
        )
        assertTrue(
            shouldReportDroppedProtection(
                wasRunning = true,
                protectionExpected = true,
                systemKeepsVpn = false,
            ),
        )
    }

    /**
     * A start is dispatched before the tunnel exists, so the flag alone says no
     * more than "a tunnel was asked for". A guard that refuses to start on the
     * flag alone turns a failed start into a shortcut that never works again:
     * the recorded shape was three enable-protection taps, the last two with no
     * log and no dialog while `tun0` had no address.
     */
    @Test
    fun `an expected tunnel is not a confirmed one`() {
        assertFalse(tunnelConfirmed(flagActive = true, coreRunning = false))
        assertTrue(tunnelConfirmed(flagActive = true, coreRunning = true))
        // The flag is the only claim of intent, so no core state can confirm a
        // start that was never dispatched.
        assertFalse(tunnelConfirmed(flagActive = false, coreRunning = true))
        assertFalse(tunnelConfirmed(flagActive = false, coreRunning = false))
    }
}
