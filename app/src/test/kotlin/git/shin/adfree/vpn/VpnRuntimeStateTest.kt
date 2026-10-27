package git.shin.adfree.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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
}
