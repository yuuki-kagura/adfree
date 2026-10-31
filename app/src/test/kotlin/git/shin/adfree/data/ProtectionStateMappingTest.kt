package git.shin.adfree.data

import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.FirewallAccess
import git.shin.adfree.model.ProtectionSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A full-record save must not drop a switch: every Kotlin field has to survive
 * the trip through the Rust record and back.
 */
class ProtectionStateMappingTest {
    @Test
    fun http3_switch_survives_the_core_round_trip() {
        val settings = ProtectionSettings(
            isHttpsFilteringEnabled = true,
            filterHttp3 = true,
        )

        val back = settings.toCoreState().toModel()

        assertTrue(back.isHttpsFilteringEnabled)
        assertTrue(back.filterHttp3)
    }

    @Test
    fun http3_is_off_by_default() {
        assertFalse(ProtectionSettings().filterHttp3)
        assertEquals(ProtectionSettings(), ProtectionSettings().toCoreState().toModel())
    }

    @Test
    fun firewall_settings_survive_the_core_round_trip() {
        val settings = ProtectionSettings(
            isFirewallEnabled = true,
            firewallGlobalRules = false,
            firewallCustomRules = false,
            firewallNotifications = false,
            firewallAllowWifi = false,
            firewallAllowWifiScreenOff = false,
            firewallAllowCellular = false,
            firewallAllowCellularScreenOff = false,
            firewallAllowRoaming = false,
        )

        val back = settings.toCoreState().toModel()

        assertTrue(back.isFirewallEnabled)
        assertFalse(back.firewallGlobalRules)
        assertFalse(back.firewallCustomRules)
        assertFalse(back.firewallNotifications)
        assertFalse(back.firewallAllowWifi)
        assertFalse(back.firewallAllowWifiScreenOff)
        assertFalse(back.firewallAllowCellular)
        assertFalse(back.firewallAllowCellularScreenOff)
        assertFalse(back.firewallAllowRoaming)
    }

    @Test
    fun all_firewall_dimensions_survive_the_core_round_trip() {
        val app = AppFirewallRule(
            packageName = "com.example.app",
            appName = "Example",
            wifiAccess = FirewallAccess.BLOCK,
            wifiScreenOffAccess = FirewallAccess.ALLOW,
            cellularAccess = FirewallAccess.INHERIT,
            cellularScreenOffAccess = FirewallAccess.BLOCK,
            roamingAccess = FirewallAccess.ALLOW,
            isFilterRouted = false,
            isHttpsFiltered = false,
            notifyBlocked = false,
        )

        assertEquals(app, app.toCoreRule().toModel(app.appName, app.category))
    }
}
