package git.shin.adfree.data

import git.shin.adfree.model.AppFirewallRule
import git.shin.adfree.model.FirewallAccess
import git.shin.adfree.model.LogLevel
import git.shin.adfree.model.ProtectionSettings
import git.shin.adfree.model.StealthPreset
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
    fun the_anti_dpi_switch_survives_the_core_round_trip() {
        val settings = ProtectionSettings(isStealthModeEnabled = true, antiDpi = true)

        val back = settings.toCoreState().toModel()

        assertTrue(back.antiDpi)
        assertFalse(ProtectionSettings().antiDpi)
    }

    @Test
    fun the_masked_address_survives_the_core_round_trip() {
        val settings = ProtectionSettings(isStealthModeEnabled = true, maskIp = "203.0.113.9")

        val back = settings.toCoreState().toModel()

        assertEquals("203.0.113.9", back.maskIp)
        assertEquals("", ProtectionSettings().maskIp)
    }

    @Test
    fun log_level_survives_the_core_round_trip() {
        val settings = ProtectionSettings(logLevel = LogLevel.DEBUG)

        assertEquals(LogLevel.DEBUG, settings.toCoreState().toModel().logLevel)
        // The shipped level is the one that logs what the ring logged before
        // levels existed, so a fresh install must not fall to Off or Debug.
        assertEquals(LogLevel.WARN, ProtectionSettings().toCoreState().toModel().logLevel)
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

    @Test
    fun a_preset_writes_exactly_the_documented_switches() {
        val standard = StealthPreset.STANDARD.applyTo(ProtectionSettings())
        assertTrue(standard.isStealthModeEnabled)
        assertTrue(standard.stripUtmTracking)
        assertTrue(standard.blockThirdPartyCookies)
        assertFalse(standard.blockWebRtcLeaks)
        assertFalse(standard.disguiseUserAgent)
        assertFalse(standard.blockAllCookies)
        assertFalse(standard.stripEtag)
        assertFalse(standard.stripThirdPartyAuthorization)
        assertFalse(standard.hideThirdPartyReferer)
        assertFalse(standard.injectGpcDnt)
        assertFalse(standard.hideSearchQuery)
        assertFalse(standard.blockPushApi)
        assertFalse(standard.blockGeolocationApi)

        val high = StealthPreset.HIGH.applyTo(ProtectionSettings())
        assertTrue(high.blockWebRtcLeaks)
        assertTrue(high.hideThirdPartyReferer)
        assertTrue(high.injectGpcDnt)
        assertTrue(high.hideSearchQuery)
        assertFalse(high.disguiseUserAgent)
        assertFalse(high.blockAllCookies)
        assertFalse(high.stripEtag)
        assertFalse(high.stripThirdPartyAuthorization)
        assertFalse(high.blockPushApi)
        assertFalse(high.blockGeolocationApi)

        val ultra = StealthPreset.ULTRA.applyTo(ProtectionSettings())
        assertTrue(ultra.stripUtmTracking)
        assertTrue(ultra.blockWebRtcLeaks)
        assertTrue(ultra.disguiseUserAgent)
        assertTrue(ultra.blockThirdPartyCookies)
        assertTrue(ultra.blockAllCookies)
        assertTrue(ultra.stripEtag)
        assertTrue(ultra.stripThirdPartyAuthorization)
        assertTrue(ultra.hideThirdPartyReferer)
        assertTrue(ultra.injectGpcDnt)
        assertTrue(ultra.hideSearchQuery)
        assertTrue(ultra.blockPushApi)
        assertTrue(ultra.blockGeolocationApi)

        // Reading the level back from the switches is what keeps the radio from
        // claiming a level the traffic does not get.
        assertEquals(StealthPreset.STANDARD, StealthPreset.of(standard))
        assertEquals(StealthPreset.HIGH, StealthPreset.of(high))
        assertEquals(StealthPreset.ULTRA, StealthPreset.of(ultra))

        // Anti-DPI and the masked address are not a level's business: the first
        // changes what a middlebox sees rather than what a site sees, and the
        // second is text the user typed. Picking a level leaves both alone, and
        // neither has any part in reading the level back.
        val level = ultra.copy(antiDpi = true, maskIp = "203.0.113.9")
        val repicked = StealthPreset.STANDARD.applyTo(level)
        assertTrue(repicked.antiDpi)
        assertEquals("203.0.113.9", repicked.maskIp)
        assertEquals(StealthPreset.ULTRA, StealthPreset.of(level))
    }

    @Test
    fun the_shipped_defaults_read_as_the_standard_level() {
        assertEquals(StealthPreset.STANDARD, StealthPreset.of(ProtectionSettings()))
    }

    @Test
    fun a_hand_set_switch_reads_as_custom_and_rewrites_nothing() {
        val mixed = StealthPreset.STANDARD.applyTo(ProtectionSettings()).copy(injectGpcDnt = true)

        assertEquals(StealthPreset.CUSTOM, StealthPreset.of(mixed))
        assertEquals(mixed, StealthPreset.CUSTOM.applyTo(mixed))
    }
}
