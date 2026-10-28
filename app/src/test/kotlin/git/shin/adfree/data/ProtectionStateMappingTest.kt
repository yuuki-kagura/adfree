package git.shin.adfree.data

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
}
