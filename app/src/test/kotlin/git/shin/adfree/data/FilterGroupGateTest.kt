package git.shin.adfree.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The group banner ("Không hoạt động") must agree with what the core
 * actually gates: AD + ANNOYANCE fold under the ads module, and
 * TRACKER + ANALYTICS + SOCIAL under tracking. A wrong mapping would show
 * a banner on a group that is filtering fine, or the reverse.
 */
class FilterGroupGateTest {

    @Test
    fun `ads annoyance and language follow the ads module`() {
        assertEquals(ModuleGate.AD_BLOCKING, FilterGroup.ADS.moduleGate)
        assertEquals(ModuleGate.AD_BLOCKING, FilterGroup.ANNOYANCES.moduleGate)
        assertEquals(ModuleGate.AD_BLOCKING, FilterGroup.LANGUAGE.moduleGate)
    }

    @Test
    fun `privacy and social follow the tracking module`() {
        assertEquals(ModuleGate.TRACKING, FilterGroup.PRIVACY.moduleGate)
        assertEquals(ModuleGate.TRACKING, FilterGroup.SOCIAL.moduleGate)
    }

    @Test
    fun `security other custom and user rules are never gated`() {
        assertNull(FilterGroup.SECURITY.moduleGate)
        assertNull(FilterGroup.OTHER.moduleGate)
    }
}
