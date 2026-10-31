package git.shin.adfree.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The group banner ("Không hoạt động") must agree with what the core
 * actually gates: AD + LANGUAGE fold under the ads module, ANNOYANCE under
 * the annoyances module, TRACKER + ANALYTICS + SOCIAL under tracking, and
 * MALWARE under browsing security. A wrong mapping would show a banner on a
 * group that is filtering fine, or the reverse.
 */
class FilterGroupGateTest {

    @Test
    fun `ads and language follow the ads module`() {
        assertEquals(ModuleGate.AD_BLOCKING, FilterGroup.ADS.moduleGate)
        assertEquals(ModuleGate.AD_BLOCKING, FilterGroup.LANGUAGE.moduleGate)
    }

    @Test
    fun `annoyances follow their own module`() {
        assertEquals(ModuleGate.ANNOYANCES, FilterGroup.ANNOYANCES.moduleGate)
    }

    @Test
    fun `privacy and social follow the tracking module`() {
        assertEquals(ModuleGate.TRACKING, FilterGroup.PRIVACY.moduleGate)
        assertEquals(ModuleGate.TRACKING, FilterGroup.SOCIAL.moduleGate)
    }

    @Test
    fun `security lists follow browsing security`() {
        assertEquals(ModuleGate.BROWSING_SECURITY, FilterGroup.SECURITY.moduleGate)
    }

    @Test
    fun `other lists are never gated`() {
        assertNull(FilterGroup.OTHER.moduleGate)
    }
}
