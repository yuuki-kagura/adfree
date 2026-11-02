package git.shin.adfree.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    /**
     * The card's one-tap Enable button flips the module behind the gate, through
     * an intent that calls one repository toggle. A gate whose toggle is missing
     * or renamed would leave a button on screen that does nothing at all, so the
     * enum-to-toggle pairing is pinned here rather than trusted to the screen.
     */
    @Test
    fun `every module gate has a repository toggle`() {
        val toggles = AdGuardRepository::class.java.methods
            .filter { method ->
                method.parameterTypes.size == 1 && method.parameterTypes[0] == java.lang.Boolean.TYPE
            }
            .map { it.name }
        for (gate in ModuleGate.entries) {
            val toggle = when (gate) {
                ModuleGate.AD_BLOCKING -> "toggleAdBlocking"
                ModuleGate.ANNOYANCES -> "toggleAnnoyances"
                ModuleGate.TRACKING -> "toggleTrackingProtection"
                ModuleGate.BROWSING_SECURITY -> "toggleBrowsingSecurity"
            }
            assertTrue("$gate needs $toggle()", toggle in toggles)
        }
    }
}
