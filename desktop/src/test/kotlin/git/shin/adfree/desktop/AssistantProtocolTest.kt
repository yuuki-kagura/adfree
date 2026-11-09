package git.shin.adfree.desktop

import git.shin.adfree.desktop.AssistantBridge.Companion.API_VERSION
import git.shin.adfree.desktop.AssistantBridge.Companion.filteringPayload
import git.shin.adfree.desktop.AssistantBridge.Companion.initPayload
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The shapes the extension reads without checking them first.
 *
 * Both fields pinned here were found the hard way: the popup accepted the
 * answers, threw one line later, and stayed on "AdGuard is starting…" with no
 * visible error. A missing key is not a smaller answer — it is a broken panel.
 */
class AssistantProtocolTest {

    private fun kotlinx.serialization.json.JsonObject.str(key: String): String? =
        this[key]?.jsonPrimitive?.contentOrNull

    private fun kotlinx.serialization.json.JsonObject.bool(key: String): Boolean? =
        this[key]?.jsonPrimitive?.booleanOrNull

    @Test
    fun `init answers the extension's api version and no unknown platform`() {
        val init = initPayload("1.0.0")

        assertEquals(API_VERSION, init.str("apiVersion"))
        assertEquals("1.0.0", init.str("version"))
        // "Linux" is not a platform this extension has: its pause gate indexes
        // a two-key table with the name, and an undefined minimum version makes
        // the popup throw. Empty means "no pause button", not "broken panel".
        assertEquals("", init.str("platform"))
        assertTrue(init.bool("isValidatedOnHost") == true)
    }

    @Test
    fun `filtering state always carries the certificate status`() {
        val state = filteringPayload("example.com", excepted = false, httpsFiltering = true)

        // The popup calls `.toUpperCase()` on this without a guard.
        assertNotNull(state.str("originalCertStatus"))
        assertEquals("VALID", state.str("originalCertStatus"))
        assertTrue(state.bool("isFilteringEnabled") == true)
        assertTrue(state.bool("isHttpsFilteringEnabled") == true)
        assertTrue(state.bool("canChangeFilteringStatus") == true)
    }

    @Test
    fun `an excepted page is reported as not filtered`() {
        val state = filteringPayload("example.com", excepted = true, httpsFiltering = true)
        assertFalse(state.bool("isFilteringEnabled") == true)
    }

    @Test
    fun `a non-web url is not filtered and still answers completely`() {
        val state = filteringPayload(null, excepted = false, httpsFiltering = false)

        assertFalse(state.bool("isFilteringEnabled") == true)
        assertFalse(state.bool("isHttpsFilteringEnabled") == true)
        assertEquals("VALID", state.str("originalCertStatus"))
        assertNull(state["originalCertIssuer"]?.jsonPrimitive?.contentOrNull)
    }
}
