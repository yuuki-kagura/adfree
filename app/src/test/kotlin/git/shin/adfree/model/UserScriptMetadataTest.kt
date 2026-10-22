package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UserScriptMetadataTest {

    private val header = """
        // ==UserScript==
        // @name         Example
        // @version      2.4.1
        // @match        https://example.com/*
        // @match        https://*.example.org/*
        // @include      /^https?:\/\/news\./
        // @run-at       document-idle
        // @grant        GM_xmlhttpRequest
        // @grant        GM_addStyle
        // ==/UserScript==

        // @match https://not-header.example/*
        console.log("hi")
    """.trimIndent()

    @Test
    fun readsTheHeaderFields() {
        val meta = parseUserScriptMetadata(header)
        assertEquals("2.4.1", meta.version)
        assertEquals("document-idle", meta.runAt)
        assertEquals(
            listOf(
                "https://example.com/*",
                "https://*.example.org/*",
                "/^https?:\\/\\/news\\./",
            ),
            meta.patterns,
        )
        assertEquals(listOf("GM_xmlhttpRequest", "GM_addStyle"), meta.grants)
        assertTrue(meta.hasBroadAccess)
    }

    @Test
    fun codeBelowTheHeaderIsNotMetadata() {
        // The `@match` after `==/UserScript==` must not replace the real ones.
        assertEquals(3, parseUserScriptMetadata(header).patterns.size)
    }

    @Test
    fun bodyWithoutAHeaderYieldsEmptyMetadata() {
        assertEquals(UserScriptMetadata(), parseUserScriptMetadata("console.log('plain')"))
        assertEquals(UserScriptMetadata(), parseUserScriptMetadata(""))
    }

    @Test
    fun grantNoneAndPassiveApisAreNotBroadAccess() {
        val meta = parseUserScriptMetadata(
            """
            // ==UserScript==
            // @grant none
            // @grant GM_log
            // ==/UserScript==
            """.trimIndent(),
        )
        assertFalse(meta.hasBroadAccess)
        assertEquals(listOf("none", "GM_log"), meta.grants)
    }

    @Test
    fun acceptsCrlfAndDropsDuplicatePatterns() {
        val body = "// ==UserScript==\r\n" +
            "// @match https://a.example/*\r\n" +
            "// @match https://a.example/*\r\n" +
            "// @run-at document-start\r\n" +
            "// ==/UserScript==\r\n"
        val meta = parseUserScriptMetadata(body)
        assertEquals(listOf("https://a.example/*"), meta.patterns)
        assertEquals("document-start", meta.runAt)
    }
}
