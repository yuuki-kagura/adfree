package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Test

/** A rules file may come from AdGuard, a hosts file, or a text editor. */
class UserRulesTextTest {

    @Test
    fun `blank lines, comments and duplicates are dropped`() {
        val text = """
            ! AdGuard comment

            ||ads.example^
            ||ads.example^
            # hosts comment
            #another comment
            @@||safe.example^
        """.trimIndent()

        assertEquals(
            listOf("||ads.example^", "@@||safe.example^"),
            parseUserRulesText(text),
        )
    }

    @Test
    fun `a BOM and CRLF do not leak into the first or last rule`() {
        val text = "\uFEFF||first.example^\r\n||second.example^\r\n"
        assertEquals(
            listOf("||first.example^", "||second.example^"),
            parseUserRulesText(text),
        )
    }

    @Test
    fun `cosmetic markers survive while hosts comments do not`() {
        val text = """
            ##.global-banner
            #%#//scriptlet('abort-on-property-read', 'ads')
            #@#.allowed
            #$#div:style(display: none)
            #?#.questionable
            # plain comment
        """.trimIndent()

        assertEquals(
            listOf(
                "##.global-banner",
                "#%#//scriptlet('abort-on-property-read', 'ads')",
                "#@#.allowed",
                "#$#div:style(display: none)",
                "#?#.questionable",
            ),
            parseUserRulesText(text),
        )
    }

    @Test
    fun `order is preserved and trimming is per line`() {
        assertEquals(
            listOf("@@||b.example^", "||a.example^"),
            parseUserRulesText("  @@||b.example^  \n\t||a.example^\n"),
        )
    }

    @Test
    fun `an empty file is an empty rule set`() {
        assertEquals(emptyList<String>(), parseUserRulesText(""))
        assertEquals(emptyList<String>(), parseUserRulesText("\n\n! only a comment\n"))
    }

    /**
     * The allowlist's per-rule switch parks a rule as `!` + rule instead of
     * deleting it, so a parked rule has to survive every read of the file —
     * and prose behind a `!` still has to go, or the user's list fills up with
     * whatever a comment line happened to say.
     */
    @Test
    fun `a parked rule survives while commented prose does not`() {
        val text = """
            !@@||safe.example^
            !||ads.example^
            !##.banner
            ! thanks for trying
            !!@@||double.example^
        """.trimIndent()

        assertEquals(
            listOf("!@@||safe.example^", "!||ads.example^", "!##.banner"),
            parseUserRulesText(text),
        )
    }

    @Test
    fun `a typed domain becomes an exception rule`() {
        assertEquals("@@||example.com^", userWhitelistRule("example.com"))
        assertEquals("@@||example.com^", userWhitelistRule("  https://Example.com/path?q=1  "))
        assertEquals("@@||*.example.com^", userWhitelistRule("*.example.com"))
        assertEquals("@@||safe.com^", userWhitelistRule("@@||safe.com^"))
    }

    @Test
    fun `invalid whitelist input is rejected`() {
        assertEquals(null, userWhitelistRule(""))
        assertEquals(null, userWhitelistRule("bad host"))
        assertEquals(null, userWhitelistRule("https://"))
        assertEquals(null, userWhitelistRule("example.com:8080"))
        assertEquals(null, userWhitelistRule("@@"))
    }

    @Test
    fun `a typed domain becomes a blocking rule`() {
        assertEquals("||example.com^", userBlockRule("example.com"))
        assertEquals("||example.com^", userBlockRule("  https://Example.com/path?q=1  "))
        assertEquals("||example.com^", userBlockRule("example.com/path?q=1"))
        assertEquals("||*.example.com^", userBlockRule("*.example.com"))
    }

    @Test
    fun `complete rule syntax is kept verbatim on the block tab`() {
        assertEquals("||ads.example^\$third-party", userBlockRule("||ads.example^\$third-party"))
        assertEquals("example.com##.banner", userBlockRule("example.com##.banner"))
        assertEquals("0.0.0.0 tracker.example", userBlockRule("0.0.0.0 tracker.example"))
        assertEquals("@@||safe.example^", userBlockRule("@@||safe.example^"))
    }

    @Test
    fun `blank, comment-only and non-host block input is rejected`() {
        assertEquals(null, userBlockRule(""))
        assertEquals(null, userBlockRule("! just a comment"))
        assertEquals(null, userBlockRule("# hosts comment"))
        assertEquals(null, userBlockRule("tétblock.com"))
        assertEquals(null, userBlockRule("not a rule"))
    }
}
