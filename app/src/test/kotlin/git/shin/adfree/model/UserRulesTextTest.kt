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
}
