package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HttpsHostTest {

    @Test
    fun acceptsDomainsAndWildcards() {
        assertEquals("example.com", normalizeHttpsHost(" example.com "))
        assertEquals("*.example.com", normalizeHttpsHost("*.Example.com."))
        assertEquals("localhost", normalizeHttpsHost("localhost"))
    }

    @Test
    fun reducesPastedUrlsToTheHost() {
        assertEquals("bank.example", normalizeHttpsHost("https://Bank.Example:443/login?x=1"))
        assertEquals("example.org", normalizeHttpsHost("example.org/path"))
    }

    @Test
    fun rejectsJunk() {
        assertNull(normalizeHttpsHost(""))
        assertNull(normalizeHttpsHost("   "))
        assertNull(normalizeHttpsHost("has space.example"))
        assertNull(normalizeHttpsHost("https://"))
        assertNull(normalizeHttpsHost("..."))
        assertNull(normalizeHttpsHost("ví-dụ.vn"))
        assertNull(normalizeHttpsHost("<script>"))
    }
}
