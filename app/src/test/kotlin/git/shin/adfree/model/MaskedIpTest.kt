package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The mask field has to hand the core what it can apply and refuse what it
 * cannot: an address that is really a host name would be advertised as one and
 * the page would read a lie it cannot check.
 */
class MaskedIpTest {
    @Test
    fun an_address_comes_back_trimmed_and_without_its_brackets() {
        assertEquals("203.0.113.9", normalizeMaskIp("  203.0.113.9 "))
        assertEquals("2001:db8::1", normalizeMaskIp("[2001:db8::1]"))
    }

    @Test
    fun empty_text_clears_the_mask_and_a_name_is_not_an_address() {
        assertEquals("", normalizeMaskIp("   "))
        assertNull(normalizeMaskIp("proxy.example"))
        assertNull(normalizeMaskIp("203.0.113.999"))
        assertNull(normalizeMaskIp("203.0.113"))
    }
}
