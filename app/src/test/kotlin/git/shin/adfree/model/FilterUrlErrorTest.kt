package git.shin.adfree.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The "Add custom filter" dialog blocks a bad URL before it can become a
 * permanent broken row; these are the acceptance rules of `filterUrlError`.
 */
class FilterUrlErrorTest {

    @Test
    fun `plain https and http urls pass`() {
        assertNull(filterUrlError("https://easylist.to/easylist/easylist.txt"))
        assertNull(filterUrlError("http://somehost.invalid:8080/list.txt"))
        // User input carries whitespace.
        assertNull(filterUrlError("  https://example.org/a.txt  "))
    }

    @Test
    fun `empty means pick a file or type a url`() {
        assertEquals("Nhập URL hoặc chọn tệp trong máy", filterUrlError(""))
        assertEquals("Nhập URL hoặc chọn tệp trong máy", filterUrlError("   "))
    }

    @Test
    fun `non http schemes are rejected`() {
        // Local files go through the file picker like the other schemes.
        assertEquals(
            "Chỉ chấp nhận URL http(s):// — dùng nút chọn tệp cho file trong máy",
            filterUrlError("file:///sdcard/list.txt"),
        )
        assertEquals(
            "Chỉ chấp nhận URL http(s):// — dùng nút chọn tệp cho file trong máy",
            filterUrlError("ftp://example.org/list.txt"),
        )
    }

    @Test
    fun `garbage and hostless urls are rejected`() {
        assertEquals("Đường dẫn không hợp lệ", filterUrlError("not a real url"))
        // `URI("https://")` throws outright, so it lands in the parse-error
        // bucket; authority present but empty keeps the hostless message.
        assertEquals("Đường dẫn không hợp lệ", filterUrlError("https://"))
        assertEquals("URL thiếu địa chỉ máy chủ", filterUrlError("https:///only-path"))
        assertEquals("URL quá dài", filterUrlError("https://a" + "b".repeat(2100) + ".org/x"))
    }
}
