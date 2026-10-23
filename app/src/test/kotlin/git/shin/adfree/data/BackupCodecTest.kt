package git.shin.adfree.data

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The backup envelope must reject foreign/future files before touching a blob. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BackupCodecTest {

    private fun filters(): JSONObject = JSONObject()
        .put("enabled_catalog_ids", JSONArray().put("adguard_base"))
        .put(
            "user_rules",
            JSONArray().put(JSONObject().put("rule", "||ads.example.com^")),
        )

    @Test
    fun `settings and filter choices round-trip`() {
        val encoded = BackupCodec.encode(
            settings = JSONObject().put("adBlocking", false).put("autoUpdate", 6),
            filters = filters(),
            nowMs = 123L,
        )
        val decoded = BackupCodec.decode(encoded)!!
        assertEquals(false, decoded.settings.getBoolean("adBlocking"))
        assertEquals(6, decoded.settings.getInt("autoUpdate"))
        assertEquals(
            "adguard_base",
            decoded.filters.getJSONArray("enabled_catalog_ids").getString(0),
        )
        assertEquals(
            "||ads.example.com^",
            decoded.filters.getJSONArray("user_rules").getJSONObject(0).getString("rule"),
        )
    }

    @Test
    fun `a first-run backup has an empty settings object`() {
        val decoded = BackupCodec.decode(
            BackupCodec.encode(settings = null, filters = JSONObject()),
        )!!
        assertEquals(0, decoded.settings.length())
        assertEquals(0, decoded.filters.length())
    }

    @Test
    fun `foreign and future files are rejected`() {
        assertNull(BackupCodec.decode("{}"))
        assertNull(BackupCodec.decode("not json"))
        assertNull(
            BackupCodec.decode(
                JSONObject()
                    .put("format", "adfree-backup")
                    .put("version", 99)
                    .put("filters", JSONObject())
                    .toString(),
            ),
        )
        assertNull(
            BackupCodec.decode(
                JSONObject()
                    .put("format", "other-app")
                    .put("version", 1)
                    .put("filters", JSONObject())
                    .toString(),
            ),
        )
    }

    @Test
    fun `a filter key with the wrong type is rejected`() {
        assertNull(
            BackupCodec.decode(
                JSONObject()
                    .put("format", "adfree-backup")
                    .put("version", 1)
                    .put(
                        "filters",
                        JSONObject().put("user_rules", "not an array"),
                    )
                    .toString(),
            ),
        )
    }

    @Test
    fun `a missing settings object restores defaults`() {
        val decoded = BackupCodec.decode(
            JSONObject()
                .put("format", "adfree-backup")
                .put("version", 1)
                .put("filters", filters())
                .toString(),
        )!!
        assertTrue(decoded.settings.length() == 0)
        assertEquals(1, decoded.filters.getJSONArray("user_rules").length())
    }
}
