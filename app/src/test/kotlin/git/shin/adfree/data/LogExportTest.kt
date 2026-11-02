package git.shin.adfree.data

import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.RequestCategory
import java.io.StringWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The export used to write the window the UI had loaded, so a log longer than
 * that window came out with rows missing while the file still looked complete.
 * These tests pin the writer to the contract the repository now relies on: it
 * drains the sequence it is handed, so the caller can page the store instead of
 * materialising it, and the count it returns is the number of rows really in
 * the file.
 */
class LogExportTest {

    @Test
    fun `an export writes every row handed to it`() {
        val total = 600
        var pulled = 0
        // Lazy on purpose: the writer must not ask for the whole store up front.
        val rows = Sequence {
            object : Iterator<NetworkRequestLog> {
                private var next = 0L
                override fun hasNext() = next < total
                override fun next(): NetworkRequestLog {
                    pulled++
                    return rowAt(next++)
                }
            }
        }
        val out = StringWriter()

        val written = writeLogCsv(rows, out)

        assertEquals(total.toLong(), written)
        assertEquals(total, pulled)
        val lines = out.toString().reader().readLines()
        assertEquals(total + 1, lines.size)
        assertEquals(COLUMN_COUNT, lines.first().split(",").size)
        assertEquals(COLUMN_COUNT, lines[1].split(",").size)
        assertTrue(lines.last().isNotBlank())
    }

    @Test
    fun `an empty store still exports a readable header`() {
        val out = StringWriter()

        val written = writeLogCsv(emptySequence(), out)

        assertEquals(0L, written)
        assertEquals(COLUMN_COUNT, out.toString().reader().readLines().single().split(",").size)
    }

    @Test
    fun `a row carries its fields in the header order`() {
        val out = StringWriter()
        writeLogCsv(sequenceOf(rowAt(7)), out)

        val fields = out.toString().reader().readLines()[1].split(",")
        assertEquals("git.shin.adfree", fields[1])
        assertEquals("ad.example.com", fields[2])
        assertEquals("10.0.0.7", fields[3])
        assertEquals(ProtocolType.DNS_UDP.name, fields[4])
        assertEquals(FilterStatus.BLOCKED.name, fields[5])
        assertEquals(RequestCategory.AD.name, fields[6])
        assertEquals("||ad.example.com^", fields[7])
        assertEquals("EasyList", fields[8])
        assertEquals("120", fields[9])
        assertEquals("4096", fields[10])
        assertEquals("7", fields[13])
    }

    @Test
    fun `an unknown app stays an empty field instead of the word null`() {
        val log = rowAt(1).copy(appPackage = null, matchedRule = null, filterListName = null, url = null, dnsAnswer = null)
        val out = StringWriter()
        writeLogCsv(sequenceOf(log), out)

        val text = out.toString()
        assertFalse(text.contains("null"))
        assertEquals("", text.reader().readLines()[1].split(",")[1])
    }

    @Test
    fun `a field with a comma or a quote is quoted and escaped`() {
        assertEquals("plain", csvField("plain"))
        assertEquals("a^b", csvField("a^b"))
        assertEquals("\"a,b\"", csvField("a,b"))
        assertEquals("\"a\"\"b\"", csvField("a\"b"))
        assertEquals("\"a\nb\"", csvField("a\nb"))
    }

    @Test
    fun `a rule with commas and quotes still lands on one line`() {
        val rule = "||a.com,b^\",\$popup"
        val log = rowAt(2).copy(matchedRule = rule)
        val out = StringWriter()
        writeLogCsv(sequenceOf(log), out)

        val lines = out.toString().reader().readLines()
        assertEquals(2, lines.size)
        assertTrue(lines[1].contains("\"" + rule.replace("\"", "\"\"") + "\""))
    }

    private fun rowAt(id: Long) = NetworkRequestLog(
        id = id,
        timestampMs = 1_730_000_000_000L + id,
        domain = "ad.example.com",
        ipAddress = "10.0.0.$id",
        protocol = ProtocolType.DNS_UDP,
        status = FilterStatus.BLOCKED,
        category = RequestCategory.AD,
        matchedRule = "||ad.example.com^",
        filterListName = "EasyList",
        appPackage = "git.shin.adfree",
        latencyMicros = 120,
        dataSavedBytes = 4_096,
        flowId = id,
    )

    private companion object {
        /** The header and every row must keep the same number of columns. */
        const val COLUMN_COUNT = 18
    }
}
