package git.shin.adfree.data

import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.RequestCategory
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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
        assertEquals("stylesheet", fields[18])
        assertEquals("https://example.com/page", fields[19])
    }

    @Test
    fun `a forwarded request exports the transport and the answer it got`() {
        val out = StringWriter()
        writeLogCsv(
            sequenceOf(
                rowAt(3).copy(
                    protocol = ProtocolType.HTTPS,
                    tlsVersion = "TLS 1.3",
                    cipher = "TLS_AES_256_GCM_SHA384",
                    httpResponseStatus = 200,
                    contentType = "text/html",
                    certSubject = "cdn.example.com",
                    certIssuer = "DigiCert TLS RSA SHA256 2020 CA1",
                    certValidFrom = 1_700_000_000_000L,
                    certValidTo = 1_800_000_000_000L,
                ),
            ),
            out,
        )

        val fields = out.toString().reader().readLines()[1].split(",")
        assertEquals(ProtocolType.HTTPS.name, fields[4])
        assertEquals("TLS 1.3", fields[20])
        assertEquals("TLS_AES_256_GCM_SHA384", fields[21])
        assertEquals("200", fields[22])
        assertEquals("text/html", fields[23])
        assertEquals("cdn.example.com", fields[24])
        assertEquals("DigiCert TLS RSA SHA256 2020 CA1", fields[25])
        assertEquals("1700000000000", fields[26])
        assertEquals("1800000000000", fields[27])

        // A DNS row was never an encrypted session, so it names none of that.
        val dnsFields = StringWriter().let { writer ->
            writeLogCsv(sequenceOf(rowAt(4)), writer)
            writer.toString().reader().readLines()[1].split(",")
        }
        assertEquals(8, dnsFields.subList(20, 28).count { it.isEmpty() })
    }

    @Test
    fun `a certificate name with commas stays inside one field`() {
        // Distinguished names are written with commas in them, which is what a
        // CSV has to survive: the row stays one line and the name travels
        // quoted, instead of spilling into every column after it.
        val out = StringWriter()
        val written = writeLogCsv(
            sequenceOf(rowAt(5).copy(certSubject = "Example, Inc, DC=London")),
            out,
        )

        val lines = out.toString().reader().readLines()
        assertEquals(1L, written)
        // Header plus one row: the commas inside the name are quoted, so they
        // never end the line.
        assertEquals(2, lines.size)
        assertTrue(lines[1].contains("\"Example, Inc, DC=London\""))
    }

    @Test
    fun `an unknown app stays an empty field instead of the word null`() {
        val log = rowAt(1).copy(
            appPackage = null,
            matchedRule = null,
            filterListName = null,
            url = null,
            dnsAnswer = null,
            requestType = null,
            source = null,
        )
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

    @Test
    fun `an export reads back as the rows it was written from`() {
        val out = StringWriter()
        writeLogCsv(
            sequenceOf(
                rowAt(1),
                rowAt(2).copy(status = FilterStatus.ALLOWED, certSubject = "a.com", certValidFrom = 5L),
                rowAt(3).copy(protocol = ProtocolType.HTTPS, url = "https://example.com/page"),
            ),
            out,
        )

        val rows = readLogCsv(out.toString())

        assertEquals(3, rows?.size)
        val first = rows?.first()
        assertEquals("10.0.0.1", first?.ipAddress)
        assertEquals(FilterStatus.BLOCKED, first?.status)
        assertEquals(ProtocolType.DNS_UDP, first?.protocol)
        assertEquals("||ad.example.com^", first?.matchedRule)
        assertEquals("EasyList", first?.filterListName)
        assertEquals("stylesheet", first?.requestType)
        assertEquals("https://example.com/page", first?.source)
        assertEquals(120L, first?.latencyMicros)
        assertEquals(4096L, first?.dataSavedBytes)
        // The file is a report, and a report that agrees with the live log on
        // where a row starts and ends is one the user can act on.
        assertEquals(FilterStatus.ALLOWED, rows?.get(1)?.status)
        assertEquals("a.com", rows?.get(1)?.certSubject)
        assertEquals(5L, rows?.get(1)?.certValidFrom)
        assertEquals("https://example.com/page", rows?.get(2)?.url)
        // The export writes whole seconds, so a sub-second row lands on its own
        // second — the only thing an imported file gives up.
        assertEquals(1_730_000_000_000L, first?.timestampMs)
        // An imported row has no store id, but the list still needs a key.
        assertTrue(rows?.all { it.id < 0L } == true)
    }

    @Test
    fun `a quoted rule with a newline inside comes back as one row`() {
        // A CSP rule really does carry a stylesheet, so the file it travels in
        // has to keep the line break inside the field instead of ending it.
        val rule = "||a.com^\$csp=body {\n    margin: 0\n}"
        val out = StringWriter()
        writeLogCsv(sequenceOf(rowAt(1).copy(matchedRule = rule)), out)

        val rows = readLogCsv(out.toString())

        assertEquals(1, rows?.size)
        assertEquals(rule, rows?.single()?.matchedRule)
    }

    @Test
    fun `a file that is not an export is refused`() {
        assertNull(readLogCsv(""))
        assertNull(readLogCsv("name,value\nadfree,1\n"))
        // A header that starts with today's columns but invents one at the end
        // is not a file this app wrote either.
        assertNull(readLogCsv("time,app,domain,mystery\n1,2,3,4\n"))
    }

    @Test
    fun `a row that cannot be read is dropped rather than guessed at`() {
        val header = StringWriter().also { writeLogCsv(emptySequence(), it) }.toString().trimEnd('\n')
        val time = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US)
            .format(Date(1_730_000_000_000L))

        val rows = readLogCsv(
            "$header\n" +
                "$time,git.shin.adfree,ad.example.com,10.0.0.1,DNS_UDP,BLOCKED,AD\n" +
                "$time,git.shin.adfree,ad.example.com,10.0.0.2,DNS_UDP,PROBABLY,AD\n" +
                "not-a-time,git.shin.adfree,ad.example.com,10.0.0.3,DNS_UDP,BLOCKED,AD\n",
        )

        assertEquals(1, rows?.size)
        assertEquals("10.0.0.1", rows?.single()?.ipAddress)
    }

    @Test
    fun `a file from an older build reads with nothing invented for its gaps`() {
        val out = StringWriter()
        writeLogCsv(sequenceOf(rowAt(1)), out)
        val lines = out.toString().reader().readLines()
        // The header and the row are cut to the same point: what an older
        // export left out stays left out, column by column.
        val older = lines.first().split(",").subList(0, 20).joinToString(",") + "\n" +
            lines[1].split(",").subList(0, 20).joinToString(",")

        val rows = readLogCsv(older)

        assertEquals("10.0.0.1", rows?.single()?.ipAddress)
        assertNull(rows?.single()?.tlsVersion)
        assertNull(rows?.single()?.certSubject)
        assertNull(rows?.single()?.certValidFrom)
    }

    @Test
    fun `an imported file counts its own decisions`() {
        val rows = listOf(
            rowAt(1),
            rowAt(2).copy(status = FilterStatus.WHITELISTED),
            rowAt(3).copy(status = FilterStatus.ALLOWED),
        )

        val imported = ImportedLog.of("adfree-activity.csv", rows)

        assertEquals("adfree-activity.csv", imported.name)
        assertEquals(3, rows.size)
        assertEquals(1L, imported.blocked)
        // A whitelist is a decision that let the request through, so the
        // allowed chip counts it with the allowed rows rather than the blocked.
        assertEquals(2L, imported.allowed)
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
        requestType = "stylesheet",
        source = "https://example.com/page",
    )

    private companion object {
        /** The header and every row must keep the same number of columns. */
        const val COLUMN_COUNT = 28
    }
}
