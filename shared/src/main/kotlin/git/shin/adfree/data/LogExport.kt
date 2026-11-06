package git.shin.adfree.data

import git.shin.adfree.model.FilterStatus
import git.shin.adfree.model.NetworkRequestLog
import git.shin.adfree.model.NetworkTransport
import git.shin.adfree.model.ProtocolType
import git.shin.adfree.model.RequestCategory
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * The CSV form of the request log, kept apart from the repository so the whole
 * store can be streamed into it without the caller holding it in memory.
 */

private const val LOG_CSV_HEADER =
    "time,app,domain,ip,protocol,status,category,rule,list,latency_us,saved_bytes," +
        "transport,roaming,flow_id,url,dns_answer,bytes_sent,bytes_recv,req_type,source," +
        "tls,cipher,http_status,content_type,cert_subject,cert_issuer," +
        "cert_valid_from,cert_valid_to"

/**
 * Writes every row of [rows], newest first, and returns how many were written.
 *
 * A sequence rather than a list: the store keeps far more rows than the UI ever
 * pages in, and an export that claims to cover the log has to read it to the
 * end without loading it first.
 */
fun writeLogCsv(rows: Sequence<NetworkRequestLog>, out: Writer): Long {
    // Not thread-safe, so it lives here rather than in a shared constant.
    val time = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US)
    out.appendLine(LOG_CSV_HEADER)
    var written = 0L
    for (log in rows) {
        out.appendLine(
            listOf(
                time.format(java.util.Date(log.timestampMs)),
                log.appPackage.orEmpty(),
                log.domain,
                log.ipAddress,
                log.protocol.name,
                log.status.name,
                log.category.name,
                log.matchedRule.orEmpty(),
                log.filterListName.orEmpty(),
                log.latencyMicros.toString(),
                log.dataSavedBytes.toString(),
                log.transport.name,
                log.roaming.toString(),
                log.flowId.toString(),
                log.url.orEmpty(),
                log.dnsAnswer.orEmpty(),
                log.bytesSent.toString(),
                log.bytesReceived.toString(),
                log.requestType.orEmpty(),
                log.source.orEmpty(),
                log.tlsVersion.orEmpty(),
                log.cipher.orEmpty(),
                log.httpResponseStatus?.toString().orEmpty(),
                log.contentType.orEmpty(),
                log.certSubject.orEmpty(),
                log.certIssuer.orEmpty(),
                log.certValidFrom?.toString().orEmpty(),
                log.certValidTo?.toString().orEmpty(),
            ).joinToString(",") { csvField(it) },
        )
        written++
    }
    return written
}

/** Quotes a field only when it would otherwise break the row. */
fun csvField(raw: String): String =
    if (raw.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
        "\"${raw.replace("\"", "\"\"")}\""
    } else {
        raw
    }

/**
 * Reads back a file [writeLogCsv] wrote, in the order it was written.
 *
 * Only our own header is accepted, and a row whose time or status cannot be
 * read is dropped rather than guessed at: an imported row is one a user may
 * decide to block or unblock on, so a half-parsed row is worse than no row.
 * Null means the file is not an AdFree log at all.
 */
fun readLogCsv(text: String): List<NetworkRequestLog>? {
    val records = parseCsvRecords(text)
    val header = records.firstOrNull()?.map { it.trim() } ?: return null
    val expected = LOG_CSV_HEADER.split(",")
    // A file from an older build carries the leading columns of today's list
    // and nothing else; its rows simply have no value for the rest, which is
    // how those same columns read in the store.
    if (header.isEmpty() || header.size > expected.size ||
        expected.subList(0, header.size) != header
    ) {
        return null
    }
    val missing = List(expected.size - header.size) { "" }
    return records.drop(1).mapIndexedNotNull { index, record ->
        if (record.isEmpty()) return@mapIndexedNotNull null
        logFromCsv(record + missing)?.copy(id = -(index + 1L))
    }
}

/**
 * A log file the user opened to look at, kept apart from this machine's own.
 *
 * The counters come with the rows because the log screen reads its header from
 * them: a file has to add up to what is in it, not to what the store holds.
 */
data class ImportedLog(
    val name: String?,
    val rows: List<NetworkRequestLog>,
    val blocked: Long,
    val allowed: Long,
) {
    companion object {
        fun of(name: String?, rows: List<NetworkRequestLog>): ImportedLog {
            val blocked = rows.count { it.status == FilterStatus.BLOCKED }
            return ImportedLog(
                name = name,
                rows = rows,
                blocked = blocked.toLong(),
                allowed = (rows.size - blocked).toLong(),
            )
        }
    }
}

/** One row of an exported log, or null when it is not trustworthy enough to show. */
private fun logFromCsv(fields: List<String>): NetworkRequestLog? {
    val timestamp = runCatching {
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US)
            .parse(fields.getOrElse(0) { "" })?.time
    }.getOrNull() ?: return null
    val status = FilterStatus.entries.firstOrNull { it.name == fields.getOrElse(5) { "" } }
        ?: return null
    val requestType = fields.getOrElse(18) { "" }.ifBlank { null }
    val url = fields.getOrElse(14) { "" }.ifBlank { null }
    return NetworkRequestLog(
        // Replaced by the caller: an imported row has no store id, and the UI
        // needs a stable key all the same.
        id = 0L,
        timestampMs = timestamp,
        domain = fields.getOrElse(2) { "" },
        ipAddress = fields.getOrElse(3) { "" },
        protocol = protocolOf(fields.getOrElse(4) { "" }, requestType, url),
        status = status,
        category = RequestCategory.entries.firstOrNull { it.name == fields.getOrElse(6) { "" } }
            ?: RequestCategory.AD,
        matchedRule = fields.getOrElse(7) { "" }.ifBlank { null },
        filterListName = fields.getOrElse(8) { "" }.ifBlank { null },
        appPackage = fields.getOrElse(1) { "" }.ifBlank { null },
        latencyMicros = fields.getOrElse(9) { "" }.toLongOrNull() ?: 0L,
        dataSavedBytes = fields.getOrElse(10) { "" }.toLongOrNull() ?: 0L,
        transport = NetworkTransport.entries.firstOrNull {
            it.name == fields.getOrElse(11) { "" }
        } ?: NetworkTransport.UNKNOWN,
        roaming = fields.getOrElse(12) { "" }.toBooleanStrictOrNull() ?: false,
        flowId = fields.getOrElse(13) { "" }.toLongOrNull() ?: 0L,
        url = url,
        dnsAnswer = fields.getOrElse(15) { "" }.ifBlank { null },
        bytesSent = fields.getOrElse(16) { "" }.toLongOrNull() ?: 0L,
        bytesReceived = fields.getOrElse(17) { "" }.toLongOrNull() ?: 0L,
        requestType = requestType,
        source = fields.getOrElse(19) { "" }.ifBlank { null },
        tlsVersion = fields.getOrElse(20) { "" }.ifBlank { null },
        cipher = fields.getOrElse(21) { "" }.ifBlank { null },
        httpResponseStatus = fields.getOrElse(22) { "" }.toIntOrNull()?.takeIf { it != 0 },
        contentType = fields.getOrElse(23) { "" }.ifBlank { null },
        certSubject = fields.getOrElse(24) { "" }.ifBlank { null },
        certIssuer = fields.getOrElse(25) { "" }.ifBlank { null },
        certValidFrom = fields.getOrElse(26) { "" }.toLongOrNull()?.takeIf { it != 0L },
        certValidTo = fields.getOrElse(27) { "" }.toLongOrNull()?.takeIf { it != 0L },
    )
}

/**
 * The transport a row travelled on. Exported files always name it; the
 * fallbacks only cover a hand-edited file, and read the request itself rather
 * than defaulting, so a DNS row never arrives as HTTPS.
 */
private fun protocolOf(name: String, requestType: String?, url: String?): ProtocolType =
    ProtocolType.entries.firstOrNull { it.name == name } ?: when {
        requestType == "dns" -> ProtocolType.DNS_UDP
        requestType == "connection" -> ProtocolType.TCP
        url?.startsWith("https://") == true -> ProtocolType.HTTPS
        else -> ProtocolType.UDP
    }

/**
 * Splits a CSV into records. Quotes are honoured, a doubled quote is one
 * quote, and a newline inside quotes is data rather than the end of a row —
 * the case [csvField] goes out of its way to produce.
 */
private fun parseCsvRecords(text: String): List<List<String>> {
    val records = mutableListOf<List<String>>()
    var row = mutableListOf<String>()
    val field = StringBuilder()
    var quoted = false
    var index = 0
    fun endField() {
        row.add(field.toString())
        field.setLength(0)
    }

    fun endRow() {
        endField()
        // A line with nothing but separators is the file's tail, not a row.
        if (row.any { it.isNotBlank() }) records.add(row.toList())
        row = mutableListOf()
    }

    while (index < text.length) {
        val char = text[index]
        when {
            quoted -> when (char) {
                '"' -> if (index + 1 < text.length && text[index + 1] == '"') {
                    field.append('"')
                    index++
                } else {
                    quoted = false
                }

                else -> field.append(char)
            }

            char == '"' -> quoted = true
            char == ',' -> endField()
            char == '\n' || char == '\r' -> {
                if (char == '\r' && index + 1 < text.length && text[index + 1] == '\n') index++
                endRow()
            }

            else -> field.append(char)
        }
        index++
    }
    if (field.isNotEmpty() || row.isNotEmpty()) endRow()
    return records
}
