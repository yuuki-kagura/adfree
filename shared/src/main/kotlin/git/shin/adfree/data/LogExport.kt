package git.shin.adfree.data

import git.shin.adfree.model.NetworkRequestLog
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * The CSV form of the request log, kept apart from the repository so the whole
 * store can be streamed into it without the caller holding it in memory.
 */

private const val LOG_CSV_HEADER =
    "time,app,domain,ip,protocol,status,category,rule,list,latency_us,saved_bytes," +
        "transport,roaming,flow_id,url,dns_answer,bytes_sent,bytes_recv"

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
