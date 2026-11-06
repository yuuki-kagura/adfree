//! The request log's SQLite side: writer thread, batching, queries.
//!
//! Events arrive from the packet path through a bounded channel; one dedicated
//! thread batches them and inserts a batch inside a single transaction, so a
//! busy page with hundreds of decisions a second still costs SQLite a few
//! commits. The packet path calls `try_send` and never blocks: if the queue is
//! full the event is dropped (and counted), because stalling there would stall
//! every connection in flight.

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::Db;
use crate::events::Event;

/// Queue depth between the packet path and the writer thread. Big enough to
/// absorb a burst (a page opening dozens of connections at once), small enough
/// that a stuck writer cannot hold megabytes of events.
const QUEUE: usize = 4_096;

/// Rows per transaction.
const BATCH: usize = 256;

/// How long a lone event may wait for company before it is committed.
const FLUSH_EVERY: Duration = Duration::from_millis(500);

/// Retention window: rows older than this are pruned.
const KEEP_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Hard row cap: pruning the tail keeps the file bounded even inside the
/// retention window on a device that browses all day.
const MAX_ROWS: i64 = 200_000;

/// Prune cadence in the writer thread.
const PRUNE_EVERY: Duration = Duration::from_secs(300);

/// What travels from the packet path (or the UI) to the writer thread.
///
/// `Event` dominates the size on purpose: events are the constant traffic and
/// the packet path must never allocate, so boxing them (the lint's suggestion)
/// would trade a stack write for a heap allocation per decision.
#[allow(clippy::large_enum_variant)]
pub enum Msg {
    Event(Event),
    /// One closed connection and what crossed it.
    Traffic(FlowTraffic),
    /// Persist everything queued so far; the ack says it is on disk.
    Flush(SyncSender<()>),
    /// Throw away everything queued *and* empty the table.
    Clear(SyncSender<()>),
}

/// Bytes a single connection moved, recorded when it retired: a TCP relay, a
/// datagram mapping or a terminated QUIC flow.
///
/// The request log counts decisions, not connections, so nothing there can
/// carry a truthful size: one DNS row stands for a host, while the app may
/// open a dozen connections to it. These rows are what the statistics screens
/// read for "data used".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowTraffic {
    pub ts_ms: i64,
    /// Package that owned the flow, empty when it could not be attributed.
    pub app: String,
    /// 0 unknown, 1 Wi-Fi, 2 cellular.
    pub transport: i64,
    pub roaming: bool,
    /// Device towards the server.
    pub sent: i64,
    /// Server towards the device.
    pub recv: i64,
}

/// The packet path's half of the channel.
pub struct Sender {
    tx: SyncSender<Msg>,
}

impl Sender {
    /// Queues one event without ever blocking. `false` means the queue was
    /// full and the event was lost.
    pub fn enqueue(&self, event: Event) -> bool {
        self.tx.try_send(Msg::Event(event)).is_ok()
    }

    /// Queues one closed connection's byte totals; never blocks.
    pub fn enqueue_traffic(&self, traffic: FlowTraffic) -> bool {
        self.tx.try_send(Msg::Traffic(traffic)).is_ok()
    }

    /// Blocks until everything queued *before this call* is committed.
    pub fn flush(&self) {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        if self.tx.send(Msg::Flush(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Empties the table (and drops whatever was still queued).
    pub fn clear(&self) {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        if self.tx.send(Msg::Clear(tx)).is_ok() {
            let _ = rx.recv();
        }
    }
}

pub fn channel() -> (Sender, Receiver<Msg>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE);
    (Sender { tx }, rx)
}

/// One row of `log_events`, owned (only the writer thread allocates rows).
#[derive(Clone, Debug)]
pub struct LogRow {
    /// SQLite rowid (0 before the row has been inserted). The UI uses it as a
    /// stable list key across pages.
    pub id: i64,
    pub ts_ms: i64,
    pub action: i64,
    pub category: i64,
    pub domain: String,
    pub ip: String,
    pub rule: String,
    pub list_name: String,
    pub latency_ns: i64,
    pub bytes_saved: i64,
    pub ipv6: bool,
    /// Package that owned the flow, empty when it could not be attributed.
    pub app: String,
    /// 0 unknown, 1 Wi-Fi, 2 cellular.
    pub transport: i64,
    pub roaming: bool,
    /// The decision id the core assigned; unique per row.
    pub flow_id: i64,
    /// Request URL, empty unless TLS termination saw one.
    pub url: String,
    /// Address(es) the engine answered a DNS query with, when it produced it.
    pub dns_answer: String,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
    /// What kind of request the decision was about, named: `script`, `image`,
    /// `dns`, `connection`. The log's tabs group on this.
    pub req_type: String,
    /// The referrer the request carried, empty unless it carried one.
    pub source: String,
    /// Which protocol the decision was made on, as the core's own code
    /// ([`crate::events::protocol`]); 0 for rows written before it was kept.
    pub proto: i64,
    /// The TLS version the upstream session negotiated, named (`TLS 1.3`),
    /// empty when nothing was encrypted.
    pub tls: String,
    /// The cipher suite of that session, in rustls' own name.
    pub cipher: String,
    /// The HTTP status the origin answered with; 0 when there was no HTTP
    /// answer, which is every blocked row and every DNS row.
    pub status: i64,
    /// The MIME type the response declared, without its parameters.
    pub ctype: String,
    /// The name the upstream certificate carried, empty for a row that never
    /// completed a handshake.
    pub cert_subj: String,
    /// Who signed that certificate.
    pub cert_iss: String,
    /// The window it claimed to be valid for, in epoch milliseconds. Both are
    /// 0 when no certificate was seen, which is not the same as a certificate
    /// valid since the epoch.
    pub cert_from: i64,
    pub cert_to: i64,
}

impl From<&Event> for LogRow {
    fn from(e: &Event) -> LogRow {
        LogRow {
            // Assigned by SQLite; only reads ever see a non-zero id.
            id: 0,
            ts_ms: e.ts_ms as i64,
            action: e.action as i64,
            category: e.category as i64,
            domain: e.domain().to_string(),
            ip: e.ip().to_string(),
            rule: e.rule().to_string(),
            list_name: e.list().to_string(),
            latency_ns: e.latency_ns as i64,
            bytes_saved: e.bytes_saved as i64,
            ipv6: e.flags & 0b01 != 0,
            app: e.app().to_string(),
            transport: e.transport() as i64,
            roaming: e.roaming(),
            flow_id: e.flow_id as i64,
            url: e.url().to_string(),
            dns_answer: e.answer().to_string(),
            bytes_sent: e.bytes_sent as i64,
            bytes_recv: e.bytes_recv as i64,
            req_type: e.req_type_name().to_string(),
            source: e.source().to_string(),
            proto: e.protocol() as i64,
            tls: e.tls_name().to_string(),
            cipher: e.cipher().to_string(),
            status: i64::from(e.status),
            ctype: e.content_type().to_string(),
            cert_subj: e.cert_subject().to_string(),
            cert_iss: e.cert_issuer().to_string(),
            cert_from: e.cert_from,
            cert_to: e.cert_to,
        }
    }
}

/// Starts the writer thread. It exits when every `Sender` is gone.
pub(super) fn spawn_writer(db: Arc<Db>, rx: Receiver<Msg>) {
    let _ = std::thread::Builder::new()
        .name("adfree-db".into())
        .stack_size(128 * 1024)
        .spawn(move || writer_loop(&db, &rx));
}

fn writer_loop(db: &Db, rx: &Receiver<Msg>) {
    let mut batch: Vec<LogRow> = Vec::with_capacity(BATCH);
    let mut traffic: Vec<FlowTraffic> = Vec::with_capacity(BATCH);
    let mut last_prune = Instant::now();
    loop {
        match rx.recv_timeout(FLUSH_EVERY) {
            Ok(Msg::Event(e)) => {
                batch.push(LogRow::from(&e));
                if batch.len() >= BATCH {
                    insert(db, &mut batch, &mut traffic);
                }
            }
            Ok(Msg::Traffic(t)) => {
                traffic.push(t);
                if traffic.len() >= BATCH {
                    insert(db, &mut batch, &mut traffic);
                }
            }
            Ok(Msg::Flush(ack)) => {
                insert(db, &mut batch, &mut traffic);
                let _ = ack.send(());
            }
            Ok(Msg::Clear(ack)) => {
                batch.clear();
                traffic.clear();
                if let Err(e) = clear(db) {
                    crate::logbuf::push_error(&format!("store: clear log: {e}"));
                }
                let _ = ack.send(());
            }
            Err(RecvTimeoutError::Timeout) => insert(db, &mut batch, &mut traffic),
            Err(RecvTimeoutError::Disconnected) => {
                insert(db, &mut batch, &mut traffic);
                return;
            }
        }
        if last_prune.elapsed() >= PRUNE_EVERY {
            last_prune = Instant::now();
            if let Err(e) = prune_db(db, KEEP_MS, MAX_ROWS) {
                crate::logbuf::push_error(&format!("store: prune log: {e}"));
            }
        }
    }
}

/// Commits both batches in one transaction. Failures are logged, not retried:
/// the log is a convenience, the packet path must never wait on it.
fn insert(db: &Db, batch: &mut Vec<LogRow>, traffic: &mut Vec<FlowTraffic>) {
    if batch.is_empty() && traffic.is_empty() {
        return;
    }
    if let Err(e) = write_batch(db, batch, traffic) {
        crate::logbuf::push_error(&format!(
            "store: write {} log rows, {} flows: {e}",
            batch.len(),
            traffic.len()
        ));
    }
    batch.clear();
    traffic.clear();
}

fn write_batch(db: &Db, rows: &[LogRow], traffic: &[FlowTraffic]) -> rusqlite::Result<()> {
    let mut conn = db.lock();
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(INSERT_SQL)?;
        for r in rows {
            stmt.execute(rusqlite::params![
                r.ts_ms,
                r.action,
                r.category,
                r.domain,
                r.ip,
                r.rule,
                r.list_name,
                r.latency_ns,
                r.bytes_saved,
                r.ipv6,
                r.app,
                r.transport,
                r.roaming,
                r.flow_id,
                r.url,
                r.dns_answer,
                r.bytes_sent,
                r.bytes_recv,
                r.req_type,
                r.source,
                r.proto,
                r.tls,
                r.cipher,
                r.status,
                r.ctype,
                r.cert_subj,
                r.cert_iss,
                r.cert_from,
                r.cert_to
            ])?;
        }
    }
    {
        let mut stmt = tx.prepare_cached(INSERT_TRAFFIC_SQL)?;
        for t in traffic {
            stmt.execute(rusqlite::params![
                t.ts_ms, t.app, t.transport, t.roaming, t.sent, t.recv
            ])?;
        }
    }
    tx.commit()
}

const COLUMNS: &str = "id, ts_ms, action, category, domain, ip, rule, list_name, \
                       latency_ns, bytes_saved, ipv6, app, transport, roaming, flow_id, \
                       url, dns_answer, bytes_sent, bytes_recv, req_type, source, \
                       proto, tls, cipher, status, ctype, cert_subj, cert_iss, \
                       cert_from, cert_to";

const INSERT_SQL: &str = "INSERT INTO log_events \
     (ts_ms, action, category, domain, ip, rule, list_name, latency_ns, bytes_saved, ipv6, app, \
      transport, roaming, flow_id, url, dns_answer, bytes_sent, bytes_recv, req_type, source, \
      proto, tls, cipher, status, ctype, cert_subj, cert_iss, cert_from, cert_to) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29)";

const INSERT_TRAFFIC_SQL: &str = "INSERT INTO flow_traffic \
     (ts_ms, app, transport, roaming, sent, recv) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<LogRow> {
    Ok(LogRow {
        id: r.get(0)?,
        ts_ms: r.get(1)?,
        action: r.get(2)?,
        category: r.get(3)?,
        domain: r.get(4)?,
        ip: r.get(5)?,
        rule: r.get(6)?,
        list_name: r.get(7)?,
        latency_ns: r.get(8)?,
        bytes_saved: r.get(9)?,
        ipv6: r.get(10)?,
        app: r.get(11)?,
        transport: r.get(12)?,
        roaming: r.get(13)?,
        flow_id: r.get(14)?,
        url: r.get(15)?,
        dns_answer: r.get(16)?,
        bytes_sent: r.get(17)?,
        bytes_recv: r.get(18)?,
        req_type: r.get(19)?,
        source: r.get(20)?,
        proto: r.get(21)?,
        tls: r.get(22)?,
        cipher: r.get(23)?,
        status: r.get(24)?,
        ctype: r.get(25)?,
        cert_subj: r.get(26)?,
        cert_iss: r.get(27)?,
        cert_from: r.get(28)?,
        cert_to: r.get(29)?,
    })
}

/// Newest first: `offset` skips that many of the newest rows.
pub(super) fn page(db: &Db, offset: u32, limit: u32) -> rusqlite::Result<Vec<LogRow>> {
    let conn = db.lock();
    let sql = format!("SELECT {COLUMNS} FROM log_events ORDER BY id DESC LIMIT ?1 OFFSET ?2");
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([limit as i64, offset as i64], row_from)?;
    rows.collect()
}

pub(super) fn count(db: &Db) -> rusqlite::Result<i64> {
    db.lock()
        .query_row("SELECT COUNT(*) FROM log_events", [], |r| r.get(0))
}

/// Rows older than `before_id`, newest first. The UI walks the log with this
/// cursor instead of OFFSET: rows arriving at the top never shift a page.
pub(super) fn page_before(db: &Db, before_id: i64, limit: u32) -> rusqlite::Result<Vec<LogRow>> {
    let conn = db.lock();
    let sql = format!(
        "SELECT {COLUMNS} FROM log_events WHERE id < ?1 ORDER BY id DESC LIMIT ?2"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([before_id, limit as i64], row_from)?;
    rows.collect()
}

/// `(blocked, allowed)` over the whole table, independent of what the UI has
/// paged in. Anything but an allow decision counts as blocked. Grouping by the
/// indexed `action` keeps this an index scan, not a table scan.
pub(super) fn status_counts(db: &Db) -> rusqlite::Result<(i64, i64)> {
    let conn = db.lock();
    let mut stmt = conn.prepare_cached("SELECT action, COUNT(*) FROM log_events GROUP BY action")?;
    let mut rows = stmt.query([])?;
    let (mut blocked, mut allowed) = (0i64, 0i64);
    while let Some(r) = rows.next()? {
        let action: i64 = r.get(0)?;
        let n: i64 = r.get(1)?;
        if action == 0 {
            allowed += n;
        } else {
            blocked += n;
        }
    }
    Ok((blocked, allowed))
}

/// Rows grouped by owning package since `since_ms`, plus the bytes they claim
/// to have saved, how much of the block count was ads vs trackers, and the
/// total request count (allowed and blocked). Anything but an allow decision
/// counts as blocked; `transport` selects one network (0 unknown, 1 Wi-Fi,
/// 2 cellular) or `-1` for all.
///
/// Real byte totals come from `flow_traffic` (one row per closed connection),
/// not from the log rows: a log row is a decision, and a host that opens twelve
/// connections still has one. The join is per package, so it cannot multiply
/// the log aggregates.
pub(super) fn usage_by_app(
    db: &Db,
    since_ms: i64,
    transport: i64,
) -> rusqlite::Result<Vec<UsageRow>> {
    let conn = db.lock();
    let mut stmt = conn.prepare_cached(
        "SELECT l.app, \
                SUM(CASE WHEN l.action != 0 THEN 1 ELSE 0 END), \
                SUM(l.bytes_saved), \
                SUM(CASE WHEN l.action != 0 AND l.category = 0 THEN 1 ELSE 0 END), \
                SUM(CASE WHEN l.action != 0 AND l.category IN (1, 2, 3) THEN 1 ELSE 0 END), \
                COUNT(*), \
                COALESCE(MAX(t.sent), 0), \
                COALESCE(MAX(t.recv), 0) \
         FROM log_events l \
         LEFT JOIN (SELECT app, SUM(sent) AS sent, SUM(recv) AS recv \
                    FROM flow_traffic \
                    WHERE ts_ms >= ?1 AND (?2 < 0 OR transport = ?2) \
                    GROUP BY app) t ON t.app = l.app \
         WHERE l.app != '' AND l.ts_ms >= ?1 AND (?2 < 0 OR l.transport = ?2) \
         GROUP BY l.app \
         ORDER BY 2 DESC",
    )?;
    let rows = stmt.query_map([since_ms, transport], |r| {
        Ok(UsageRow {
            app: r.get(0)?,
            blocked: r.get(1)?,
            bytes_saved: r.get(2)?,
            ads: r.get(3)?,
            trackers: r.get(4)?,
            requests: r.get(5)?,
            bytes_sent: r.get(6)?,
            bytes_recv: r.get(7)?,
        })
    })?;
    rows.collect()
}

/// One package's totals over a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow {
    pub app: String,
    pub blocked: i64,
    pub bytes_saved: i64,
    pub ads: i64,
    pub trackers: i64,
    pub requests: i64,
    /// Bytes that crossed this package's closed connections.
    pub bytes_sent: i64,
    pub bytes_recv: i64,
}

/// The `Các dịch vụ` view: the log grouped by the domain a decision was made
/// about, biggest blocked count first, capped at 200 groups. `transport`
/// selects one network (`0` unknown, `1` Wi-Fi, `2` cellular) or `-1` for all.
///
/// Deliberately narrower than [`usage_by_app`]: no bytes on the wire, because
/// `flow_traffic` has no domain column and inventing one would mean joining a
/// table this view does not need. The company name is not here either — this
/// returns domains and the Kotlin side resolves them against the service
/// table, so a missing or stale dataset costs a label, not a query.
pub(super) fn usage_by_domain(
    db: &Db,
    since_ms: i64,
    transport: i64,
) -> rusqlite::Result<Vec<DomainUsageRow>> {
    let conn = db.lock();
    let mut stmt = conn.prepare_cached(
        "SELECT domain, \
                SUM(CASE WHEN action != 0 THEN 1 ELSE 0 END), \
                COUNT(*), \
                SUM(bytes_saved) \
         FROM log_events \
         WHERE domain != '' AND ts_ms >= ?1 AND (?2 < 0 OR transport = ?2) \
         GROUP BY domain \
         ORDER BY 2 DESC \
         LIMIT 200",
    )?;
    let rows = stmt.query_map([since_ms, transport], |r| {
        Ok(DomainUsageRow {
            domain: r.get(0)?,
            blocked: r.get(1)?,
            requests: r.get(2)?,
            bytes_saved: r.get(3)?,
        })
    })?;
    rows.collect()
}

/// One domain's totals over a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainUsageRow {
    pub domain: String,
    pub blocked: i64,
    pub requests: i64,
    pub bytes_saved: i64,
}

/// Whole-log totals over a window, unattributed rows included. The statistics
/// header shows these; per-app rows are a narrower view of the same data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowTotalsRow {
    pub ads: i64,
    pub trackers: i64,
    pub requests: i64,
    pub bytes_saved: i64,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
}

pub(super) fn window_totals(
    db: &Db,
    since_ms: i64,
    transport: i64,
) -> rusqlite::Result<WindowTotalsRow> {
    let conn = db.lock();
    let mut row = conn.query_row(
        "SELECT \
                COALESCE(SUM(CASE WHEN action != 0 AND category = 0 THEN 1 ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN action != 0 AND category IN (1, 2, 3) THEN 1 ELSE 0 END), 0), \
                COUNT(*), \
                COALESCE(SUM(bytes_saved), 0), \
                COALESCE(SUM(bytes_sent), 0), \
                COALESCE(SUM(bytes_recv), 0) \
         FROM log_events \
         WHERE ts_ms >= ?1 AND (?2 < 0 OR transport = ?2)",
        [since_ms, transport],
        |r| {
            Ok(WindowTotalsRow {
                ads: r.get(0)?,
                trackers: r.get(1)?,
                requests: r.get(2)?,
                bytes_saved: r.get(3)?,
                bytes_sent: r.get(4)?,
                bytes_recv: r.get(5)?,
            })
        },
    )?;
    // A log row is a decision, so the only sizes it can carry are the few bytes
    // the engine itself wrote (DNS answers). Real traffic is counted once per
    // connection in `flow_traffic` and added here.
    let (sent, recv) = conn.query_row(
        "SELECT COALESCE(SUM(sent), 0), COALESCE(SUM(recv), 0) \
         FROM flow_traffic WHERE ts_ms >= ?1 AND (?2 < 0 OR transport = ?2)",
        [since_ms, transport],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )?;
    row.bytes_sent += sent;
    row.bytes_recv += recv;
    Ok(row)
}

pub(super) fn clear(db: &Db) -> rusqlite::Result<()> {
    let conn = db.lock();
    conn.execute("DELETE FROM log_events", [])?;
    conn.execute("DELETE FROM flow_traffic", [])?;
    Ok(())
}

/// Drops rows outside the retention window (by age) and beyond the cap (by
/// count). Returns how many were deleted.
pub(super) fn prune_db(db: &Db, keep_ms: u64, max_rows: i64) -> rusqlite::Result<usize> {
    let cutoff = crate::util::now_ms().saturating_sub(keep_ms) as i64;
    let conn = db.lock();
    let by_age = conn.execute("DELETE FROM log_events WHERE ts_ms < ?1", [cutoff])?;
    let by_count = conn.execute(
        "DELETE FROM log_events WHERE id < (SELECT MIN(id) FROM \
         (SELECT id FROM log_events ORDER BY id DESC LIMIT ?1))",
        [max_rows],
    )?;
    // Connection rows follow the same window; the table has no explicit id, so
    // the implicit rowid plays the part.
    let traffic_age = conn.execute("DELETE FROM flow_traffic WHERE ts_ms < ?1", [cutoff])?;
    let traffic_count = conn.execute(
        "DELETE FROM flow_traffic WHERE rowid < (SELECT MIN(rowid) FROM \
         (SELECT rowid FROM flow_traffic ORDER BY rowid DESC LIMIT ?1))",
        [max_rows],
    )?;
    Ok(by_age + by_count + traffic_age + traffic_count)
}
