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
    /// Persist everything queued so far; the ack says it is on disk.
    Flush(SyncSender<()>),
    /// Throw away everything queued *and* empty the table.
    Clear(SyncSender<()>),
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
    let mut last_prune = Instant::now();
    loop {
        match rx.recv_timeout(FLUSH_EVERY) {
            Ok(Msg::Event(e)) => {
                batch.push(LogRow::from(&e));
                if batch.len() >= BATCH {
                    insert(db, &mut batch);
                }
            }
            Ok(Msg::Flush(ack)) => {
                insert(db, &mut batch);
                let _ = ack.send(());
            }
            Ok(Msg::Clear(ack)) => {
                batch.clear();
                if let Err(e) = clear(db) {
                    crate::logbuf::push(&format!("store: clear log: {e}"));
                }
                let _ = ack.send(());
            }
            Err(RecvTimeoutError::Timeout) => insert(db, &mut batch),
            Err(RecvTimeoutError::Disconnected) => {
                insert(db, &mut batch);
                return;
            }
        }
        if last_prune.elapsed() >= PRUNE_EVERY {
            last_prune = Instant::now();
            if let Err(e) = prune_db(db, KEEP_MS, MAX_ROWS) {
                crate::logbuf::push(&format!("store: prune log: {e}"));
            }
        }
    }
}

/// Commits the batch in one transaction. Failures are logged, not retried:
/// the log is a convenience, the packet path must never wait on it.
fn insert(db: &Db, batch: &mut Vec<LogRow>) {
    if batch.is_empty() {
        return;
    }
    if let Err(e) = write_batch(db, batch) {
        crate::logbuf::push(&format!("store: write {} log rows: {e}", batch.len()));
    }
    batch.clear();
}

fn write_batch(db: &Db, rows: &[LogRow]) -> rusqlite::Result<()> {
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
                r.bytes_recv
            ])?;
        }
    }
    tx.commit()
}

const COLUMNS: &str = "id, ts_ms, action, category, domain, ip, rule, list_name, \
                       latency_ns, bytes_saved, ipv6, app, transport, roaming, flow_id, \
                       url, dns_answer, bytes_sent, bytes_recv";

const INSERT_SQL: &str = "INSERT INTO log_events \
     (ts_ms, action, category, domain, ip, rule, list_name, latency_ns, bytes_saved, ipv6, app, \
      transport, roaming, flow_id, url, dns_answer, bytes_sent, bytes_recv) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)";

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
pub(super) fn usage_by_app(
    db: &Db,
    since_ms: i64,
    transport: i64,
) -> rusqlite::Result<Vec<UsageRow>> {
    let conn = db.lock();
    let mut stmt = conn.prepare_cached(
        "SELECT app, \
                SUM(CASE WHEN action != 0 THEN 1 ELSE 0 END), \
                SUM(bytes_saved), \
                SUM(CASE WHEN action != 0 AND category = 0 THEN 1 ELSE 0 END), \
                SUM(CASE WHEN action != 0 AND category IN (1, 2, 3) THEN 1 ELSE 0 END), \
                COUNT(*) \
         FROM log_events \
         WHERE app != '' AND ts_ms >= ?1 AND (?2 < 0 OR transport = ?2) \
         GROUP BY app \
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
    conn.query_row(
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
    )
}

pub(super) fn clear(db: &Db) -> rusqlite::Result<()> {
    db.lock().execute("DELETE FROM log_events", [])?;
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
    Ok(by_age + by_count)
}
