//! Everything the core keeps between runs: one directory, one database.
//!
//! The platform hands a writable directory down once (`core_set_data_root`)
//! and never touches anything inside it again. Filter bodies, userscript
//! bodies, the CA and the SQLite database live here, so every platform shares
//! a single implementation of "where does state go" and a future port does not
//! need a second data directory.
//!
//! ```text
//! <root>/filters/<id>.txt   filter list bodies
//! <root>/scripts/<id>.js    userscript bodies
//! <root>/core/ca.pem        local CA certificate (PEM)
//! <root>/core/ca-key.pem    local CA private key (PEM)
//! <root>/adfree.db          SQLite: request log, settings, registries
//! ```
//!
//! The file names predate the move (Kotlin wrote them), so an installed app
//! keeps its data without a migration step.

mod log;

pub use log::{LogRow, UsageRow, WindowTotalsRow};

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Where the core keeps its files and its database.
pub struct Store {
    root: PathBuf,
    db: Arc<Db>,
    log: log::Sender,
}

/// The one SQLite connection.
///
/// SQLite serialises writers anyway and the UI reads a page at a time, so a
/// mutex around a single connection beats a pool here; WAL keeps readers from
/// ever waiting on the writer thread.
pub(super) struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Poison-proof lock: the mutex is only ever held across parameterised
    /// statements, so a panic cannot leave SQLite in a broken state and the
    /// log must keep working after one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Store {
    /// Opens (creating if needed) the whole layout under `root`.
    pub fn open(root: &Path) -> Result<Store, String> {
        for dir in ["filters", "scripts", "core"] {
            let path = root.join(dir);
            std::fs::create_dir_all(&path)
                .map_err(|e| format!("create {}: {e}", path.display()))?;
        }
        let db_path = root.join("adfree.db");
        let conn =
            Connection::open(&db_path).map_err(|e| format!("open {}: {e}", db_path.display()))?;
        conn.execute_batch(
            // WAL: readers never wait on the writer. NORMAL is its standard
            // companion — a power cut can lose the last seconds, never the file.
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| format!("pragma: {e}"))?;
        migrate(&conn)?;
        let db = Arc::new(Db {
            conn: Mutex::new(conn),
        });
        let (log, rx) = log::channel();
        log::spawn_writer(Arc::clone(&db), rx);
        Ok(Store {
            root: root.to_path_buf(),
            db,
            log,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Bodies of the downloaded filter lists (`filters/<id>.txt`).
    pub fn filters_dir(&self) -> PathBuf {
        self.root.join("filters")
    }

    /// Bodies of the user scripts (`scripts/<id>.js`).
    pub fn scripts_dir(&self) -> PathBuf {
        self.root.join("scripts")
    }

    /// The CA certificate and key (`ca.pem`, `ca-key.pem`).
    pub fn core_dir(&self) -> PathBuf {
        self.root.join("core")
    }

    /// Queues a log row for the writer thread. Never blocks; `false` means the
    /// queue was full and the row was dropped.
    pub fn log_enqueue(&self, event: &crate::events::Event) -> bool {
        self.log.enqueue(*event)
    }

    /// Waits until everything queued so far is committed (tests, shutdown).
    pub fn log_flush(&self) {
        self.log.flush();
    }

    /// Empties the log: queued rows are dropped too, so a clear is a clear.
    pub fn log_clear(&self) {
        self.log.clear();
    }

    /// One page of the request log, newest first. `limit` is capped so a bad
    /// call cannot pull the whole table into memory.
    pub fn log_page(&self, offset: u32, limit: u32) -> Vec<LogRow> {
        let limit = limit.min(500);
        match log::page(&self.db, offset, limit) {
            Ok(rows) => rows,
            Err(e) => {
                crate::logbuf::push(&format!("store: read log page: {e}"));
                Vec::new()
            }
        }
    }

    /// One page older than `before_id`, newest first (cursor paging, so live
    /// inserts at the top cannot shift the rows under the user's finger).
    pub fn log_page_before(&self, before_id: i64, limit: u32) -> Vec<LogRow> {
        let limit = limit.min(500);
        match log::page_before(&self.db, before_id, limit) {
            Ok(rows) => rows,
            Err(e) => {
                crate::logbuf::push(&format!("store: read log page before {before_id}: {e}"));
                Vec::new()
            }
        }
    }

    pub fn log_count(&self) -> u64 {
        match log::count(&self.db) {
            Ok(n) => n.max(0) as u64,
            Err(e) => {
                crate::logbuf::push(&format!("store: count log: {e}"));
                0
            }
        }
    }

    /// `(blocked, allowed)` across the whole log, not just the loaded window.
    pub fn log_status_counts(&self) -> (u64, u64) {
        match log::status_counts(&self.db) {
            Ok((blocked, allowed)) => (blocked.max(0) as u64, allowed.max(0) as u64),
            Err(e) => {
                crate::logbuf::push(&format!("store: log status counts: {e}"));
                (0, 0)
            }
        }
    }

    /// `(package, blocked, bytes_saved, ads, trackers, requests)` since
    /// `since_ms`, biggest blocked count first, restricted to one transport
    /// when `transport >= 0`. The UI passes its local midnight, so "today"
    /// means the user's day.
    pub fn log_usage_by_app(&self, since_ms: i64, transport: i64) -> Vec<UsageRow> {
        match log::usage_by_app(&self.db, since_ms, transport) {
            Ok(mut rows) => {
                for row in &mut rows {
                    row.blocked = row.blocked.max(0);
                    row.bytes_saved = row.bytes_saved.max(0);
                    row.ads = row.ads.max(0);
                    row.trackers = row.trackers.max(0);
                    row.requests = row.requests.max(0);
                }
                rows
            }
            Err(e) => {
                crate::logbuf::push(&format!("store: app usage: {e}"));
                Vec::new()
            }
        }
    }

    /// Whole-window totals, including rows the core could not attribute.
    pub fn log_window_totals(&self, since_ms: i64, transport: i64) -> WindowTotalsRow {
        match log::window_totals(&self.db, since_ms, transport) {
            Ok(row) => row,
            Err(e) => {
                crate::logbuf::push(&format!("store: window totals: {e}"));
                WindowTotalsRow::default()
            }
        }
    }

    // ------------------------------------------------------------ typed state

    /// One typed state record, serialized by the core. `None` means it was
    /// never written (or the row was lost), so the caller applies defaults.
    pub fn state_get(&self, key: &str) -> Option<String> {
        self.db
            .lock()
            .query_row("SELECT json FROM state WHERE key = ?1", [key], |r| r.get(0))
            .ok()
    }

    pub fn state_set(&self, key: &str, json: &str) -> Result<(), String> {
        self.db
            .lock()
            .execute(
                "INSERT INTO state (key, json, updated_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET json = excluded.json, updated_ms = excluded.updated_ms",
                rusqlite::params![key, json, crate::util::now_ms() as i64],
            )
            .map(|_| ())
            .map_err(|e| format!("state write {key}: {e}"))
    }

    /// Writes several records in one transaction, leaving other keys alone.
    pub fn state_put_all(&self, entries: &[(String, String)]) -> Result<(), String> {
        let mut conn = self.db.lock();
        let tx = conn
            .transaction()
            .map_err(|e| format!("state transaction: {e}"))?;
        {
            let now = crate::util::now_ms() as i64;
            let mut stmt = tx
                .prepare(
                    "INSERT INTO state (key, json, updated_ms) VALUES (?1, ?2, ?3)
                     ON CONFLICT(key) DO UPDATE SET json = excluded.json, updated_ms = excluded.updated_ms",
                )
                .map_err(|e| format!("state prepare: {e}"))?;
            for (key, json) in entries {
                stmt.execute(rusqlite::params![key, json, now])
                    .map_err(|e| format!("state write {key}: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("state commit: {e}"))
    }

    /// Replaces the whole state table in one transaction (backup restore).
    pub fn state_replace_all(&self, entries: &[(String, String)]) -> Result<(), String> {
        let mut conn = self.db.lock();
        let tx = conn
            .transaction()
            .map_err(|e| format!("state transaction: {e}"))?;
        tx.execute("DELETE FROM state", [])
            .map_err(|e| format!("state clear: {e}"))?;
        {
            let now = crate::util::now_ms() as i64;
            let mut stmt = tx
                .prepare("INSERT INTO state (key, json, updated_ms) VALUES (?1, ?2, ?3)")
                .map_err(|e| format!("state prepare: {e}"))?;
            for (key, json) in entries {
                stmt.execute(rusqlite::params![key, json, now])
                    .map_err(|e| format!("state write {key}: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("state commit: {e}"))
    }

    pub fn state_keys(&self) -> Vec<String> {
        let conn = self.db.lock();
        let Ok(mut stmt) = conn.prepare("SELECT key FROM state ORDER BY key") else {
            return Vec::new();
        };
        let rows = stmt.query_map([], |r| r.get::<_, String>(0));
        match rows {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Bookkeeping that is not user data (migration markers).
    pub fn meta_get(&self, key: &str) -> Option<String> {
        self.db
            .lock()
            .query_row("SELECT value FROM state_meta WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .ok()
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<(), String> {
        self.db
            .lock()
            .execute(
                "INSERT INTO state_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, value],
            )
            .map(|_| ())
            .map_err(|e| format!("state_meta write {key}: {e}"))
    }

    // ------------------------------------------------------------- platform blobs

    /// The app's settings blob, exactly as it was saved.
    pub fn settings_get(&self) -> Option<String> {
        self.blob_get(1)
    }

    /// Replaces the settings blob (atomic).
    pub fn settings_set(&self, json: &str) -> Result<(), String> {
        self.blob_set(1, json)
    }

    /// The filter/script choices blob (enabled lists, custom lists, user
    /// rules, userscripts), exactly as the platform serialized it.
    pub fn filters_get(&self) -> Option<String> {
        self.blob_get(2)
    }

    pub fn filters_set(&self, json: &str) -> Result<(), String> {
        self.blob_set(2, json)
    }

    /// Reads one platform blob by row id; the platform owns the schema and
    /// the ids only need to be unique.
    pub fn blob_get(&self, id: i64) -> Option<String> {
        self.db
            .lock()
            .query_row("SELECT json FROM settings WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .ok()
    }

    pub fn blob_set(&self, id: i64, json: &str) -> Result<(), String> {
        self.db
            .lock()
            .execute(
                "INSERT INTO settings (id, json, updated_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated_ms = excluded.updated_ms",
                rusqlite::params![id, json, crate::util::now_ms() as i64],
            )
            .map(|_| ())
            .map_err(|e| format!("settings write: {e}"))
    }
}

/// Schema migrations, keyed on `PRAGMA user_version`.
fn migrate(conn: &Connection) -> Result<(), String> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| format!("read schema version: {e}"))?;
    if version < 1 {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE settings (
                 id         INTEGER PRIMARY KEY CHECK (id = 1),
                 json       TEXT NOT NULL,
                 updated_ms INTEGER NOT NULL
             );
             CREATE TABLE log_events (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts_ms       INTEGER NOT NULL,
                 action      INTEGER NOT NULL,
                 category    INTEGER NOT NULL,
                 domain      TEXT NOT NULL,
                 ip          TEXT NOT NULL,
                 rule        TEXT NOT NULL,
                 list_name   TEXT NOT NULL,
                 latency_ns  INTEGER NOT NULL DEFAULT 0,
                 bytes_saved INTEGER NOT NULL DEFAULT 0,
                 ipv6        INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX log_events_ts ON log_events(ts_ms);
             PRAGMA user_version = 1;
             COMMIT;",
        )
        .map_err(|e| format!("migrate schema to v1: {e}"))?;
    }
    if version < 2 {
        // v2: the settings table becomes a generic blob table — filter and
        // script choices live in row 2, so the "only id 1" check has to go.
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE settings RENAME TO settings_v1;
             CREATE TABLE settings (
                 id         INTEGER PRIMARY KEY,
                 json       TEXT NOT NULL,
                 updated_ms INTEGER NOT NULL
             );
             INSERT INTO settings (id, json, updated_ms)
                 SELECT id, json, updated_ms FROM settings_v1;
             DROP TABLE settings_v1;
             PRAGMA user_version = 2;
             COMMIT;",
        )
        .map_err(|e| format!("migrate schema to v2: {e}"))?;
    }
    if version < 3 {
        // v3: every log row can name the app the flow belonged to. Rows from
        // older builds keep an empty name rather than a wrong one.
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE log_events ADD COLUMN app TEXT NOT NULL DEFAULT '';
             PRAGMA user_version = 3;
             COMMIT;",
        )
        .map_err(|e| format!("migrate schema to v3: {e}"))?;
    }
    if version < 4 {
        // v4: the core owns the schema. `settings` stays as an archive of the
        // platform-written blobs; `state` holds one typed JSON value per
        // collection and `state_meta` marks one-time work (the import).
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE state (
                 key        TEXT PRIMARY KEY,
                 json       TEXT NOT NULL,
                 updated_ms INTEGER NOT NULL
             );
             CREATE TABLE state_meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             PRAGMA user_version = 4;
             COMMIT;",
        )
        .map_err(|e| format!("migrate schema to v4: {e}"))?;
    }
    if version < 5 {
        // v5: the chips count the whole log by decision; grouping over the
        // indexed action column keeps that an index scan.
        conn.execute_batch(
            "BEGIN;
             CREATE INDEX IF NOT EXISTS log_events_action ON log_events(action);
             PRAGMA user_version = 5;
             COMMIT;",
        )
        .map_err(|e| format!("migrate schema to v5: {e}"))?;
    }
    if version < 6 {
        // v6: a row names the transport and roaming state it was decided on,
        // the request URL when TLS termination saw one, the DNS answer when
        // the engine produced it, and the bytes that crossed the flow when
        // known. Old rows read as unknown/zero.
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE log_events ADD COLUMN transport INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE log_events ADD COLUMN roaming INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE log_events ADD COLUMN flow_id INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE log_events ADD COLUMN url TEXT NOT NULL DEFAULT '';
             ALTER TABLE log_events ADD COLUMN dns_answer TEXT NOT NULL DEFAULT '';
             ALTER TABLE log_events ADD COLUMN bytes_sent INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE log_events ADD COLUMN bytes_recv INTEGER NOT NULL DEFAULT 0;
             CREATE INDEX IF NOT EXISTS log_events_transport_action
                 ON log_events(transport, action);
             PRAGMA user_version = 6;
             COMMIT;",
        )
        .map_err(|e| format!("migrate schema to v6: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{allow_event, block_event, with_app, ACTION_BLOCK};

    /// Store in a fresh directory; the process id keeps parallel test
    /// binaries from colliding.
    fn temp_store(tag: &str) -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!("adfree-store-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).expect("store opens");
        (store, dir)
    }

    #[test]
    fn creates_the_layout() {
        let (store, dir) = temp_store("layout");
        assert!(store.filters_dir().is_dir());
        assert!(store.scripts_dir().is_dir());
        assert!(store.core_dir().is_dir());
        assert!(dir.join("adfree.db").is_file());
    }

    #[test]
    fn log_round_trip_newest_first() {
        let (store, _) = temp_store("roundtrip");
        let mut ev = block_event(
            ACTION_BLOCK,
            "ads.example",
            "10.0.0.1",
            "||ads.example^",
            "Ad lists",
            0,
            1234,
            567,
            false,
        );
        ev = with_app(ev, "com.example.browser");
        ev.ts_ms = 1_000;
        assert!(store.log_enqueue(&ev));
        store.log_enqueue(&allow_event("ok.example", "10.0.0.2", 42));
        store.log_flush();

        let rows = store.log_page(0, 10);
        assert_eq!(rows.len(), 2);
        // Newest first: the allow event went in last.
        assert_eq!(rows[0].domain, "ok.example");
        assert_eq!(rows[1].domain, "ads.example");
        assert_eq!(rows[1].rule, "||ads.example^");
        assert_eq!(rows[1].list_name, "Ad lists");
        assert_eq!(rows[1].latency_ns, 1234);
        assert_eq!(rows[1].bytes_saved, 567);
        assert_eq!(rows[1].action, i64::from(ACTION_BLOCK));
        assert_eq!(rows[1].ts_ms, 1_000);
        assert!(!rows[1].ipv6);
        assert_eq!(rows[1].app, "com.example.browser");
        assert_eq!(rows[0].app, "", "unattributed rows stay empty, not guessed");
    }

    /// A database written by an older build has no `app` column; opening it
    /// must add the column and leave the existing rows readable.
    #[test]
    fn a_v2_log_opens_with_an_empty_app_column() {
        let dir = std::env::temp_dir().join(format!("adfree-store-{}-v2", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let conn = Connection::open(dir.join("adfree.db")).unwrap();
            conn.execute_batch(
                "CREATE TABLE settings (
                     id         INTEGER PRIMARY KEY,
                     json       TEXT NOT NULL,
                     updated_ms INTEGER NOT NULL
                 );
                 CREATE TABLE log_events (
                     id          INTEGER PRIMARY KEY AUTOINCREMENT,
                     ts_ms       INTEGER NOT NULL,
                     action      INTEGER NOT NULL,
                     category    INTEGER NOT NULL,
                     domain      TEXT NOT NULL,
                     ip          TEXT NOT NULL,
                     rule        TEXT NOT NULL,
                     list_name   TEXT NOT NULL,
                     latency_ns  INTEGER NOT NULL DEFAULT 0,
                     bytes_saved INTEGER NOT NULL DEFAULT 0,
                     ipv6        INTEGER NOT NULL DEFAULT 0
                 );
                 INSERT INTO log_events
                     (ts_ms, action, category, domain, ip, rule, list_name)
                     VALUES (1234, 1, 0, 'old.example', '10.0.0.1', '||old.example^', 'Old list');
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        }

        let store = Store::open(&dir).expect("v2 store opens");
        let rows = store.log_page(0, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, "old.example");
        assert_eq!(rows[0].app, "", "no app was recorded before v3");
        // The migrated table accepts new rows with an app.
        store.log_enqueue(&with_app(
            allow_event("new.example", "10.0.0.2", 1),
            "com.example.app",
        ));
        store.log_flush();
        assert_eq!(store.log_page(0, 1)[0].app, "com.example.app");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A v5 database predates the transport/URL/answer columns; opening it
    /// must add them and leave the existing rows readable as unknown.
    #[test]
    fn a_v5_log_gains_the_network_columns() {
        let dir = std::env::temp_dir().join(format!("adfree-store-{}-v5", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let conn = Connection::open(dir.join("adfree.db")).unwrap();
            conn.execute_batch(
                "CREATE TABLE settings (
                     id         INTEGER PRIMARY KEY,
                     json       TEXT NOT NULL,
                     updated_ms INTEGER NOT NULL
                 );
                 CREATE TABLE state (
                     key        TEXT PRIMARY KEY,
                     json       TEXT NOT NULL,
                     updated_ms INTEGER NOT NULL
                 );
                 CREATE TABLE state_meta (
                     key   TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 CREATE TABLE log_events (
                     id          INTEGER PRIMARY KEY AUTOINCREMENT,
                     ts_ms       INTEGER NOT NULL,
                     action      INTEGER NOT NULL,
                     category    INTEGER NOT NULL,
                     domain      TEXT NOT NULL,
                     ip          TEXT NOT NULL,
                     rule        TEXT NOT NULL,
                     list_name   TEXT NOT NULL,
                     latency_ns  INTEGER NOT NULL DEFAULT 0,
                     bytes_saved INTEGER NOT NULL DEFAULT 0,
                     ipv6        INTEGER NOT NULL DEFAULT 0,
                     app         TEXT NOT NULL DEFAULT ''
                 );
                 CREATE INDEX log_events_ts ON log_events(ts_ms);
                 CREATE INDEX log_events_action ON log_events(action);
                 INSERT INTO log_events
                     (ts_ms, action, category, domain, ip, rule, list_name, app)
                     VALUES (1234, 1, 0, 'old.example', '10.0.0.1', '||old.example^', 'Old list', 'com.example.old');
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        }

        let store = Store::open(&dir).expect("v5 store opens");
        let rows = store.log_page(0, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, "old.example");
        assert_eq!(rows[0].transport, 0, "old rows read as unknown");
        assert!(!rows[0].roaming);
        assert_eq!(rows[0].url, "");
        assert_eq!(rows[0].dns_answer, "");
        assert_eq!(rows[0].flow_id, 0);
        assert_eq!(rows[0].bytes_sent, 0);
        assert_eq!(rows[0].bytes_recv, 0);

        let mut fresh = with_app(
            crate::events::with_traffic(
                crate::events::with_url(
                    crate::events::with_answer(allow_event("new.example", "10.0.0.2", 1), "10.0.0.2"),
                    "https://new.example/path",
                ),
                12,
                34,
            ),
            "com.example.new",
        );
        fresh.set_network(1, true);
        store.log_enqueue(&fresh);
        store.log_flush();
        let row = &store.log_page(0, 1)[0];
        assert_eq!(row.transport, 1);
        assert!(row.roaming);
        assert_eq!(row.url, "https://new.example/path");
        assert_eq!(row.dns_answer, "10.0.0.2");
        assert_eq!(row.bytes_sent, 12);
        assert_eq!(row.bytes_recv, 34);

        // The transport filter now narrows by the migrated column.
        assert_eq!(store.log_usage_by_app(0, 1).len(), 1);
        assert!(store.log_usage_by_app(0, 2).is_empty());
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_pages_and_counts() {        let (store, _) = temp_store("pages");
        for i in 0..700u64 {
            let mut ev = allow_event(&format!("h{i}.test"), "10.0.0.9", i as u32);
            ev.ts_ms = 2_000 + i;
            store.log_enqueue(&ev);
        }
        store.log_flush();
        assert_eq!(store.log_count(), 700);

        let first = store.log_page(0, 300);
        assert_eq!(first.len(), 300);
        assert_eq!(first[0].domain, "h699.test");
        let second = store.log_page(300, 300);
        assert_eq!(second.len(), 300);
        assert_eq!(second[0].domain, "h399.test");
        let third = store.log_page(600, 300);
        assert_eq!(third.len(), 100);
        assert_eq!(third[0].domain, "h99.test");
        // Past the end and a bogus limit stay sane.
        assert!(store.log_page(700, 300).is_empty());
        assert!(store.log_page(0, 0).is_empty());
    }

    #[test]
    fn app_usage_counts_blocked_rows_and_bytes() {
        let (store, _) = temp_store("usage");
        let mut blocked = with_app(
            block_event(
                ACTION_BLOCK,
                "ads.test",
                "",
                "||ads.test^",
                "Ads",
                0,
                10,
                100,
                false,
            ),
            "com.example.browser",
        );
        blocked.ts_ms = 2_000;
        store.log_enqueue(&blocked);
        let mut blocked2 = with_app(
            block_event(
                ACTION_BLOCK,
                "track.test",
                "",
                "||track.test^",
                "Ads",
                1,
                10,
                50,
                false,
            ),
            "com.example.browser",
        );
        blocked2.ts_ms = 2_100;
        store.log_enqueue(&blocked2);
        // An allowed row bumps the row count but not the blocked count.
        let mut allowed = with_app(allow_event("ok.test", "10.0.0.2", 5), "com.example.browser");
        allowed.ts_ms = 2_200;
        store.log_enqueue(&allowed);
        // Before the window, and unattributed: both excluded.
        let mut old = with_app(
            block_event(ACTION_BLOCK, "old.test", "", "", "Ads", 0, 10, 999, false),
            "com.example.browser",
        );
        old.ts_ms = 500;
        store.log_enqueue(&old);
        let mut orphan = block_event(ACTION_BLOCK, "orphan.test", "", "", "Ads", 0, 10, 7, false);
        orphan.ts_ms = 2_300;
        store.log_enqueue(&orphan);
        store.log_flush();

        let usage = store.log_usage_by_app(1_000, -1);
        assert_eq!(
            usage,
            vec![UsageRow {
                app: "com.example.browser".to_string(),
                blocked: 2,
                bytes_saved: 150,
                ads: 1,
                trackers: 1,
                requests: 3,
            }],
            "window and attribution both apply"
        );
        // The transport filter excludes rows stamped as unknown.
        assert!(store.log_usage_by_app(1_000, 1).is_empty());

        // The header totals include the unattributed row and older windows.
        let totals = store.log_window_totals(1_000, -1);
        assert_eq!(totals.ads, 2, "two ad rows, ignored before the window");
        assert_eq!(totals.trackers, 1);
        assert_eq!(totals.requests, 4, "two blocks, an allow and the orphan");
        assert_eq!(totals.bytes_saved, 157);
        assert_eq!(store.log_window_totals(1_000, 1), WindowTotalsRow::default());
    }

    #[test]
    fn status_counts_cover_the_whole_log_not_a_page() {
        let (store, _) = temp_store("status");
        for i in 0..3u64 {
            store.log_enqueue(&allow_event(&format!("ok{i}.test"), "", i as u32));
        }
        for i in 0..2u64 {
            let mut ev = block_event(
                ACTION_BLOCK,
                &format!("ads{i}.test"),
                "",
                "||ads^",
                "Ads",
                0,
                10,
                1,
                false,
            );
            ev.ts_ms = 3_000 + i;
            store.log_enqueue(&ev);
        }
        store.log_flush();
        // The page is capped well below the table, the counts are not.
        assert_eq!(store.log_page(0, 2).len(), 2);
        assert_eq!(store.log_status_counts(), (2, 3));
    }

    #[test]
    fn cursor_paging_walks_older_rows_without_offset_drift() {
        let (store, _) = temp_store("cursor");
        for i in 0..5u64 {
            store.log_enqueue(&allow_event(&format!("h{i}.test"), "", i as u32));
        }
        store.log_flush();

        let newest = store.log_page(0, 2);
        assert_eq!(newest[0].domain, "h4.test");
        assert_eq!(newest[1].domain, "h3.test");
        // The cursor is the last row the UI holds, not a row number.
        let older = store.log_page_before(newest[1].id, 2);
        assert_eq!(older[0].domain, "h2.test");
        assert_eq!(older[1].domain, "h1.test");
        let last = store.log_page_before(older[1].id, 2);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].domain, "h0.test");
        assert!(store.log_page_before(last[0].id, 2).is_empty());

        // A row arriving at the top moves nothing: the next cursor page still
        // starts right below the rows already on screen.
        store.log_enqueue(&allow_event("h5.test", "", 9));
        store.log_flush();
        let older = store.log_page_before(newest[1].id, 2);
        assert_eq!(older[0].domain, "h2.test");
        assert_eq!(store.log_page(0, 1)[0].domain, "h5.test");
    }

    #[test]
    fn log_clear_drops_queued_and_stored_rows() {
        let (store, _) = temp_store("clear");
        store.log_enqueue(&allow_event("a.test", "", 0));
        store.log_flush();
        store.log_enqueue(&allow_event("b.test", "", 0)); // still queued
        store.log_clear(); // must drop the queue too
        assert_eq!(store.log_count(), 0);
        assert!(store.log_page(0, 10).is_empty());
    }

    #[test]
    fn prune_by_age_and_cap() {
        let (store, _) = temp_store("prune");
        let now = crate::util::now_ms();
        for i in 0..5u64 {
            let mut old = allow_event(&format!("old{i}.test"), "", 0);
            old.ts_ms = now - 10 * 24 * 60 * 60 * 1_000;
            store.log_enqueue(&old);
        }
        for i in 0..5u64 {
            let mut fresh = allow_event(&format!("new{i}.test"), "", 0);
            fresh.ts_ms = now - i;
            store.log_enqueue(&fresh);
        }
        store.log_flush();
        assert_eq!(store.log_count(), 10);

        // Age window: the ten-day-old rows go.
        let removed = log::prune_db(&store.db, 7 * 24 * 60 * 60 * 1_000, 1_000_000).unwrap();
        assert_eq!(removed, 5);
        assert_eq!(store.log_count(), 5);

        // Cap: only the three newest stay, whatever their age.
        let removed = log::prune_db(&store.db, u64::MAX, 3).unwrap();
        assert_eq!(removed, 2);
        let rows = store.log_page(0, 10);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].domain, "new4.test");
        assert_eq!(rows[2].domain, "new2.test");
    }

    #[test]
    fn reopens_with_the_rows_intact() {
        let (store, dir) = temp_store("reopen");
        for i in 0..3u64 {
            store.log_enqueue(&allow_event(&format!("h{i}.test"), "", 0));
        }
        store.log_flush();
        let before = store.log_count();
        drop(store);

        let reopened = Store::open(&dir).expect("reopen");
        assert_eq!(reopened.log_count(), before);
        assert_eq!(reopened.log_page(0, 10).len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_survive_a_reopen() {
        let (store, dir) = temp_store("settings");
        assert_eq!(store.settings_get(), None);
        store.settings_set("{\"protection\":true}").unwrap();
        assert_eq!(
            store.settings_get().as_deref(),
            Some("{\"protection\":true}")
        );
        store.settings_set("{\"protection\":false}").unwrap();
        assert_eq!(
            store.settings_get().as_deref(),
            Some("{\"protection\":false}")
        );
        drop(store);

        let reopened = Store::open(&dir).expect("reopen");
        assert_eq!(
            reopened.settings_get().as_deref(),
            Some("{\"protection\":false}")
        );
    }

    #[test]
    fn filter_choices_live_next_to_settings() {
        let (store, dir) = temp_store("filters-blob");
        assert_eq!(store.filters_get(), None);
        store.settings_set("{\"protection\":true}").unwrap();
        store.filters_set("{\"enabled\":[\"a\"]}").unwrap();
        store.filters_set("{\"enabled\":[\"a\",\"b\"]}").unwrap();
        // Each blob keeps its own row: writing one never disturbs the other.
        assert_eq!(
            store.settings_get().as_deref(),
            Some("{\"protection\":true}")
        );
        assert_eq!(
            store.filters_get().as_deref(),
            Some("{\"enabled\":[\"a\",\"b\"]}")
        );
        drop(store);

        let reopened = Store::open(&dir).expect("reopen");
        assert_eq!(
            reopened.filters_get().as_deref(),
            Some("{\"enabled\":[\"a\",\"b\"]}")
        );
        assert_eq!(
            reopened.settings_get().as_deref(),
            Some("{\"protection\":true}")
        );
    }

    #[test]
    fn v3_opens_with_state_tables_and_keeps_the_legacy_blobs() {
        let dir = std::env::temp_dir().join(format!("adfree-store-{}-v3", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let conn = Connection::open(dir.join("adfree.db")).unwrap();
            conn.execute_batch(
                "CREATE TABLE settings (
                     id         INTEGER PRIMARY KEY,
                     json       TEXT NOT NULL,
                     updated_ms INTEGER NOT NULL
                 );
                 CREATE TABLE log_events (
                     id          INTEGER PRIMARY KEY AUTOINCREMENT,
                     ts_ms       INTEGER NOT NULL,
                     action      INTEGER NOT NULL,
                     category    INTEGER NOT NULL,
                     domain      TEXT NOT NULL,
                     ip          TEXT NOT NULL,
                     rule        TEXT NOT NULL,
                     list_name   TEXT NOT NULL,
                     latency_ns  INTEGER NOT NULL DEFAULT 0,
                     bytes_saved INTEGER NOT NULL DEFAULT 0,
                     ipv6        INTEGER NOT NULL DEFAULT 0,
                     app         TEXT NOT NULL DEFAULT ''
                 );
                 INSERT INTO settings VALUES (1, '{\"protection\":true}', 1);
                 INSERT INTO settings VALUES (2, '{\"user_rules\":[\"a\"]}', 2);
                 PRAGMA user_version = 3;",
            )
            .unwrap();
        }

        let store = Store::open(&dir).expect("v3 store opens");
        // The archive is untouched: the import reads it, it does not consume it.
        assert_eq!(
            store.settings_get().as_deref(),
            Some("{\"protection\":true}")
        );
        assert_eq!(
            store.filters_get().as_deref(),
            Some("{\"user_rules\":[\"a\"]}")
        );
        // The new tables exist and start empty.
        assert!(store.state_keys().is_empty());
        assert_eq!(store.meta_get("legacy_imported"), None);
        store.state_set("protection", "{}").unwrap();
        store.meta_set("legacy_imported", "1").unwrap();
        assert_eq!(store.state_keys(), vec!["protection"]);
        assert_eq!(store.meta_get("legacy_imported").as_deref(), Some("1"));
        drop(store);

        let reopened = Store::open(&dir).expect("v4 reopen");
        assert_eq!(reopened.state_keys(), vec!["protection"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_replace_all_is_atomic_and_drops_absent_keys() {
        let (store, _) = temp_store("state-replace");
        store
            .state_put_all(&[
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ])
            .unwrap();
        assert_eq!(store.state_keys(), vec!["a", "b"]);
        store
            .state_replace_all(&[("b".to_string(), "3".to_string())])
            .unwrap();
        assert_eq!(store.state_keys(), vec!["b"]);
        assert_eq!(store.state_get("b").as_deref(), Some("3"));
    }

    #[test]
    fn a_burst_larger_than_a_batch_is_fully_written() {
        let (store, _) = temp_store("burst");
        let mut accepted = 0u64;
        for i in 0..1_000u64 {
            let mut ev = allow_event("burst.test", "", i as u32);
            ev.ts_ms = 5_000 + i;
            if store.log_enqueue(&ev) {
                accepted += 1;
            }
        }
        store.log_flush();
        // Everything the queue accepted is on disk and nothing else.
        assert_eq!(store.log_count(), accepted);
        assert!(accepted > 0);
    }
}
