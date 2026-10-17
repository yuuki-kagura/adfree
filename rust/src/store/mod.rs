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

pub use log::LogRow;

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
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("open {}: {e}", db_path.display()))?;
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

    pub fn log_count(&self) -> u64 {
        match log::count(&self.db) {
            Ok(n) => n.max(0) as u64,
            Err(e) => {
                crate::logbuf::push(&format!("store: count log: {e}"));
                0
            }
        }
    }

    // ------------------------------------------------------------- settings

    /// The app's settings blob, exactly as it was saved.
    pub fn settings_get(&self) -> Option<String> {
        self.db
            .lock()
            .query_row("SELECT json FROM settings WHERE id = 1", [], |r| r.get(0))
            .ok()
    }

    /// Replaces the settings blob (single row, atomic).
    pub fn settings_set(&self, json: &str) -> Result<(), String> {
        self.db
            .lock()
            .execute(
                "INSERT INTO settings (id, json, updated_ms) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated_ms = excluded.updated_ms",
                rusqlite::params![json, crate::util::now_ms() as i64],
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{allow_event, block_event, ACTION_BLOCK};

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
    }

    #[test]
    fn log_pages_and_counts() {
        let (store, _) = temp_store("pages");
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
        assert_eq!(store.settings_get().as_deref(), Some("{\"protection\":true}"));
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
