//! Who owns a domain: the labels behind the services breakdown.
//!
//! The table is the app's own work — `assets/services.tsv`, one registrable
//! domain and the company that owns it, sorted by byte order on the first
//! field. It is compiled in, so the labels exist before the store opens and
//! without a file read; a downloaded table in `filters/services.tsv` replaces
//! it when the user subscribes to one.
//!
//! Nothing is parsed until the first lookup, which only happens while the
//! breakdown switch is on. The lookup is a binary search over the text's own
//! line offsets: no map, no per-row allocation, so a table grown to tens of
//! thousands of rows costs four bytes per row instead of a copy of every
//! string in the file.

use std::borrow::Cow;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

/// The table this build ships.
pub const BUILTIN: &str = include_str!("../assets/services.tsv");

/// Id and extension of the downloaded override, kept with the filter lists.
pub const OVERRIDE_ID: &str = "services";
pub const OVERRIDE_EXT: &str = "tsv";

/// One table: its text, and the byte offset of every data row in sort order.
struct Table {
    text: Cow<'static, str>,
    starts: Vec<usize>,
}

impl Table {
    fn new(text: Cow<'static, str>) -> Self {
        let starts = scan(&text);
        Table { text, starts }
    }

    /// The line starting at `off`, without its newline or carriage return.
    fn line(&self, off: usize) -> &str {
        let rest = &self.text[off..];
        let end = rest.find('\n').unwrap_or(rest.len());
        rest[..end].strip_suffix('\r').unwrap_or(&rest[..end])
    }

    /// The domain a line is keyed by.
    fn key_at(&self, off: usize) -> &str {
        key_of(self.line(off))
    }

    fn company_at(&self, off: usize) -> &str {
        company_of(self.line(off))
    }

    fn find(&self, key: &str) -> Option<usize> {
        match self
            .starts
            .binary_search_by(|&off| self.key_at(off).as_bytes().cmp(key.as_bytes()))
        {
            Ok(i) => Some(self.starts[i]),
            Err(_) => None,
        }
    }

    /// Suffix walk at label boundaries: `ads.doubleclick.net` belongs to the
    /// `doubleclick.net` row, and never to a shorter suffix that is not a
    /// label boundary. Each candidate is one binary search, so a host with
    /// five labels costs five searches over a table nobody copied.
    fn lookup(&self, domain: &str) -> Option<&str> {
        let mut start = 0usize;
        loop {
            if let Some(off) = self.find(&domain[start..]) {
                let company = self.company_at(off);
                return (!company.is_empty()).then_some(company);
            }
            match domain[start..].find('.') {
                Some(dot) => start += dot + 1,
                None => return None,
            }
        }
    }
}

/// The domain a line is keyed by.
fn key_of(line: &str) -> &str {
    match line.find('\t') {
        Some(tab) => &line[..tab],
        None => line,
    }
}

/// The company a line carries, empty when the row has no second field.
fn company_of(line: &str) -> &str {
    match line.split_once('\t') {
        Some((_, company)) => company,
        None => "",
    }
}

/// True when a row is a lookup entry: not a comment, not blank, two fields.
fn is_row(line: &str) -> bool {
    !line.is_empty() && !line.starts_with('#') && line.contains('\t')
}

/// Offsets of the data rows: non-empty, not a comment, and carrying a tab.
fn scan(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    for line in text.split('\n') {
        if is_row(line.strip_suffix('\r').unwrap_or(line)) {
            out.push(offset);
        }
        offset += line.len() + 1;
    }
    out
}

/// True when the data rows are in byte order on the first field. A table from
/// elsewhere that is not sorted would answer lookups with silent misses, so
/// the download is refused rather than trusted.
pub fn is_sorted(text: &str) -> bool {
    let mut previous: Option<&str> = None;
    for line in text.lines() {
        if !is_row(line) {
            continue;
        }
        let key = key_of(line);
        if previous.is_some_and(|before| before.as_bytes() > key.as_bytes()) {
            return false;
        }
        previous = Some(key);
    }
    true
}

/// Number of lookup rows in a body. A file with none is not a table.
pub fn row_count(text: &str) -> usize {
    scan(text).len()
}

fn built_in() -> Arc<Table> {
    static CELL: OnceLock<Arc<Table>> = OnceLock::new();
    Arc::clone(CELL.get_or_init(|| Arc::new(Table::new(Cow::Borrowed(BUILTIN)))))
}

/// The downloaded table, re-read only when its mtime moves. Held for as long
/// as a [`Resolver`] lives, so a page of lookups keeps one copy.
fn downloaded(dir: &Path) -> Option<Arc<Table>> {
    static CACHE: Mutex<Option<(i64, Arc<Table>)>> = Mutex::new(None);
    let outcome = crate::assets::state(dir, OVERRIDE_ID, OVERRIDE_EXT, false)?;
    let modified = outcome.modified_ms;
    let mut cache = CACHE.lock().ok()?;
    if cache.as_ref().map(|(ms, _)| *ms) == Some(modified) {
        return Some(Arc::clone(&cache.as_ref()?.1));
    }
    let text = crate::assets::read_text(dir, OVERRIDE_ID, OVERRIDE_EXT)?;
    let table = Arc::new(Table::new(Cow::Owned(text)));
    *cache = Some((modified, Arc::clone(&table)));
    Some(table)
}

/// Which table answers lookups, decided once per batch of rows.
pub struct Resolver {
    table: Arc<Table>,
}

impl Resolver {
    /// `filters_dir` is `None` while the store is still closed, which leaves
    /// the shipped table in charge.
    pub fn new(filters_dir: Option<&Path>) -> Self {
        let table = filters_dir.and_then(downloaded).unwrap_or_else(built_in);
        Resolver { table }
    }

    /// The company owning `domain`, or `None` when the table has no row for
    /// it: the UI then shows the name and claims nothing beyond it.
    pub fn company(&self, domain: &str) -> Option<String> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() || !domain.is_ascii() {
            return None;
        }
        self.table.lookup(&domain).map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_shipped_table_is_sorted_and_deduped() {
        let table = Table::new(Cow::Borrowed(BUILTIN));
        assert!(table.starts.len() > 50);
        assert!(is_sorted(BUILTIN));
        let keys: Vec<&str> = table.starts.iter().map(|&off| table.key_at(off)).collect();
        let mut unique = keys.clone();
        unique.dedup();
        assert_eq!(keys, unique, "a repeated key hides a row");
    }

    #[test]
    fn a_subdomain_takes_its_registrable_domain_row() {
        let r = Resolver::new(None);
        assert_eq!(r.company("ads.doubleclick.net").as_deref(), Some("Google"));
        assert_eq!(
            r.company("sb.l.google.com").as_deref(),
            Some("Google"),
            "the walk keeps going until it hits a label boundary that is in the table"
        );
    }

    #[test]
    fn the_case_and_the_trailing_dot_do_not_matter() {
        let r = Resolver::new(None);
        assert_eq!(r.company("Criteo.COM.").as_deref(), Some("Criteo"));
        assert_eq!(r.company("criteo.com").as_deref(), Some("Criteo"));
    }

    #[test]
    fn a_domain_the_table_does_not_know_is_left_as_it_is() {
        let r = Resolver::new(None);
        assert_eq!(r.company("example.invalid"), None);
        assert_eq!(r.company(""), None);
        assert_eq!(r.company("xn--80ak6aa92e.com"), None);
    }

    #[test]
    fn the_lookup_never_matches_inside_a_label() {
        // `notdoubleclick.net` is a different registrable domain.
        let r = Resolver::new(None);
        assert_eq!(r.company("notdoubleclick.net"), None);
    }

    #[test]
    fn the_table_is_built_on_first_use_only() {
        // A downloaded file wins over the shipped one, and a directory with no
        // file leaves the shipped table alone.
        let missing = PathBuf::from("/nonexistent-adfree-store");
        assert_eq!(
            Resolver::new(Some(&missing))
                .company("doubleclick.net")
                .as_deref(),
            Some("Google")
        );
    }

    #[test]
    fn the_services_table_stays_on_disk() {
        // Nothing is read until a lookup asks: the shipped table is searched in
        // place, and a downloaded one is read once per change of mtime.
        let dir = std::env::temp_dir().join(format!("adfree-services-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            Resolver::new(Some(&dir))
                .company("doubleclick.net")
                .as_deref(),
            Some("Google"),
            "a store with no downloaded table still answers from the shipped one"
        );
        std::fs::create_dir_all(&dir).unwrap();
        crate::assets::save(
            &dir,
            OVERRIDE_ID,
            OVERRIDE_EXT,
            "# test table\ndoubleclick.net\tExample Co\n",
        )
        .unwrap();
        assert_eq!(
            Resolver::new(Some(&dir))
                .company("ads.doubleclick.net")
                .as_deref(),
            Some("Example Co"),
            "the downloaded table replaces the shipped one"
        );
        // Dropping it puts the shipped labels back.
        crate::assets::remove(&dir, OVERRIDE_ID, OVERRIDE_EXT);
        assert_eq!(
            Resolver::new(Some(&dir))
                .company("doubleclick.net")
                .as_deref(),
            Some("Google")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_table_in_the_wrong_order_is_refused() {
        assert!(!is_sorted("z.example\tZ\na.example\tA\n"));
        assert!(is_sorted("a.example\tA\nz.example\tZ\n"));
        // Comments and blanks do not break the order, but rows are counted.
        assert!(is_sorted("# header\na.example\tA\n\nz.example\tZ\n"));
        assert_eq!(row_count("# header\na.example\tA\n\nz.example\tZ\n"), 2);
        assert_eq!(row_count("just a domain, no company\n"), 0);
    }
}
