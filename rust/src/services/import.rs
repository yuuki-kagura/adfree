//! Turning somebody else's dataset into this app's table.
//!
//! The breakdown wants three labels per domain: the company that owns it, the
//! service's own name, and what kind of service it is. That is the shape the
//! survey found in the field, and it is what these three publish:
//!
//! - **AdGuard** ships `assets/preset/trackers.json` inside its APK: a
//!   `trackerDomains` map from domain to tracker id, a `trackers` map from that
//!   id to `name`, `companyId` and `categoryId`, and a `categories` map from
//!   the id to a slug. Nothing downloads it at runtime, so this is the file the
//!   app's own company breakdown is built from.
//! - **Ghostery TrackerDB** (`@ghostery/trackerdb`, `dist/trackerdb.json`) keys
//!   `patterns` by a service key carrying `name`, `category`, `organization`
//!   and a `domains` list, with `domains` mapping a domain to that key, and
//!   `organizations` / `categories` carrying the display names.
//! - **DuckDuckGo Tracker Radar** describes one domain per file: `domain`, an
//!   `owner` with `name` and `displayName`, and `categories` as display
//!   strings. The repository shards those files by region, so what arrives here
//!   is the merged form — an object under `domains`, an array, a bare map
//!   keyed by domain, or a single file's object.
//!
//! All of them become the same sorted, deduplicated body the lookup binary
//! searches, with the provenance written into the header comments. A body that
//! is already in this format is passed through untouched.

use std::collections::BTreeMap;

use serde_json::Value;

/// One domain's labels while the rows are still being collected.
#[derive(Default)]
struct Fields {
    company: String,
    tracker: String,
    category: String,
}

type Rows = BTreeMap<String, Fields>;

/// A converted body: what to call the source in the header, plus its rows.
struct Converted {
    label: &'static str,
    rows: Rows,
}

/// Normalise a downloaded body into this app's table format.
///
/// A body that is already a text table is passed through untouched, so the
/// caller's own checks decide whether it is usable. `Err` says why a JSON body
/// is unusable, which the caller answers by keeping the table it already had.
pub fn to_table(body: &str) -> Result<String, String> {
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return Ok(body.to_owned());
    }
    let (value, converted) = dataset(body)?;
    Ok(render(
        std::slice::from_ref(&converted.label),
        &converted.rows,
        note(&value).as_deref(),
    ))
}

/// Merge several datasets into one table, in the order given.
///
/// The first source that names a domain's company owns that row, and the rest
/// only add domains it does not have — so an older release's hand-written names
/// survive a newer dataset that calls the same host something else, and the
/// merged file is still one sorted table.
pub fn merge(bodies: &[&str]) -> Result<String, String> {
    let mut labels: Vec<&'static str> = Vec::new();
    let mut merged = Rows::new();
    let mut updated = String::new();
    for body in bodies {
        let rows = if is_json(body) {
            let (value, converted) = dataset(body)?;
            if !labels.contains(&converted.label) {
                labels.push(converted.label);
            }
            if updated.is_empty() {
                updated = note(&value).unwrap_or_default();
            }
            converted.rows
        } else {
            if !labels.contains(&SHIPPED_LABEL) {
                labels.push(SHIPPED_LABEL);
            }
            table_rows(body)
        };
        absorb(&mut merged, rows);
    }
    if merged.is_empty() {
        return Err("nothing to merge".to_string());
    }
    Ok(render(
        &labels,
        &merged,
        (!updated.is_empty()).then_some(updated.as_str()),
    ))
}

/// The label a body already in this app's format is credited with.
const SHIPPED_LABEL: &str = "the table this project authors";

fn is_json(body: &str) -> bool {
    let trimmed = body.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

/// Rows of a body that is already a table in this format.
fn table_rows(body: &str) -> Rows {
    let mut rows = Rows::new();
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || !line.contains('\t') {
            continue;
        }
        insert(
            &mut rows,
            super::key_of(line),
            Fields {
                company: super::company_of(line).to_owned(),
                tracker: super::tracker_of(line).to_owned(),
                category: super::category_of(line).to_owned(),
            },
        );
    }
    rows
}

/// Folds one source's rows into the merged set. A domain the earlier source
/// already named a company for keeps that row as it was written: labels from
/// two datasets do not get stitched into one row.
fn absorb(merged: &mut Rows, rows: Rows) {
    for (domain, fields) in rows {
        match merged.get_mut(&domain) {
            Some(existing) if !existing.company.is_empty() => {}
            Some(existing) => {
                if !fields.company.is_empty() {
                    *existing = fields;
                }
            }
            None => {
                merged.insert(domain, fields);
            }
        }
    }
}

/// A JSON body read and recognised: its parsed value and the rows it describes.
fn dataset(body: &str) -> Result<(Value, Converted), String> {
    let value: Value = serde_json::from_str(body.trim_start())
        .map_err(|e| format!("the JSON body could not be parsed: {e}"))?;
    let converted = convert(&value).ok_or("no known tracker dataset in this JSON body")?;
    if converted.rows.is_empty() {
        return Err(format!("{} carried no usable domains", converted.label));
    }
    Ok((value, converted))
}

/// The `timeUpdated` stamp AdGuard's file carries, when it has one.
fn note(value: &Value) -> Option<String> {
    value
        .get("timeUpdated")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn convert(value: &Value) -> Option<Converted> {
    for (label, convert) in [
        ("AdGuard trackers", adguard as fn(&Value, &mut Rows) -> bool),
        ("Ghostery TrackerDB", ghostery),
        ("DuckDuckGo Tracker Radar", duckduckgo),
    ] {
        let mut rows = Rows::new();
        if convert(value, &mut rows) && !rows.is_empty() {
            return Some(Converted { label, rows });
        }
    }
    None
}

/// AdGuard's `trackers.json`: domain → tracker id → tracker, with the category
/// id resolved through the file's own `categories` map.
fn adguard(value: &Value, rows: &mut Rows) -> bool {
    let Some(trackers) = value.get("trackers").and_then(Value::as_object) else {
        return false;
    };
    let categories = value.get("categories").cloned().unwrap_or(Value::Null);
    let mut seen = false;
    if let Some(map) = value.get("trackerDomains").and_then(Value::as_object) {
        for (domain, id) in map {
            let Some(tracker) = id.as_str().and_then(|id| trackers.get(id)) else {
                continue;
            };
            seen = true;
            insert(rows, domain, adguard_fields(tracker, &categories));
        }
    }
    // A release that hangs domains off the tracker instead is still the same
    // file: the `domains` array on each entry names the same hosts.
    if !seen {
        for tracker in trackers.values() {
            let Some(list) = tracker.get("domains").and_then(Value::as_array) else {
                continue;
            };
            for domain in list.iter().filter_map(Value::as_str) {
                seen = true;
                insert(rows, domain, adguard_fields(tracker, &categories));
            }
        }
    }
    seen
}

/// One AdGuard tracker entry: its company, its own name, and the category
/// resolved through the file's map. An entry with no `companyId` still names
/// the service, and that name is what the app groups the host under, so the row
/// carries it instead of an empty company.
fn adguard_fields(tracker: &Value, categories: &Value) -> Fields {
    let name = label(tracker.get("name")).unwrap_or_default();
    Fields {
        company: label(tracker.get("companyId"))
            .or_else(|| label(nested(tracker.get("company"), "name")))
            .or_else(|| (!name.is_empty()).then(|| name.clone()))
            .unwrap_or_default(),
        tracker: name,
        category: adguard_category(categories, tracker.get("categoryId")),
    }
}

/// AdGuard's `categories` are keyed by the id as a string and hold a slug.
fn adguard_category(categories: &Value, id: Option<&Value>) -> String {
    let key = match id {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => return String::new(),
    };
    label(categories.get(&key)).unwrap_or_default()
}

/// Ghostery's TrackerDB: `domains` names the pattern a domain belongs to, and
/// `patterns` carries the service name plus the keys its category and
/// organization display names are looked up under.
fn ghostery(value: &Value, rows: &mut Rows) -> bool {
    let Some(patterns) = value.get("patterns").and_then(Value::as_object) else {
        return false;
    };
    let organizations = value.get("organizations").and_then(Value::as_object);
    let categories = value.get("categories").and_then(Value::as_object);
    let mut seen = false;
    if let Some(map) = value.get("domains").and_then(Value::as_object) {
        for (domain, key) in map {
            let Some(key) = key.as_str() else { continue };
            let Some(pattern) = patterns.get(key) else {
                continue;
            };
            seen = true;
            insert(rows, domain, ghostery_fields(pattern, organizations, categories));
        }
    }
    for pattern in patterns.values() {
        let Some(list) = pattern.get("domains").and_then(Value::as_array) else {
            continue;
        };
        // A pattern's own `domains` list may name hosts the `domains` map does
        // not reach, and the same key resolves either way.
        for domain in list.iter().filter_map(Value::as_str) {
            seen = true;
            insert(rows, domain, ghostery_fields(pattern, organizations, categories));
        }
    }
    seen
}

fn ghostery_fields(
    pattern: &Value,
    organizations: Option<&serde_json::Map<String, Value>>,
    categories: Option<&serde_json::Map<String, Value>>,
) -> Fields {
    let organization = label(pattern.get("organization"));
    let category = label(pattern.get("category"));
    let tracker = label(pattern.get("name")).unwrap_or_default();
    Fields {
        company: organization
            .as_deref()
            .and_then(|key| organizations?.get(key))
            .and_then(|org| label(org.get("name")))
            .or_else(|| (!tracker.is_empty()).then(|| tracker.clone()))
            .unwrap_or_default(),
        tracker,
        category: category
            .as_deref()
            .and_then(|key| categories?.get(key))
            .and_then(|cat| label(cat.get("name")))
            .or(category)
            .unwrap_or_default(),
    }
}

/// DuckDuckGo's Tracker Radar, in whichever of its merged forms the file arrives
/// in. Region shards have to be joined before upload, so nothing here reads a
/// directory.
fn duckduckgo(value: &Value, rows: &mut Rows) -> bool {
    let mut items: Vec<(Option<String>, &Value)> = Vec::new();
    match value {
        Value::Array(list) => items.extend(list.iter().map(|item| (None, item))),
        Value::Object(map) => {
            match map.get("domains") {
                Some(Value::Object(inner)) => {
                    items.extend(inner.iter().map(|(k, item)| (Some(k.clone()), item)));
                }
                Some(Value::Array(list)) => {
                    items.extend(list.iter().map(|item| (None, item)));
                }
                _ => {
                    if map.contains_key("owner") || map.contains_key("prevalence") {
                        items.push((None, value));
                    } else {
                        items.extend(map.iter().map(|(k, item)| (Some(k.clone()), item)));
                    }
                }
            }
        }
        _ => return false,
    }
    let mut seen = false;
    for (key, item) in items {
        // A region shard's object is the only thing that qualifies: it names an
        // owner, or is the record the radar builds for a domain.
        if item.get("owner").is_none() && item.get("prevalence").is_none() {
            continue;
        }
        let domain = label(item.get("domain")).or(key).unwrap_or_default();
        if domain.is_empty() {
            continue;
        }
        let owner = item.get("owner");
        let company = owner
            .and_then(|owner| label(owner.get("displayName")))
            .or_else(|| owner.and_then(|owner| label(owner.get("name"))))
            .unwrap_or_default();
        let category = item
            .get("categories")
            .and_then(Value::as_array)
            .and_then(|list| list.first())
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        seen = true;
        insert(
            rows,
            &domain,
            Fields {
                company,
                tracker: String::new(),
                category,
            },
        );
    }
    seen
}

/// One string field, cleaned of anything that would break the row apart.
fn label(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(s) => s.as_str(),
        Value::Number(n) => return Some(n.to_string()),
        _ => return None,
    };
    let cleaned: String = text
        .chars()
        .map(|c| if c == '\t' || c.is_ascii_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.trim();
    (!cleaned.is_empty()).then(|| cleaned.to_owned())
}

fn nested<'a>(value: Option<&'a Value>, field: &str) -> Option<&'a Value> {
    value.and_then(|value| value.get(field))
}

/// Adds one domain, merging the labels two sources both describe it with.
fn insert(rows: &mut Rows, domain: &str, fields: Fields) {
    let Some(key) = host(domain) else { return };
    let entry = rows.entry(key).or_default();
    if entry.company.is_empty() {
        entry.company = fields.company;
    }
    if entry.tracker.is_empty() {
        entry.tracker = fields.tracker;
    }
    if entry.category.is_empty() {
        entry.category = fields.category;
    }
}

/// The row key: lower-case, no trailing dot, and a shape that could be looked
/// up at all. An IDNA host would never match, because the lookup refuses
/// anything non-ASCII, so those rows are dropped rather than kept as dead weight.
fn host(domain: &str) -> Option<String> {
    let host = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host.is_ascii()
        || host.contains(' ')
        || host.contains('@')
        || host.contains('/')
        || host.contains('*')
    {
        return None;
    }
    Some(host)
}

/// The body a resolver can binary search: header, then one row per domain in
/// byte order. Trailing empty fields are left out, so a table that only knows
/// companies still reads as the two-column form this project authored.
fn render(labels: &[&str], rows: &Rows, updated: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Converted from {} by the AdFree services importer.\n",
        labels.join(" + ")
    ));
    if let Some(updated) = updated {
        out.push_str(&format!("# The source names this build {updated}.\n"));
    }
    out.push_str(&format!(
        "# {} domains, one per line, tab separated: domain, company, service, category.\n",
        rows.len()
    ));
    out.push_str("# Terms: the sources' own; see docs/adguard-survey/PLAN.md.\n");
    for (domain, fields) in rows {
        let row = [
            domain.as_str(),
            fields.company.as_str(),
            fields.tracker.as_str(),
            fields.category.as_str(),
        ];
        let last = row.iter().rposition(|field| !field.is_empty());
        let Some(last) = last else { continue };
        out.push_str(&row[..=last].join("\t"));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_already_in_this_format_is_left_alone() {
        let body = "doubleclick.net\tGoogle\n";
        assert_eq!(to_table(body).unwrap(), body);
    }

    #[test]
    fn adguard_trackers_become_company_tracker_and_category() {
        let body = r#"{
          "timeUpdated": "2023-04-22T00:08:45.193Z",
          "categories": {"4": "advertising", "6": "site_analytics"},
          "trackers": {
            "doubleclick": {"name": "DoubleClick", "companyId": "google", "categoryId": 4},
            "nope": {"name": "Unknown", "companyId": "", "categoryId": 99}
          },
          "trackerDomains": {
            "doubleclick.net": "doubleclick",
            "ads.DoubleClick.net": "doubleclick",
            "orphan.example": "missing"
          }
        }"#;
        let table = to_table(body).unwrap();
        let lines: Vec<&str> = table.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            vec![
                "ads.doubleclick.net\tgoogle\tDoubleClick\tadvertising",
                "doubleclick.net\tgoogle\tDoubleClick\tadvertising",
            ],
            "a host no tracker names is dropped, and the walk needs the lower-case key"
        );
        assert!(table.starts_with("# Converted from AdGuard trackers"));
        assert!(table.contains("2023-04-22T00:08:45.193Z"));
    }

    #[test]
    fn ghostery_patterns_resolve_their_organization_and_category() {
        let body = r#"{
          "categories": {"site_analytics": {"name": "Site Analytics"}},
          "organizations": {"1000mercis": {"name": "1000mercis"}},
          "patterns": {
            "1000mercis": {"name": "1000mercis", "category": "site_analytics",
                            "organization": "1000mercis", "domains": ["mmtro.com"]}
          },
          "domains": {"mmtro.com": "1000mercis", "second.com": "1000mercis"}
        }"#;
        let table = to_table(body).unwrap();
        assert!(table.contains("mmtro.com\t1000mercis\t1000mercis\tSite Analytics\n"));
        assert!(table.contains("second.com\t1000mercis\t1000mercis\tSite Analytics\n"));
    }

    #[test]
    fn duckduckgo_domains_take_their_owner_display_name() {
        let body = r#"{
          "domains": {
            "doubleclick.net": {"domain": "doubleclick.net",
                                 "owner": {"name": "Google LLC", "displayName": "Google"},
                                 "categories": ["Ad Motivated Tracking", "Advertising"]},
            "fling.com": {"owner": {"name": "Fling"}, "prevalence": 0.01, "categories": []}
          }
        }"#;
        let table = to_table(body).unwrap();
        assert!(table.contains("doubleclick.net\tGoogle\t\tAd Motivated Tracking\n"));
        assert!(table.contains("fling.com\tFling\n"));
    }

    #[test]
    fn a_json_body_that_is_not_a_tracker_dataset_is_refused() {
        assert!(to_table("{\"filters\": [1, 2]}").is_err());
        assert!(to_table("{not json").is_err());
    }

    #[test]
    fn merging_keeps_the_first_source_s_labels_and_adds_the_rest() {
        let shipped = "doubleclick.net\tGoogle\n";
        let dataset = r#"{"trackers": {"adform": {"name": "AdForm", "companyId": "Adform"}},
                          "trackerDomains": {"adform.net": "adform", "doubleclick.net": "adform"}}"#;
        let merged = merge(&[shipped, dataset]).unwrap();
        assert!(
            merged.contains("doubleclick.net\tGoogle\n"),
            "the hand-written name survives the dataset's version of the row"
        );
        assert!(merged.contains("adform.net\tAdform\tAdForm\n"));
        assert!(merged.contains(&format!("# Converted from {SHIPPED_LABEL}")));
        assert!(crate::services::is_sorted(&merged));
    }

    #[test]
    fn the_converted_body_is_searchable() {
        let body = r#"{"trackers": {"b": {"name": "B", "companyId": "co"},
                                     "a": {"name": "A", "companyId": "co"}},
                       "trackerDomains": {"z.example": "b", "a.example": "a"}}"#;
        let table = to_table(body).unwrap();
        assert!(crate::services::is_sorted(&table));
        assert_eq!(crate::services::row_count(&table), 2);
        let resolver_dir = std::env::temp_dir().join(format!("adfree-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&resolver_dir);
        std::fs::create_dir_all(&resolver_dir).unwrap();
        crate::assets::save(&resolver_dir, super::super::OVERRIDE_ID, "tsv", &table).unwrap();
        let resolver = crate::services::Resolver::new(Some(&resolver_dir));
        assert_eq!(
            resolver.entry("www.z.example").as_ref().map(|e| e.company.as_str()),
            Some("co")
        );
        assert_eq!(
            resolver.entry("a.example").as_ref().map(|e| e.tracker.as_str()),
            Some("A")
        );
        let _ = std::fs::remove_dir_all(&resolver_dir);
    }
}
