//! `$jsonprune` — the JSON body edits AdGuard filter lists ask for.
//!
//! CoreLibs implements `$jsonprune`; the crate this engine is built on has
//! never seen the modifier, so both the matching (see
//! [`crate::filter::FilterEngine::jsonprune_plan`]) and the edit itself live
//! here. This module is the edit half: the expression language, the walk of
//! expression and document, and the rewrite.
//!
//! The language is the "modified JSONPath" the AdGuard knowledge base
//! documents (create-own-filters, `$jsonprune`): Goessner JSONPath with
//! script expressions taken out and a handful of filter expressions added.
//! The rules this engine accepts are the ones the reference documents, and a
//! rule carrying anything else is dropped rather than half-run:
//!
//! - `$` roots the expression; `.name` reads a property, `..name` reads it at
//!   any depth, `.*` and `..*` take every child, `[a, b]` takes several keys
//!   or array indexes at once and `["a b"]` / `['a b']` quote a key.
//! - `[?(has <key>)]` keeps the children that carry the key,
//!   `[?(key-eq <key> <value>)]` the children whose key equals the value and
//!   `[?(key-substr <key> <value>)]` the children whose key holds the value
//!   as a substring. A `<key>` that starts with `$` is a nested expression
//!   rooted at the child (AdGuard v1.11 and later), anything else a property
//!   name.
//! - Whitespace outside quoted strings means nothing, both quote characters
//!   are equal (a `\` escapes the next character inside quotes), and the
//!   characters `$` and `,` arrive escaped as `\$` and `\,` — the rule-level
//!   escapes are undone here, before the expression is read.
//!
//! What the dialect does not have is not guessed at: an expression ending in
//! `..`, a slice (`[1:2]`), a negative index, a `?(...)` predicate other than
//! the three above — none of them parse, and the rule that carries one is
//! dropped with the build's dropped-count. The one thing an expression may
//! select but no rewrite can take is the document root (`$`), which is left
//! in place.
//!
//! What the reference calls JSONP — a call wrapper around a JSON document,
//! `cb({…});` — is understood too: when the body is not JSON as it stands,
//! one identifier-call shell around it is tried, and only the JSON inside is
//! rewritten; every other byte of the body stays where it was.

use serde_json::Value;

/// One parsed `$jsonprune` expression.
#[derive(Clone, Debug)]
pub struct JsonPrune {
    steps: Vec<Step>,
}

/// One parsed expression, with the rule text it came from.
///
/// What a request's [`crate::filter::JsonprunePlan`] holds: the plan is built
/// per request and outlives the engine build it borrowed from, so the text
/// and the expression are copied out of it.
#[derive(Clone, Debug)]
pub struct JsonpruneRule {
    /// The rule exactly as the list wrote it: the log shows it.
    pub text: String,
    expression: JsonPrune,
}

impl JsonpruneRule {
    pub fn new(text: String, expression: JsonPrune) -> JsonpruneRule {
        JsonpruneRule { text, expression }
    }
}

/// One step of an expression: what it selects, and whether it reaches the
/// selection through `..`.
#[derive(Clone, Debug)]
struct Step {
    kind: StepKind,
    /// `..`: the step applies to the node and to every node under it.
    recursive: bool,
}

#[derive(Clone, Debug)]
enum StepKind {
    /// `.name` / `["name"]`
    Key(String),
    /// `.*`
    Wildcard,
    /// `[0]`
    Index(usize),
    /// `[a, "b c", 0]`
    Union(Vec<Selector>),
    /// `[?(...)]`
    Filter(Filter),
}

#[derive(Clone, Debug)]
enum Selector {
    Key(String),
    Index(usize),
    Wildcard,
}

/// One `[?(...)]` predicate.
#[derive(Clone, Debug)]
enum Filter {
    Has(KeyNav),
    KeyEq(KeyNav, Literal),
    KeySubstr(KeyNav, String),
}

/// What a predicate's key argument names: a property, or a nested expression
/// (a string starting with `$`) rooted at the child under test.
#[derive(Clone, Debug)]
enum KeyNav {
    Key(String),
    Path(Box<JsonPrune>),
}

/// The literal a `key-eq` compares against.
#[derive(Clone, Debug)]
enum Literal {
    Str(String),
    Bool(bool),
    Null,
    Number(f64),
}

/// One element of a walk, and of the path back to the node it named.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PathElem {
    /// Ordering: a property sorts before an index. Paths under one parent are
    /// all of one kind — a node is an object or an array, never both — so
    /// the relative order is only ever compared within one kind.
    Key(String),
    Index(usize),
}

impl JsonPrune {
    /// Reads one `$jsonprune` value, escapes included. `None` when the value
    /// is not an expression this engine runs.
    pub fn parse(value: &str) -> Option<JsonPrune> {
        let mut parser = Parser::new(&unescape(value));
        let expression = parser.parse_expression().ok()?;
        // Every byte has to have been read: a trailing `)` or quote is not an
        // expression.
        parser.skip_whitespace();
        (parser.peek().is_none()).then_some(expression)
    }

    /// Takes every node the expression selects out of `document`. `true` when
    /// anything was taken.
    fn prune(&self, document: &mut Value) -> bool {
        let mut paths: Vec<Vec<PathElem>> = self
            .select(document)
            .into_iter()
            .map(|(path, _)| path)
            // The root is not an item of anything: an expression selecting it
            // is an expression this engine leaves the document for.
            .filter(|path| !path.is_empty())
            .collect();
        paths.sort();
        paths.dedup();
        let mut removed = false;
        // Deepest first: a child path is always longer than the path of the
        // parent it belongs to, and taking the child first keeps the parent's
        // other children where the paths say they are.
        for path in paths.into_iter().rev() {
            removed |= remove_at(document, &path);
        }
        removed
    }

    /// Every node the expression selects, with the path that leads to it.
    fn select<'a>(&'a self, document: &'a Value) -> Vec<(Vec<PathElem>, &'a Value)> {
        let mut current: Vec<(Vec<PathElem>, &Value)> = vec![(Vec::new(), document)];
        for step in &self.steps {
            let mut next: Vec<(Vec<PathElem>, &Value)> = Vec::new();
            for (path, node) in &current {
                if step.recursive {
                    collect_subtree(&step.kind, path, node, &mut next);
                } else {
                    apply_step(&step.kind, path, node, &mut next);
                }
            }
            current = next;
        }
        current
    }
}

/// The values a predicate's key argument reaches on one child.
fn key_values<'a>(nav: &'a KeyNav, candidate: &'a Value) -> Vec<&'a Value> {
    match nav {
        KeyNav::Key(key) => candidate.get(key).into_iter().collect(),
        KeyNav::Path(expression) => expression
            .select(candidate)
            .into_iter()
            .map(|(_, node)| node)
            .collect(),
    }
}

impl Filter {
    fn matches(&self, candidate: &Value) -> bool {
        match self {
            Filter::Has(nav) => !key_values(nav, candidate).is_empty(),
            Filter::KeyEq(nav, literal) => key_values(nav, candidate)
                .into_iter()
                .any(|value| literal.equals(value)),
            Filter::KeySubstr(nav, needle) => key_values(nav, candidate)
                .into_iter()
                .any(|value| value.as_str().is_some_and(|text| text.contains(needle))),
        }
    }
}

impl Literal {
    fn equals(&self, value: &Value) -> bool {
        match self {
            Literal::Str(text) => value.as_str() == Some(text),
            Literal::Bool(flag) => value.as_bool() == Some(*flag),
            Literal::Null => value.is_null(),
            // A number compares as the f64 both sides read as: the dialect
            // has one number type, like the JSONPath it comes from.
            Literal::Number(number) => value.as_f64() == Some(*number),
        }
    }
}

/// One `..` step on one node: the step applied to the node itself and to
/// every node under it, depth first.
fn collect_subtree<'a>(
    kind: &StepKind,
    path: &[PathElem],
    node: &'a Value,
    out: &mut Vec<(Vec<PathElem>, &'a Value)>,
) {
    apply_step(kind, path, node, out);
    match node {
        Value::Object(map) => {
            for (key, child) in map {
                let mut child_path = path.to_vec();
                child_path.push(PathElem::Key(key.clone()));
                collect_subtree(kind, &child_path, child, out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(PathElem::Index(index));
                collect_subtree(kind, &child_path, child, out);
            }
        }
        _ => {}
    }
}

/// One step on one node: the children it selects.
fn apply_step<'a>(
    kind: &StepKind,
    path: &[PathElem],
    node: &'a Value,
    out: &mut Vec<(Vec<PathElem>, &'a Value)>,
) {
    match kind {
        StepKind::Key(key) => {
            if let Some(child) = node.get(key) {
                out.push((extended(path, PathElem::Key(key.clone())), child));
            }
        }
        StepKind::Wildcard => each_child(path, node, out),
        StepKind::Index(index) => {
            if let Some(child) = node.get(*index) {
                out.push((extended(path, PathElem::Index(*index)), child));
            }
        }
        StepKind::Union(selectors) => {
            for selector in selectors {
                match selector {
                    Selector::Key(key) => apply_step(&StepKind::Key(key.clone()), path, node, out),
                    Selector::Wildcard => each_child(path, node, out),
                    Selector::Index(index) => apply_step(&StepKind::Index(*index), path, node, out),
                }
            }
        }
        StepKind::Filter(filter) => match node {
            Value::Object(map) => {
                for (key, child) in map {
                    if filter.matches(child) {
                        out.push((extended(path, PathElem::Key(key.clone())), child));
                    }
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    if filter.matches(child) {
                        out.push((extended(path, PathElem::Index(index)), child));
                    }
                }
            }
            _ => {}
        },
    }
}

/// Every child of one node: the values of an object or the items of an array.
fn each_child<'a>(path: &[PathElem], node: &'a Value, out: &mut Vec<(Vec<PathElem>, &'a Value)>) {
    match node {
        Value::Object(map) => {
            for (key, child) in map {
                out.push((extended(path, PathElem::Key(key.clone())), child));
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                out.push((extended(path, PathElem::Index(index)), child));
            }
        }
        _ => {}
    }
}

fn extended(path: &[PathElem], elem: PathElem) -> Vec<PathElem> {
    let mut full = Vec::with_capacity(path.len() + 1);
    full.extend_from_slice(path);
    full.push(elem);
    full
}

/// Takes the node one path names out of `document`. `false` when the path no
/// longer resolves — a node an earlier path already took.
fn remove_at(document: &mut Value, path: &[PathElem]) -> bool {
    let Some((last, parents)) = path.split_last() else {
        return false;
    };
    let mut node = document;
    for elem in parents {
        node = match (elem, node) {
            (PathElem::Key(key), Value::Object(map)) => match map.get_mut(key) {
                Some(child) => child,
                None => return false,
            },
            (PathElem::Index(index), Value::Array(items)) => match items.get_mut(*index) {
                Some(child) => child,
                None => return false,
            },
            _ => return false,
        };
    }
    match (last, node) {
        (PathElem::Key(key), Value::Object(map)) => map.remove(key).is_some(),
        (PathElem::Index(index), Value::Array(items)) => (*index < items.len())
            .then(|| items.remove(*index))
            .is_some(),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// The rule-level escapes and the parser
// ---------------------------------------------------------------------------

/// Undoes the two escapes the rule syntax puts into a `$jsonprune` value: a
/// `\$` is a `$` and a `\,` a `,` — the characters that would otherwise end
/// the value or split the option list. Any other `\x` is left alone; the
/// dialect has no other escape.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(next @ ('$' | ',')) => out.push(next),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => out.push('\\'),
            }
            continue;
        }
        out.push(ch);
    }
    out
}

struct Parser {
    chars: Vec<char>,
    at: usize,
}

type Parsed<T> = Result<T, ()>;

impl Parser {
    fn new(text: &str) -> Parser {
        Parser {
            chars: text.chars().collect(),
            at: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn next(&mut self) -> Option<char> {
        let ch = self.peek();
        if ch.is_some() {
            self.at += 1;
        }
        ch
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.at += 1;
        }
    }

    fn expect(&mut self, wanted: char) -> Parsed<()> {
        if self.next() == Some(wanted) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// `$` then the steps, up to the end of the expression.
    fn parse_expression(&mut self) -> Parsed<JsonPrune> {
        self.skip_whitespace();
        self.expect('$')?;
        let mut steps = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => break,
                Some('.') => {
                    self.next();
                    // `..` is the same step reached recursively; `...` is not
                    // an expression. Whitespace has no meaning, so the two
                    // dots may be written apart.
                    self.skip_whitespace();
                    let recursive = self.peek() == Some('.');
                    if recursive {
                        self.next();
                    }
                    self.skip_whitespace();
                    match self.peek() {
                        Some('[') => steps.push(Step {
                            kind: self.parse_bracket()?,
                            recursive,
                        }),
                        Some('*') => {
                            self.next();
                            steps.push(Step {
                                kind: StepKind::Wildcard,
                                recursive,
                            });
                        }
                        Some(c) if is_quote(c) => {
                            let key = self.parse_quoted()?;
                            steps.push(Step {
                                kind: StepKind::Key(key),
                                recursive,
                            });
                        }
                        Some(c) if is_name_char(c) => {
                            steps.push(Step {
                                kind: StepKind::Key(self.parse_name()),
                                recursive,
                            });
                        }
                        // `$.a..` and `$.a..[` land here: the dialect has no
                        // expression ending in `..`.
                        _ => return Err(()),
                    }
                }
                Some('[') => steps.push(Step {
                    kind: self.parse_bracket()?,
                    recursive: false,
                }),
                _ => return Err(()),
            }
        }
        Ok(JsonPrune { steps })
    }

    /// `[` … `]`: a union of selectors, or one `?(…)` predicate.
    fn parse_bracket(&mut self) -> Parsed<StepKind> {
        self.expect('[')?;
        self.skip_whitespace();
        if self.peek() == Some('?') {
            let filter = self.parse_filter()?;
            self.skip_whitespace();
            self.expect(']')?;
            return Ok(StepKind::Filter(filter));
        }
        let mut selectors = Vec::new();
        loop {
            self.skip_whitespace();
            selectors.push(self.parse_selector()?);
            self.skip_whitespace();
            match self.next() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err(()),
            }
        }
        if selectors.len() == 1 {
            return Ok(match selectors.pop().expect("one selector") {
                Selector::Key(key) => StepKind::Key(key),
                Selector::Index(index) => StepKind::Index(index),
                Selector::Wildcard => StepKind::Wildcard,
            });
        }
        Ok(StepKind::Union(selectors))
    }

    /// One item of a union: a key (bare or quoted), an array index or `*`.
    fn parse_selector(&mut self) -> Parsed<Selector> {
        match self.peek() {
            Some(c) if is_quote(c) => Ok(Selector::Key(self.parse_quoted()?)),
            Some('*') => {
                self.next();
                Ok(Selector::Wildcard)
            }
            // A slice (`[1:2]`) or a negative index reads as neither a name
            // nor an index, and neither is guessed at.
            Some('-') => Err(()),
            Some(c) if c.is_ascii_digit() => Ok(Selector::Index(self.parse_index()?)),
            Some(c) if is_name_char(c) => {
                let name = self.parse_name();
                // A bare name that reads like a number is an array index in
                // every JSONPath around; one that carries a `:` was a slice.
                if name.chars().all(|c| c.is_ascii_digit()) {
                    return name.parse::<usize>().map(Selector::Index).map_err(|_| ());
                }
                Ok(Selector::Key(name))
            }
            _ => Err(()),
        }
    }

    /// `?(…)`: the three predicates the dialect documents, no more.
    fn parse_filter(&mut self) -> Parsed<Filter> {
        self.expect('?')?;
        self.expect('(')?;
        self.skip_whitespace();
        let name = self.parse_name();
        self.skip_whitespace();
        let filter = match name.as_str() {
            "has" => Filter::Has(self.parse_key_nav()?),
            "key-eq" => {
                let nav = self.parse_key_nav()?;
                self.skip_whitespace();
                let literal = self.parse_literal()?;
                Filter::KeyEq(nav, literal)
            }
            "key-substr" => {
                let nav = self.parse_key_nav()?;
                self.skip_whitespace();
                let needle = match self.peek() {
                    Some(c) if is_quote(c) => self.parse_quoted()?,
                    _ => self.parse_name(),
                };
                Filter::KeySubstr(nav, needle)
            }
            _ => return Err(()),
        };
        self.skip_whitespace();
        self.expect(')')?;
        Ok(filter)
    }

    /// A predicate key: a quoted or bare string; one starting with `$` is a
    /// nested expression rooted at the child under test.
    fn parse_key_nav(&mut self) -> Parsed<KeyNav> {
        let key = match self.peek() {
            Some(c) if is_quote(c) => self.parse_quoted()?,
            _ => self.parse_name(),
        };
        if !key.starts_with('$') {
            return Ok(KeyNav::Key(key));
        }
        let mut nested = Parser::new(&key);
        Ok(KeyNav::Path(Box::new(nested.parse_expression()?)))
    }

    /// A predicate value: a quoted string; bare, a JSON literal (`true`,
    /// `false`, `null`, a number) or a string.
    fn parse_literal(&mut self) -> Parsed<Literal> {
        if let Some(c) = self.peek() {
            if is_quote(c) {
                return Ok(Literal::Str(self.parse_quoted()?));
            }
        }
        let word = self.parse_name();
        match word.as_str() {
            "true" => Ok(Literal::Bool(true)),
            "false" => Ok(Literal::Bool(false)),
            "null" => Ok(Literal::Null),
            _ => match word.parse::<f64>() {
                Ok(number) => Ok(Literal::Number(number)),
                Err(_) => Ok(Literal::Str(word)),
            },
        }
    }

    /// A bare name: everything up to a character the syntax gives meaning to.
    fn parse_name(&mut self) -> String {
        let mut name = String::new();
        while let Some(ch) = self.peek() {
            if !is_name_char(ch) {
                break;
            }
            name.push(ch);
            self.at += 1;
        }
        name
    }

    /// A `'…'` or `"…"` string; a `\` inside escapes the next character.
    fn parse_quoted(&mut self) -> Parsed<String> {
        let quote = self.next().ok_or(())?;
        if !is_quote(quote) {
            return Err(());
        }
        let mut text = String::new();
        loop {
            match self.next().ok_or(())? {
                '\\' => text.push(self.next().ok_or(())?),
                ch if ch == quote => return Ok(text),
                ch => text.push(ch),
            }
        }
    }

    fn parse_index(&mut self) -> Parsed<usize> {
        let digits = self.parse_name();
        digits.parse().map_err(|_| ())
    }
}

/// Whether a character can be part of a bare name. The syntax's own
/// characters — the dots and brackets of the path, the filter punctuation,
/// the quote characters and the comma — end one.
fn is_name_char(ch: char) -> bool {
    !matches!(ch, '.' | '[' | ']' | '(' | ')' | '"' | '\'' | ',' | ':') && !ch.is_whitespace()
}

fn is_quote(ch: char) -> bool {
    ch == '"' || ch == '\''
}

// ---------------------------------------------------------------------------
// Reading a body, and the JSONP shell
// ---------------------------------------------------------------------------

/// A parsed body and, for JSONP, the bytes the wrapper keeps around the JSON.
type Wrapper = Option<(Vec<u8>, Vec<u8>)>;

/// Applies the rules, in the order given, to one response body. `None` when
/// no rule changed anything: a body that is not JSON, and a JSON document no
/// expression selects anything in, go over untouched.
///
/// A rule that matches the request but not the body is not stopped by the
/// next one: every rule of the plan reads what the rules before it left.
pub fn prune_body(rules: &[JsonpruneRule], body: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    let mut current: Option<Vec<u8>> = None;
    let mut applied: Vec<String> = Vec::new();
    for rule in rules {
        let input = current.as_deref().unwrap_or(body);
        let Some(next) = apply_one(&rule.expression, input) else {
            continue;
        };
        current = Some(next);
        applied.push(rule.text.clone());
    }
    current.map(|body| (body, applied))
}

/// One rule on one body: re-serialized with its matches taken out, or `None`.
fn apply_one(expression: &JsonPrune, body: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let (mut document, wrapper) = parse_body(text)?;
    if !expression.prune(&mut document) {
        return None;
    }
    let json = serde_json::to_vec(&document).ok()?;
    Some(match wrapper {
        None => json,
        Some((prefix, suffix)) => {
            let mut out = prefix;
            out.extend_from_slice(&json);
            out.extend_from_slice(&suffix);
            out
        }
    })
}

/// The document of a body: JSON as it stands, or the JSON inside one JSONP
/// call shell.
fn parse_body(text: &str) -> Option<(Value, Wrapper)> {
    if let Ok(document) = serde_json::from_str(text) {
        return Some((document, None));
    }
    let (prefix, inner, suffix) = split_jsonp(text)?;
    let document = serde_json::from_str(inner).ok()?;
    Some((document, Some((prefix, suffix))))
}

/// Splits `caller(…);` into the bytes before the JSON, the JSON text and the
/// bytes after it. The caller is one identifier-shaped name — letters,
/// digits, `_`, `$` and dots for `window.cb` — and after the closing `)` at
/// most whitespace and one `;` may follow. Anything else is not the shell the
/// reference documents, and no guess is made.
fn split_jsonp(text: &str) -> Option<(Vec<u8>, &str, Vec<u8>)> {
    let open = text.find('(')?;
    if !is_jsonp_caller(text[..open].trim()) {
        return None;
    }
    let trimmed = text.trim_end();
    let body = match trimmed.strip_suffix(';') {
        Some(body) => body.trim_end(),
        None => trimmed,
    };
    let close = body.rfind(')')?;
    if close <= open {
        return None;
    }
    let inner = &text[open + 1..close];
    let document = inner.trim();
    if document.is_empty() {
        return None;
    }
    // Every byte that is not the document itself stays where it was.
    let start = open + 1 + (inner.len() - inner.trim_start().len());
    let prefix = text.as_bytes()[..start].to_vec();
    let suffix = text.as_bytes()[start + document.len()..].to_vec();
    Some((prefix, document, suffix))
}

fn is_jsonp_caller(caller: &str) -> bool {
    let mut chars = caller.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(expression: &str) -> JsonPrune {
        JsonPrune::parse(expression).unwrap_or_else(|| panic!("`{expression}` must parse"))
    }

    /// The document `expression` prunes `input` down to.
    fn pruned(expression: &str, input: Value) -> Value {
        let mut document = input;
        let prune = parse(expression);
        prune.prune(&mut document);
        document
    }

    #[test]
    fn a_union_under_recursive_descent_takes_keys_at_any_depth() {
        // The knowledge base's first example.
        let out = pruned(
            r#"$..[one\, "two three"]"#,
            json!({
                "one": 1,
                "two": {
                    "two three": 23,
                    "four five": 45
                }
            }),
        );
        assert_eq!(out, json!({"two": {"four five": 45}}));
    }

    #[test]
    fn a_has_filter_takes_the_children_that_carry_the_key() {
        let out = pruned(
            "$.a[?(has ad_origin)]",
            json!({
                "a": [
                    {"ad_origin": "https://example.org", "b": 42},
                    {"b": 1234}
                ]
            }),
        );
        assert_eq!(out, json!({"a": [{"b": 1234}]}));
    }

    #[test]
    fn a_key_eq_filter_walks_levels_and_arrays() {
        let out = pruned(
            "$.*.*[?(key-eq 'Some key' 'Some value')]",
            json!({
                "a": {"b": {"c": {"Some key": "Some value"}, "d": {"Some key": "Other value"}}},
                "e": {"f": [{"Some key": "Some value"}, {"Some key": "Other value"}]}
            }),
        );
        assert_eq!(
            out,
            json!({
                "a": {"b": {"d": {"Some key": "Other value"}}},
                "e": {"f": [{"Some key": "Other value"}]}
            })
        );
    }

    #[test]
    fn a_nested_path_key_selects_children_that_carry_it() {
        let out = pruned(
            r#"$.elems[?(has "$.a.b.c")]"#,
            json!({
                "elems": [
                    {"a": {"b": {"c": 123}}, "k": "v"},
                    {"d": {"e": {"f": 123}}, "k1": "v1"}
                ]
            }),
        );
        assert_eq!(
            out,
            json!({"elems": [{"d": {"e": {"f": 123}}, "k1": "v1"}]})
        );
    }

    #[test]
    fn a_nested_path_key_eq_compares_what_the_path_selects() {
        let out = pruned(
            r#"$.elems[?(key-eq "$.a.b.c" "abc")]"#,
            json!({
                "elems": [
                    {"a": {"b": {"c": 123}}},
                    {"a": {"b": {"c": "abc"}}}
                ]
            }),
        );
        assert_eq!(out, json!({"elems": [{"a": {"b": {"c": 123}}}]}));
    }

    #[test]
    fn a_recursive_filter_reads_the_children_of_every_node_below() {
        // The pixai shape: each feed entry nests the ad object, and
        // `..[?(…)]` has to reach it wherever it is. A predicate reads the
        // children of the node it is applied to — never the node itself — so
        // `second` stays even though it carries `isAd` (the KB's level-3
        // example reads the same way).
        let out = pruned(
            r#"$.feed.*..[?(key-eq "$.isAd" true)]"#,
            json!({
                "feed": {
                    "first": {"node": {"isAd": false, "id": 1}, "id": 10},
                    "second": {"ad": {"isAd": true, "id": 2}, "isAd": true, "id": 20},
                    "nested": {"wrap": {"ad": {"isAd": true, "id": 3}}, "id": 30}
                }
            }),
        );
        assert_eq!(
            out,
            json!({
                "feed": {
                    "first": {"node": {"isAd": false, "id": 1}, "id": 10},
                    "second": {"isAd": true, "id": 20},
                    "nested": {"wrap": {}, "id": 30}
                }
            })
        );
    }

    #[test]
    fn a_key_substr_filter_reads_substrings_of_string_values() {
        let out = pruned(
            "$.instructions..entries..[?(key-substr 'entryId' 'promoted-tweet-')]",
            json!({
                "instructions": [{
                    "entries": [
                        {"entryId": "promoted-tweet-123", "x": 1},
                        {"entryId": "tweet-456", "x": 2},
                        {"no": "entryId"}
                    ],
                    "rest": {"entries": [{"entryId": "promoted-tweet-9"}]}
                }]
            }),
        );
        assert_eq!(
            out,
            json!({
                "instructions": [{
                    "entries": [{"entryId": "tweet-456", "x": 2}, {"no": "entryId"}],
                    "rest": {"entries": []}
                }]
            })
        );
    }

    #[test]
    fn a_quoted_key_that_starts_with_a_dollar_is_read_as_a_path() {
        // The MSN shape: the child itself is a string the needle is looked
        // for in (`'$'` roots a path at that very child).
        let out = pruned(
            r"$.configRef[?(key-substr '$' 'NativeAd')]",
            json!({
                "configRef": {
                    "one": "NativeAd-placeholder",
                    "two": "something else"
                }
            }),
        );
        assert_eq!(out, json!({"configRef": {"two": "something else"}}));
    }

    #[test]
    fn a_bare_asterisk_takes_every_child() {
        let out = pruned(
            "$.adBreak.*",
            json!({"adBreak": {"a": 1, "b": 2}, "keep": 3}),
        );
        assert_eq!(out, json!({"adBreak": {}, "keep": 3}));
    }

    #[test]
    fn a_union_of_indexes_takes_array_items() {
        let out = pruned("$.a[0, 2]", json!({"a": [1, 2, 3, 4]}));
        assert_eq!(out, json!({"a": [2, 4]}));
    }

    #[test]
    fn a_wildcard_under_descent_reaches_every_level() {
        let out = pruned(
            "$.a..b",
            json!({"a": {"b": 1, "c": {"b": 2}, "d": [{"b": 3}]}}),
        );
        assert_eq!(out, json!({"a": {"c": {}, "d": [{}]}}));
    }

    #[test]
    fn quoted_keys_carry_dots_and_slashes() {
        let out = pruned(
            r#"$.configs["ConsumptionPage/gallery_default"].properties.ad"#,
            json!({"configs": {"ConsumptionPage/gallery_default": {"properties": {"ad": 1, "keep": 2}}}}),
        );
        assert_eq!(
            out,
            json!({"configs": {"ConsumptionPage/gallery_default": {"properties": {"keep": 2}}}})
        );
        let out = pruned(
            "$.configs['SliceShow/ntpmsn'].properties.ad",
            json!({"configs": {"SliceShow/ntpmsn": {"properties": {"ad": 1}}}}),
        );
        assert_eq!(
            out,
            json!({"configs": {"SliceShow/ntpmsn": {"properties": {}}}})
        );
    }

    #[test]
    fn whitespace_outside_quotes_means_nothing() {
        // Spaces around the dots and inside the brackets change nothing.
        let out = pruned("$ . a . . b", json!({"a": {"b": 1, "c": 2}}));
        assert_eq!(out, json!({"a": {"c": 2}}));
        let out = pruned(
            "$  ..  [ one ,  'two three' ]",
            json!({"one": 1, "two": {"two three": 23, "four five": 45}}),
        );
        assert_eq!(out, json!({"two": {"four five": 45}}));
    }

    #[test]
    fn a_dotted_bracket_step_reads_the_same_as_a_plain_one() {
        let out = pruned(
            "$.entries.[?(has ad)]",
            json!({"entries": [{"ad": 1}, {"b": 2}]}),
        );
        assert_eq!(out, json!({"entries": [{"b": 2}]}));
    }

    #[test]
    fn the_root_is_not_taken_off_the_document() {
        let out = pruned("$", json!({"a": 1}));
        assert_eq!(out, json!({"a": 1}));
    }

    #[test]
    fn nothing_that_could_not_be_run_is_guessed_at() {
        for expression in [
            // The reference has no expressions ending in `..` …
            "$.a..",
            // … no script expressions, and no filters besides the three …
            "$[?(@.a == 1)]",
            "$.a[?(exists b)]",
            // … no slices and no negative indexes …
            "$.a[1:2]",
            "$.a[-1]",
            // … and no other syntax either.
            "$.",
            "$.a[",
            "$.a[?(has b]",
            "",
            "a.b",
            "$.a]",
            "$.'unclosed",
        ] {
            assert!(
                JsonPrune::parse(expression).is_none(),
                "`{expression}` must not parse"
            );
        }
    }

    #[test]
    fn escaped_dollars_and_commas_read_as_plain_ones() {
        assert!(JsonPrune::parse(r"\$..[a\, b]").is_some());
        assert!(JsonPrune::parse(r"\$.a[?(key-eq '\$' true)]").is_some());
        // A backslash before anything else stays where it is: a name may
        // carry it.
        assert!(JsonPrune::parse(r"$.a\b").is_some());
    }

    #[test]
    fn a_body_that_is_not_json_goes_untouched() {
        let rules = [JsonpruneRule {
            text: "test".to_string(),
            expression: parse("$.ad"),
        }];
        assert!(prune_body(&rules, b"<!doctype html><html></html>").is_none());
        assert!(prune_body(&rules, b"{\"keep\": 1}").is_none());
    }

    #[test]
    fn a_jsonp_body_is_rewritten_inside_its_shell() {
        let rules = [JsonpruneRule {
            text: "test".to_string(),
            expression: parse("$.ad"),
        }];
        let (out, applied) =
            prune_body(&rules, b"\tcb({\n  \"ad\": 1,\n  \"keep\": 2\n});\n").expect("changed");
        assert_eq!(applied, ["test"]);
        assert_eq!(out, b"\tcb({\"keep\":2});\n");
        // A shell that is not one: nothing is guessed at.
        assert!(prune_body(&rules, b"jQuery(function(){ return 1; });").is_none());
        assert!(prune_body(&rules, b"(function(){ return 1; })()").is_none());
    }

    #[test]
    fn every_rule_of_a_plan_reads_what_the_rules_before_it_left() {
        let rules = [
            JsonpruneRule {
                text: "first".to_string(),
                expression: parse("$.a"),
            },
            JsonpruneRule {
                text: "second".to_string(),
                expression: parse("$.b"),
            },
        ];
        let (out, applied) =
            prune_body(&rules, br#"{"a": 1, "b": 2, "keep": 3}"#).expect("changed");
        assert_eq!(applied, ["first", "second"]);
        assert_eq!(out, br#"{"keep":3}"#);
        // A rule that matches nothing does not stop the next one.
        let rules = [
            JsonpruneRule {
                text: "first".to_string(),
                expression: parse("$.missing"),
            },
            JsonpruneRule {
                text: "second".to_string(),
                expression: parse("$.b"),
            },
        ];
        let (out, applied) = prune_body(&rules, br#"{"a": 1, "b": 2}"#).expect("changed");
        assert_eq!(applied, ["second"]);
        assert_eq!(out, br#"{"a":1}"#);
    }

    #[test]
    fn every_expression_the_live_lists_carry_reads() {
        // The `$jsonprune` values of the shipped AdGuard lists, escapes
        // undone: the dialect's whole working set as the lists spell it.
        for expression in [
            "$.adBreak.*",
            "$.adBreakLocations.*",
            "$.adBreaks.*",
            "$..[adPlacements, adSlots, playerAds]",
            "$.advertisements[?(has advertisementId)]",
            "$.configs[\"ConsumptionPage/gallery_default\"].properties.componentConfigs.slideshowConfigs..interstitialNativeAds",
            "$.configs['GalleryPage/ntpmsn'].properties.fullScreenSlideshowSettings.interstitialNativeAds",
            "$.configs['GalleryPage/ntpmsn'].properties.slideshowWCSettings.interstitialNativeAds",
            "$.configs['SlideShow/ntpmsn'].properties.additionalChildExperiences..children..childExperienceConfigInfo.configRef[?(key-substr '$' 'NativeAd')]",
            "$.cuepointPlaylist",
            "$.data.home.home_timeline_urt.instructions..entries..[?(key-substr 'entryId' 'promoted-tweet-')]",
            "$.data.immersiveMedia.timeline.instructions..entries..[?(key-substr 'entryId' 'promoted-tweet-')]",
            "$.data.publicDynamicConfig.campaign.feed.*..[?(key-eq \"$.isAd\" true)]",
            "$.data.threaded_conversation_with_injections_v2.instructions..entries.[?(has \"$.content.items..item.itemContent.promotedMetadata.advertiser_results\")]",
            "$.entries[?(has \"$..command.reelWatchEndpoint.adClientParams.isAd\")]",
            "$.properties.componentConfigs.slideshowConfigs..interstitialNativeAds",
            "$.properties.componentConfigs.slideshowConfigs.interstitialNativeAds",
            "$.results..[?(has adTitle)]",
            "$..results..[?(has adTitle)]",
            "$.sections..cards..[?(key-substr 'type' 'PartnerUpsell')]",
            "$.sections..subSections..cards..[?(key-substr 'type' 'nativead')]",
            "$.vodPlaybackUrls.result.playbackUrls.cuepoints",
        ] {
            assert!(
                JsonPrune::parse(expression).is_some(),
                "`{expression}` must read"
            );
        }
    }

    #[test]
    fn sibling_indexes_are_taken_from_the_end() {
        // Both items of the same array selected at different depths: the
        // deeper path has to be applied first, and the earlier index before
        // the later one.
        let out = pruned("$[*].b", json!([{"b": 1}, {"keep": 2}, {"b": 3}]));
        assert_eq!(out, json!([{}, {"keep": 2}, {}]));
        let out = pruned(
            "$..[?(has b)]",
            json!({"a": [{"b": 1}, {"keep": 2}, {"b": 3}], "b": 9}),
        );
        assert_eq!(out, json!({"a": [{"keep": 2}], "b": 9}));
    }
}
