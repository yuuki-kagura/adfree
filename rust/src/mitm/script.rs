//! User-supplied scripts.
//!
//! The user writes JS and we keep the list; when serving `/adfree-user.js` (or
//! inlining), the scripts are stitched into one file. Keeping it separate means
//! one `<script src>` per response instead of full bodies inside the HTML.

/// Caps so a client never downloads too much.
pub const MAX_SCRIPTS: usize = 32;
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;

/// One user script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserScript {
    pub name: String,
    pub body: String,
    pub enabled: bool,
}

/// Script list plus serving state.
#[derive(Clone, Debug, Default)]
pub struct ScriptSet {
    scripts: Vec<UserScript>,
    /// Master switch for script injection.
    pub enabled: bool,
    /// URL mà ta dùng trong `<script src>`.
    pub serve_path: String,
}

impl ScriptSet {
    pub fn new() -> Self {
        ScriptSet {
            scripts: Vec::new(),
            enabled: false,
            serve_path: "/adfree-user.js".to_string(),
        }
    }

    /// Replace the whole list, dropping over-long or empty entries.
    pub fn replace_all(&mut self, scripts: Vec<UserScript>) -> usize {
        self.scripts = scripts
            .into_iter()
            .filter(|s| !s.name.is_empty() && !s.body.is_empty())
            .filter(|s| s.body.len() <= MAX_SCRIPT_BYTES)
            .take(MAX_SCRIPTS)
            .collect();
        self.scripts.len()
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.scripts.is_empty()
    }

    pub fn scripts(&self) -> &[UserScript] {
        &self.scripts
    }

    /// Combined JS body (enabled scripts only).
    pub fn combined_js(&self) -> String {
        if !self.is_enabled() {
            return String::new();
        }
        let mut out = String::with_capacity(256);
        out.push_str("/* AdFree user scripts */\n");
        out.push_str("(function(){'use strict';\n");
        for script in self.scripts.iter().filter(|s| s.enabled) {
            out.push_str("/* "); // isolate errors per script
            out.push_str(&script.name.replace("*/", "* /"));
            out.push_str(" */\ntry{\n");
            out.push_str(&script.body);
            out.push_str("\n}catch(e){console.warn('AdFree script failed:',e);}\n");
        }
        out.push_str("})();\n");
        out
    }

    /// The path we answer when a client requests it.
    pub fn serve_path(&self) -> &str {
        &self.serve_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(name: &str, body: &str) -> UserScript {
        UserScript {
            name: name.to_string(),
            body: body.to_string(),
            enabled: true,
        }
    }

    #[test]
    fn disabled_set_serves_nothing() {
        let mut set = ScriptSet::new();
        set.replace_all(vec![script("a", "console.log(1)")]);
        assert!(set.combined_js().is_empty());
        set.set_enabled(true);
        assert!(set.is_enabled());
        assert!(set.combined_js().contains("console.log(1)"));
    }

    #[test]
    fn replaces_the_whole_list() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script("one", "let a = 1;"), script("two", "let b = 2;")]);
        assert_eq!(set.scripts().len(), 2);
        set.replace_all(vec![script("only", "let c = 3;")]);
        assert_eq!(set.scripts().len(), 1);
        let js = set.combined_js();
        assert!(js.contains("let c = 3;"));
        assert!(!js.contains("let a = 1;"));
    }

    #[test]
    fn filters_empty_and_huge_scripts() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        let huge = "x".repeat(MAX_SCRIPT_BYTES + 1);
        set.replace_all(vec![
            UserScript { name: String::new(), body: "a".into(), enabled: true },
            UserScript { name: "empty".into(), body: String::new(), enabled: true },
            UserScript { name: "big".into(), body: huge, enabled: true },
            script("ok", "let ok = true;"),
        ]);
        assert_eq!(set.scripts().len(), 1);
        assert_eq!(set.scripts()[0].name, "ok");
    }

    #[test]
    fn caps_the_number_of_scripts() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        let many: Vec<UserScript> = (0..40)
            .map(|i| script(&format!("s{i}"), "console.log(1)"))
            .collect();
        set.replace_all(many);
        assert_eq!(set.scripts().len(), MAX_SCRIPTS);
    }

    #[test]
    fn only_enabled_scripts_are_combined() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![
            script("on", "let on = 1;"),
            UserScript {
                name: "off".into(),
                body: "let off = 1;".into(),
                enabled: false,
            },
        ]);
        let js = set.combined_js();
        assert!(js.contains("let on = 1;"));
        assert!(!js.contains("let off = 1;"));
    }

    #[test]
    fn combined_js_wraps_each_script_in_try_catch() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script("broken", "this is not javascript ((")]);
        let js = set.combined_js();
        assert!(js.contains("try{"), "every script must be isolated");
        assert!(js.contains("}catch(e)"));
        assert!(js.contains("'use strict'"));
    }

    #[test]
    fn serve_path_defaults_to_a_stable_url() {
        let set = ScriptSet::new();
        assert_eq!(set.serve_path(), "/adfree-user.js");
    }
}
