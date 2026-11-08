//! Teaches Node the CA through the user's own shell configuration.
//!
//! Every store this crate already writes — the distro bundle, the NSS
//! databases, the JDK keystore — is invisible to Node. Node ships its own
//! bundled root list and reads neither the system bundle nor NSS, so a Node CLI
//! (`pi`, `npm`, anything built on it) rejects the CA on every connection to a
//! host it has not seen before. That is the failure a person meets as "the
//! filter breaks the network until I restart the app": the first request to a
//! new host fails the handshake, and only a fresh process — one whose first
//! connection the proxy has already learned — gets through.
//!
//! The one knob Node honours for this is `NODE_EXTRA_CA_CERTS`. A packaged
//! application cannot set a user's environment, but it can write the file that
//! user's shell already reads on every start. This module does exactly that,
//! for the shells actually present on the machine and for the login shell named
//! by `$SHELL`, between markers so a re-run replaces the block instead of
//! appending a second copy and an uninstall can take it cleanly back out.
//!
//! It runs in the app's own process, never as root: these are the signed-in
//! user's rc files, and a root-owned `.bashrc` is one the user's editor can no
//! longer save.

use std::path::{Path, PathBuf};

/// The marker lines around the managed block. Kept in one place so the writers
/// and the remover below cannot disagree about what a block is.
pub const START: &str = "# >>> adfree node ca >>>";
pub const END: &str = "# <<< adfree node ca <<<";

/// rc files written when they already exist, in the order they are checked.
const EXISTING: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".zshrc",
    ".config/fish/config.fish",
    ".profile",
];

/// One rc file and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    pub path: String,
    pub ok: bool,
    pub detail: String,
}

impl Edit {
    fn ok(path: &Path) -> Self {
        Self { path: path.display().to_string(), ok: true, detail: String::new() }
    }

    fn failed(path: &Path, detail: impl Into<String>) -> Self {
        Self { path: path.display().to_string(), ok: false, detail: detail.into() }
    }
}

/// Writes the managed block for `pem_path` into the shell rc files of the
/// signed-in user.
pub fn install(pem_path: &str) -> Vec<Edit> {
    let home = match std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        Some(h) => PathBuf::from(h),
        None => return Vec::new(),
    };
    let shell = std::env::var("SHELL").unwrap_or_default();
    install_with(pem_path, &home, &shell)
}

/// Removes the managed block from every rc file that has one.
pub fn remove() -> Vec<Edit> {
    let home = match std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        Some(h) => PathBuf::from(h),
        None => return Vec::new(),
    };
    let shell = std::env::var("SHELL").unwrap_or_default();
    remove_with(&home, &shell)
}

/// [`install`] with the home directory and login shell passed in, so tests need
/// no environment and no real user.
pub fn install_with(pem_path: &str, home: &Path, shell: &str) -> Vec<Edit> {
    if !Path::new(pem_path).is_file() {
        return vec![Edit::failed(Path::new(pem_path), format!("no certificate at {pem_path}"))];
    }
    targets(home, shell)
        .into_iter()
        .map(|file| write(&file, &line_for(&file, pem_path)))
        .collect()
}

/// [`remove`] with the home directory and login shell passed in.
pub fn remove_with(home: &Path, shell: &str) -> Vec<Edit> {
    targets(home, shell).into_iter().map(|file| strip(&file)).collect()
}

/// The rc files to write: those that already exist, plus the one belonging to
/// the login shell when that shell is known and its file is not among them yet.
pub fn targets(home: &Path, shell: &str) -> Vec<PathBuf> {
    let mut chosen: Vec<PathBuf> = Vec::new();
    for rel in EXISTING {
        let file = home.join(rel);
        if file.is_file() {
            chosen.push(file);
        }
    }
    if let Some(rel) = canonical_for(shell) {
        let file = home.join(rel);
        if !chosen.iter().any(|c| c == &file) {
            chosen.push(file);
        }
    }
    chosen
}

/// Maps `$SHELL` (a path or a bare name) to the rc file that shell reads.
fn canonical_for(shell: &str) -> Option<&'static str> {
    match shell.rsplit('/').next().unwrap_or("") {
        "fish" => Some(".config/fish/config.fish"),
        "zsh" => Some(".zshrc"),
        "bash" => Some(".bashrc"),
        "sh" | "dash" | "ksh" => Some(".profile"),
        _ => None,
    }
}

fn write(file: &Path, line: &str) -> Edit {
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    let body = without_block(&existing).trim_end().to_string();
    let mut out = String::new();
    if !body.is_empty() {
        out.push_str(&body);
        out.push_str("\n\n");
    }
    out.push_str(START);
    out.push('\n');
    out.push_str("# Added by AdFree. Node ignores the system CA stores; this makes it\n");
    out.push_str("# (and every Node CLI, such as `pi` or npm) trust the AdFree CA.\n");
    out.push_str(line);
    out.push('\n');
    out.push_str(END);
    out.push('\n');
    match file.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|_| std::fs::write(file, out)) {
        Ok(()) => Edit::ok(file),
        Err(e) => Edit::failed(file, e.to_string()),
    }
}

fn strip(file: &Path) -> Edit {
    if !file.is_file() {
        return Edit::ok(file);
    }
    let existing = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(e) => return Edit::failed(file, e.to_string()),
    };
    if !existing.contains(START) {
        return Edit::ok(file);
    }
    let body = without_block(&existing);
    let body = body.trim_end().to_string();
    let mut out = body;
    out.push('\n');
    match std::fs::write(file, out) {
        Ok(()) => Edit::ok(file),
        Err(e) => Edit::failed(file, e.to_string()),
    }
}

/// Drops the managed block, markers included, from `text`.
fn without_block(text: &str) -> String {
    let Some(start) = text.find(START) else {
        return text.to_string();
    };
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let Some(end_rel) = text[start..].find(END) else {
        return text.to_string();
    };
    let mut tail = start + end_rel + END.len();
    while tail < text.len() && text.as_bytes()[tail] == b'\n' {
        tail += 1;
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..line_start]);
    out.push_str(&text[tail..]);
    out
}

/// fish spells an exported variable differently from a POSIX shell.
fn line_for(file: &Path, pem_path: &str) -> String {
    if file.to_string_lossy().ends_with("config.fish") {
        format!("set -gx NODE_EXTRA_CA_CERTS \"{pem_path}\"")
    } else {
        format!("export NODE_EXTRA_CA_CERTS=\"{pem_path}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("adfree-shell-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pem_in(home: &Path) -> String {
        let pem = home.join("adfree-ca.pem");
        std::fs::write(&pem, "-----BEGIN CERTIFICATE-----\n").unwrap();
        pem.display().to_string()
    }

    #[test]
    fn writes_the_right_syntax_for_each_shell_in_use() {
        let home = temp_home("syntax");
        std::fs::write(home.join(".bashrc"), "alias ll='ls -l'\n").unwrap();
        std::fs::create_dir_all(home.join(".config/fish")).unwrap();
        std::fs::write(home.join(".config/fish/config.fish"), "set -gx EDITOR vim\n").unwrap();
        let pem = pem_in(&home);

        let edits = install_with(&pem, &home, "/usr/bin/fish");
        assert!(edits.iter().all(|e| e.ok), "{edits:?}");

        let bash = std::fs::read_to_string(home.join(".bashrc")).unwrap();
        assert!(bash.contains("alias ll"), "kept the user's lines: {bash}");
        assert!(bash.contains(&format!("export NODE_EXTRA_CA_CERTS=\"{pem}\"")), "bash gets an export: {bash}");

        let fish = std::fs::read_to_string(home.join(".config/fish/config.fish")).unwrap();
        assert!(fish.contains("EDITOR vim"), "kept the user's lines: {fish}");
        assert!(fish.contains(&format!("set -gx NODE_EXTRA_CA_CERTS \"{pem}\"")), "fish gets set -gx: {fish}");
    }

    #[test]
    fn a_second_install_replaces_the_block_instead_of_appending_one() {
        let home = temp_home("idempotent");
        std::fs::write(home.join(".bashrc"), "export PATH=$PATH\n").unwrap();
        let pem = pem_in(&home);
        install_with(&pem, &home, "/bin/bash");
        install_with(&pem, &home, "/bin/bash");

        let text = std::fs::read_to_string(home.join(".bashrc")).unwrap();
        assert_eq!(text.matches(START).count(), 1, "exactly one block: {text}");
        assert!(text.contains("export PATH"), "the user's lines survive: {text}");
    }

    #[test]
    fn removing_takes_the_block_out_and_leaves_the_rest() {
        let home = temp_home("remove");
        std::fs::write(home.join(".zshrc"), "export EDITOR=nvim\n").unwrap();
        let pem = pem_in(&home);
        install_with(&pem, &home, "/bin/zsh");

        let edits = remove_with(&home, "/bin/zsh");
        assert!(edits.iter().all(|e| e.ok), "{edits:?}");

        let text = std::fs::read_to_string(home.join(".zshrc")).unwrap();
        assert!(!text.contains("NODE_EXTRA_CA_CERTS"), "no stale trust line: {text}");
        assert!(text.contains("EDITOR=nvim"), "the user's lines survive: {text}");
    }

    #[test]
    fn creates_the_login_shells_file_but_not_one_the_user_does_not_run() {
        let home = temp_home("create");
        let pem = pem_in(&home);
        install_with(&pem, &home, "/usr/bin/fish");

        assert!(home.join(".config/fish/config.fish").is_file(), "fish is created for the login shell");
        assert!(!home.join(".bashrc").exists(), "a bash file is not invented");
    }
}
