//! Rebuilds `assets/services.tsv` from tracker datasets.
//!
//! The file this writes is the table the shipped build carries, so the sources
//! are named here rather than in a script that could drift from the format:
//!
//! ```sh
//! cd rust
//! cargo run --example services_dataset -- \
//!     assets/services.tsv \
//!     /tmp/trackers.json \
//!     /tmp/trackerdb.json
//! ```
//!
//! Each argument is one body: a table already in this format, or a JSON dataset
//! in one of the shapes `services::import` knows. Order is precedence — the
//! first source that names a domain's company owns that label — so the shipped
//! table goes first when its hand-written names should survive. The result is
//! written over the last argument unless `--out` names a path.

use std::path::PathBuf;

fn main() {
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut out = PathBuf::from("assets/services.tsv");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--out" {
            out = args.next().expect("--out needs a path").into();
        } else {
            inputs.push(arg.into());
        }
    }
    if inputs.is_empty() {
        eprintln!("usage: services_dataset [--out <path>] <body> [<body>…]");
        std::process::exit(2);
    }
    let bodies: Vec<String> = inputs
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()))
        })
        .collect();
    let texts: Vec<&str> = bodies.iter().map(String::as_str).collect();
    let text = adfree_core::services::import::merge(&texts)
        .expect("the inputs are not tracker datasets");
    std::fs::write(&out, &text)
        .unwrap_or_else(|e| panic!("{} could not be written: {e}", out.display()));
    println!(
        "{}: {} rows from {} bodies",
        out.display(),
        adfree_core::services::row_count(&text),
        bodies.len()
    );
}
