//! Build the wait set's kernel side.

fn main() {
    println!("cargo:rerun-if-changed=vendor/wepoll/wepoll.c");
    println!("cargo:rerun-if-changed=vendor/wepoll/wepoll.h");

    // Windows: `epoll` does not exist, so the tree carries wepoll — a
    // BSD-licensed implementation over IOCP and `\Device\Afd` — and the wait set
    // calls the same four functions it calls on Unix. Compiling C for the
    // Windows target is not new here: the TLS stack already does it.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        cc::Build::new()
            .file("vendor/wepoll/wepoll.c")
            .include("vendor/wepoll")
            // The header's export decoration is for DLL consumers; we link the
            // object directly into the cdylib.
            .define("WEPOLL_EXPORT", "")
            .warnings(false)
            .compile("wepoll");
    }
}
