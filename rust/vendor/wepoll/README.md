# wepoll

`epoll` for Windows, built on IOCP and `\Device\Afd` (the kernel's socket
polling interface), so the wait set keeps one implementation and one set of
semantics on both platforms.

Vendored, not fetched at build time: it is a build input, and a build that needs
the network to compile is a build that fails on a bad day.

* Upstream: <https://github.com/piscisaureus/wepoll>
* Version: 1.5.8
* Licence: BSD-2-Clause (see `LICENSE`)

Compiled by `rust/build.rs` for Windows targets only; nothing else in the tree
includes `wepoll.h`.
