//! Names the process behind a desktop connection.
//!
//! The redirect hands the proxy a socket, and a socket carries addresses, not
//! owners. `SO_PEERCRED` is the obvious answer and it is the wrong one: Linux
//! leaves the struct zeroed on an `AF_INET` socket, so the call that looks
//! successful reports uid 0 and pid 0. The process has to be found the way
//! `ss -p` finds it — the kernel's own socket table names the inode the
//! connection belongs to, and the process holding that inode is the process
//! that opened it.
//!
//! Both ends are loopback by construction (the desktop listeners serve this
//! machine only), so the port pair alone picks the right row out of the table.
//!
//! The search costs what it costs: reading every process's file descriptors
//! takes tens of milliseconds on a desktop with a few hundred processes, and
//! that is time a connection waits. Three things keep it off the request path
//! as far as the kernel lets us: the last answer's processes are looked in
//! first (the next socket usually belongs to one of them), the whole table is
//! walked at most once per short window (a burst of connections from a page
//! load is one walk, not fifty), and every inode seen on the way is remembered
//! so the sockets that were already open when it was read need no search.

use crate::fxhash::FxHashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Instant;

/// The connection's far end: who to show in the log's Process column.
pub struct Peer {
    pub pid: u32,
    /// The process name, ready for the log: `comm`, or the command's own first
    /// word when `comm` is empty.
    pub name: String,
}

/// Shortest gap between two full walks of the process table. A page load opens
/// dozens of connections; one walk answers the whole burst, and a socket newer
/// than that walk goes unnamed rather than paying for a second one.
#[cfg(unix)]
const WALK_MISS_GAP_MS: u64 = 200;
/// Longest a walk is trusted. Inode numbers are recycled, so an entry that has
/// aged out is confirmed by a fresh look instead of believed.
#[cfg(unix)]
const WALK_GAP_MS: u64 = 5_000;
/// How many of the recently answered processes are searched before the whole
/// table is. A browser, a mail client, a game: whatever is talking now keeps
/// talking, so its descriptors are the first place to look.
#[cfg(unix)]
const RECENT_PIDS: usize = 4;
/// Both caches are bounded: a desktop has a few thousand processes and a few
/// thousand sockets, and this is the guard against a table that never stops
/// growing.
const MAX_ENTRIES: usize = 4096;

/// The answers of the last searches, kept by the core for every proxy thread.
pub struct Table {
    /// Socket inode to the process holding it.
    #[cfg(unix)]
    holders: FxHashMap<u64, u32>,
    /// Process id to its name; kept across searches because it does not
    /// change.
    names: FxHashMap<u32, String>,
    /// The processes the last answers came from, newest first.
    #[cfg(unix)]
    recent: Vec<u32>,
    /// When the whole table was last walked, and whether that walk finished.
    #[cfg(unix)]
    walked: Option<Instant>,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub fn new() -> Self {
        Table {
            #[cfg(unix)]
            holders: FxHashMap::default(),
            names: FxHashMap::default(),
            #[cfg(unix)]
            recent: Vec::new(),
            #[cfg(unix)]
            walked: None,
        }
    }

    /// The process that opened the connection between `client` — the peer
    /// address of the accepted socket — and `our`, this listener's address.
    ///
    /// `None` means the socket could not be attributed: it is not in the
    /// kernel table, it belongs to a process this one may not read, or it is
    /// newer than the last walk and the walk window says to wait. The caller
    /// then logs the row without a process, which is what AdGuard's own log
    /// does for a flow it cannot name.
    // The two bodies are exclusive at compile time, so the Windows one is the
    // function's tail expression and its `return` is redundant — but only when
    // compiled for Windows, which is exactly when the lint looks.
    #[allow(clippy::needless_return)]
    pub fn owner(&mut self, client: SocketAddr, our: SocketAddr) -> Option<Peer> {
        #[cfg(windows)]
        {
            return self.owner_windows(client, our, false);
        }
        #[cfg(unix)]
        {
            let inode = socket_of(client, our)?;
            let pid = self.pid_of(inode)?;
            Some(Peer {
                pid,
                name: self.name_of(pid)?,
            })
        }
    }

    /// The process behind a *UDP* socket, by its local port: the DNS listener
    /// receives a lookup from a socket the kernel names the same way, and on a
    /// desktop that is the only thing that can say which program asked (the
    /// platform's uid→package table is an Android answer and is empty here).
    #[allow(clippy::needless_return)]
    pub fn owner_udp(&mut self, port: u16) -> Option<Peer> {
        #[cfg(windows)]
        {
            let local = SocketAddr::from(([127, 0, 0, 1], port));
            return self.owner_windows(local, local, true);
        }
        #[cfg(unix)]
        {
            let inode = udp_socket_of(port)?;
            let pid = self.pid_of(inode)?;
            Some(Peer {
                pid,
                name: self.name_of(pid)?,
            })
        }
    }

    /// The Windows answer to the same question.
    ///
    /// There is no inode to walk: the IP helper tables map a socket straight to
    /// the process that holds it, so the walk-and-cache machinery above has
    /// nothing to cache beyond the names. A port can be reported by both
    /// families — a resolver bound to `::` takes IPv6 rows — so the family the
    /// client actually used is tried first and the other one after it.
    #[cfg(windows)]
    fn owner_windows(&mut self, client: SocketAddr, _our: SocketAddr, udp: bool) -> Option<Peer> {
        use crate::sys::winproc;
        let v6 = client.is_ipv6();
        let pid = if udp {
            winproc::udp_owner_of_port(client.port(), v6)
                .or_else(|| winproc::udp_owner_of_port(client.port(), !v6))
        } else {
            winproc::tcp_owner_of_port(client.port(), v6)
                .or_else(|| winproc::tcp_owner_of_port(client.port(), !v6))
        }?;
        Some(Peer {
            pid,
            name: self.name_of(pid)?,
        })
    }

    #[cfg(unix)]
    fn pid_of(&mut self, inode: u64) -> Option<u32> {
        let now = Instant::now();
        if self.trusted(&now, WALK_GAP_MS) {
            if let Some(pid) = self.holders.get(&inode) {
                let pid = *pid;
                self.remember_pid(pid);
                return Some(pid);
            }
        }
        let recent = self.recent.clone();
        for pid in recent.iter().take(RECENT_PIDS) {
            if search_pid(*pid, inode, &mut self.holders) {
                self.remember_pid(*pid);
                return Some(*pid);
            }
        }
        if self.trusted(&now, WALK_MISS_GAP_MS) {
            return None;
        }
        self.walked = Some(now);
        let pid = walk(inode, &mut self.holders);
        if let Some(pid) = pid {
            self.remember_pid(pid);
        }
        pid
    }

    /// Puts a pid at the front of the recently-answered list.
    #[cfg(unix)]
    fn remember_pid(&mut self, pid: u32) {
        self.recent.retain(|other| *other != pid);
        self.recent.insert(0, pid);
        self.recent.truncate(RECENT_PIDS);
    }

    /// Whether the last walk is younger than `gap_ms`.
    #[cfg(unix)]
    fn trusted(&self, now: &Instant, gap_ms: u64) -> bool {
        self.walked
            .is_some_and(|at| now.duration_since(at).as_millis() < gap_ms as u128)
    }

    /// `comm` is what a filter author expects to match on, and it is short. A
    /// process that left an empty name behind still has a command line, so its
    /// first word is the fallback.
    fn name_of(&mut self, pid: u32) -> Option<String> {
        if let Some(name) = self.names.get(&pid) {
            return Some(name.clone());
        }
        let name = name_of_process(pid)?;
        if self.names.len() >= MAX_ENTRIES {
            self.names.clear();
        }
        self.names.insert(pid, name.clone());
        Some(name)
    }
}

/// Whether this process holds the socket, searching its descriptors and
/// recording every socket it turns out to hold.
#[cfg(unix)]
fn search_pid(pid: u32, inode: u64, holders: &mut FxHashMap<u64, u32>) -> bool {
    let fds = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(fds) => fds,
        Err(_) => return false,
    };
    let mut found = false;
    for fd in fds.flatten() {
        if let Some(seen) = socket_inode(&fd.path()) {
            if seen == inode {
                found = true;
            }
            note(holders, seen, pid);
        }
    }
    found
}

/// One pass over the process table, stopping at the process that owns the
/// socket and remembering the sockets of every process it looked in.
#[cfg(unix)]
fn walk(inode: u64, holders: &mut FxHashMap<u64, u32>) -> Option<u32> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        if search_pid(pid, inode, holders) {
            return Some(pid);
        }
    }
    None
}

/// The socket inode a descriptor points at, if it points at one.
#[cfg(unix)]
fn socket_inode(path: &Path) -> Option<u64> {
    let target = std::fs::read_link(path).ok()?;
    let name = target.file_name()?.to_string_lossy();
    let inner = name
        .strip_prefix("socket:[")?
        .strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

#[cfg(unix)]
fn note(holders: &mut FxHashMap<u64, u32>, inode: u64, pid: u32) {
    if holders.len() >= MAX_ENTRIES {
        holders.clear();
    }
    holders.insert(inode, pid);
}

#[cfg(windows)]
fn name_of_process(pid: u32) -> Option<String> {
    crate::sys::winproc::process_name(pid)
}

/// Runtimes whose own name is never the answer: a log row that says "node"
/// tells the user nothing about which tool made the request. `free-pi-cli`
/// runs as `node /home/shin/.bun/bin/free-pi-cli`, and what a person
/// recognises in that command line is the script, not the interpreter.
///
/// Java is deliberately absent: its arguments are class paths and flags
/// (`-cp … git.shin.adfree.desktop.AdFreeDesktopKt`), so the first non-flag
/// word is not a script and would be a false name.
#[cfg(unix)]
const INTERPRETERS: &[&str] = &["node", "bun", "deno", "python", "python3", "ruby", "perl", "electron"];

/// The script an interpreter was told to run, if that is a better answer than
/// the interpreter's own name.
#[cfg(unix)]
fn script_of(comm: &str, cmdline: &[u8]) -> Option<String> {
    // `node-MainThread`, `node-node`, …: the part before the dash is the
    // runtime, the rest is what the runtime calls its thread.
    let runtime = comm.split('-').next().unwrap_or(comm);
    if !INTERPRETERS.contains(&runtime) {
        return None;
    }
    let mut words = cmdline.split(|byte| *byte == 0).filter(|w| !w.is_empty());
    words.next()?; // argv[0] is the interpreter itself
    for word in words.take(4) {
        let text = String::from_utf8_lossy(word);
        // `node -e 'code'` has no script, and the code would become the name.
        if matches!(text.as_ref(), "-e" | "--eval" | "-p" | "--print") {
            return None;
        }
        if text.starts_with('-') {
            continue;
        }
        let file = text.rsplit('/').next().unwrap_or("").trim();
        let stem = [".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".pl"]
            .iter()
            .find_map(|ext| file.strip_suffix(ext))
            .unwrap_or(file);
        if stem.is_empty() {
            continue;
        }
        return Some(stem.to_string());
    }
    None
}

#[cfg(unix)]
fn name_of_process(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|text| text.trim().to_string())
        .unwrap_or_default();
    // The process table names the runtime; the command line names the tool.
    if let Some(name) = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|cmdline| script_of(&comm, &cmdline))
    {
        return Some(name);
    }
    if !comm.is_empty() {
        return Some(comm);
    }
    let line = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let argv0 = line
        .split(|b| *b == 0)
        .next()
        .map(|word| String::from_utf8_lossy(word).to_string())
        .unwrap_or_default();
    let last = argv0.rsplit('/').next().unwrap_or("").to_string();
    (!last.is_empty()).then_some(last)
}

/// The kernel's row for the client side of this connection: its socket inode.
///
/// The client's socket is the row whose *local* port is the port the peer
/// speaks from and whose *remote* port is our own listener. The table is read
/// fresh every time: it is one file, only two port columns are compared, and a
/// connection that is not in it is a connection that is not ours to name.
#[cfg(unix)]
fn socket_of(client: SocketAddr, our: SocketAddr) -> Option<u64> {
    // The listener is dual-stack, so a loopback client arrives here as an
    // IPv4-mapped IPv6 address while its own socket to the real host sits in
    // the IPv4 table. The table is chosen by the address the kernel actually
    // routes, not by the shape of the socket it arrived on.
    let path = if client.ip().to_canonical().is_ipv6() {
        "/proc/net/tcp6"
    } else {
        "/proc/net/tcp"
    };
    let text = std::fs::read_to_string(path).ok()?;
    // The exact pair answers when the connection reaches the proxy unrewritten
    // (SOCKS and a browser told to use the proxy explicitly both do). The
    // redirect does not: it rewrites the *destination* only, so the client's
    // own socket still reads `→ the real host:443`, and the row that names the
    // process can never match our port. What survives the rewrite is the
    // client's source port, which is why that is the fallback key.
    let mut redirected: Option<u64> = None;
    let mut redirected_ambiguous = false;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // 0 the slot, 1 local, 2 remote, 3 state, 4..9 the queue pairs, the
        // uid and the timeout, 9 the inode.
        let (Some(local), Some(remote)) = (cols.get(1), cols.get(2)) else {
            continue;
        };
        if port_of(local) != Some(client.port()) {
            continue;
        }
        let Some(inode) = cols.get(9).and_then(|i| i.parse::<u64>().ok()) else {
            continue;
        };
        if inode == 0 {
            continue;
        }
        if port_of(remote) == Some(our.port()) {
            return Some(inode);
        }
        if redirected.is_some() {
            // One source port, several sockets: the answer cannot be trusted to
            // be this connection's, and a wrong process name would blame the
            // wrong app in the log and in the `$app=` rules.
            redirected_ambiguous = true;
        }
        redirected = Some(inode);
    }
    if redirected_ambiguous {
        return None;
    }
    redirected
}

/// The inode of the unconnected-or-connected UDP socket whose local port is
/// `port`, looked for in both address families (a resolver client may bind
/// either, and the listener sees only its address).
#[cfg(unix)]
fn udp_socket_of(port: u16) -> Option<u64> {
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let Some(local) = cols.get(1) else { continue };
            if port_of(local) != Some(port) {
                continue;
            }
            let Some(inode) = cols.get(9).and_then(|i| i.parse::<u64>().ok()) else {
                continue;
            };
            if inode != 0 {
                return Some(inode);
            }
        }
    }
    None
}

/// The hex `port` half of an `ADDRESS:PORT` column.
#[cfg(unix)]
fn port_of(field: &str) -> Option<u16> {
    u16::from_str_radix(field.rsplit(':').next()?, 16).ok()
}

#[cfg(all(test, unix))]
mod tests {
    /// The row a user reads should name the tool, not the runtime it happens to
    /// be written in. `free-pi-cli` is `node /home/shin/.bun/bin/free-pi-cli`.
    #[test]
    #[cfg(unix)]
    fn an_interpreted_cli_is_named_after_its_script() {
        let cmdline = b"node\0/home/shin/.bun/bin/free-pi-cli\0";
        assert_eq!(
            script_of("node-MainThread", cmdline).as_deref(),
            Some("free-pi-cli")
        );
        assert_eq!(script_of("node", cmdline).as_deref(), Some("free-pi-cli"));
        assert_eq!(
            script_of("bun", b"bun\0/usr/local/bin/openchamber\0").as_deref(),
            Some("openchamber")
        );
        assert_eq!(
            script_of("python3", b"python3\0/srv/tool/job.py\0").as_deref(),
            Some("job")
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_plain_program_keeps_its_own_name() {
        assert_eq!(script_of("chrome", b"/opt/chrome/chrome\0--type=renderer\0"), None);
        assert_eq!(script_of("java", b"java\0-cp\0/lib/a.jar\0Main\0"), None);
    }

    #[test]
    #[cfg(unix)]
    fn a_flag_is_not_a_script_and_neither_is_inline_code() {
        // `node --inspect app.js`: the flag is skipped, the script is not.
        assert_eq!(
            script_of("node", b"node\0--inspect\0/app/server.mjs\0").as_deref(),
            Some("server")
        );
        // `node -e 'code'` has no script at all; naming the code would be worse
        // than naming the runtime.
        assert_eq!(script_of("node", b"node\0-e\0console.log(1)\0"), None);
        // Nothing after the interpreter: fall back to "node".
        assert_eq!(script_of("node", b"node\0"), None);
    }

    use super::*;
    use std::net::TcpListener;
    use std::net::TcpStream;

    /// The whole point of the module, measured against the running kernel: a
    /// loopback connection opened by this test process has to come back
    /// naming this test process.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_loopback_connection_names_the_process_that_opened_it() {
        let mut table = Table::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let our = listener.local_addr().unwrap();
        let client = TcpStream::connect(our).unwrap();
        let (accepted, from) = listener.accept().unwrap();
        assert_eq!(from, client.local_addr().unwrap());
        let peer = table.owner(from, our).expect("the owning process is found");
        assert_eq!(peer.pid, std::process::id());
        assert!(!peer.name.is_empty(), "the test binary has a name");
        // Both ends have to stay open until after the lookup: a closed socket
        // leaves the kernel table and there is nothing left to resolve.
        drop((accepted, client));
    }

    /// The second ask for one socket is answered from the search the first
    /// did, and names the same process.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_second_lookup_repeats_the_first() {
        let mut table = Table::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let our = listener.local_addr().unwrap();
        let client = TcpStream::connect(our).unwrap();
        let (accepted, from) = listener.accept().unwrap();
        let first = table.owner(from, our).expect("found");
        let second = table.owner(from, our).expect("still found");
        assert_eq!(first.pid, second.pid);
        assert_eq!(first.name, second.name);
        drop((accepted, client));
    }

    /// A burst of connections from one process is one search of that process,
    /// not one of the machine: after the first answer the newest sockets of
    /// the same process are found in its own descriptors.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_burst_from_one_process_is_answered_by_that_process_alone() {
        let mut table = Table::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let our = listener.local_addr().unwrap();
        let mut clients = Vec::new();
        let mut accepted = Vec::new();
        for round in 0..3 {
            let client = TcpStream::connect(our).unwrap();
            let (stream, from) = listener.accept().unwrap();
            let peer = table
                .owner(from, our)
                .unwrap_or_else(|| panic!("connection {round} is attributed"));
            assert_eq!(peer.pid, std::process::id());
            clients.push(client);
            accepted.push(stream);
        }
    }

    /// The redirect rewrites the destination, so the client's own socket says
    /// `→ the real host:443` and never mentions the proxy's port. The source
    /// port is what still identifies it, and finding the process through that
    /// is what keeps the log's Process column (and every `$app=` rule) honest
    /// on a Linux desktop.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_redirected_connection_is_named_through_its_source_port() {
        let mut table = Table::new();
        let real = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(real.local_addr().unwrap()).unwrap();
        let (accepted, from) = real.accept().unwrap();
        // The port the redirect sent it to, which no row of the client's own
        // socket names.
        let our: SocketAddr = "127.0.0.1:3129".parse().unwrap();
        let peer = table
            .owner(from, our)
            .expect("the source port alone names the process");
        assert_eq!(peer.pid, std::process::id());
        drop((accepted, client));
    }

    /// The DNS listener gets a datagram and nothing else: no address pair, no
    /// connection, and on a desktop no uid→package table. The socket's own
    /// row in the kernel's UDP table still names the process that asked, which
    /// is what the log's Process column has to show for a DNS row.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_udp_socket_names_its_process_by_local_port() {
        let mut table = Table::new();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let peer = table
            .owner_udp(port)
            .expect("the socket's own row names the process");
        assert_eq!(peer.pid, std::process::id());
        assert!(!peer.name.is_empty());
        drop(socket);
        // The row is gone with the socket, and no guess is made in its place.
        assert!(udp_socket_of(port).is_none());
    }

    #[test]
    fn a_connection_that_is_not_in_the_table_has_no_owner() {
        let mut table = Table::new();
        // Nothing speaks on a port this high, so no row can match it.
        let from: SocketAddr = "127.0.0.1:65001".parse().unwrap();
        let our: SocketAddr = "127.0.0.1:65002".parse().unwrap();
        assert!(socket_of(from, our).is_none());
        assert!(table.owner(from, our).is_none());
    }

    #[test]
    fn the_port_is_the_hex_half_of_the_address_column() {
        assert_eq!(port_of("0100007F:1F90"), Some(8080));
        assert_eq!(
            port_of("00000000000000000000000001000000:0050"),
            Some(80),
            "the same column in the IPv6 table"
        );
        assert_eq!(port_of("0100007F:ZZZZ"), None);
    }

    #[test]
    fn only_a_socket_descriptor_names_an_inode() {
        let own = format!("/proc/{}/fd/0", std::process::id());
        // Descriptor 0 of a test process is whatever the harness gave it; the
        // reader has to answer with an inode only for a real socket link.
        let as_inode = socket_inode(Path::new(&own));
        if let Some(inode) = as_inode {
            assert!(inode > 0);
        }
        assert_eq!(socket_inode(Path::new("/proc/self/exe")), None);
        assert_eq!(socket_inode(Path::new("/definitely/not/here")), None);
    }

    /// The process this test runs in is a real one, so the name the module
    /// finds for it is what the kernel calls it: `comm` is capped at 15
    /// characters, and it is the string the log will show.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_process_is_named_by_what_the_kernel_calls_it() {
        let mut table = Table::new();
        let pid = std::process::id();
        let name = table.name_of(pid).expect("this process has a name");
        assert!(!name.is_empty());
        assert!(name.len() <= 15, "{name}");
        assert_eq!(table.name_of(pid).unwrap(), name, "and the name is cached");
    }

    /// The cost the whole design is arranged to avoid paying twice: one
    /// attribution of a fresh connection, measured. Ignored so a normal test
    /// run does not fail on a busy machine.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn what_one_attribution_costs() {
        let mut table = Table::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let our = listener.local_addr().unwrap();
        let mut held = Vec::new();
        for round in 0..5u32 {
            let client = TcpStream::connect(our).unwrap();
            let (accepted, from) = listener.accept().unwrap();
            let started = Instant::now();
            let peer = table.owner(from, our);
            println!(
                "round {round}: {:?} for {}",
                started.elapsed(),
                peer.map(|p| p.name).unwrap_or_default()
            );
            held.push((client, accepted));
        }
    }
}
