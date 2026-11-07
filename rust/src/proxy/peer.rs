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
use std::path::Path;
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
const WALK_MISS_GAP_MS: u64 = 200;
/// Longest a walk is trusted. Inode numbers are recycled, so an entry that has
/// aged out is confirmed by a fresh look instead of believed.
const WALK_GAP_MS: u64 = 5_000;
/// How many of the recently answered processes are searched before the whole
/// table is. A browser, a mail client, a game: whatever is talking now keeps
/// talking, so its descriptors are the first place to look.
const RECENT_PIDS: usize = 4;
/// Both caches are bounded: a desktop has a few thousand processes and a few
/// thousand sockets, and this is the guard against a table that never stops
/// growing.
const MAX_ENTRIES: usize = 4096;

/// The answers of the last searches, kept by the core for every proxy thread.
pub struct Table {
    /// Socket inode to the process holding it.
    holders: FxHashMap<u64, u32>,
    /// Process id to its name; kept across searches because it does not
    /// change.
    names: FxHashMap<u32, String>,
    /// The processes the last answers came from, newest first.
    recent: Vec<u32>,
    /// When the whole table was last walked, and whether that walk finished.
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
            holders: FxHashMap::default(),
            names: FxHashMap::default(),
            recent: Vec::new(),
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
    pub fn owner(&mut self, client: SocketAddr, our: SocketAddr) -> Option<Peer> {
        let inode = socket_of(client, our)?;
        let pid = self.pid_of(inode)?;
        Some(Peer {
            pid,
            name: self.name_of(pid)?,
        })
    }

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
    fn remember_pid(&mut self, pid: u32) {
        self.recent.retain(|other| *other != pid);
        self.recent.insert(0, pid);
        self.recent.truncate(RECENT_PIDS);
    }

    /// Whether the last walk is younger than `gap_ms`.
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
fn socket_inode(path: &Path) -> Option<u64> {
    let target = std::fs::read_link(path).ok()?;
    let name = target.file_name()?.to_string_lossy();
    let inner = name
        .strip_prefix("socket:[")?
        .strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

fn note(holders: &mut FxHashMap<u64, u32>, inode: u64, pid: u32) {
    if holders.len() >= MAX_ENTRIES {
        holders.clear();
    }
    holders.insert(inode, pid);
}

fn name_of_process(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|text| text.trim().to_string())
        .unwrap_or_default();
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

/// The hex `port` half of an `ADDRESS:PORT` column.
fn port_of(field: &str) -> Option<u16> {
    u16::from_str_radix(field.rsplit(':').next()?, 16).ok()
}

#[cfg(test)]
mod tests {
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
