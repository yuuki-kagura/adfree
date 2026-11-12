//! WinDivert, the piece of Windows that plays the part of `nft`.
//!
//! On Linux the kernel moves traffic without being asked: a rule table
//! redirects, conntrack remembers, and the proxy reads the memory back. On
//! Windows there is no such table, so this module holds the socket and calls a
//! driver that intercepts packets, and [`crate::winnat`] does the remembering.
//!
//! Two decisions keep the rest of the port honest:
//!
//! * **the DLL is loaded at run time**, not linked. `WinDivert.dll` and the
//!   driver it installs on first `WinDivertOpen` are shipped beside the
//!   executable; a build machine does not need the import library, and a machine
//!   without the driver fails with a sentence instead of a missing-DLL dialog at
//!   startup.
//! * **the filter excludes what must not be touched.** `not impostor` skips
//!   packets this code injected (a redirected packet re-enters the loopback
//!   path, and without that bit the redirect would eat its own output), the
//!   proxy's own port range is excluded on both protocols, and anything already
//!   aimed inside is left alone.
//!
//! What this module does *not* do is decide. Each packet is parsed, handed to
//! `winnat::Nat`, and the answer is applied here: that split is what lets the
//! rules be tested on a Linux laptop.

#![cfg(windows)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::packet::Packet;
use crate::winnat::{self, Decision, Endpoint, Nat, Shape};

/// The proxy's local port range, excluded from the filter: these are the
/// proxy's own connections to origins, and redirecting them would be a loop.
pub const OWN_PORTS: (u16, u16) = (40000, 40999);

/// `WINDIVERT_LAYER_NETWORK`.
const LAYER_NETWORK: i32 = 0;
/// `WINDIVERT_FLAG_SNIFF` is deliberately not used: sniffed packets are visible
/// but not delivered, so a redirect through it would double every packet.
const FLAGS_NONE: u64 = 0;

/// The filter for traffic leaving the machine: the four protocols the redirect
/// has an opinion about, minus the proxy's own dialling and anything already
/// pointed inside.
fn outbound_filter() -> String {
    format!(
        "outbound and not impostor \
         and (tcp.DstPort == 80 or tcp.DstPort == 443 \
              or udp.DstPort == 53 or udp.DstPort == 443) \
         and not (tcp.SrcPort >= {lo} and tcp.SrcPort <= {hi}) \
         and not (udp.SrcPort >= {lo} and udp.SrcPort <= {hi}) \
         and not (ip.DstAddr == 127.0.0.1) \
         and not (ipv6.DstAddr == ::1)",
        lo = OWN_PORTS.0,
        hi = OWN_PORTS.1
    )
}

/// The filter for the answers: only the two local listeners can produce them.
fn inbound_filter(proxy: Endpoint, dns: Endpoint) -> String {
    format!(
        "inbound and not impostor and ((tcp.SrcPort == {pp}) or (udp.SrcPort == {dp}))",
        pp = proxy.port,
        dp = dns.port
    )
}

/// `WINDIVERT_ADDRESS`, 64 bytes on every Windows target.
///
/// The bitfield is flattened to a `u32` because its layout is fixed by the C
/// ABI: byte 0 is the layer, byte 1 the event, and the flags start at bit 16
/// (sniffed, outbound, loopback, impostor, ipv6, ip/tcp/udp checksum).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    pub bits: u32,
    pub _reserved: u32,
    pub data: [u8; 48],
}

impl Default for Address {
    fn default() -> Self {
        // `WINDIVERT_ADDRESS` is filled in by the driver; the initial value only
        // has to be defined, not meaningful.
        Self {
            timestamp: 0,
            bits: 0,
            _reserved: 0,
            data: [0u8; 48],
        }
    }
}

const _: () = assert!(std::mem::size_of::<Address>() == 64);

type Handle = *mut c_void;

type OpenFn = unsafe extern "system" fn(*const i8, i32, i16, u64) -> Handle;
type RecvFn = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *const Address) -> i32;
type CloseFn = unsafe extern "system" fn(Handle) -> i32;
type CalcFn = unsafe extern "system" fn(*mut u8, u32, *mut Address, u64) -> i32;

/// The five entry points the redirect needs, resolved once.
pub struct Api {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    close: CloseFn,
    calc: CalcFn,
    _dll: *mut c_void,
}

// The function pointers are immutable once resolved and the DLL stays loaded for
// the process's life, which is what makes sharing the table safe.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

impl Api {
    /// Resolves `WinDivert.dll`.
    ///
    /// Three places are tried, in this order, because the app is installed in
    /// three shapes: the directory the application says (it unpacks the copy
    /// from its own jar there — see [`set_dir`]), the launcher's own directory
    /// (`LoadLibraryW` alone searches it), and the current directory, which is
    /// what a developer running from the repository has.
    pub fn load() -> Result<Api, String> {
        let dll = match load_from_known_places() {
            Some(dll) => dll,
            None => return Err(missing_dll()),
        };
        unsafe fn sym<T>(dll: *mut c_void, name: &[u8]) -> Result<T, String> {
            use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
            let p = unsafe { GetProcAddress(dll, name.as_ptr()) };
            match p {
                Some(f) => Ok(unsafe { std::mem::transmute_copy(&f) }),
                None => Err(format!(
                    "WinDivert.dll has no {} (wrong version?)",
                    String::from_utf8_lossy(&name[..name.len() - 1])
                )),
            }
        }
        let api = Api {
            open: unsafe { sym(dll, b"WinDivertOpen\0") }?,
            recv: unsafe { sym(dll, b"WinDivertRecv\0") }?,
            send: unsafe { sym(dll, b"WinDivertSend\0") }?,
            close: unsafe { sym(dll, b"WinDivertClose\0") }?,
            calc: unsafe { sym(dll, b"WinDivertHelperCalcChecksums\0") }?,
            _dll: dll,
        };
        Ok(api)
    }
}

/// Where the application said the DLL is. Set once, from the files the app
/// unpacked out of its own jar; unset in a test or a developer's checkout, where
/// the fallbacks are what matter.
static DIR: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Tells the loader where `WinDivert.dll` and `WinDivert64.sys` live. They are a
/// pair: the driver is loaded from the same directory as the DLL, so pointing at
/// one means pointing at both.
pub fn set_dir(dir: &str) {
    if let Ok(mut slot) = DIR.lock() {
        *slot = Some(std::path::PathBuf::from(dir));
    }
}

fn missing_dll() -> String {
    "WinDivert.dll is missing: the application unpacks it on first run, and a      development checkout needs it in the current directory"
        .to_string()
}

/// The full path of the running image's directory, so "beside the launcher" can
/// be turned into an absolute path without walking the environment.
fn exe_dirs() -> Vec<std::path::PathBuf> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    let mut buf = vec![0u16; 1024];
    let len = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        return Vec::new();
    }
    let path = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]));
    let Some(dir) = path.parent() else {
        return Vec::new();
    };
    // jpackage puts application resources in `lib/app/resources` below `bin/`.
    vec![
        dir.to_path_buf(),
        dir.join("windivert"),
        dir.join("lib/app/resources/windivert"),
        dir.parent().map(|p| p.join("lib/app/resources/windivert")).unwrap_or_default(),
    ]
}

fn load_from_known_places() -> Option<Handle> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(slot) = DIR.lock() {
        if let Some(dir) = slot.as_ref() {
            candidates.push(dir.join("WinDivert.dll"));
        }
    }
    candidates.extend(exe_dirs().into_iter().map(|d| d.join("WinDivert.dll")));
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let dll = unsafe { LoadLibraryW(wide.as_ptr()) };
        if !dll.is_null() {
            return Some(dll);
        }
    }
    // Last: the plain name, which is the current directory and the system paths.
    let name: Vec<u16> = "WinDivert.dll\0".encode_utf16().collect();
    let dll = unsafe { LoadLibraryW(name.as_ptr()) };
    if dll.is_null() {
        None
    } else {
        Some(dll)
    }
}

/// One interception handle. Dropped = closed, and the driver stays installed
/// until the machine reboots or the last handle goes away.
struct Filter {
    handle: Handle,
    api: Arc<Api>,
    /// Whether this handle has been closed. `WinDivertRecv` blocks until a
    /// packet arrives, so the only way to end a loop that is waiting inside the
    /// driver is to close the handle underneath it — and closing twice would be
    /// a use-after-free.
    closed: AtomicBool,
}

impl Filter {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            unsafe {
                (self.api.close)(self.handle);
            }
        }
    }
}

impl Filter {
    fn open(api: &Arc<Api>, filter: &str) -> Result<Filter, String> {
        let c: Vec<u8> = filter.bytes().chain(std::iter::once(0)).collect();
        let handle = unsafe {
            (api.open)(
                c.as_ptr() as *const i8,
                LAYER_NETWORK,
                0,
                FLAGS_NONE,
            )
        };
        if handle.is_null() || handle as isize == -1 {
            return Err(format!(
                "WinDivertOpen failed for `{filter}`: the driver is not installed, or the \
                 application is not elevated"
            ));
        }
        Ok(Filter {
            handle,
            api: api.clone(),
            closed: AtomicBool::new(false),
        })
    }

    /// Blocks until a packet arrives. `Ok(None)` means "nothing this pass": the
    /// caller checks its stop flag and calls again.
    fn recv(&self, buf: &mut [u8], addr: &mut Address) -> Result<Option<usize>, String> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let mut len = 0u32;
        let ok = unsafe {
            (self.api.recv)(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
                addr,
            )
        };
        if ok == 0 {
            return Ok(None);
        }
        Ok(Some(len as usize))
    }

    fn send(&self, buf: &mut [u8], addr: &Address) -> bool {
        let mut sent = 0u32;
        let ok = unsafe {
            (self.api.send)(
                self.handle,
                buf.as_ptr(),
                buf.len() as u32,
                &mut sent,
                addr,
            )
        };
        ok != 0
    }

    /// Recomputes IP and L4 checksums after an edit. WinDivert does this on
    /// injection anyway when the address's checksum bits are clear, but being
    /// explicit means the bytes in the driver's queue are already correct.
    fn fix_checksums(&self, buf: &mut [u8], addr: &mut Address) {
        unsafe {
            (self.api.calc)(buf.as_mut_ptr(), buf.len() as u32, addr, 0);
        }
    }
}

// A WinDivert handle is a reference to a kernel object, and every entry point
// above takes it as an argument: the driver's API is already usable from any
// thread and from several at once. The `Filter` wrapper adds no interior state
// that would make that untrue.
unsafe impl Send for Filter {}
unsafe impl Sync for Filter {}
unsafe impl Send for Redirector {}
unsafe impl Sync for Redirector {}

impl Drop for Filter {
    fn drop(&mut self) {
        self.close();
    }
}

/// The redirect as one object: two handles, one table, one stop flag.
pub struct Redirector {
    out: Filter,
    inc: Filter,
    nat: std::sync::Mutex<Nat>,
    stop: Arc<AtomicBool>,
    seen: AtomicU64,
}

impl Redirector {
    pub fn start(proxy: Endpoint, dns: Endpoint) -> Result<Arc<Redirector>, String> {
        let api = Arc::new(Api::load()?);
        let out = Filter::open(&api, &outbound_filter())?;
        let inc = Filter::open(&api, &inbound_filter(proxy, dns))?;
        let redirector = Arc::new(Redirector {
            out,
            inc,
            nat: std::sync::Mutex::new(Nat::new(proxy, dns, OWN_PORTS)),
            stop: Arc::new(AtomicBool::new(false)),
            seen: AtomicU64::new(0),
        });
        crate::logbuf::push_error(&format!(
            "[net] redirecting to {proxy} (dns {dns}) with WinDivert"
        ));
        Ok(redirector)
    }

    /// Ends both loops: the flag stops the next pass, and closing the handles
    /// releases a thread that is already blocked inside `recv`.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.out.close();
        self.inc.close();
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn packets_seen(&self) -> u64 {
        self.seen.load(Ordering::Relaxed)
    }

    pub fn live_mappings(&self) -> usize {
        self.nat.lock().map(|n| n.live_mappings()).unwrap_or(0)
    }

    /// One outbound pass. Returns how many packets were handed back to the
    /// driver (which is not the same as packets seen: a dropped QUIC packet is a
    /// decision, not an omission).
    pub fn pump_outbound(&self, buf: &mut [u8]) -> usize {
        let mut addr = Address::default();
        let Ok(len) = self.out.recv(buf, &mut addr) else {
            return 0;
        };
        let Some(len) = len else {
            return 0;
        };
        if len < 20 {
            self.out.send(&mut buf[..len], &addr);
            return 1;
        }
        self.seen.fetch_add(1, Ordering::Relaxed);
        let now = now_secs();
        let Some(pkt) = Packet::parse(&buf[..len]) else {
            // Fragments, extension-header chains, truncated heads: nothing the
            // redirect can reason about, so nothing it should touch.
            self.out.send(&mut buf[..len], &addr);
            return 1;
        };
        let shape = Shape::of(&pkt);
        let decision = match self.nat.lock() {
            Ok(mut nat) => nat.outbound(&pkt, now),
            Err(_) => Decision::Pass,
        };
        match decision {
            Decision::Drop => 0,
            Decision::Destination(to) => {
                if !winnat::set_destination(&mut buf[..len], shape, to) {
                    // A family mismatch: reinjecting the packet unchanged keeps
                    // the machine connected; dropping it would look like a
                    // network fault.
                    self.out.send(&mut buf[..len], &addr);
                    return 1;
                }
                self.out.fix_checksums(&mut buf[..len], &mut addr);
                self.out.send(&mut buf[..len], &addr);
                1
            }
            // `Pass` and `Source` on the outbound path: nothing to do.
            _ => {
                self.out.send(&mut buf[..len], &addr);
                1
            }
        }
    }

    /// One inbound pass: put the server's address back on the proxy's answer.
    pub fn pump_inbound(&self, buf: &mut [u8]) -> usize {
        let mut addr = Address::default();
        let Ok(len) = self.inc.recv(buf, &mut addr) else {
            return 0;
        };
        let Some(len) = len else {
            return 0;
        };
        if len < 20 {
            self.inc.send(&mut buf[..len], &addr);
            return 1;
        }
        let now = now_secs();
        let mut rewritten = false;
        if let Some(pkt) = Packet::parse(&buf[..len]) {
            let shape = Shape::of(&pkt);
            let decision = match self.nat.lock() {
                Ok(mut nat) => nat.inbound(&pkt, now),
                Err(_) => Decision::Pass,
            };
            if let Decision::Source(from) = decision {
                rewritten = winnat::set_source(&mut buf[..len], shape, from);
            }
        }
        if rewritten {
            self.inc.fix_checksums(&mut buf[..len], &mut addr);
        }
        self.inc.send(&mut buf[..len], &addr);
        1
    }

    /// Forgets connections that have gone quiet.
    pub fn sweep(&self) -> usize {
        let now = now_secs();
        self.nat.lock().map(|mut n| n.sweep(now)).unwrap_or(0)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Runs both passes on this thread until `stop` is set. Each pass blocks inside
/// the driver, so the stop flag is only noticed after a packet or an idle
/// timeout: that is why the handles live in [`Redirector`] rather than on the
/// stack of the loop.
pub fn run(redirector: &Arc<Redirector>) {
    let mut buf = vec![0u8; 65575];
    let mut ticks = 0u32;
    while !redirector.stopped() {
        redirector.pump_outbound(&mut buf);
        redirector.pump_inbound(&mut buf);
        ticks += 1;
        if ticks.is_multiple_of(64) {
            redirector.sweep();
        }
    }
}
