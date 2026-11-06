//! Root mode: install the local CA into the OS trust store with elevation.
//!
//! Android ignores user-installed CAs in apps targeting API 24+ (Cronet in
//! Google apps is the visible case). With root the certificate can live in the
//! system store instead: a Magisk module overlays it at boot, a plain root
//! shell gets a live bind mount, and desktop Linux refreshes the distro bundle.
//! Without elevation nothing here runs; the engine keeps splicing the apps that
//! reject the CA (see `Core::note_client_cert_rejection`).
//!
//! Every path written here is fixed. The only variable interpolated into a
//! shell command is the certificate's subject hash (eight hex digits) and the
//! PEM itself, which travels through a quoted heredoc.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Where Android stores system CAs before the Conscrypt APEX.
#[cfg(any(target_os = "android", test))]
const ANDROID_CACERTS: &str = "/system/etc/security/cacerts";
/// The same store on Android 14+.
#[cfg(any(target_os = "android", test))]
const ANDROID_APEX_CACERTS: &str = "/apex/com.android.conscrypt/cacerts";
/// Root-writable staging area for the live-overlay script.
#[cfg(any(target_os = "android", test))]
const ANDROID_STAGE: &str = "/data/local/tmp/adfree_ca";
/// Magisk keeps modules here; a directory is a module.
#[cfg(any(target_os = "android", test))]
const MAGISK_MODULE_DIR: &str = "/data/adb/modules/adfree_ca";
/// File name the certificate keeps in whichever distro anchor directory this
/// machine has; the directory itself is a `LinuxStore`.
#[cfg(any(target_os = "linux", test))]
const LINUX_CA_NAME: &str = "adfree-ca.crt";

/// One distro's answer: the directory an admin anchor belongs in, and the
/// command that rebuilds the bundle from it. A machine has exactly one of
/// these, so guessing the Debian layout — as this file used to — means both
/// writing somewhere that does not exist and never seeing a CA that is
/// installed correctly.
#[cfg(any(target_os = "linux", test))]
struct LinuxStore {
    anchors: &'static str,
    /// Where the refresh command may live, in the order distros ship it.
    refresh: &'static [&'static str],
    refresh_args: &'static [&'static str],
}

#[cfg(any(target_os = "linux", test))]
const LINUX_STORES: [LinuxStore; 3] = [
    LinuxStore {
        anchors: "/usr/local/share/ca-certificates",
        refresh: &["/usr/sbin/update-ca-certificates", "/usr/bin/update-ca-certificates"],
        refresh_args: &[],
    },
    LinuxStore {
        anchors: "/etc/ca-certificates/trust-source/anchors",
        refresh: &["/usr/bin/update-ca-trust", "/usr/sbin/update-ca-trust"],
        refresh_args: &[],
    },
    LinuxStore {
        anchors: "/etc/pki/ca-trust/source/anchors",
        refresh: &["/usr/bin/update-ca-trust", "/usr/sbin/update-ca-trust"],
        refresh_args: &["extract"],
    },
];

/// `su` may show a consent dialog, so the first probe can take a while.
#[cfg(target_os = "android")]
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Cheap lookups (`command -v`, `[ -d ... ]`).
const SHORT_TIMEOUT: Duration = Duration::from_secs(3);
/// Writing the module or the live overlay over `su`.
const ROOT_TIMEOUT: Duration = Duration::from_secs(60);

/// Why the root-trust status is what it is. The UI owns the wording; this
/// code is the stable part that crosses the FFI boundary.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustDetail {
    #[default]
    None,
    PlatformUnsupported,
    InvalidCa,
    SuMissing,
    AlreadyInstalled,
    RootGranted,
    RootPending,
    PermissionDenied,
    MagiskModuleWritten,
    MagiskWriteFailed,
    InstalledLive,
    MountPending,
    MountFailed,
    Uninstalled,
    UninstalledNeedsReboot,
    UninstallFailed,
    NeedsRoot,
    NeedsRootToRemove,
    TempWriteFailed,
    InstalledLinux,
    LinuxInstallFailed,
    RemovedLinux,
    LinuxRemoveFailed,
    NoCa,
    NoCaToRemove,
}

/// Result of a root-mode operation, shown as the UI's status line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootTrust {
    /// A `su` binary exists (Android); root or passwordless sudo (Linux).
    pub su_present: bool,
    /// The last elevation attempt succeeded.
    pub root_granted: bool,
    /// Our certificate is readable from the active system store right now.
    pub installed: bool,
    /// It will be active after a reboot (Magisk module written, or an old
    /// overlay still mounted after removal).
    pub needs_reboot: bool,
    /// The user-facing state; Kotlin maps it to a localized string.
    pub detail_code: TrustDetail,
    /// English diagnostic from the failed command, kept for logs only.
    pub detail: String,
}

/// Last elevation result in this process, so the status line does not have to
/// spawn `su` (and pop its dialog) on every screen resume.
#[cfg(target_os = "android")]
static ROOT_GRANTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Reads the current state without elevating.
pub fn status(der: Option<&[u8]>) -> RootTrust {
    #[cfg(target_os = "android")]
    {
        android_status(der)
    }
    #[cfg(target_os = "linux")]
    {
        linux_status(der)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = der;
        RootTrust {
            detail_code: TrustDetail::PlatformUnsupported,
            ..RootTrust::default()
        }
    }
}

/// Installs `der` into the system store, elevating if needed.
pub fn install(der: &[u8]) -> RootTrust {
    #[cfg(target_os = "android")]
    {
        android_install(der)
    }
    #[cfg(target_os = "linux")]
    {
        linux_install(der)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = der;
        RootTrust {
            detail_code: TrustDetail::PlatformUnsupported,
            ..RootTrust::default()
        }
    }
}

/// Removes the certificate from the system store.
pub fn remove(der: &[u8]) -> RootTrust {
    #[cfg(target_os = "android")]
    {
        android_remove(der)
    }
    #[cfg(target_os = "linux")]
    {
        linux_remove(der)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = der;
        RootTrust {
            detail_code: TrustDetail::PlatformUnsupported,
            ..RootTrust::default()
        }
    }
}

/// Installs the certificate carried by `pem`, which is given as text instead
/// of being read from a running engine. The desktop hands this to a
/// short-lived root process, and that process must not open the user's
/// database: as root it would leave rows the app can no longer write.
pub fn install_pem(pem: &str) -> RootTrust {
    match crate::mitm::ca::decode_cert_pem(pem) {
        Ok(der) => install(&der),
        Err(e) => RootTrust {
            detail_code: TrustDetail::InvalidCa,
            detail: e,
            ..RootTrust::default()
        },
    }
}

// -------------------------------------------------------------------- shared

/// Android names CA files `<subject_hash_old>.0`, where the hash is the MD5 of
/// the DER-encoded subject read as a little-endian u32. Computing it here keeps
/// the install independent of an `openssl` binary (Android has none).
#[cfg(any(target_os = "android", test))]
fn cert_file_name(der: &[u8]) -> Option<String> {
    use md5::{Digest, Md5};
    let subject = subject_der(der)?;
    let digest = Md5::digest(subject);
    let value = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    Some(format!("{value:08x}.0"))
}

/// DER-encoded Name of the certificate's subject (the bytes OpenSSL hashes).
#[cfg(any(target_os = "android", test))]
fn subject_der(der: &[u8]) -> Option<&[u8]> {
    let (tag, _, certificate) = der_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, _, tbs) = der_tlv(certificate)?;
    if tag != 0x30 {
        return None;
    }
    let mut pos = 0usize;
    // v3 has [0] EXPLICIT version; v1 omits it.
    let (tag, header, value) = der_tlv(tbs.get(pos..)?)?;
    if tag == 0xa0 {
        pos += header + value.len();
    }
    // serialNumber, signature, issuer, validity — then the subject.
    for _ in 0..4 {
        let (_, header, value) = der_tlv(tbs.get(pos..)?)?;
        pos = pos.checked_add(header + value.len())?;
    }
    let (tag, header, value) = der_tlv(tbs.get(pos..)?)?;
    if tag != 0x30 {
        return None;
    }
    let end = pos.checked_add(header + value.len())?;
    tbs.get(pos..end)
}

/// One DER TLV: `(tag, header length, value)`.
#[cfg(any(target_os = "android", test))]
fn der_tlv(input: &[u8]) -> Option<(u8, usize, &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (header, len) = if first & 0x80 == 0 {
        (2usize, first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None; // indefinite or absurd length
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *input.get(2 + i)? as usize;
        }
        (2 + n, len)
    };
    let value = input.get(header..header.checked_add(len)?)?;
    Some((tag, header, value))
}

fn pem_from_der(der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// True when `pem` holds exactly `der`.
fn cert_matches_file(pem: &[u8], der: &[u8]) -> bool {
    use base64::Engine as _;
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map(|decoded| decoded == der)
        .unwrap_or(false)
}

/// The certificate file is present in either system store and holds `der`.
#[cfg(target_os = "android")]
fn cert_installed(der: &[u8]) -> bool {
    let Some(name) = cert_file_name(der) else {
        return false;
    };
    [ANDROID_CACERTS, ANDROID_APEX_CACERTS].iter().any(|dir| {
        fs::read(Path::new(dir).join(&name))
            .map(|bytes| cert_matches_file(&bytes, der))
            .unwrap_or(false)
    })
}

/// Runs a command with a deadline. `su` may wait on a consent dialog, and a
/// denied probe must not wedge the caller's IO thread forever.
fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<std::process::Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                break;
            }
        }
    }
    child.wait_with_output().ok()
}

// ------------------------------------------------------------------- android

#[cfg(target_os = "android")]
fn su_path() -> Option<String> {
    for path in [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/debug_ramdisk/su",
    ] {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    let out = run_with_timeout("sh", &["-c", "command -v su"], SHORT_TIMEOUT)?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && !path.is_empty() {
        Some(path)
    } else {
        None
    }
}

#[cfg(target_os = "android")]
fn su_granted(su: &str) -> bool {
    run_with_timeout(su, &["-c", "id"], PROBE_TIMEOUT)
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).contains("uid=0"))
        .unwrap_or(false)
}

#[cfg(target_os = "android")]
fn su_script(su: &str, script: &str, timeout: Duration) -> Result<(), String> {
    let out = run_with_timeout(su, &["-c", script], timeout)
        .ok_or_else(|| "could not run su".to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.lines().last().unwrap_or("").trim();
    Err(if err.is_empty() {
        "root command failed".to_string()
    } else {
        err.to_string()
    })
}

#[cfg(target_os = "android")]
fn android_status(der: Option<&[u8]>) -> RootTrust {
    use std::sync::atomic::Ordering;
    let su = su_path();
    let installed = der.map(cert_installed).unwrap_or(false);
    let granted = ROOT_GRANTED.load(Ordering::Relaxed);
    let detail_code = if installed {
        TrustDetail::AlreadyInstalled
    } else if su.is_none() {
        TrustDetail::SuMissing
    } else if granted {
        TrustDetail::RootGranted
    } else {
        TrustDetail::RootPending
    };
    RootTrust {
        su_present: su.is_some(),
        root_granted: granted,
        installed,
        needs_reboot: false,
        detail_code,
        detail: String::new(),
    }
}

#[cfg(target_os = "android")]
fn android_install(der: &[u8]) -> RootTrust {
    use std::sync::atomic::Ordering;
    let Some(name) = cert_file_name(der) else {
        return RootTrust {
            detail_code: TrustDetail::InvalidCa,
            ..RootTrust::default()
        };
    };
    let Some(su) = su_path() else {
        return RootTrust {
            detail_code: TrustDetail::SuMissing,
            ..RootTrust::default()
        };
    };
    if cert_installed(der) {
        ROOT_GRANTED.store(true, Ordering::Relaxed);
        return RootTrust {
            su_present: true,
            root_granted: true,
            installed: true,
            needs_reboot: false,
            detail_code: TrustDetail::AlreadyInstalled,
            detail: String::new(),
        };
    }
    if !su_granted(&su) {
        return RootTrust {
            su_present: true,
            root_granted: false,
            installed: false,
            needs_reboot: false,
            detail_code: TrustDetail::PermissionDenied,
            detail: String::new(),
        };
    }
    ROOT_GRANTED.store(true, Ordering::Relaxed);

    let magisk = run_with_timeout(
        &su,
        &["-c", "[ -d /data/adb/magisk ] && echo magisk"],
        SHORT_TIMEOUT,
    )
    .map(|out| String::from_utf8_lossy(&out.stdout).contains("magisk"))
    .unwrap_or(false);

    let pem = pem_from_der(der);
    let (detail_code, detail, needs_reboot) = if magisk {
        match su_script(&su, &magisk_script(&name, &pem), ROOT_TIMEOUT) {
            Ok(()) => (TrustDetail::MagiskModuleWritten, String::new(), true),
            Err(e) => (TrustDetail::MagiskWriteFailed, e, false),
        }
    } else {
        match su_script(&su, &live_script(&name, &pem), ROOT_TIMEOUT) {
            Ok(()) => {
                let visible = cert_installed(der);
                if visible {
                    (TrustDetail::InstalledLive, String::new(), false)
                } else {
                    (TrustDetail::MountPending, String::new(), false)
                }
            }
            Err(e) => (TrustDetail::MountFailed, e, false),
        }
    };
    let installed = cert_installed(der);
    crate::logbuf::push(&format!(
        "root trust: install magisk={magisk} installed={installed}"
    ));
    RootTrust {
        su_present: true,
        root_granted: true,
        installed,
        needs_reboot: needs_reboot && !installed,
        detail_code,
        detail,
    }
}

#[cfg(target_os = "android")]
fn android_remove(der: &[u8]) -> RootTrust {
    use std::sync::atomic::Ordering;
    let Some(name) = cert_file_name(der) else {
        return RootTrust {
            detail_code: TrustDetail::InvalidCa,
            ..RootTrust::default()
        };
    };
    let Some(su) = su_path() else {
        return RootTrust {
            detail_code: TrustDetail::SuMissing,
            ..RootTrust::default()
        };
    };
    if !su_granted(&su) {
        return RootTrust {
            su_present: true,
            root_granted: false,
            installed: cert_installed(der),
            needs_reboot: false,
            detail_code: TrustDetail::PermissionDenied,
            detail: String::new(),
        };
    }
    ROOT_GRANTED.store(true, Ordering::Relaxed);

    let script = format!(
        r#"
if [ -d {MAGISK_MODULE_DIR} ]; then
    rm -rf {MAGISK_MODULE_DIR}
    echo module
    exit 0
fi
umount {ANDROID_APEX_CACERTS} 2>/dev/null
umount {ANDROID_CACERTS} 2>/dev/null
rm -f {ANDROID_STAGE}/{name}
rm -rf {ANDROID_STAGE}
echo live
"#
    );
    // The live overlay lives in init's mount namespace, so undo it there.
    let script = format!(
        "if command -v nsenter >/dev/null 2>&1; then nsenter -t 1 -m -- sh -c {shell}; else sh -c {shell}; fi",
        shell = shell_single_quote(&script)
    );
    let (detail_code, detail, needs_reboot, installed) = match su_script(&su, &script, ROOT_TIMEOUT)
    {
        Ok(()) => {
            let installed = cert_installed(der);
            if installed {
                (
                    TrustDetail::UninstalledNeedsReboot,
                    String::new(),
                    true,
                    installed,
                )
            } else {
                (TrustDetail::Uninstalled, String::new(), false, false)
            }
        }
        Err(e) => (TrustDetail::UninstallFailed, e, false, cert_installed(der)),
    };
    RootTrust {
        su_present: true,
        root_granted: true,
        installed,
        needs_reboot,
        detail_code,
        detail,
    }
}

/// Magisk module: `system/` overlays Android 13 and older at boot; the
/// post-fs-data script handles the Conscrypt APEX on 14+, where the store is
/// not under `/system` and MagicMount cannot reach it.
#[cfg(any(target_os = "android", test))]
fn magisk_script(name: &str, pem: &str) -> String {
    format!(
        r#"
set -e
DIR={MAGISK_MODULE_DIR}
rm -rf "$DIR"
mkdir -p "$DIR/system/etc/security/cacerts" "$DIR/cacerts"
cat > "$DIR/module.prop" <<'ADFREE_EOF'
id=adfree_ca
name=AdFree system CA
version=1
versionCode=1
author=AdFree
description=Trusts the AdFree MITM CA system-wide (apps that ignore user CAs).
ADFREE_EOF
cat > "$DIR/system/etc/security/cacerts/{name}" <<'ADFREE_EOF'
{pem}ADFREE_EOF
cp -f "$DIR/system/etc/security/cacerts/{name}" "$DIR/cacerts/{name}"
cat > "$DIR/post-fs-data.sh" <<'ADFREE_EOF'
#!/system/bin/sh
# Android 14+ keeps the system CAs in the Conscrypt APEX, which MagicMount
# cannot overlay: bind a fully populated copy over it early in boot.
APEX={ANDROID_APEX_CACERTS}
MOD={MAGISK_MODULE_DIR}/cacerts
[ -d "$APEX" ] || exit 0
[ -d "$MOD" ] || exit 0
TMP=/data/adb/adfree_ca_apex
rm -rf "$TMP"
mkdir -p "$TMP" || exit 0
cp -a "$APEX"/. "$TMP"/ 2>/dev/null || exit 0
cp -f "$MOD"/* "$TMP"/ || exit 0
chmod 644 "$TMP"/* 2>/dev/null
chown 0:0 "$TMP"/* 2>/dev/null
chcon u:object_r:system_security_cacerts_file:s0 "$TMP"/* 2>/dev/null
mount --bind "$TMP" "$APEX" || exit 0
ADFREE_EOF
chmod 755 "$DIR/post-fs-data.sh"
chmod 644 "$DIR/module.prop" "$DIR/system/etc/security/cacerts/{name}" "$DIR/cacerts/{name}"
"#
    )
}

/// Plain root: a live bind mount over the system store, in init's mount
/// namespace so every process sees it.
#[cfg(any(target_os = "android", test))]
fn live_script(name: &str, pem: &str) -> String {
    format!(
        r#"
set -e
STAGE={ANDROID_STAGE}
rm -rf "$STAGE"
mkdir -p "$STAGE"
cat > "$STAGE/cert.pem" <<'ADFREE_EOF'
{pem}ADFREE_EOF
cat > "$STAGE/live.sh" <<'ADFREE_EOF'
#!/system/bin/sh
set -e
STAGE={ANDROID_STAGE}
CERT="$STAGE/cert.pem"
overlay() {{
    [ -d "$1" ] || return 0
    rm -rf "$2"
    mkdir -p "$2"
    cp -a "$1"/. "$2"/ 2>/dev/null || true
    cp -f "$CERT" "$2"/{name}
    chmod 644 "$2"/* 2>/dev/null || true
    chown 0:0 "$2"/* 2>/dev/null || true
    chcon u:object_r:system_security_cacerts_file:s0 "$2"/* 2>/dev/null || true
    mount --bind "$2" "$1"
}}
overlay {ANDROID_CACERTS} "$STAGE/cacerts"
overlay {ANDROID_APEX_CACERTS} "$STAGE/apex"
ADFREE_EOF
chmod 755 "$STAGE/live.sh"
if command -v nsenter >/dev/null 2>&1; then
    nsenter -t 1 -m -- /system/bin/sh "$STAGE/live.sh"
else
    /system/bin/sh "$STAGE/live.sh"
fi
"#
    )
}

/// Single-quote a string for `sh`, escaping embedded quotes.
#[cfg(any(target_os = "android", test))]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// --------------------------------------------------------------------- linux

/// `path` joined under `root` with its leading slash dropped, so one set of
/// absolute paths serves both the real system and a test's fake tree.
#[cfg(any(target_os = "linux", test))]
fn under(root: &Path, path: &str) -> std::path::PathBuf {
    root.join(path.strip_prefix('/').unwrap_or(path))
}

/// The distro store this machine has, searched for under `root`.
#[cfg(any(target_os = "linux", test))]
fn linux_store_under(root: &Path) -> Option<&'static LinuxStore> {
    LINUX_STORES.iter().find(|store| {
        under(root, store.anchors).is_dir()
            && store.refresh.iter().any(|program| under(root, program).is_file())
    })
}

#[cfg(target_os = "linux")]
fn linux_store() -> Option<&'static LinuxStore> {
    linux_store_under(Path::new("/"))
}

/// Where the certificate is written for this store. Detection reads the same
/// function, which is the whole point: an install that lands somewhere the
/// check does not look is a switch that can never come on.
#[cfg(any(target_os = "linux", test))]
fn anchor_target(store: &LinuxStore, root: &Path) -> std::path::PathBuf {
    under(root, store.anchors).join(LINUX_CA_NAME)
}

/// Every anchor path the certificate could be living at, so a CA placed by
/// hand in another family's directory is still recognised.
#[cfg(any(target_os = "linux", test))]
fn anchor_targets(root: &Path) -> Vec<std::path::PathBuf> {
    LINUX_STORES
        .iter()
        .map(|store| anchor_target(store, root))
        .collect()
}

#[cfg(target_os = "linux")]
fn elevated_linux() -> bool {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    run_with_timeout("sudo", &["-n", "true"], SHORT_TIMEOUT)
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_installed(der: Option<&[u8]>) -> bool {
    let Some(der) = der else {
        return false;
    };
    anchor_targets(Path::new("/"))
        .iter()
        .any(|path| {
            fs::read(path)
                .map(|bytes| cert_matches_file(&bytes, der))
                .unwrap_or(false)
        })
}

#[cfg(target_os = "linux")]
fn linux_status(der: Option<&[u8]>) -> RootTrust {
    let elevated = elevated_linux();
    let installed = linux_installed(der);
    let detail_code = if installed {
        TrustDetail::InstalledLinux
    } else if elevated {
        TrustDetail::RootGranted
    } else {
        TrustDetail::NeedsRoot
    };
    RootTrust {
        su_present: elevated,
        root_granted: elevated,
        installed,
        needs_reboot: false,
        detail_code,
        detail: String::new(),
    }
}

/// Runs an elevation-appropriate command (`sudo -n` when not already root).
#[cfg(target_os = "linux")]
fn linux_run(program: &str, args: &[&str]) -> Result<(), String> {
    let as_root = unsafe { libc::geteuid() } == 0;
    let out = if as_root {
        run_with_timeout(program, args, ROOT_TIMEOUT)
    } else {
        let mut full = vec!["-n", program];
        full.extend_from_slice(args);
        run_with_timeout("sudo", &full, ROOT_TIMEOUT)
    }
    .ok_or_else(|| format!("could not run {program}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Rebuilds the bundle from the anchor directory this store owns. Probing the
/// command through the store rather than by name is what keeps the write and
/// the refresh from disagreeing about which distro this is.
#[cfg(target_os = "linux")]
fn update_linux_bundle(store: &LinuxStore) -> Result<(), String> {
    let Some(program) = store.refresh.iter().find(|path| Path::new(path).is_file()) else {
        return Err("no update-ca-certificates/update-ca-trust command for this anchor directory".to_string());
    };
    linux_run(program, store.refresh_args)
}

#[cfg(target_os = "linux")]
fn linux_install(der: &[u8]) -> RootTrust {
    let Some(store) = linux_store() else {
        return RootTrust {
            detail_code: TrustDetail::LinuxInstallFailed,
            detail: "no ca-certificates anchor directory on this system".to_string(),
            ..RootTrust::default()
        };
    };
    if !elevated_linux() {
        return RootTrust {
            detail_code: TrustDetail::NeedsRoot,
            ..RootTrust::default()
        };
    }
    let pem = pem_from_der(der);
    let temp = std::env::temp_dir().join(LINUX_CA_NAME);
    if let Err(e) = fs::write(&temp, pem) {
        return RootTrust {
            su_present: true,
            root_granted: true,
            detail_code: TrustDetail::TempWriteFailed,
            detail: e.to_string(),
            ..RootTrust::default()
        };
    }
    let target = anchor_target(store, Path::new("/"));
    let staged = temp.to_string_lossy().to_string();
    let installed_path = target.to_string_lossy().to_string();
    let install = linux_run("install", &["-m", "644", &staged, &installed_path])
        .and_then(|()| update_linux_bundle(store));
    let _ = fs::remove_file(&temp);
    match install {
        Ok(()) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail_code: TrustDetail::InstalledLinux,
            detail: String::new(),
        },
        Err(e) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail_code: TrustDetail::LinuxInstallFailed,
            detail: e,
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_remove(der: &[u8]) -> RootTrust {
    if !elevated_linux() {
        return RootTrust {
            detail_code: TrustDetail::NeedsRootToRemove,
            ..RootTrust::default()
        };
    }
    // Every family's path, not just this distro's: a CA copied in by hand
    // during setup is still ours to clean up.
    let targets: Vec<String> = anchor_targets(Path::new("/"))
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let mut args = vec!["-f".to_string()];
    args.extend(targets);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let removed = linux_run("rm", &arg_refs).and_then(|()| match linux_store() {
        Some(store) => update_linux_bundle(store),
        None => Ok(()),
    });
    match removed {
        Ok(()) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail_code: TrustDetail::RemovedLinux,
            detail: String::new(),
        },
        Err(e) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail_code: TrustDetail::LinuxRemoveFailed,
            detail: e,
        },
    }
}

// ---------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Self-signed P-256 CA with `CN=AdFree Local CA,O=AdFree`. Expected name
    /// from `openssl x509 -subject_hash_old`: 539aec40.
    const FIXTURE_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBrDCCAVGgAwIBAgIUO02gew12c3fotY1kTd/NXCIpN4wwCgYIKoZIzj0EAwIw
KzEYMBYGA1UEAwwPQWRGcmVlIExvY2FsIENBMQ8wDQYDVQQKDAZBZEZyZWUwHhcN
MjYxMDI2MTc1ODI2WhcNMzYxMDIzMTc1ODI2WjArMRgwFgYDVQQDDA9BZEZyZWUg
TG9jYWwgQ0ExDzANBgNVBAoMBkFkRnJlZTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABAbB33tRPMivPWjzJAS14Euw72MeGUc9uAgzEE/HZtwdEpg0N/QBXMQvl6q5
bPsdWsPSOTZamWsZLJUY5Cp7br6jUzBRMB0GA1UdDgQWBBTAZ5fl2TuI2Z3/k6Zd
8hJ7XoYWWzAfBgNVHSMEGDAWgBTAZ5fl2TuI2Z3/k6Zd8hJ7XoYWWzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDBlYB+GEksjvc9b0YPIcP37bRo
iRjL+xZqkbnzAis6uQIhAJc+z9Z5CRp5OFQT110aMAqyuGpi5rouQa7kYzl2smXB
-----END CERTIFICATE-----
";

    fn fixture_der() -> Vec<u8> {
        let body: String = FIXTURE_PEM
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("fixture der")
    }

    #[test]
    fn file_name_matches_openssl_subject_hash_old() {
        assert_eq!(
            cert_file_name(&fixture_der()).as_deref(),
            Some("539aec40.0")
        );
    }

    #[test]
    fn a_truncated_certificate_yields_no_name() {
        let der = fixture_der();
        assert!(cert_file_name(&der[..der.len() / 2]).is_none());
        assert!(cert_file_name(&[]).is_none());
    }

    #[test]
    fn pem_round_trips_and_matches_its_der() {
        let der = fixture_der();
        let pem = pem_from_der(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(cert_matches_file(pem.as_bytes(), &der));
        assert!(!cert_matches_file(pem.as_bytes(), &der[..der.len() - 1]));
    }

    #[test]
    fn magisk_module_names_the_cert_and_handles_the_apex() {
        let script = magisk_script("539aec40.0", FIXTURE_PEM);
        assert!(script.contains("system/etc/security/cacerts/539aec40.0"));
        assert!(script.contains("post-fs-data.sh"));
        assert!(script.contains(ANDROID_APEX_CACERTS));
        assert!(script.contains("mount --bind \"$TMP\" \"$APEX\""));
        assert!(script.contains("id=adfree_ca"));
        // The certificate must stay inside its quoted heredoc.
        assert_eq!(script.matches("ADFREE_EOF").count() % 2, 0);
    }

    #[test]
    fn live_overlay_runs_in_the_global_mount_namespace() {
        let script = live_script("539aec40.0", FIXTURE_PEM);
        assert!(script.contains("nsenter -t 1 -m"));
        assert!(script.contains("mount --bind \"$2\" \"$1\""));
        assert!(script.contains(ANDROID_CACERTS));
        assert!(script.contains(ANDROID_APEX_CACERTS));
    }

    #[test]
    fn shell_quotes_single_quotes() {
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_single_quote("plain"), "'plain'");
    }

    /// A throwaway directory tree standing in for a distro's layout. Built by
    /// hand: the crate has no temp-dir dev dependency.
    fn fake_root(tag: &str, files: &[&str], dirs: &[&str]) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "adfree-trust-test-{}-{tag}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        for path in dirs {
            std::fs::create_dir_all(under(&root, path)).expect("fake anchor dir");
        }
        for path in files {
            let target = under(&root, path);
            std::fs::create_dir_all(target.parent().expect("fake parent")).expect("fake parent");
            std::fs::write(target, b"").expect("fake program");
        }
        root
    }

    #[test]
    fn every_store_writes_where_the_check_reads() {
        for (index, store) in LINUX_STORES.iter().enumerate() {
            let root = fake_root(
                &format!("store{index}"),
                store.refresh,
                &[store.anchors],
            );
            let found = linux_store_under(&root)
                .unwrap_or_else(|| panic!("{} has an anchor dir and a refresh command", store.anchors));
            assert_eq!(found.anchors, store.anchors);
            assert_eq!(found.refresh, store.refresh);
            // The install target and the install check are the same path; a CA
            // written anywhere else would never flip the switch.
            assert!(anchor_targets(&root).contains(&anchor_target(store, &root)));
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn an_arch_machine_is_not_read_as_debian() {
        // This host's actual shape, after the Debian directory was created by
        // hand: both anchor dirs exist, only p11-kit's command does. Picking
        // Debian here would write a PEM nobody rehashes and report the CA as
        // missing forever.
        let root = fake_root(
            "arch",
            &["/usr/bin/update-ca-trust"],
            &[
                "/usr/local/share/ca-certificates",
                "/etc/ca-certificates/trust-source/anchors",
            ],
        );
        let store = linux_store_under(&root).expect("arch store");
        assert_eq!(store.anchors, "/etc/ca-certificates/trust-source/anchors");
        assert_eq!(store.refresh_args, &[] as &[&str]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn text_that_holds_no_certificate_is_refused_before_anything_is_written() {
        // The elevated helper passes the PEM straight through. A file that is
        // not a certificate must fail here, not end up inside the trust store.
        let trust = install_pem("adfree-ca.pem: no such luck\n");
        assert_eq!(trust.detail_code, TrustDetail::InvalidCa);
        assert!(!trust.installed);
    }

    #[test]
    fn anchor_dirs_without_a_refresh_command_are_not_a_store() {
        // A directory alone is not an answer: without the rehash the anchor is
        // inert, and an install that claims success would be a lie.
        let root = fake_root("orphan", &[], &["/usr/local/share/ca-certificates"]);
        assert!(linux_store_under(&root).is_none());
        let empty = fake_root("empty", &[], &[]);
        assert!(linux_store_under(&empty).is_none());
        assert_eq!(anchor_targets(&empty).len(), LINUX_STORES.len());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
