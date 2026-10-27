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
/// Where the distro's update command looks on Debian-family Linux.
#[cfg(target_os = "linux")]
const LINUX_CA_FILE: &str = "/usr/local/share/ca-certificates/adfree-ca.crt";

/// `su` may show a consent dialog, so the first probe can take a while.
#[cfg(target_os = "android")]
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Cheap lookups (`command -v`, `[ -d ... ]`).
const SHORT_TIMEOUT: Duration = Duration::from_secs(3);
/// Writing the module or the live overlay over `su`.
const ROOT_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// User-facing explanation (Vietnamese, like the settings screen).
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
            detail: "Nền tảng này không hỗ trợ chế độ root.".to_string(),
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
            detail: "Nền tảng này không hỗ trợ chế độ root.".to_string(),
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
            detail: "Nền tảng này không hỗ trợ chế độ root.".to_string(),
            ..RootTrust::default()
        }
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
        .ok_or_else(|| "không chạy được su".to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.lines().last().unwrap_or("").trim();
    Err(if err.is_empty() {
        "lệnh root thất bại".to_string()
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
    let detail = if installed {
        "CA đã nằm trong system store — mọi app tin chứng chỉ.".to_string()
    } else if su.is_none() {
        "Không thấy su: máy chưa root, dùng chứng chỉ người dùng.".to_string()
    } else if granted {
        "Có quyền root. Cài CA vào system store để Cronet và app khác tin.".to_string()
    } else {
        "Thấy su. Quyền root sẽ được hỏi khi cài.".to_string()
    };
    RootTrust {
        su_present: su.is_some(),
        root_granted: granted,
        installed,
        needs_reboot: false,
        detail,
    }
}

#[cfg(target_os = "android")]
fn android_install(der: &[u8]) -> RootTrust {
    use std::sync::atomic::Ordering;
    let Some(name) = cert_file_name(der) else {
        return RootTrust {
            detail: "Chứng chỉ CA không hợp lệ.".to_string(),
            ..RootTrust::default()
        };
    };
    let Some(su) = su_path() else {
        return RootTrust {
            detail: "Không tìm thấy su — máy chưa root.".to_string(),
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
            detail: "CA đã nằm trong system store.".to_string(),
        };
    }
    if !su_granted(&su) {
        return RootTrust {
            su_present: true,
            root_granted: false,
            installed: false,
            needs_reboot: false,
            detail: "Quyền root bị từ chối — chưa cài được CA hệ thống.".to_string(),
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
    let (outcome, needs_reboot) = if magisk {
        match su_script(&su, &magisk_script(&name, &pem), ROOT_TIMEOUT) {
            Ok(()) => (
                "Đã tạo module Magisk. Khởi động lại máy để CA có hiệu lực.".to_string(),
                true,
            ),
            Err(e) => (format!("Không ghi được module Magisk: {e}"), false),
        }
    } else {
        match su_script(&su, &live_script(&name, &pem), ROOT_TIMEOUT) {
            Ok(()) => {
                let visible = cert_installed(der);
                if visible {
                    (
                        "Đã cài CA vào system store (có hiệu lực ngay).".to_string(),
                        false,
                    )
                } else {
                    (
                        "Đã mount CA nhưng store chưa thấy ngay — thử lại hoặc dùng Magisk."
                            .to_string(),
                        false,
                    )
                }
            }
            Err(e) => (format!("Không mount được CA vào system store: {e}"), false),
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
        detail: outcome,
    }
}

#[cfg(target_os = "android")]
fn android_remove(der: &[u8]) -> RootTrust {
    use std::sync::atomic::Ordering;
    let Some(name) = cert_file_name(der) else {
        return RootTrust {
            detail: "Chứng chỉ CA không hợp lệ.".to_string(),
            ..RootTrust::default()
        };
    };
    let Some(su) = su_path() else {
        return RootTrust {
            detail: "Không tìm thấy su — máy chưa root.".to_string(),
            ..RootTrust::default()
        };
    };
    if !su_granted(&su) {
        return RootTrust {
            su_present: true,
            root_granted: false,
            installed: cert_installed(der),
            needs_reboot: false,
            detail: "Quyền root bị từ chối — chưa gỡ được.".to_string(),
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
    let outcome = match su_script(&su, &script, ROOT_TIMEOUT) {
        Ok(()) => {
            let installed = cert_installed(der);
            if installed {
                (
                    "Đã gỡ CA — khởi động lại máy để bỏ hẳn.".to_string(),
                    true,
                    installed,
                )
            } else {
                ("Đã gỡ CA khỏi system store.".to_string(), false, false)
            }
        }
        Err(e) => (
            format!("Không gỡ được CA hệ thống: {e}"),
            false,
            cert_installed(der),
        ),
    };
    RootTrust {
        su_present: true,
        root_granted: true,
        installed: outcome.2,
        needs_reboot: outcome.1,
        detail: outcome.0,
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
    fs::read(LINUX_CA_FILE)
        .map(|bytes| cert_matches_file(&bytes, der))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_status(der: Option<&[u8]>) -> RootTrust {
    let elevated = elevated_linux();
    let installed = linux_installed(der);
    let detail = if installed {
        "CA đã nằm trong system store của hệ điều hành.".to_string()
    } else if elevated {
        "Có quyền root/sudo. Cài CA vào system store để mọi ứng dụng tin.".to_string()
    } else {
        "Cần quyền root hoặc sudo không mật khẩu để cài vào system store.".to_string()
    };
    RootTrust {
        su_present: elevated,
        root_granted: elevated,
        installed,
        needs_reboot: false,
        detail,
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
    .ok_or_else(|| format!("không chạy được {program}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(target_os = "linux")]
fn update_linux_bundle() -> Result<(), String> {
    if Path::new("/usr/sbin/update-ca-certificates").exists()
        || Path::new("/usr/bin/update-ca-certificates").exists()
    {
        return linux_run("update-ca-certificates", &[]);
    }
    if Path::new("/usr/bin/update-ca-trust").exists()
        || Path::new("/usr/sbin/update-ca-trust").exists()
    {
        return linux_run("update-ca-trust", &["extract"]);
    }
    Err("không tìm thấy update-ca-certificates/update-ca-trust".to_string())
}

#[cfg(target_os = "linux")]
fn linux_install(der: &[u8]) -> RootTrust {
    if !elevated_linux() {
        return RootTrust {
            detail: "Cần quyền root hoặc sudo không mật khẩu để cài CA hệ thống.".to_string(),
            ..RootTrust::default()
        };
    }
    let pem = pem_from_der(der);
    let temp = std::env::temp_dir().join("adfree-ca.crt");
    if let Err(e) = fs::write(&temp, pem) {
        return RootTrust {
            su_present: true,
            root_granted: true,
            detail: format!("Không ghi được tệp tạm: {e}"),
            ..RootTrust::default()
        };
    }
    let staged = temp.to_string_lossy().to_string();
    let install = linux_run("install", &["-m", "644", &staged, LINUX_CA_FILE])
        .and_then(|()| update_linux_bundle());
    let _ = fs::remove_file(&temp);
    match install {
        Ok(()) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail: "Đã cài CA vào system store của hệ điều hành.".to_string(),
        },
        Err(e) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail: format!("Không cài được CA hệ thống: {e}"),
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_remove(der: &[u8]) -> RootTrust {
    if !elevated_linux() {
        return RootTrust {
            detail: "Cần quyền root hoặc sudo không mật khẩu để gỡ CA hệ thống.".to_string(),
            ..RootTrust::default()
        };
    }
    let removed = linux_run("rm", &["-f", LINUX_CA_FILE]).and_then(|()| update_linux_bundle());
    match removed {
        Ok(()) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail: "Đã gỡ CA khỏi system store của hệ điều hành.".to_string(),
        },
        Err(e) => RootTrust {
            su_present: true,
            root_granted: true,
            installed: linux_installed(Some(der)),
            needs_reboot: false,
            detail: format!("Không gỡ được CA hệ thống: {e}"),
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
}
