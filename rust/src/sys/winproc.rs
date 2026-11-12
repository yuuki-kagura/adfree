//! Who owns a connection on Windows.
//!
//! Linux answers this from `/proc`: the socket table names an inode, and the
//! process holding that inode is the process that opened it. Windows has no
//! inode and no `/proc`, but it has the question written down twice — the IP
//! helper API's owner tables map a socket to a process id, and the process API
//! turns an id into a name. That is the whole module.
//!
//! The port is the key, not the address pair, for the same reason it is on
//! Linux: the redirect rewrites the *destination*, so a client's own socket
//! still reads "→ the real host:443" and can never match our listener's port.

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};

/// `TCP_TABLE_OWNER_PID_ALL`.
const TCP_ALL: i32 = 5;
/// `UDP_TABLE_OWNER_PID`.
const UDP_PID: i32 = 1;
/// `MIB_TCP_STATE_ESTAB`: a connected socket is the one that is talking.
const STATE_ESTABLISHED: u32 = 5;
/// The address family numbers the IP helper API takes: Winsock's own, not this
/// crate's.
const IPV4: u32 = 2;
const IPV6: u32 = 23;

/// One IP helper table, in the buffer the API filled.
///
/// The call is made twice on purpose: the first asks how much room it needs,
/// the second fills exactly that. Both tables are the same shape at the front —
/// a count, then rows — which is why they share this.
fn fetch(tcp: bool, ipv6: bool) -> Option<Vec<u8>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, GetExtendedUdpTable};

    let family = if ipv6 { IPV6 } else { IPV4 };
    fn call(tcp: bool, family: u32, buf: *mut u8, size: &mut u32) -> u32 {
        unsafe {
            if tcp {
                GetExtendedTcpTable(buf.cast(), size, 0, family, TCP_ALL, 0)
            } else {
                GetExtendedUdpTable(buf.cast(), size, 0, family, UDP_PID, 0)
            }
        }
    }
    let mut size = 0u32;
    let status = call(tcp, family, std::ptr::null_mut(), &mut size);
    if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    let status = call(tcp, family, buffer.as_mut_ptr(), &mut size);
    if status != NO_ERROR {
        return None;
    }
    buffer.truncate(size as usize);
    Some(buffer)
}

/// The process id holding the TCP socket whose *local* port is `port`.
///
/// A port can appear more than once — a listening socket, a socket in
/// `TIME_WAIT`, the connection itself — so an established row wins.
pub fn tcp_owner_of_port(port: u16, ipv6: bool) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID;

    let buffer = fetch(true, ipv6)?;
    let count = unsafe { *buffer.as_ptr().cast::<u32>() } as usize;
    if count == 0 {
        return None;
    }
    let rows = unsafe {
        std::slice::from_raw_parts(buffer.as_ptr().add(4).cast::<MIB_TCPROW_OWNER_PID>(), count)
    };
    let mut answer = None;
    for row in rows {
        if local_port(row.dwLocalPort) != port {
            continue;
        }
        if row.dwState == STATE_ESTABLISHED {
            return Some(row.dwOwningPid);
        }
        answer = answer.or(Some(row.dwOwningPid));
    }
    answer
}

/// The process id holding the UDP socket whose local port is `port` — the DNS
/// listener's question, phrased the same way.
pub fn udp_owner_of_port(port: u16, ipv6: bool) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::MIB_UDPROW_OWNER_PID;

    let buffer = fetch(false, ipv6)?;
    let count = unsafe { *buffer.as_ptr().cast::<u32>() } as usize;
    if count == 0 {
        return None;
    }
    let rows = unsafe {
        std::slice::from_raw_parts(buffer.as_ptr().add(4).cast::<MIB_UDPROW_OWNER_PID>(), count)
    };
    rows.iter()
        .find(|row| local_port(row.dwLocalPort) == port)
        .map(|row| row.dwOwningPid)
}

/// A process id as the log's Process column shows it: the executable's file
/// name, which is what a filter author writes a rule about.
pub fn process_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // A protected process answers nothing to anyone; the row is logged
        // without a name, exactly as a Linux process this user cannot read is.
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    unsafe {
        CloseHandle(handle);
    }
    if ok == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buf[..len as usize]);
    let name = path.rsplit(['\\', '/']).next().unwrap_or("").to_string();
    (!name.is_empty()).then_some(name)
}

/// `dwLocalPort` holds the port in network byte order in its low two bytes.
fn local_port(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The port encoding is the one detail that silently breaks: a table read
    /// with the bytes reversed names the wrong process for every row.
    #[test]
    fn the_port_is_read_out_of_network_order() {
        // 443 as the API stores it: 0xBB01 in the low half.
        assert_eq!(local_port(0x0000_BB01), 443);
        assert_eq!(local_port(0x0000_5000), 80);
        assert_eq!(local_port(0x0000_0016), 0x1600);
    }
}
