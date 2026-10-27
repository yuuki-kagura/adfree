//! Address rules for every resolver protocol.
//!
//! One validator feeds the settings UI, the legacy import and the engine, so a
//! value can never be accepted by the form and rejected by the core.
//!
//! * UDP accepts an IPv4 literal, optionally with a port. The upstream socket
//!   is IPv4 today, so an IPv6 literal is rejected with a precise error rather
//!   than failing silently later.
//! * DoT accepts `tls://host[:port]` or `host[:port]` (hostname or literal).
//! * DoH requires a full `https://...` URL.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::model::{DnsError, DnsProtocol, DnsValidation};

pub fn validate(protocol: DnsProtocol, raw: &str) -> DnsValidation {
    let mut out = DnsValidation {
        protocol,
        ..DnsValidation::default()
    };
    match normalize(protocol, raw) {
        Ok((address, port)) => {
            out.valid = true;
            out.address = address;
            out.port = port;
            out.error = DnsError::None;
        }
        Err(error) => {
            out.error = error;
            out.address = raw.trim().to_string();
            out.port = protocol.default_port();
        }
    }
    out
}

pub fn normalize(protocol: DnsProtocol, raw: &str) -> Result<(String, u16), DnsError> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(DnsError::Empty);
    }
    match protocol {
        DnsProtocol::Udp => normalize_udp(text),
        DnsProtocol::Dot => normalize_dot(text),
        DnsProtocol::Doh => normalize_doh(text),
    }
}

fn normalize_udp(text: &str) -> Result<(String, u16), DnsError> {
    if text.contains("://") {
        return Err(DnsError::UnsupportedScheme);
    }
    let (host, port) = split_host_port(text, 53)?;
    let host = host.trim_matches(['[', ']']);
    if Ipv4Addr::from_str(host).is_ok() {
        return Ok((host.to_string(), port));
    }
    if Ipv6Addr::from_str(host).is_ok() {
        return Err(DnsError::IpV6UdpUnsupported);
    }
    Err(DnsError::InvalidAddress)
}

fn normalize_dot(text: &str) -> Result<(String, u16), DnsError> {
    let text = text
        .strip_prefix("tls://")
        .or_else(|| text.strip_prefix("TLS://"))
        .unwrap_or(text);
    let text = text.trim_end_matches('/');
    if text.contains('/') {
        return Err(DnsError::InvalidAddress);
    }
    let (host, port) = split_host_port(text, 853)?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(DnsError::Empty);
    }
    let numeric = Ipv4Addr::from_str(host).is_ok() || Ipv6Addr::from_str(host).is_ok();
    let name = !numeric
        && host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !numeric && !name {
        return Err(DnsError::InvalidAddress);
    }
    Ok((host.to_string(), port))
}

fn normalize_doh(text: &str) -> Result<(String, u16), DnsError> {
    let lower = text.to_ascii_lowercase();
    if !lower.starts_with("https://") {
        return Err(if text.contains("://") {
            DnsError::UnsupportedScheme
        } else {
            DnsError::InvalidAddress
        });
    }
    let rest = &text["https://".len()..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(DnsError::InvalidAddress);
    }
    let (host, port) = split_host_port(authority, 443)?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(DnsError::InvalidAddress);
    }
    Ok((text.to_string(), port))
}

/// Splits `host`, `host:port`, `[v6]` and `[v6]:port`. An unbracketed string
/// with several colons is an IPv6 literal, not a host/port pair.
fn split_host_port(text: &str, default_port: u16) -> Result<(String, u16), DnsError> {
    if let Some(rest) = text.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(DnsError::InvalidAddress);
        };
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            default_port
        } else if let Some(p) = after.strip_prefix(':') {
            parse_port(p)?
        } else {
            return Err(DnsError::InvalidAddress);
        };
        return Ok((host.to_string(), port));
    }
    let colons = text.matches(':').count();
    if colons == 1 {
        let (host, port) = text.split_once(':').unwrap();
        return Ok((host.to_string(), parse_port(port)?));
    }
    Ok((text.to_string(), default_port))
}

fn parse_port(raw: &str) -> Result<u16, DnsError> {
    let port = raw.parse::<u16>().map_err(|_| DnsError::InvalidPort)?;
    if port == 0 {
        return Err(DnsError::InvalidPort);
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_accepts_ipv4_with_optional_port() {
        assert_eq!(
            normalize(DnsProtocol::Udp, "1.1.1.1").unwrap(),
            ("1.1.1.1".to_string(), 53)
        );
        assert_eq!(
            normalize(DnsProtocol::Udp, " 94.140.14.14:5353 ").unwrap(),
            ("94.140.14.14".to_string(), 5353)
        );
    }

    #[test]
    fn udp_rejects_names_urls_and_ipv6() {
        assert_eq!(
            normalize(DnsProtocol::Udp, "dns.example"),
            Err(DnsError::InvalidAddress)
        );
        assert_eq!(
            normalize(DnsProtocol::Udp, "https://dns.example/dns-query"),
            Err(DnsError::UnsupportedScheme)
        );
        assert_eq!(
            normalize(DnsProtocol::Udp, "2606:4700::1111"),
            Err(DnsError::IpV6UdpUnsupported)
        );
    }

    #[test]
    fn dot_accepts_scheme_hostname_and_default_port() {
        assert_eq!(
            normalize(DnsProtocol::Dot, "tls://dns.adguard-dns.com").unwrap(),
            ("dns.adguard-dns.com".to_string(), 853)
        );
        assert_eq!(
            normalize(DnsProtocol::Dot, "[2606:4700::1111]:8853").unwrap(),
            ("2606:4700::1111".to_string(), 8853)
        );
    }

    #[test]
    fn doh_requires_https_and_keeps_the_url() {
        assert_eq!(
            normalize(DnsProtocol::Doh, "https://dns.adguard-dns.com/dns-query").unwrap(),
            ("https://dns.adguard-dns.com/dns-query".to_string(), 443)
        );
        assert_eq!(
            normalize(DnsProtocol::Doh, "http://dns.example/dns-query"),
            Err(DnsError::UnsupportedScheme)
        );
        assert_eq!(
            normalize(DnsProtocol::Doh, "dns.example"),
            Err(DnsError::InvalidAddress)
        );
    }

    #[test]
    fn zero_port_is_not_a_port() {
        assert_eq!(
            normalize(DnsProtocol::Udp, "1.1.1.1:0"),
            Err(DnsError::InvalidPort)
        );
    }
}
