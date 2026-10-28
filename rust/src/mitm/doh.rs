//! HTTPS endpoints of encrypted DNS providers.
//!
//! The MITM speaks HTTP/1.1 only, and a DoH client insists on HTTP/2 (Chrome's
//! Secure DNS aborts when the negotiated protocol is not h2). Terminating one
//! of these flows therefore costs the client its DNS — every page then fails
//! with `BAD_SECURE_CONFIG` — while the traffic inside is encrypted and
//! unfilterable either way. `block_doh` is the switch for refusing provider
//! ranges at the packet level; whatever reaches the MITM is what the user asked
//! to keep working, so it goes to the origin untouched.

/// Exact host names (lowercase, as the SNI reports them).
const HOSTS: &[&str] = &[
    "chrome.cloudflare-dns.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard-dns.com",
    "doh.mullvad.net",
    "doh.cleanbrowsing.org",
    "doh.dns.sb",
];

/// NextDNS mints a host per configuration under this domain.
const NEXTDNS: &str = "nextdns.io";

/// Is this the HTTPS endpoint of an encrypted-DNS provider?
pub fn is_endpoint(host: &str) -> bool {
    HOSTS.contains(&host) || host == NEXTDNS || host.ends_with(".nextdns.io")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_known_endpoints_are_recognized() {
        assert!(is_endpoint("chrome.cloudflare-dns.com"));
        assert!(is_endpoint("dns.google"));
        assert!(is_endpoint("dns.nextdns.io"));
        assert!(is_endpoint("abc123.dns.nextdns.io"));
    }

    #[test]
    fn lookalikes_are_not_endpoints() {
        assert!(!is_endpoint("example.com"));
        assert!(!is_endpoint("cloudflare-dns.com.example.com"));
        assert!(!is_endpoint("notnextdns.io"));
        assert!(!is_endpoint(""));
    }
}
