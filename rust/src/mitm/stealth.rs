//! Stealth-mode helpers: the request bits AdGuard hides from sites.
//!
//! Everything here is pure so the rules can be tested without a socket:
//! tracking parameters, third-party classification, STUN detection and the
//! fixed user agent the disguise replaces the client's own with.

use crate::filter::url_host;

/// The user agent a disguised request carries.
///
/// Chrome's own reduced Android UA: it hides the device model and the exact
/// version while still saying "a mobile browser", so sites keep serving the
/// layout the user actually expects.
pub const DISGUISED_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";

/// Query parameters whose only job is to name the campaign that sent a
/// visitor. `utm_*` is matched by prefix; the rest are the one-off click ids
/// the big ad networks add.
const TRACKING_PARAMS: &[&str] = &[
    "fbclid",
    "gclid",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "yclid",
    "twclid",
    "igshid",
    "igsh",
    "mc_cid",
    "mc_eid",
    "_hsenc",
    "_hsmi",
    "mkt_tok",
    "_openstat",
    "vero_conv",
    "vero_id",
    "wickedid",
    "rb_clickid",
    "s_cid",
    "elqtrackid",
    "elqtrack",
    "oly_anon_id",
    "oly_enc_id",
    "pk_campaign",
    "pk_kwd",
    "pk_source",
    "pk_medium",
    "piwik_campaign",
    "piwik_kwd",
];

/// Whether one query parameter name is a tracking parameter.
fn is_tracking_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("utm_") || TRACKING_PARAMS.contains(&lower.as_str())
}

/// Removes the tracking parameters from an absolute URL.
///
/// Only the query is touched: the path, the fragment and the order of the
/// parameters that stay are exactly as the client wrote them. `None` when
/// there is no query or nothing to remove, so a caller can leave the request
/// head alone.
pub fn strip_tracking_params(url: &str) -> Option<String> {
    let (without_fragment, fragment) = match url.find('#') {
        Some(index) => (&url[..index], &url[index..]),
        None => (url, ""),
    };
    let (path, query) = without_fragment.split_once('?')?;
    if query.is_empty() {
        return None;
    }
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        if is_tracking_param(name) {
            removed = true;
        } else {
            kept.push(pair);
        }
    }
    if !removed {
        return None;
    }
    let mut out = String::with_capacity(url.len());
    out.push_str(path);
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    out.push_str(fragment);
    Some(out)
}

/// Whether a request is cross-site from the page that made it.
///
/// `Sec-Fetch-Site` is authoritative when the browser sends it. Without it
/// the referrer is compared by registrable-ish host: the same host, or one
/// nested under the other (`www.example.com` and `static.example.com`), is
/// first-party. No referrer means a navigation or a client that hides it —
/// both are left alone rather than guessed at.
pub fn is_third_party(request_host: &str, referer: Option<&str>, site: Option<&str>) -> bool {
    match site.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("cross-site") => return true,
        Some(value)
            if value.eq_ignore_ascii_case("same-origin")
                || value.eq_ignore_ascii_case("same-site") =>
        {
            return false
        }
        _ => {}
    }
    let Some(referer) = referer.filter(|value| !value.is_empty()) else {
        return false;
    };
    let referer_host = url_host(referer);
    !same_site(request_host, referer_host)
}

/// Whether two hosts belong to the same site, by the suffix rule the cookie
/// boundary uses: `a.example.com` and `b.example.com` are the same site,
/// `example.com.evil.test` is not.
fn same_site(left: &str, right: &str) -> bool {
    let left = left.trim_start_matches("www.").to_ascii_lowercase();
    let right = right.trim_start_matches("www.").to_ascii_lowercase();
    if left.is_empty() || right.is_empty() {
        return true;
    }
    if left == right {
        return true;
    }
    left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

/// STUN/TURN ports: the signalling WebRTC uses to discover a public address.
/// The fixed ranges are IANA's; Google's STUN service uses the 19302 block.
pub fn is_webrtc_port(port: u16) -> bool {
    matches!(port, 3478 | 5349 | 19302..=19309)
}

/// Whether a UDP datagram is a STUN message.
///
/// The magic cookie at offset 4 is what tells STUN from every other UDP
/// protocol; the port alone would miss a server on a non-standard one. The
/// header checks keep a random datagram that happens to carry the cookie from
/// being dropped.
pub fn is_stun_datagram(payload: &[u8]) -> bool {
    if payload.len() < 20 || payload[0] & 0xc0 != 0 {
        return false;
    }
    // DTLS shares the leading zero bits; its record types (20..23) are where
    // the two protocols would otherwise collide.
    if matches!(payload[0], 20..=23) {
        return false;
    }
    if payload[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return false;
    }
    let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    len.is_multiple_of(4) && len + 20 <= payload.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking_parameters_leave_the_rest_in_order() {
        let url = "https://shop.test/item?id=7&utm_source=news&fbclid=abc&color=red#top";
        assert_eq!(
            strip_tracking_params(url).as_deref(),
            Some("https://shop.test/item?id=7&color=red#top")
        );
    }

    #[test]
    fn an_utm_parameter_is_matched_by_prefix() {
        assert_eq!(
            strip_tracking_params("https://a.test/?utm_campaign=x&keep=1&utm_content=y").as_deref(),
            Some("https://a.test/?keep=1")
        );
    }

    #[test]
    fn a_url_without_tracking_parameters_is_untouched() {
        assert!(strip_tracking_params("https://a.test/?keep=1").is_none());
        assert!(strip_tracking_params("https://a.test/path").is_none());
        assert!(strip_tracking_params("https://a.test/#frag").is_none());
    }

    #[test]
    fn dropping_every_parameter_leaves_a_bare_path() {
        assert_eq!(
            strip_tracking_params("https://a.test/?gclid=x").as_deref(),
            Some("https://a.test/")
        );
    }

    #[test]
    fn a_cross_site_fetch_is_third_party() {
        assert!(is_third_party(
            "cdn.test",
            Some("https://shop.test/"),
            Some("cross-site")
        ));
        assert!(!is_third_party(
            "cdn.test",
            Some("https://shop.test/"),
            Some("same-site")
        ));
        assert!(!is_third_party(
            "cdn.test",
            Some("https://shop.test/"),
            Some("same-origin")
        ));
    }

    #[test]
    fn the_referrer_decides_when_the_fetch_header_is_missing() {
        assert!(!is_third_party(
            "www.shop.test",
            Some("https://shop.test/page"),
            None
        ));
        assert!(!is_third_party(
            "static.shop.test",
            Some("https://www.shop.test/"),
            None
        ));
        assert!(is_third_party(
            "tracker.test",
            Some("https://shop.test/"),
            None
        ));
        assert!(!is_third_party("shop.test", None, None));
    }

    #[test]
    fn stun_is_recognised_by_its_magic_cookie() {
        let mut binding = [0u8; 20];
        binding[0] = 0x00;
        binding[1] = 0x01;
        binding[2] = 0x00;
        binding[3] = 0x00;
        binding[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert!(is_stun_datagram(&binding));
        assert!(!is_stun_datagram(b"hello"));
        let mut dtls = binding;
        dtls[0] = 0x16;
        assert!(!is_stun_datagram(&dtls));
    }

    #[test]
    fn webrtc_ports_are_the_signalling_ones() {
        assert!(is_webrtc_port(3478));
        assert!(is_webrtc_port(5349));
        assert!(is_webrtc_port(19302));
        assert!(!is_webrtc_port(443));
        assert!(!is_webrtc_port(53));
    }
}
