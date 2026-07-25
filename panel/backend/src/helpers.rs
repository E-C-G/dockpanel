/// Shared helper functions used across multiple route modules.
use sha2::{Sha256, Digest};

/// Hash an agent token using SHA-256. Agent tokens are high-entropy (UUIDs)
/// so SHA-256 is sufficient — no need for slow hashing (argon2/bcrypt).
pub fn hash_agent_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    hex::encode(hash)
}

/// Build Cloudflare API headers from credentials.
///
/// If `email` is provided, uses Global API Key auth (X-Auth-Email + X-Auth-Key).
/// Otherwise, uses Bearer token auth.
pub fn cf_headers(token: &str, email: Option<&str>) -> reqwest::header::HeaderMap {
    // The stored Cloudflare token / global API key is encrypted at rest (see
    // dns::create_zone). Decrypt here — the single choke point every CF caller funnels
    // through — so no read site can forget to. The legacy fallback returns any
    // pre-encryption plaintext value (and a freshly-entered token during validation)
    // unchanged, so the round trip is transparent.
    let token = crate::services::secrets_crypto::decrypt_credential_from_env(token);
    let token = token.as_str();
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(em) = email {
        if let (Ok(e_val), Ok(k_val)) = (em.parse(), token.parse()) {
            headers.insert("X-Auth-Email", e_val);
            headers.insert("X-Auth-Key", k_val);
        }
    } else if let Ok(bearer) = format!("Bearer {token}").parse() {
        headers.insert("Authorization", bearer);
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_agent_token_deterministic() {
        let hash1 = hash_agent_token("test-token-123");
        let hash2 = hash_agent_token("test-token-123");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_agent_token_different_inputs() {
        let hash1 = hash_agent_token("token-a");
        let hash2 = hash_agent_token("token-b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_agent_token_length() {
        let hash = hash_agent_token("any-token");
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hash_agent_token_hex_format() {
        let hash = hash_agent_token("test");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_agent_token_known_value() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let hash = hash_agent_token("hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_hash_empty_token() {
        let hash = hash_agent_token("");
        assert_eq!(hash.len(), 64);
    }
}

/// True if an IPv4 address is loopback / private / link-local / CGNAT / unspecified
/// / broadcast — i.e. one an SSRF guard must reject.
fn v4_is_internal(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || o[0] == 169 // link-local/metadata block (broad; matches the original guard)
        || (o[0] == 100 && (o[1] & 0xC0) == 0x40) // CGNAT 100.64.0.0/10
}

/// True if an IPv6 address is loopback / unspecified / ULA (fc00::/7) /
/// link-local (fe80::/10), OR is an IPv4-mapped address whose embedded v4 is
/// internal (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`, …). Rust's
/// `Ipv6Addr::is_loopback()` is false for the mapped forms, so those must be
/// normalized explicitly — that was the SSRF-validator gap.
fn v6_is_internal(v6: std::net::Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() {
        return true;
    }
    if let Some(v4) = v6.to_ipv4_mapped() {
        if v4_is_internal(v4) {
            return true;
        }
    }
    let seg = v6.segments();
    (seg[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
}

/// True if an IP is one an SSRF guard must reject (loopback / private / link-local /
/// ULA / CGNAT / IPv4-mapped-internal / unspecified).
fn ip_is_internal(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4_is_internal(v4),
        std::net::IpAddr::V6(v6) => v6_is_internal(v6),
    }
}

/// True if a redirect target `host` is internal: a literal internal IP, `localhost`,
/// OR a hostname that resolves (blocking) to any internal IP. For use inside a reqwest
/// redirect-policy closure, which is synchronous and cannot `.await` — so this resolves
/// with the blocking std resolver. That is acceptable here: it only runs when a monitored
/// target actually returns a 3xx (rare), inside the background uptime task. Fails CLOSED
/// (treats an unresolvable target as internal) so a redirect is never followed blindly.
pub fn host_resolves_internal_blocking(host: &str, port: u16) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return ip_is_internal(ip);
    }
    use std::net::ToSocketAddrs;
    match (h, port).to_socket_addrs() {
        Ok(addrs) => addrs.into_iter().any(|a| ip_is_internal(a.ip())),
        Err(_) => true, // cannot resolve → do not follow
    }
}

/// SSRF protection: validate that a URL does not resolve to an internal/private address.
///
/// Checks loopback, private (RFC 1918), link-local, ULA, CGNAT, IPv4-mapped-IPv6,
/// and unspecified addresses. Resolves DNS to catch bypass via hostnames that map
/// to internal IPs.
pub async fn validate_url_not_internal(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("URL is required".to_string());
    }
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("URL must use http or https".to_string());
    }

    // Extract host from URL (strip scheme, take up to next / or :)
    let after_scheme = if url.starts_with("https://") { &url[8..] } else { &url[7..] };
    let host = after_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if host.is_empty() {
        return Err("URL has no hostname".to_string());
    }

    // Block obvious internal hostnames
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
        return Err("URL points to a local address".to_string());
    }

    // Resolve hostname to IP addresses and check each one
    let lookup_host = format!("{}:80", host.trim_matches(|c| c == '[' || c == ']'));
    match tokio::net::lookup_host(&lookup_host).await {
        Ok(addrs) => {
            for addr in addrs {
                if ip_is_internal(addr.ip()) {
                    return Err("URL resolves to a private/internal address".to_string());
                }
            }
        }
        Err(_) => {
            return Err("URL hostname could not be resolved".to_string());
        }
    }

    Ok(())
}

/// Detect the server's public IPv4 address.
///
/// Tries the ipify.org API first (5s timeout), falls back to local UDP socket detection.
pub async fn detect_public_ip() -> String {
    match reqwest::Client::new()
        .get("https://api.ipify.org")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => {
            let ip = resp.text().await.unwrap_or_default().trim().to_string();
            if ip.is_empty() { String::new() } else { ip }
        }
        Err(_) => {
            use std::net::UdpSocket;
            UdpSocket::bind("0.0.0.0:0")
                .and_then(|s| { s.connect("8.8.8.8:53")?; s.local_addr() })
                .map(|a| a.ip().to_string())
                .unwrap_or_default()
        }
    }
}

/// Cache for [`detect_public_ip_cached`]: the resolved address and when it was read.
static PUBLIC_IP_CACHE: std::sync::Mutex<Option<(String, std::time::Instant)>> =
    std::sync::Mutex::new(None);

/// How long a detected public IP stays fresh. A box's public address changes
/// approximately never; five minutes is short enough that a real change is picked
/// up quickly and long enough that an interactive preflight is effectively free.
const PUBLIC_IP_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// [`detect_public_ip`] with a short-lived cache.
///
/// The uncached version makes an outbound HTTPS request to api.ipify.org on EVERY
/// call. That is fine for a once-per-provision check, but the DNS preflight runs
/// as the user types a domain — uncached, a single create-site form would issue
/// dozens of external requests and get rate-limited.
pub async fn detect_public_ip_cached() -> String {
    if let Ok(guard) = PUBLIC_IP_CACHE.lock() {
        if let Some((ip, at)) = guard.as_ref() {
            if at.elapsed() < PUBLIC_IP_TTL && !ip.is_empty() {
                return ip.clone();
            }
        }
    }

    let ip = detect_public_ip().await;

    // Never cache a failure — a transient network blip would otherwise pin an
    // empty address for the whole TTL and silently disable every DNS check.
    if !ip.is_empty() {
        if let Ok(mut guard) = PUBLIC_IP_CACHE.lock() {
            *guard = Some((ip.clone(), std::time::Instant::now()));
        }
    }
    ip
}

/// Parse the certificate expiry string the agent returns for SSL
/// provision / renew / DNS-01 responses.
///
/// The agent builds this with `x509_parser`'s `not_after.to_datetime().to_string()`
/// (agent `services/ssl.rs::get_cert_expiry`). That is a `time::OffsetDateTime`
/// `Display`, which renders as `"<date> <time> <offset>"` — e.g.
/// `2026-10-23 09:41:07.0 +00:00:00`. It never emits a literal `UTC`.
///
/// Every panel-side call site used to parse it with `"%Y-%m-%d %H:%M:%S%.f UTC"`,
/// which cannot match that shape, so the parse always failed and `sites.ssl_expiry`
/// was left NULL forever. That silently starved three features that read it: the
/// dashboard SSL countdown, `alert_engine::check_ssl_expiry` (whose query is
/// `WHERE ssl_enabled = TRUE AND ssl_expiry IS NOT NULL`, so it matched no rows at
/// all), and the ARI renewal bookkeeping in `auto_healer`.
///
/// Tolerant by design — panel and agent are separately-versioned binaries and a
/// fleet can run a mix, so accept the legacy `UTC` spelling and RFC 3339 too rather
/// than trade one brittle format for another.
/// Rewrite a trailing `+HH:MM:00` offset to `+HH:MM` so chrono can consume it.
/// Returns `None` when the string doesn't end in a zero-seconds offset, leaving the
/// caller to try its other formats.
fn strip_zero_offset_seconds(s: &str) -> Option<String> {
    // "+00:00:00" — 9 bytes, all ASCII, so byte indexing is safe.
    let tail = s.as_bytes();
    if tail.len() < 9 {
        return None;
    }
    let t = &tail[tail.len() - 9..];
    let shaped = matches!(t[0], b'+' | b'-')
        && t[1].is_ascii_digit()
        && t[2].is_ascii_digit()
        && t[3] == b':'
        && t[4].is_ascii_digit()
        && t[5].is_ascii_digit()
        && t[6] == b':'
        && t[7].is_ascii_digit()
        && t[8].is_ascii_digit();
    // Only whole-minute offsets: `:00` seconds carry no information to lose.
    if shaped && t[7] == b'0' && t[8] == b'0' {
        Some(s[..s.len() - 3].to_string())
    } else {
        None
    }
}

pub fn parse_agent_cert_expiry(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // The current agent format. chrono's `%z` family stops after `+HH:MM`, so the
    // trailing `:SS` the `time` crate always prints would be left unconsumed and the
    // whole parse rejected. Drop that group first — but only when it is `:00`, so a
    // genuinely sub-minute offset falls through instead of being silently shifted.
    let normalised = strip_zero_offset_seconds(s);
    if let Ok(dt) = chrono::DateTime::parse_from_str(
        normalised.as_deref().unwrap_or(s),
        "%Y-%m-%d %H:%M:%S%.f %:z",
    ) {
        return Some(dt.with_timezone(&chrono::Utc));
    }

    // RFC 3339 / ISO 8601, in case the agent ever serialises a chrono type instead.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }

    // Legacy spelling kept so a newer panel never regresses an older agent.
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f UTC") {
        return Some(dt.and_utc());
    }

    None
}

#[cfg(test)]
mod cert_expiry_tests {
    use super::parse_agent_cert_expiry;
    use chrono::{Datelike, Timelike};

    /// THE regression test. This exact string is what
    /// `time::OffsetDateTime`'s `Display` produces, which is what the agent
    /// sends. If this ever fails, `ssl_expiry` is silently NULL again and the
    /// SSL countdown + expiry alerts go dark with no error anywhere.
    #[test]
    fn parses_the_format_the_agent_actually_sends() {
        let dt = parse_agent_cert_expiry("2026-10-23 09:41:07.0 +00:00:00")
            .expect("agent's time::OffsetDateTime Display form must parse");
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 10);
        assert_eq!(dt.day(), 23);
        assert_eq!(dt.hour(), 9);
        assert_eq!(dt.minute(), 41);
        assert_eq!(dt.second(), 7);
    }

    #[test]
    fn parses_without_fractional_seconds() {
        assert!(parse_agent_cert_expiry("2026-10-23 09:41:07 +00:00:00").is_some());
    }

    #[test]
    fn parses_a_non_utc_offset_and_normalises_to_utc() {
        let dt = parse_agent_cert_expiry("2026-10-23 11:41:07.0 +02:00:00")
            .expect("offset form must parse");
        assert_eq!(dt.hour(), 9, "must be converted to UTC, not read as wall time");
    }

    #[test]
    fn still_parses_the_legacy_utc_spelling() {
        assert!(parse_agent_cert_expiry("2026-10-23 09:41:07.0 UTC").is_some());
    }

    #[test]
    fn parses_rfc3339() {
        assert!(parse_agent_cert_expiry("2026-10-23T09:41:07Z").is_some());
    }

    #[test]
    fn rejects_junk_instead_of_defaulting() {
        assert!(parse_agent_cert_expiry("").is_none());
        assert!(parse_agent_cert_expiry("   ").is_none());
        assert!(parse_agent_cert_expiry("not a date").is_none());
        assert!(parse_agent_cert_expiry("2026-10-23").is_none());
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::{ip_is_internal, v4_is_internal, v6_is_internal};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn v4_internal_ranges_blocked() {
        for s in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0", "100.64.0.1"] {
            assert!(v4_is_internal(s.parse::<Ipv4Addr>().unwrap()), "{s} should be internal");
        }
    }

    #[test]
    fn v4_public_allowed() {
        for s in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.1"] {
            assert!(!v4_is_internal(s.parse::<Ipv4Addr>().unwrap()), "{s} should be public");
        }
    }

    #[test]
    fn v6_mapped_loopback_and_metadata_blocked() {
        // The exact gap: IPv4-mapped IPv6 whose is_loopback() is false.
        assert!(v6_is_internal("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap()));
        assert!(v6_is_internal("::ffff:169.254.169.254".parse::<Ipv6Addr>().unwrap()));
        assert!(v6_is_internal("::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn v6_ula_and_link_local_blocked() {
        assert!(v6_is_internal("fc00::1".parse::<Ipv6Addr>().unwrap()));
        assert!(v6_is_internal("fd00:ec2::254".parse::<Ipv6Addr>().unwrap()));
        assert!(v6_is_internal("fe80::1".parse::<Ipv6Addr>().unwrap()));
        assert!(v6_is_internal("::1".parse::<Ipv6Addr>().unwrap()));
        assert!(v6_is_internal("::".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn v6_public_allowed() {
        assert!(!v6_is_internal("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()));
        assert!(!ip_is_internal("2001:4860:4860::8888".parse::<std::net::IpAddr>().unwrap()));
    }
}
