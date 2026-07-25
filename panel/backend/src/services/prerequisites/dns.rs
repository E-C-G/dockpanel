//! The DNS vertical (v2.28.0) — "does this domain point here yet?"
//!
//! The prerequisite behind every HTTP-01 certificate, and the single most common
//! reason a new user's site doesn't work.

use super::copy::{
    self, DNS_ENTER_A_DOMAIN, DNS_NOT_RESOLVING, DNS_NO_PUBLIC_IP, DNS_POINTS_ELSEWHERE,
    DNS_POINTS_ELSEWHERE_SUBDOMAIN, DNS_POINTS_HERE, DNS_POINTS_HERE_CHECK,
};
use super::{DnsRecordHint, PrereqResult, Remediation};
use std::net::IpAddr;

/// Split a domain into the (host, apex-ish) pair used to spell a DNS record.
///
/// Deliberately a heuristic, not a Public Suffix List lookup: pulling in a PSL
/// crate (and keeping it current) is not worth it when the cost of being wrong
/// is cosmetic. A multi-part TLD like `example.co.uk` will be described as host
/// `example` under `co.uk`, which is wrong — which is exactly why every result
/// also carries the unambiguous `fqdn` spelling, and why the copy tells the user
/// to use whichever field their provider asks for.
pub(super) fn split_record_name(domain: &str) -> (String, String) {
    let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        // Apex: example.com
        ("@".to_string(), domain.to_string())
    } else {
        let host = labels[..labels.len() - 2].join(".");
        let apex = labels[labels.len() - 2..].join(".");
        (host, apex)
    }
}

/// Reject anything that isn't plausibly a hostname before we do network work.
pub(super) fn looks_like_a_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Check: does `domain` resolve to the address this panel is reachable at?
///
/// Severity is assigned from *consequence*, and the s252 fresh-box audit is what
/// calibrated it:
///
/// * **Nothing resolves** → `Blocking`. HTTP-01 cannot possibly complete; the CA
///   has nowhere to connect. Gating here saves a guaranteed-failed order.
/// * **Resolves somewhere else** → `Warning`, NOT blocking. The audit drove a
///   Cloudflare-proxied ("orange cloud") domain and issuance *succeeded*, because
///   Cloudflare forwards `/.well-known/acme-challenge/` to the origin. That
///   configuration resolves to Cloudflare's addresses and is indistinguishable
///   from "pointed at the wrong server" by IP alone — so blocking it would refuse
///   a setup we have direct evidence works.
pub async fn check_dns_points_here(domain: &str) -> PrereqResult {
    let check: &copy::Prereq = &DNS_POINTS_HERE_CHECK;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    if !looks_like_a_domain(&domain) {
        return check.result(&DNS_ENTER_A_DOMAIN, &[]);
    }

    let server_ip = crate::helpers::detect_public_ip_cached().await;
    if server_ip.is_empty() {
        // We don't know our own address, so we cannot judge theirs. Say so
        // plainly rather than inventing a verdict.
        return check.result(&DNS_NO_PUBLIC_IP, &[]);
    }

    let (host, apex) = split_record_name(&domain);
    let record_type = if server_ip.parse::<IpAddr>().map(|ip| ip.is_ipv6()).unwrap_or(false) {
        "AAAA"
    } else {
        "A"
    };
    let hint = DnsRecordHint::new(
        host.clone(),
        domain.clone(),
        record_type,
        server_ip.clone(),
        "Auto (or 300)",
    );

    let resolved: Vec<String> = match tokio::net::lookup_host(format!("{domain}:80")).await {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => Vec::new(),
    };

    if resolved.is_empty() {
        return check
            .result(&DNS_NOT_RESOLVING, &[("domain", &domain)])
            .with_expected(server_ip)
            .with_remediation(Remediation::DnsRecord { record: hint });
    }

    if resolved.iter().any(|ip| ip == &server_ip) {
        let rendered = check.result(
            &DNS_POINTS_HERE,
            &[("domain", &domain), ("server_ip", &server_ip)],
        );
        return rendered.with_expected(server_ip).with_observed(resolved);
    }

    // An apex and a subdomain differ in the advice, not in the verdict: someone
    // pointing `www` has to edit the `www` record, and telling them to point "the
    // domain" here sends them to change the wrong one.
    let rendered = {
        let joined = resolved.join(", ");
        let outcome = if host == "@" {
            &DNS_POINTS_ELSEWHERE
        } else {
            &DNS_POINTS_ELSEWHERE_SUBDOMAIN
        };
        check.result(
            outcome,
            &[
                ("domain", domain.as_str()),
                ("resolved", joined.as_str()),
                ("server_ip", server_ip.as_str()),
                ("apex", apex.as_str()),
            ],
        )
    };

    rendered
        .with_expected(server_ip)
        .with_observed(resolved)
        .with_remediation(Remediation::DnsRecord { record: hint })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::prerequisites::PrereqState;

    #[test]
    fn apex_domains_use_the_at_sign() {
        assert_eq!(split_record_name("example.com"), ("@".into(), "example.com".into()));
    }

    #[test]
    fn subdomains_keep_only_their_host_part() {
        assert_eq!(
            split_record_name("www.example.com"),
            ("www".into(), "example.com".into())
        );
        assert_eq!(
            split_record_name("a.b.example.com"),
            ("a.b".into(), "example.com".into())
        );
    }

    #[test]
    fn rejects_things_that_are_not_domains() {
        for bad in ["", "localhost", "no-dot", ".leading.com", "trailing.com.", "a b.com", "sp@ce.com"] {
            assert!(!looks_like_a_domain(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn accepts_ordinary_domains() {
        for good in ["example.com", "www.example.com", "a-b.example.co.uk", "x.y.z.example.io"] {
            assert!(looks_like_a_domain(good), "{good} must be accepted");
        }
    }

    #[tokio::test]
    async fn a_malformed_domain_is_unknown_not_a_failure() {
        let r = check_dns_points_here("not-a-domain").await;
        assert_eq!(r.state, PrereqState::Unknown);
        assert!(!r.blocks());
    }
}
