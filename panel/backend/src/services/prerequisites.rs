//! The prerequisite layer — "what you need to do first".
//!
//! Features declare what must already be true before they can work; a shared
//! checker evaluates those conditions and returns STRUCTURED results; the
//! frontend renders them at one of three urgencies. One registry of checks and
//! one registry of copy, so guidance can't drift the way scattered `title`
//! attributes do.
//!
//! The governing rule (brief §3A.1): **block only when it would actually fail,
//! warn when it probably will, explain passively otherwise.** Over-blocking is
//! its own bad UX.
//!
//! Why this exists as a registry rather than an inline guard: the DNS condition
//! was already being computed correctly inside `POST /api/sites/{id}/ssl`, which
//! returned a precise 412 — but as a prose string, at one call site, at the
//! moment of failure. Nothing else in the product could ask "is this domain
//! pointed here yet?" before the user committed to an action. Promoting the
//! check to a callable that returns data rather than a sentence is what lets the
//! create-site form, the SSL panel and the 412 all share one source of truth.

use serde::Serialize;
use std::net::IpAddr;

/// Whether a prerequisite currently holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrereqState {
    /// Verified true — the dependent action can proceed.
    Satisfied,
    /// Verified false — the dependent action will fail or half-succeed.
    Unsatisfied,
    /// We could not determine it. Never treated as failure: an unknown must not
    /// block a user whose setup is fine but whose check we couldn't run.
    Unknown,
}

/// How loudly to present an unmet prerequisite — chosen by consequence, not by
/// how confident the check is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrereqSeverity {
    /// The action *will* fail. Gate the control and say why.
    Blocking,
    /// The action *probably* will, or may leave a mess. Warn, but let them proceed.
    Warning,
    /// Context only. Passive helper text.
    Info,
}

/// The exact DNS record a user should create, with values filled in.
///
/// Per brief §3A.3 this must be the record itself — name, type, value, TTL —
/// never a description of a record.
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecordHint {
    /// The host/name field as most DNS UIs want it (`@` for an apex).
    pub name: String,
    /// The same record spelled as a full domain, for the providers that want that.
    pub fqdn: String,
    pub record_type: String,
    pub value: String,
    pub ttl: String,
}

/// The result of evaluating one prerequisite.
#[derive(Debug, Clone, Serialize)]
pub struct PrereqResult {
    /// Stable identifier, e.g. `dns.points_here`. Greppable; the frontend keys
    /// copy and test selectors off it.
    pub key: String,
    pub state: PrereqState,
    pub severity: PrereqSeverity,
    /// One short line naming the situation.
    pub title: String,
    /// The explanation, in the user's terms — what is true and what to do.
    pub detail: String,
    /// What we expected to see (the server's address, for DNS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// What we actually observed.
    pub observed: Vec<String>,
    /// The record to create, when there is a concrete one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<DnsRecordHint>,
}

impl PrereqResult {
    /// True when a control gated on this prerequisite should be disabled.
    pub fn blocks(&self) -> bool {
        self.state == PrereqState::Unsatisfied && self.severity == PrereqSeverity::Blocking
    }
}

/// Split a domain into the (host, apex-ish) pair used to spell a DNS record.
///
/// Deliberately a heuristic, not a Public Suffix List lookup: pulling in a PSL
/// crate (and keeping it current) is not worth it when the cost of being wrong
/// is cosmetic. A multi-part TLD like `example.co.uk` will be described as host
/// `example` under `co.uk`, which is wrong — which is exactly why every result
/// also carries the unambiguous `fqdn` spelling, and why the copy tells the user
/// to use whichever field their provider asks for.
fn split_record_name(domain: &str) -> (String, String) {
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
fn looks_like_a_domain(domain: &str) -> bool {
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
/// This is the prerequisite behind every HTTP-01 certificate, and the single
/// most common reason a new user's site doesn't work.
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
    let key = "dns.points_here".to_string();
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    if !looks_like_a_domain(&domain) {
        return PrereqResult {
            key,
            state: PrereqState::Unknown,
            severity: PrereqSeverity::Info,
            title: "Enter a domain".to_string(),
            detail: "Once you enter a domain, DockPanel checks whether it already points here."
                .to_string(),
            expected: None,
            observed: Vec::new(),
            remediation: None,
        };
    }

    let server_ip = crate::helpers::detect_public_ip_cached().await;
    if server_ip.is_empty() {
        // We don't know our own address, so we cannot judge theirs. Say so
        // plainly rather than inventing a verdict.
        return PrereqResult {
            key,
            state: PrereqState::Unknown,
            severity: PrereqSeverity::Info,
            title: "Couldn't determine this server's public address".to_string(),
            detail: "DockPanel could not detect its own public IP, so it can't check whether \
                     the domain points here. SSL issuance will still be attempted."
                .to_string(),
            expected: None,
            observed: Vec::new(),
            remediation: None,
        };
    }

    let (host, apex) = split_record_name(&domain);
    let record_type = if server_ip.parse::<IpAddr>().map(|ip| ip.is_ipv6()).unwrap_or(false) {
        "AAAA"
    } else {
        "A"
    };
    let hint = DnsRecordHint {
        name: host.clone(),
        fqdn: domain.clone(),
        record_type: record_type.to_string(),
        value: server_ip.clone(),
        ttl: "Auto (or 300)".to_string(),
    };

    let resolved: Vec<String> = match tokio::net::lookup_host(format!("{domain}:80")).await {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => Vec::new(),
    };

    if resolved.is_empty() {
        return PrereqResult {
            key,
            state: PrereqState::Unsatisfied,
            severity: PrereqSeverity::Blocking,
            title: format!("{domain} doesn't resolve yet"),
            detail: format!(
                "No DNS record was found for {domain}. Create the record below at whoever \
                 manages this domain's DNS, then check again. New records usually appear \
                 within a few minutes."
            ),
            expected: Some(server_ip),
            observed: Vec::new(),
            remediation: Some(hint),
        };
    }

    if resolved.iter().any(|ip| ip == &server_ip) {
        return PrereqResult {
            key,
            state: PrereqState::Satisfied,
            severity: PrereqSeverity::Info,
            title: format!("{domain} points here"),
            detail: format!("{domain} resolves to this server ({server_ip})."),
            expected: Some(server_ip),
            observed: resolved,
            remediation: None,
        };
    }

    PrereqResult {
        key,
        state: PrereqState::Unsatisfied,
        severity: PrereqSeverity::Warning,
        title: format!("{domain} points somewhere else"),
        detail: format!(
            "{domain} resolves to {} rather than this server ({server_ip}).\n\n\
             If you use Cloudflare's proxy (the orange cloud), this is expected and \
             certificate issuance normally still works — Cloudflare passes the validation \
             request through to this server. You can continue.\n\n\
             Otherwise the domain is pointed at a different host. Update the record below \
             and check again{}.",
            resolved.join(", "),
            if host == "@" {
                String::new()
            } else {
                format!(" — note this is the record for {}, not for {apex}", &domain)
            }
        ),
        expected: Some(server_ip),
        observed: resolved,
        remediation: Some(hint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A `Warning` must never gate a control — only `Blocking` does. This is the
    /// s252 orange-cloud case: it looks unsatisfied but demonstrably works.
    #[test]
    fn only_blocking_unsatisfied_results_gate_a_control() {
        let warn = PrereqResult {
            key: "dns.points_here".into(),
            state: PrereqState::Unsatisfied,
            severity: PrereqSeverity::Warning,
            title: String::new(),
            detail: String::new(),
            expected: None,
            observed: vec![],
            remediation: None,
        };
        assert!(!warn.blocks(), "a warning must let the user proceed");

        let blocking = PrereqResult { severity: PrereqSeverity::Blocking, ..warn.clone() };
        assert!(blocking.blocks());

        let satisfied = PrereqResult { state: PrereqState::Satisfied, ..blocking.clone() };
        assert!(!satisfied.blocks());

        let unknown = PrereqResult { state: PrereqState::Unknown, ..blocking.clone() };
        assert!(!unknown.blocks(), "an undeterminable check must never block");
    }

    #[tokio::test]
    async fn a_malformed_domain_is_unknown_not_a_failure() {
        let r = check_dns_points_here("not-a-domain").await;
        assert_eq!(r.state, PrereqState::Unknown);
        assert!(!r.blocks());
    }
}
