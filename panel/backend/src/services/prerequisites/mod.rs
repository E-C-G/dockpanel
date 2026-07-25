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
//!
//! # Layout
//!
//! This module holds the shared vocabulary — the result type, the severity rule,
//! the remediation shapes. One submodule per vertical:
//!
//! | Module   | Answers |
//! |----------|---------|
//! | [`dns`]  | does this domain point at this server yet? (v2.28.0) |
//! | [`apps`] | can this container actually start with these settings? |
//! | [`mail`] | are this domain's mail records actually published? |
//! | [`backups`] | will these backups survive losing this machine? |
//!
//! Adding a vertical is a new submodule plus a route; it is never an edit to an
//! existing check.
//!
//! [`copy`] holds every sentence all four of them say. A check module decides
//! *which* outcome a situation is; it does not decide what that outcome says, and
//! it cannot, because the words are not in it. That separation is what lets the
//! documentation be generated rather than written — see [`copy::manual`].

use serde::Serialize;

pub mod apps;
pub mod backups;
pub mod copy;
pub mod dns;
pub mod mail;

// The DNS vertical shipped in v2.28.0 addressed as
// `services::prerequisites::check_dns_points_here`, and its wiring was verified
// on a fresh box. Re-export so splitting the file moves no call sites.
pub use dns::check_dns_points_here;

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
    /// Why this record exists, in the user's terms. Optional because the DNS
    /// vertical's single record needs no caption — the callout says it. A set of
    /// five mail records does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Whether this particular record was found published. `None` when the set
    /// was produced without checking (the "here is what to create" case).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

impl DnsRecordHint {
    /// A record with no caption and no observed state — the v2.28.0 shape.
    pub fn new(
        name: impl Into<String>,
        fqdn: impl Into<String>,
        record_type: impl Into<String>,
        value: impl Into<String>,
        ttl: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            fqdn: fqdn.into(),
            record_type: record_type.into(),
            value: value.into(),
            ttl: ttl.into(),
            purpose: None,
            present: None,
        }
    }

    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    pub fn with_present(mut self, present: bool) -> Self {
        self.present = Some(present);
        self
    }
}

/// The concrete thing that would fix an unmet prerequisite.
///
/// Deliberately a closed set of SHAPES rather than free prose: every arm is
/// something the frontend can render as an action (copy this, click this) rather
/// than as a sentence the user has to translate into one. Convention #4 of the
/// design doc — give `remediation` real values, not a description.
///
/// Tagged by `kind` so the renderer dispatches on data, not on the check's key.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Remediation {
    /// One DNS record to create. The DNS vertical's shape.
    DnsRecord { record: DnsRecordHint },
    /// A set of records that must all exist — mail's MX/SPF/DKIM/DMARC, where
    /// each carries its own `present` flag so the user sees which one is missing
    /// rather than being told to re-check all five.
    DnsRecords { records: Vec<DnsRecordHint> },
    /// A value the panel can supply on the user's behalf: the next free port, a
    /// generated password. `applies_to` names the form field it belongs in, so
    /// the frontend can offer to fill it rather than making the user retype it.
    Value {
        label: String,
        value: String,
        applies_to: String,
        /// Never echo this into logs or activity records.
        #[serde(default)]
        secret: bool,
    },
    /// Somewhere else in the product the user has to go and set something up.
    Link { label: String, href: String },
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
    /// The fix, when there is a concrete one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

impl PrereqResult {
    /// True when a control gated on this prerequisite should be disabled.
    ///
    /// This is the ONLY rule for gating a control. Never re-derive it — an
    /// `unknown` must never block, and a `warning` must never block, however
    /// confident the check happens to feel.
    pub fn blocks(&self) -> bool {
        self.state == PrereqState::Unsatisfied && self.severity == PrereqSeverity::Blocking
    }

    /// Fixture constructor. **Tests only, deliberately.**
    ///
    /// In the running product there is exactly one way to produce a
    /// `PrereqResult` — [`copy::Prereq::result`] — and that is not a convention,
    /// it is the absence of an alternative: a check cannot invent a sentence
    /// because it has no constructor that takes one. Removing the four
    /// hand-rolled constructors that shipped through v2.29.0 is what turned the
    /// registry from the recommended path into the only path.
    #[cfg(test)]
    pub(crate) fn fixture(
        key: impl Into<String>,
        state: PrereqState,
        severity: PrereqSeverity,
    ) -> Self {
        Self {
            key: key.into(),
            state,
            severity,
            title: String::new(),
            detail: String::new(),
            expected: None,
            observed: Vec::new(),
            remediation: None,
        }
    }

    pub fn with_expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self
    }

    pub fn with_observed(mut self, observed: Vec<String>) -> Self {
        self.observed = observed;
        self
    }

    pub fn with_remediation(mut self, remediation: Remediation) -> Self {
        self.remediation = Some(remediation);
        self
    }
}

/// The first blocking result in a set, if any.
///
/// A surface with several prerequisites gates on the whole set, and should say
/// which one it is gating on rather than listing everything at equal urgency.
pub fn first_blocker(results: &[PrereqResult]) -> Option<&PrereqResult> {
    results.iter().find(|r| r.blocks())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warning(key: &str) -> PrereqResult {
        PrereqResult::fixture(key, PrereqState::Unsatisfied, PrereqSeverity::Warning)
    }
    fn blocking(key: &str) -> PrereqResult {
        PrereqResult::fixture(key, PrereqState::Unsatisfied, PrereqSeverity::Blocking)
    }
    fn unknown(key: &str) -> PrereqResult {
        PrereqResult::fixture(key, PrereqState::Unknown, PrereqSeverity::Info)
    }

    /// A `Warning` must never gate a control — only `Blocking` does. This is the
    /// s252 orange-cloud case: it looks unsatisfied but demonstrably works.
    #[test]
    fn only_blocking_unsatisfied_results_gate_a_control() {
        assert!(!warning("t").blocks(), "a warning must let the user proceed");
        assert!(blocking("t").blocks());

        assert!(!PrereqResult::fixture("t", PrereqState::Satisfied, PrereqSeverity::Info).blocks());
        assert!(
            !unknown("t").blocks(),
            "an undeterminable check must never block"
        );
    }

    #[test]
    fn first_blocker_ignores_warnings_and_unknowns() {
        let set = vec![warning("a"), unknown("b"), blocking("c"), blocking("d")];
        assert_eq!(first_blocker(&set).map(|r| r.key.as_str()), Some("c"));
        assert!(first_blocker(&set[..2]).is_none());
    }

    /// The remediation shapes must round-trip as a tagged union — the frontend
    /// dispatches on `kind`, so a rename here is a silent renderer break.
    #[test]
    fn remediation_serializes_with_a_kind_tag() {
        let v = serde_json::to_value(Remediation::Value {
            label: "Free port".into(),
            value: "8081".into(),
            applies_to: "port".into(),
            secret: false,
        })
        .unwrap();
        assert_eq!(v["kind"], "value");
        assert_eq!(v["value"], "8081");

        let r = serde_json::to_value(Remediation::DnsRecord {
            record: DnsRecordHint::new("@", "example.com", "A", "1.2.3.4", "300"),
        })
        .unwrap();
        assert_eq!(r["kind"], "dns_record");
        assert_eq!(r["record"]["value"], "1.2.3.4");
        assert!(
            r["record"].get("purpose").is_none(),
            "an absent caption must not serialize as null"
        );
    }
}
