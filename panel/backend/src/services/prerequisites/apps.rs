//! The Docker-apps vertical — "can this container actually start like this?"
//!
//! The app templates are the most-used surface in the product and their failures
//! are the least self-explanatory: the deploy runs for as long as it takes to
//! pull the image, and *then* reports something like
//! `Deploy failed: port is already allocated` or nothing at all while the
//! container restart-loops on a missing password. Every condition checked here is
//! knowable before the pull starts.
//!
//! # Why the checks are pure and the I/O is not
//!
//! Each `check_*` takes facts and returns a verdict. Gathering the facts (three
//! agent calls and a query) lives in the route. That split is deliberate — it is
//! what makes the interesting cases testable without a Docker daemon, and lesson
//! #79f is the reason: the SSL ladder was untestable for exactly as long as its
//! decision stayed inside an async DB loop.

use std::collections::HashMap;

use super::{PrereqResult, Remediation};

/// What the user is about to deploy.
#[derive(Debug, Clone)]
pub struct AppDeployIntent {
    pub template_id: String,
    pub name: String,
    pub port: u16,
    pub env: HashMap<String, String>,
    pub memory_mb: Option<u64>,
}

/// One environment variable a template declares, as the agent reports it.
#[derive(Debug, Clone)]
pub struct AppEnvSpec {
    pub name: String,
    pub label: String,
    pub default: String,
    pub required: bool,
    pub secret: bool,
}

/// Who currently holds a host port, in the user's terms.
#[derive(Debug, Clone)]
pub struct PortHolder {
    pub port: u16,
    /// e.g. "the app `grafana`" or "the site example.com".
    pub description: String,
}

/// Everything about the host the checks need, gathered once.
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    pub used_ports: Vec<PortHolder>,
    /// Names of containers DockPanel already manages.
    pub taken_names: Vec<String>,
    pub mem_total_mb: Option<u64>,
    pub mem_used_mb: Option<u64>,
    /// The agent's bind probe for the requested port. `None` when we couldn't ask
    /// — an older fleet agent has no `/system/port-check`, and a check we cannot
    /// run must degrade to `unknown`, never to a refusal.
    pub port_probe_free: Option<bool>,
}

impl HostFacts {
    fn holder_of(&self, port: u16) -> Option<&PortHolder> {
        self.used_ports.iter().find(|h| h.port == port)
    }

    /// The next port at or above `from` that nothing known is using.
    ///
    /// Deliberately deterministic: the preflight re-runs as the user types, and a
    /// suggestion that changed each time would be worse than none. Only consults
    /// what we know — the agent probe covers a single port, so a suggestion is a
    /// starting point, not a promise.
    fn next_free_port(&self, from: u16) -> Option<u16> {
        (from.max(1024)..=65000).find(|p| self.holder_of(*p).is_none())
    }
}

/// Check: every environment variable the template *requires* has a value.
///
/// This is the highest-yield check in the vertical. 104 of the shipped templates
/// declare at least one variable that is `required` with no default — the
/// database passwords, `SECRET_KEY_BASE`, `MEILI_MASTER_KEY`, and so on. The
/// deploy form marks them with a red asterisk and then lets you submit anyway:
/// the button is gated only on the app name being non-empty.
///
/// What happens next is the part worth blocking. The agent resolves each variable
/// as `env.get(name).unwrap_or(default)` and then **drops it entirely if the
/// result is empty** — so the variable is not passed as blank, it is not passed at
/// all. `postgres` refuses to initialise, `grafana` silently keeps its built-in
/// password, and the user finds out after the pull, from container logs.
///
/// `Blocking`, because the template's own author declared it required and the fix
/// is to type something into a field that is already on screen.
pub fn check_required_env(intent: &AppDeployIntent, specs: &[AppEnvSpec]) -> PrereqResult {
    let key = "apps.required_env";

    let missing: Vec<&AppEnvSpec> = specs
        .iter()
        .filter(|s| s.required)
        // Mirror the agent's own resolution rule exactly: a provided value wins,
        // otherwise the default, and an empty result is omitted from the container.
        .filter(|s| {
            intent
                .env
                .get(&s.name)
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .is_none()
                && s.default.trim().is_empty()
        })
        .collect();

    if missing.is_empty() {
        return PrereqResult::satisfied(
            key,
            "Required settings are filled in",
            "Every setting this app needs has a value.",
        );
    }

    let names: Vec<String> = missing
        .iter()
        .map(|s| format!("{} ({})", s.label, s.name))
        .collect();
    let secrets: Vec<&&AppEnvSpec> = missing.iter().filter(|s| s.secret).collect();

    let detail = if secrets.len() == missing.len() {
        format!(
            "{} needs a value for {}. These are passwords or keys with no safe default — \
             the container is started without them entirely, which usually means it refuses \
             to start or comes up with no protection at all.\n\n\
             Use Generate to have DockPanel pick a strong value.",
            intent.template_id,
            names.join(", ")
        )
    } else {
        format!(
            "{} needs a value for {}. Without it the setting is not passed to the container \
             at all, so the app starts misconfigured — usually failing minutes later, after \
             the image has finished downloading.",
            intent.template_id,
            names.join(", ")
        )
    };

    PrereqResult::blocking(
        key,
        if missing.len() == 1 {
            format!("{} needs a value", missing[0].label)
        } else {
            format!("{} required settings have no value", missing.len())
        },
        detail,
    )
    .with_observed(names)
}

/// Check: is the requested host port actually free?
///
/// `POST /api/apps/deploy` validates only that the port is non-zero. The sites
/// surface has had "that port is already in use by another site on this server"
/// since long before this layer existed (`routes/sites.rs`); apps never got the
/// equivalent, so a collision surfaces as a Docker error after the pull.
///
/// Three sources, in order of authority: the host's own bind probe, then the
/// containers DockPanel manages, then the sites it proxies.
pub fn check_port_available(intent: &AppDeployIntent, facts: &HostFacts) -> PrereqResult {
    let key = "apps.port_available";
    let port = intent.port;

    if port == 0 {
        return PrereqResult::blocking(
            key,
            "Choose a port",
            "Pick the host port this app should be reachable on.",
        );
    }

    let suggestion = facts.next_free_port(port.saturating_add(1)).map(|p| Remediation::Value {
        label: "Use this port instead".to_string(),
        value: p.to_string(),
        applies_to: "port".to_string(),
        secret: false,
    });

    // Something DockPanel knows about holds it — we can name what.
    if let Some(holder) = facts.holder_of(port) {
        let mut r = PrereqResult::blocking(
            key,
            format!("Port {port} is already in use"),
            format!(
                "Port {port} is taken by {}. Two things cannot publish on the same host \
                 port, so this deploy would fail once the image finished downloading.",
                holder.description
            ),
        )
        .with_observed(vec![holder.description.clone()]);
        if let Some(s) = suggestion {
            r = r.with_remediation(s);
        }
        return r;
    }

    match facts.port_probe_free {
        Some(true) => PrereqResult::satisfied(
            key,
            format!("Port {port} is free"),
            format!("Nothing is listening on port {port}."),
        ),
        Some(false) => {
            // Nothing of ours holds it, yet the bind failed — so something outside
            // DockPanel does. We can't name it, but the consequence is identical.
            let mut r = PrereqResult::blocking(
                key,
                format!("Port {port} is already in use"),
                format!(
                    "Something on this server is already listening on port {port}. It isn't \
                     managed by DockPanel, so it may be another service you installed \
                     yourself. Pick a different port, or stop whatever is using this one."
                ),
            );
            if let Some(s) = suggestion {
                r = r.with_remediation(s);
            }
            r
        }
        None => PrereqResult::unknown(
            key,
            "Couldn't check the port",
            format!(
                "DockPanel couldn't ask this server whether port {port} is free, so it will \
                 be attempted as-is."
            ),
        ),
    }
}

/// Check: is the app name already taken?
///
/// Container names are unique per host, and the deploy form pre-fills the name
/// with the template id — so deploying a second Postgres collides by default.
pub fn check_name_available(intent: &AppDeployIntent, facts: &HostFacts) -> PrereqResult {
    let key = "apps.name_available";
    let name = intent.name.trim();

    if name.is_empty() {
        return PrereqResult::unknown(key, "Name this app", "Give the app a name to continue.");
    }

    if facts.taken_names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        // Suggest name-2, name-3, … rather than a random suffix: predictable, and
        // it matches what someone deploying a second copy would have typed.
        let suggestion = (2..50)
            .map(|n| format!("{name}-{n}"))
            .find(|candidate| !facts.taken_names.iter().any(|n| n.eq_ignore_ascii_case(candidate)));

        let mut r = PrereqResult::blocking(
            key,
            format!("An app called {name} already exists"),
            format!(
                "This server already runs an app named {name}. Container names have to be \
                 unique, so this deploy would be refused. Pick a different name."
            ),
        )
        .with_observed(vec![name.to_string()]);

        if let Some(s) = suggestion {
            r = r.with_remediation(Remediation::Value {
                label: "Use this name instead".to_string(),
                value: s,
                applies_to: "name".to_string(),
                secret: false,
            });
        }
        return r;
    }

    PrereqResult::satisfied(key, "Name is available", format!("No other app is called {name}."))
}

/// Check: does the server have the memory this deploy asks for?
///
/// `Warning`, never blocking. Over-committing memory is normal practice, the
/// kernel will page, and the operator may know something we don't about what is
/// about to be freed. What is *not* acceptable is finding out from an OOM kill.
pub fn check_resource_headroom(intent: &AppDeployIntent, facts: &HostFacts) -> PrereqResult {
    let key = "apps.resource_headroom";

    let (Some(total), Some(used), Some(want)) = (facts.mem_total_mb, facts.mem_used_mb, intent.memory_mb)
    else {
        return PrereqResult::unknown(
            key,
            "Memory not checked",
            "No memory limit was set for this app, or this server's memory couldn't be read.",
        );
    };

    let free = total.saturating_sub(used);

    if want > total {
        return PrereqResult::warning(
            key,
            "That's more memory than this server has",
            format!(
                "This app is limited to {want} MB, but the server only has {total} MB in total \
                 ({free} MB currently free). The limit will be accepted, but the container can \
                 never reach it — and the server will start swapping first."
            ),
        )
        .with_expected(format!("{total} MB total"))
        .with_observed(vec![format!("{want} MB requested"), format!("{free} MB free")]);
    }

    if want > free {
        return PrereqResult::warning(
            key,
            "Less free memory than this app is allowed",
            format!(
                "This app is allowed {want} MB but only {free} MB of the server's {total} MB is \
                 free right now. It will still start; if it actually uses its full limit, the \
                 kernel will have to reclaim memory from something else."
            ),
        )
        .with_expected(format!("{free} MB free"))
        .with_observed(vec![format!("{want} MB requested")]);
    }

    PrereqResult::satisfied(
        key,
        "Enough memory",
        format!("{free} MB free, {want} MB requested."),
    )
}

/// Evaluate every Docker-app prerequisite for one intended deploy.
///
/// Order matters only for presentation: the first blocker is the one the caller
/// shows against a gated button, so the cheapest thing to fix comes first.
pub fn evaluate(intent: &AppDeployIntent, specs: &[AppEnvSpec], facts: &HostFacts) -> Vec<PrereqResult> {
    vec![
        check_required_env(intent, specs),
        check_port_available(intent, facts),
        check_name_available(intent, facts),
        check_resource_headroom(intent, facts),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> AppDeployIntent {
        AppDeployIntent {
            template_id: "postgres".into(),
            name: "postgres".into(),
            port: 5432,
            env: HashMap::new(),
            memory_mb: None,
        }
    }

    fn spec(name: &str, default: &str, required: bool, secret: bool) -> AppEnvSpec {
        AppEnvSpec {
            name: name.into(),
            label: name.into(),
            default: default.into(),
            required,
            secret,
        }
    }

    // ── required env ──────────────────────────────────────────────────────

    /// The shipped shape of the 104 affected templates: required, no default.
    #[test]
    fn a_required_var_with_no_default_and_no_value_blocks() {
        let r = check_required_env(&intent(), &[spec("POSTGRES_PASSWORD", "", true, true)]);
        assert!(r.blocks());
        assert!(r.detail.contains("Generate"), "an all-secret set should offer generation");
    }

    #[test]
    fn a_required_var_with_a_default_is_satisfied() {
        // The agent falls back to the default, so nothing is missing.
        let r = check_required_env(&intent(), &[spec("PUID", "1000", true, false)]);
        assert!(!r.blocks());
    }

    #[test]
    fn an_optional_var_never_blocks() {
        let r = check_required_env(&intent(), &[spec("TZ", "", false, false)]);
        assert!(!r.blocks());
    }

    /// Whitespace is not a value: the agent trims nothing, but a container given
    /// `PASSWORD=" "` is misconfigured in a way the user did not intend.
    #[test]
    fn whitespace_does_not_satisfy_a_required_var() {
        let mut i = intent();
        i.env.insert("POSTGRES_PASSWORD".into(), "   ".into());
        assert!(check_required_env(&i, &[spec("POSTGRES_PASSWORD", "", true, true)]).blocks());
    }

    #[test]
    fn a_supplied_value_satisfies_the_check() {
        let mut i = intent();
        i.env.insert("POSTGRES_PASSWORD".into(), "hunter2".into());
        assert!(!check_required_env(&i, &[spec("POSTGRES_PASSWORD", "", true, true)]).blocks());
    }

    // ── port ──────────────────────────────────────────────────────────────

    #[test]
    fn a_port_held_by_a_managed_app_blocks_and_names_the_holder() {
        let facts = HostFacts {
            used_ports: vec![PortHolder { port: 5432, description: "the app `pg-old`".into() }],
            port_probe_free: Some(false),
            ..Default::default()
        };
        let r = check_port_available(&intent(), &facts);
        assert!(r.blocks());
        assert!(r.detail.contains("pg-old"), "must name what holds the port");
        assert!(matches!(r.remediation, Some(Remediation::Value { .. })));
    }

    /// Nothing of ours holds it, but the host says the bind fails — still fatal,
    /// we just can't say who.
    #[test]
    fn a_port_held_by_something_unmanaged_still_blocks() {
        let facts = HostFacts { port_probe_free: Some(false), ..Default::default() };
        let r = check_port_available(&intent(), &facts);
        assert!(r.blocks());
        assert!(r.detail.contains("managed by DockPanel"));
        assert!(r.observed.is_empty(), "we cannot name a holder we don't manage");
    }

    /// The fleet case: an agent too old to have `/system/port-check`. A check we
    /// cannot run must never turn into a refusal.
    #[test]
    fn an_unprobeable_port_is_unknown_not_blocked() {
        let facts = HostFacts { port_probe_free: None, ..Default::default() };
        let r = check_port_available(&intent(), &facts);
        assert!(!r.blocks());
        assert_eq!(r.state, super::super::PrereqState::Unknown);
    }

    #[test]
    fn a_free_port_is_satisfied() {
        let facts = HostFacts { port_probe_free: Some(true), ..Default::default() };
        assert_eq!(
            check_port_available(&intent(), &facts).state,
            super::super::PrereqState::Satisfied
        );
    }

    /// The suggestion must skip every port we know is taken, not merely the one
    /// that was asked for.
    #[test]
    fn the_suggested_port_skips_all_known_holders() {
        let facts = HostFacts {
            used_ports: vec![
                PortHolder { port: 8080, description: "a".into() },
                PortHolder { port: 8081, description: "b".into() },
                PortHolder { port: 8082, description: "c".into() },
            ],
            port_probe_free: Some(false),
            ..Default::default()
        };
        let mut i = intent();
        i.port = 8080;
        let r = check_port_available(&i, &facts);
        match r.remediation {
            Some(Remediation::Value { ref value, .. }) => assert_eq!(value, "8083"),
            other => panic!("expected a port suggestion, got {other:?}"),
        }
    }

    // ── name ──────────────────────────────────────────────────────────────

    #[test]
    fn a_taken_name_blocks_and_suggests_the_next_free_one() {
        let facts = HostFacts {
            taken_names: vec!["postgres".into(), "postgres-2".into()],
            ..Default::default()
        };
        let r = check_name_available(&intent(), &facts);
        assert!(r.blocks());
        match r.remediation {
            Some(Remediation::Value { ref value, .. }) => assert_eq!(value, "postgres-3"),
            other => panic!("expected a name suggestion, got {other:?}"),
        }
    }

    /// Docker treats names case-insensitively for our purposes here; a check that
    /// missed `Postgres` would hand the user a name that still collides.
    #[test]
    fn name_collision_is_case_insensitive() {
        let facts = HostFacts { taken_names: vec!["POSTGRES".into()], ..Default::default() };
        assert!(check_name_available(&intent(), &facts).blocks());
    }

    // ── memory ────────────────────────────────────────────────────────────

    #[test]
    fn asking_for_more_memory_than_the_box_has_warns_but_never_blocks() {
        let mut i = intent();
        i.memory_mb = Some(8192);
        let facts = HostFacts { mem_total_mb: Some(2048), mem_used_mb: Some(900), ..Default::default() };
        let r = check_resource_headroom(&i, &facts);
        assert!(!r.blocks(), "over-committing memory is the operator's call");
        assert_eq!(r.state, super::super::PrereqState::Unsatisfied);
    }

    #[test]
    fn no_memory_limit_means_nothing_to_check() {
        let facts = HostFacts { mem_total_mb: Some(2048), mem_used_mb: Some(900), ..Default::default() };
        assert_eq!(
            check_resource_headroom(&intent(), &facts).state,
            super::super::PrereqState::Unknown
        );
    }

    #[test]
    fn a_limit_that_fits_in_free_memory_is_satisfied() {
        let mut i = intent();
        i.memory_mb = Some(512);
        let facts = HostFacts { mem_total_mb: Some(2048), mem_used_mb: Some(900), ..Default::default() };
        assert_eq!(
            check_resource_headroom(&i, &facts).state,
            super::super::PrereqState::Satisfied
        );
    }

    // ── the set ───────────────────────────────────────────────────────────

    /// The whole point of the gate: a deploy that would fail is refused before the
    /// image pull, and `first_blocker` names the reason.
    #[test]
    fn evaluate_surfaces_the_first_blocker() {
        let facts = HostFacts {
            used_ports: vec![PortHolder { port: 5432, description: "the app `pg`".into() }],
            port_probe_free: Some(false),
            ..Default::default()
        };
        let results = evaluate(&intent(), &[spec("POSTGRES_PASSWORD", "", true, true)], &facts);
        let blocker = super::super::first_blocker(&results).expect("must block");
        assert_eq!(blocker.key, "apps.required_env");
    }

    #[test]
    fn a_complete_intent_on_a_healthy_host_blocks_on_nothing() {
        let mut i = intent();
        i.env.insert("POSTGRES_PASSWORD".into(), "s3cret".into());
        i.memory_mb = Some(256);
        let facts = HostFacts {
            mem_total_mb: Some(2048),
            mem_used_mb: Some(400),
            port_probe_free: Some(true),
            ..Default::default()
        };
        let results = evaluate(&i, &[spec("POSTGRES_PASSWORD", "", true, true)], &facts);
        assert!(super::super::first_blocker(&results).is_none());
    }
}
