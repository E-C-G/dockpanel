//! Opening ports in the firewall this box is actually enforcing with.
//!
//! The agent only ever spoke `ufw`. On the RHEL family the running firewall is
//! **firewalld**, so every `ufw allow` was either a no-op or landed in a
//! rule set nothing was consulting — while the caller logged success anyway
//! (s265). `setup.sh` has the same distinction as `FW_MGR`; this is its
//! agent-side counterpart.

use crate::safe_cmd::safe_command;
use std::time::Duration;
use tokio::sync::OnceCell;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Firewall {
    Firewalld,
    Ufw,
    /// No firewall is running. Opening a port is vacuously fine — the port is
    /// already reachable — so callers should treat this as success, not
    /// failure, or they will warn about a problem the box does not have.
    None,
}

static FW: OnceCell<Firewall> = OnceCell::const_new();

/// Detected once per process. A firewall can in principle be installed while
/// the agent runs, but every caller here is a service installer, and the
/// alternative is re-probing on every port.
pub async fn detect() -> Firewall {
    *FW.get_or_init(|| async {
        // firewalld first: when both are present it is the one whose nftables
        // rules the kernel is actually consulting on these distros.
        if run("firewall-cmd", &["--state"]).await {
            Firewall::Firewalld
        } else if run("ufw", &["status"]).await {
            Firewall::Ufw
        } else {
            Firewall::None
        }
    })
    .await
}

/// Open `port`/tcp. Returns whether the port is now allowed.
///
/// Unlike the code this replaces, the result is **returned** rather than
/// discarded — a caller that logs "ports opened" without checking is stating
/// something it does not know.
pub async fn allow_tcp(port: &str) -> bool {
    match detect().await {
        Firewall::Firewalld => {
            let spec = format!("{port}/tcp");
            // --permanent survives reboots but does nothing until reloaded;
            // the plain call applies now but is lost on restart. Both, then.
            let permanent = run("firewall-cmd", &["--permanent", "--add-port", &spec]).await;
            let runtime = run("firewall-cmd", &["--add-port", &spec]).await;
            permanent && runtime
        }
        Firewall::Ufw => run("ufw", &["allow", &format!("{port}/tcp")]).await,
        Firewall::None => true,
    }
}

/// Apply staged firewalld rules. No-op elsewhere.
pub async fn reload() {
    if detect().await == Firewall::Firewalld {
        let _ = run("firewall-cmd", &["--reload"]).await;
    }
}

/// Open several ports and report which ones failed, so the caller can say
/// something true about the outcome.
pub async fn allow_tcp_ports(ports: &[&str]) -> Vec<String> {
    let mut failed = Vec::new();
    for p in ports {
        if !allow_tcp(p).await {
            failed.push((*p).to_string());
        }
    }
    reload().await;
    failed
}

async fn run(bin: &str, args: &[&str]) -> bool {
    tokio::time::timeout(
        Duration::from_secs(60),
        safe_command(bin).args(args).output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|o| o.status.success())
    .unwrap_or(false)
}
