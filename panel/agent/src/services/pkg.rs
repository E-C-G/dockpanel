//! Package facts that hold on both package-manager families.
//!
//! DockPanel supports Debian/Ubuntu **and** the RHEL family (Rocky, AlmaLinux,
//! CentOS Stream, Fedora), but every package query in the agent used to be
//! `dpkg`. On an RPM box there is no `dpkg` at all, so those queries did not
//! merely return the wrong answer — they returned `false` for *everything*,
//! and the Services page reported PHP and Fail2Ban as "not installed" while
//! both were installed and running (s265).
//!
//! There were four separate hand-rolled copies of `is_installed`, in
//! `service_installer.rs`, `php.rs`, `mail.rs`, `server_utils.rs` and
//! `iac.rs`. This module exists so there is **one** of them: a fifth copy is
//! how the fourth one got missed.
//!
//! Package *names* differ too, so a manager swap alone is not enough —
//! `pdns-server` is `pdns`, `redis-server` is `redis`, and the three Debian
//! Dovecot packages are one `dovecot`. Callers keep passing the Debian name
//! (which is what the installers use) and [`is_installed`] translates.

use crate::safe_cmd::safe_command;
use std::time::Duration;
use tokio::sync::OnceCell;

/// Which package database this box actually has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PkgMgr {
    Dpkg,
    Rpm,
    /// Neither binary is present. Every query answers `false` — the same
    /// thing the old dpkg-only code did, but now it is a stated outcome
    /// rather than an accident of which distro we happened to be on.
    Unknown,
}

static MGR: OnceCell<PkgMgr> = OnceCell::const_new();

/// Detected once per process: the package database does not change under a
/// running agent, and every status endpoint calls this.
pub async fn manager() -> PkgMgr {
    *MGR.get_or_init(|| async {
        if which("dpkg-query").await || which("dpkg").await {
            PkgMgr::Dpkg
        } else if which("rpm").await {
            PkgMgr::Rpm
        } else {
            PkgMgr::Unknown
        }
    })
    .await
}

/// The RPM name for a package the Debian-side code asks about.
///
/// Every entry here was verified against `dnf list` on a Rocky 9.8 box with
/// EPEL enabled (s265) — not inferred from the Debian name. Anything absent
/// falls through unchanged, which is right for the many packages that share a
/// name (`postfix`, `fail2ban`, `opendkim`, `certbot`, `nginx`).
fn rpm_name(debian: &str) -> &str {
    match debian {
        "pdns-server" => "pdns",
        "redis-server" => "redis",
        // Debian splits Dovecot per protocol; the RHEL family ships one package.
        "dovecot-imapd" | "dovecot-pop3d" | "dovecot-lmtpd" => "dovecot",
        // Debian's periodic-upgrade package; dnf's equivalent timer service.
        "unattended-upgrades" => "dnf-automatic",
        // The nginx ModSecurity connector, not the bare library.
        "libmodsecurity3" | "libmodsecurity3t64" => "nginx-mod-modsecurity",
        other => {
            // Debian carries one FPM package per PHP version (`php8.3-fpm`);
            // the RHEL family has a single `php-fpm` whose version comes from
            // the enabled module stream. Callers iterating 8.1..8.5 would
            // otherwise report every version absent.
            if other.starts_with("php") && other.ends_with("-fpm") {
                "php-fpm"
            } else {
                other
            }
        }
    }
}

/// True when `package` is installed. Takes the Debian package name.
///
/// Note for callers that iterate PHP versions: on RPM every `php{v}-fpm` maps
/// to the one `php-fpm`, so a `true` here means "some PHP-FPM is installed",
/// not "that specific version is". Use the version the binary reports
/// (`php-fpm -v`) when the exact version matters.
pub async fn is_installed(package: &str) -> bool {
    match manager().await {
        PkgMgr::Dpkg => {
            // `dpkg -s` exits non-zero for a package that was removed but not
            // purged; `-l` prints a line for it with a `rc` state. Requiring
            // `ii` is what distinguishes installed from residual-config.
            run_ok("dpkg", &["-l", package], |out| out.contains("ii")).await
        }
        PkgMgr::Rpm => run_ok("rpm", &["-q", rpm_name(package)], |_| true).await,
        PkgMgr::Unknown => false,
    }
}

/// Explanation for a feature whose installer is still apt-only, or `None`
/// when this box can run it.
///
/// The RHEL family can *run* DockPanel — s265 fixed the two things that
/// stopped it — but the optional-service installers below still shell out to
/// `apt-get`. Without this guard they fail with `Failed to find executable
/// apt-get: No such file or directory`, which is a true sentence that tells
/// an operator nothing about what to do. Name the limitation instead.
/// `what` is the action in progress, e.g. `"Installing PHP"`.
pub async fn apt_only_reason(what: &str) -> Option<String> {
    match manager().await {
        PkgMgr::Dpkg => None,
        _ => Some(format!(
            "{what} from the panel is not supported on this distribution yet — DockPanel's \
             optional-service installers are still Debian/Ubuntu-only. Use your system package \
             manager (dnf) and the panel will detect the result."
        )),
    }
}

/// Run a query and apply `accept` to its stdout when it exits 0.
async fn run_ok(bin: &str, args: &[&str], accept: impl Fn(&str) -> bool) -> bool {
    tokio::time::timeout(
        Duration::from_secs(120),
        safe_command(bin).args(args).output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|o| o.status.success() && accept(&String::from_utf8_lossy(&o.stdout)))
    .unwrap_or(false)
}

async fn which(cmd: &str) -> bool {
    tokio::time::timeout(
        Duration::from_secs(30),
        safe_command("which").arg(cmd).output(),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .map(|o| o.status.success())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_names_that_actually_differ() {
        assert_eq!(rpm_name("pdns-server"), "pdns");
        assert_eq!(rpm_name("redis-server"), "redis");
        assert_eq!(rpm_name("dovecot-imapd"), "dovecot");
        assert_eq!(rpm_name("dovecot-lmtpd"), "dovecot");
        assert_eq!(rpm_name("unattended-upgrades"), "dnf-automatic");
        assert_eq!(rpm_name("libmodsecurity3t64"), "nginx-mod-modsecurity");
    }

    #[test]
    fn collapses_every_php_fpm_version_to_the_single_rpm_package() {
        for v in ["8.1", "8.2", "8.3", "8.4", "8.5"] {
            assert_eq!(rpm_name(&format!("php{v}-fpm")), "php-fpm");
        }
        assert_eq!(rpm_name("php-fpm"), "php-fpm");
    }

    #[test]
    fn leaves_shared_names_alone() {
        for p in ["postfix", "fail2ban", "opendkim", "certbot", "nginx"] {
            assert_eq!(rpm_name(p), p);
        }
    }
}
