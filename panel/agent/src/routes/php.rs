use axum::{
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use crate::safe_cmd::{safe_command, safe_command_unsandboxed};

use super::AppState;

/// Allowed PHP versions (distro repos, deb.sury.org, or ondrej/php PPA).
const ALLOWED_VERSIONS: &[&str] = &["8.1", "8.2", "8.3", "8.4", "8.5"];

/// PHP extensions to install with each version — each is installed only if
/// this apt source actually has a candidate for it. Newer PHP releases build
/// some of these in (8.5 absorbed opcache), so a fixed all-or-nothing list
/// would fail the entire transaction over one obsolete package name.
const COMMON_EXTENSIONS: &[&str] = &[
    "mysql", "pgsql", "sqlite3", "curl", "gd", "mbstring",
    "xml", "zip", "bcmath", "intl", "readline", "opcache", "redis", "imagick",
];

#[derive(Serialize)]
struct PhpVersion {
    version: String,
    installed: bool,
    fpm_running: bool,
    socket: String,
}

#[derive(Serialize)]
struct PhpListResponse {
    versions: Vec<PhpVersion>,
}

#[derive(Deserialize)]
struct InstallRequest {
    version: String,
}

#[derive(Serialize)]
struct InstallResponse {
    success: bool,
    message: String,
    version: String,
}

/// Check if a PHP-FPM version is installed.
///
/// On RPM boxes there is one `php-fpm` package rather than one per version,
/// so `services::pkg` collapses every `php{v}-fpm` onto it — a `true` there
/// means "some PHP-FPM is installed". `socket_exists` below is what actually
/// distinguishes the versions on either family.
async fn is_installed(version: &str) -> bool {
    crate::services::pkg::is_installed(&format!("php{version}-fpm")).await
}

/// Check if a PHP-FPM socket file exists.
fn socket_exists(version: &str) -> bool {
    std::path::Path::new(&format!("/run/php/php{version}-fpm.sock")).exists()
}

/// Check if PHP-FPM service is active.
async fn is_fpm_running(version: &str) -> bool {
    safe_command("systemctl")
        .args(["is-active", "--quiet", &format!("php{version}-fpm")])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// GET /php/versions — List all PHP versions with install/running status.
async fn list_versions() -> Json<PhpListResponse> {
    let mut versions = Vec::new();

    for &v in ALLOWED_VERSIONS {
        let installed = is_installed(v).await;
        let fpm_running = if installed {
            is_fpm_running(v).await || socket_exists(v)
        } else {
            false
        };

        versions.push(PhpVersion {
            version: v.to_string(),
            installed,
            fpm_running,
            socket: format!("/run/php/php{v}-fpm.sock"),
        });
    }

    Json(PhpListResponse { versions })
}

/// POST /php/install — Install a PHP version with common extensions.
async fn install_version(
    Json(body): Json<InstallRequest>,
) -> Result<Json<InstallResponse>, (StatusCode, Json<InstallResponse>)> {
    let version = body.version.trim();

    if !ALLOWED_VERSIONS.contains(&version) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(InstallResponse {
                success: false,
                message: format!("Invalid version. Allowed: {}", ALLOWED_VERSIONS.join(", ")),
                version: version.to_string(),
            }),
        ));
    }

    // Check if already installed
    if is_installed(version).await {
        return Ok(Json(InstallResponse {
            success: true,
            message: format!("PHP {version} is already installed"),
            version: version.to_string(),
        }));
    }

    // Ensure php{version}-fpm is available from some apt source. On Debian 13
    // and Ubuntu 24.04 the requested version may already be in the default
    // repo. If not, configure a 3rd-party repo: deb.sury.org for Debian,
    // ppa:ondrej/php for Ubuntu. (Pre-v2.8.16 used Ondrej PPA for both,
    // which doesn't work on Debian — packages aren't built for trixie.)
    let pkg_available = safe_command("bash")
        .args(["-c", &format!("apt-cache show php{version}-fpm 2>/dev/null | grep -q '^Package:'")])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !pkg_available {
        let osr = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        let parse = |key: &str| -> String {
            osr.lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_default()
        };
        let os_id = parse("ID");
        let codename = parse("VERSION_CODENAME");

        // Each repo script: (1) pre-checks that the 3rd-party repo actually
        // publishes for this release — brand-new distro releases lag behind
        // (ppa:ondrej/php had no Ubuntu 26.04 builds at that release's
        // launch); (2) verifies the requested version exists after adding.
        // Failing either way exits non-zero, and the failure branch below
        // REMOVES the added source — a dead source left behind breaks every
        // later `apt-get update` on the box with a 404.
        let repo_cmd = if os_id == "debian" && !codename.is_empty() {
            tracing::info!("Adding deb.sury.org repo for Debian ({codename})...");
            format!(
                "curl -sfI --max-time 15 https://packages.sury.org/php/dists/{codename}/Release > /dev/null || \
                     {{ echo 'deb.sury.org publishes no PHP packages for Debian {codename} yet' >&2; exit 42; }}; \
                 apt-get update -qq && apt-get install -y -qq apt-transport-https lsb-release ca-certificates curl gnupg && \
                 curl -sSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg && \
                 echo 'deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ {codename} main' > /etc/apt/sources.list.d/sury-php.list && \
                 apt-get update -qq && \
                 {{ apt-cache policy php{version}-fpm 2>/dev/null | grep -q 'Candidate: [0-9]' || \
                     {{ echo 'php{version}-fpm is still unavailable after adding deb.sury.org' >&2; exit 43; }}; }}"
            )
        } else if os_id == "ubuntu" && !codename.is_empty() {
            tracing::info!("Adding ppa:ondrej/php for Ubuntu ({codename})...");
            format!(
                "curl -sfI --max-time 15 https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/{codename}/Release > /dev/null || \
                     {{ echo 'ppa:ondrej/php publishes no packages for Ubuntu {codename} yet' >&2; exit 42; }}; \
                 apt-get update -qq && apt-get install -y -qq software-properties-common && \
                 add-apt-repository -y ppa:ondrej/php && apt-get update -qq && \
                 {{ apt-cache policy php{version}-fpm 2>/dev/null | grep -q 'Candidate: [0-9]' || \
                     {{ echo 'php{version}-fpm is still unavailable after adding ppa:ondrej/php' >&2; exit 43; }}; }}"
            )
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(InstallResponse {
                    success: false,
                    message: format!("Unsupported distro for PHP install: ID='{os_id}'. Install PHP {version} manually."),
                    version: version.to_string(),
                }),
            ));
        };

        let repo_result = safe_command_unsandboxed("bash", &[])
            .args(["-c", &repo_cmd])
            .output()
            .await;

        match repo_result {
            Ok(o) if !o.status.success() => {
                // Roll the source back so a failed attempt can't poison apt.
                let _ = safe_command_unsandboxed("bash", &[])
                    .args(["-c",
                        "rm -f /etc/apt/sources.list.d/sury-php.list \
                               /etc/apt/sources.list.d/ondrej-ubuntu-php-*.sources \
                               /etc/apt/sources.list.d/ondrej-ubuntu-php-*.list; \
                         apt-get update -qq || true"])
                    .output()
                    .await;
                let err = String::from_utf8_lossy(&o.stderr);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(InstallResponse {
                        success: false,
                        message: format!("Failed to configure PHP repo: {err}"),
                        version: version.to_string(),
                    }),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(InstallResponse {
                        success: false,
                        message: format!("Failed to configure PHP repo: {e}"),
                        version: version.to_string(),
                    }),
                ));
            }
            Ok(_) => {}
        }
    }

    // Core first (must succeed), then every extension this apt source has a
    // real candidate for. `apt-cache show` is not enough — a package can
    // keep a stanza while its Candidate is "(none)" (php-opcache on Ubuntu
    // 26.04, where OPcache became built-in) and one dead name fails the
    // whole apt transaction.
    let ext_names = COMMON_EXTENSIONS.join(" ");
    let install_cmd = format!(
        "set -e; export DEBIAN_FRONTEND=noninteractive; \
         apt-get install -y -qq php{version}-fpm php{version}-cli php{version}-common; \
         avail=''; \
         for e in {ext_names}; do \
             p=\"php{version}-$e\"; \
             c=$(apt-cache policy \"$p\" 2>/dev/null | sed -n 's/^  Candidate: //p'); \
             if [ -n \"$c\" ] && [ \"$c\" != '(none)' ]; then avail=\"$avail $p\"; fi; \
         done; \
         if [ -n \"$avail\" ]; then apt-get install -y -qq $avail; fi"
    );

    tracing::info!("Installing PHP {version} (core + available extensions)");

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        safe_command_unsandboxed("bash", &[])
            .args(["-c", &install_cmd])
            .output(),
    )
    .await;

    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InstallResponse {
                    success: false,
                    message: format!("Install command failed: {e}"),
                    version: version.to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InstallResponse {
                    success: false,
                    message: "Installation timed out (5 min limit)".into(),
                    version: version.to_string(),
                }),
            ));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(InstallResponse {
                success: false,
                message: format!("apt install failed:\n{stdout}\n{stderr}"),
                version: version.to_string(),
            }),
        ));
    }

    // Enable and start FPM service
    let _ = safe_command("systemctl")
        .args(["enable", "--now", &format!("php{version}-fpm")])
        .output()
        .await;

    tracing::info!("PHP {version} installed and started");

    Ok(Json(InstallResponse {
        success: true,
        message: format!("PHP {version} installed with FPM and all available extensions"),
        version: version.to_string(),
    }))
}

// ──────────────────────────────────────────────────────────────
// PHP Extensions Manager
// ──────────────────────────────────────────────────────────────

type PhpApiErr = (StatusCode, Json<serde_json::Value>);

fn php_api_err(status: StatusCode, msg: &str) -> PhpApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

/// GET /php/extensions/{version} — List installed PHP extensions.
async fn list_extensions(Path(version): Path<String>) -> Result<Json<serde_json::Value>, PhpApiErr> {
    if !ALLOWED_VERSIONS.contains(&version.as_str()) {
        return Err(php_api_err(StatusCode::BAD_REQUEST, &format!("Invalid PHP version. Allowed: {}", ALLOWED_VERSIONS.join(", "))));
    }

    // List all installed extensions
    let output = safe_command("php")
        .args([&format!("-d"), "error_reporting=0", "-m"])
        .env("PATH", "/usr/bin:/usr/sbin:/bin")
        .output().await
        .map_err(|e| php_api_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let extensions: Vec<String> = stdout.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('['))
        .map(|l| l.trim().to_lowercase())
        .collect();

    // List available (installable) extensions
    let avail_output = safe_command("apt-cache")
        .args(["search", &format!("php{version}-")])
        .output().await;

    let available: Vec<String> = avail_output.ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines()
            .filter_map(|l| {
                let pkg = l.split_whitespace().next()?;
                let ext = pkg.strip_prefix(&format!("php{version}-"))?;
                if ["common", "cli", "fpm", "dev", "dbg"].contains(&ext) { return None; }
                Some(ext.to_string())
            })
            .collect())
        .unwrap_or_default();

    Ok(Json(serde_json::json!({ "installed": extensions, "available": available, "version": version })))
}

/// POST /php/extensions/install — Install a PHP extension.
async fn install_extension(Json(body): Json<serde_json::Value>) -> Result<Json<serde_json::Value>, PhpApiErr> {
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("8.3");
    let extension = body.get("extension").and_then(|v| v.as_str()).unwrap_or("");

    if !ALLOWED_VERSIONS.contains(&version) {
        return Err(php_api_err(StatusCode::BAD_REQUEST, &format!("Invalid PHP version. Allowed: {}", ALLOWED_VERSIONS.join(", "))));
    }

    if extension.is_empty() || !extension.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(php_api_err(StatusCode::BAD_REQUEST, "Invalid extension name"));
    }

    let package = format!("php{version}-{extension}");
    tracing::info!("Installing PHP extension: {package}");

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        safe_command_unsandboxed("apt-get", &[])
            .args(["install", "-y", &package])
            .output()
    ).await
        .map_err(|_| php_api_err(StatusCode::GATEWAY_TIMEOUT, "Install timed out"))?
        .map_err(|e| php_api_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = &stderr[..200.min(stderr.len())];
        return Err(php_api_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Install failed: {msg}")));
    }

    // Restart PHP-FPM
    let _ = safe_command("systemctl")
        .args(["restart", &format!("php{version}-fpm")])
        .output().await;

    tracing::info!("PHP extension installed: {package}");
    Ok(Json(serde_json::json!({ "ok": true, "package": package })))
}

/// POST /php/uninstall — Remove a PHP version and all its extensions.
async fn uninstall_version(
    Json(body): Json<InstallRequest>,
) -> Result<Json<InstallResponse>, (StatusCode, Json<InstallResponse>)> {
    let version = body.version.trim();

    if !ALLOWED_VERSIONS.contains(&version) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(InstallResponse {
                success: false,
                message: format!("Invalid version. Allowed: {}", ALLOWED_VERSIONS.join(", ")),
                version: version.to_string(),
            }),
        ));
    }

    // Check if installed
    if !is_installed(version).await {
        return Ok(Json(InstallResponse {
            success: true,
            message: format!("PHP {version} is not installed"),
            version: version.to_string(),
        }));
    }

    // 1. Stop and disable FPM service
    let _ = safe_command("systemctl")
        .args(["stop", &format!("php{version}-fpm")])
        .output()
        .await;
    let _ = safe_command("systemctl")
        .args(["disable", &format!("php{version}-fpm")])
        .output()
        .await;

    // 2. Purge all php{version}-* packages
    tracing::info!("Uninstalling PHP {version}...");
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        safe_command_unsandboxed("bash", &[])
            .args(["-c", &format!(
                "apt-get purge -y php{version}-* 2>&1"
            )])
            .output(),
    )
    .await;

    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InstallResponse {
                    success: false,
                    message: format!("Purge command failed: {e}"),
                    version: version.to_string(),
                }),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InstallResponse {
                    success: false,
                    message: "Uninstall timed out (5 min limit)".into(),
                    version: version.to_string(),
                }),
            ));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(InstallResponse {
                success: false,
                message: format!("apt purge failed:\n{stdout}\n{stderr}"),
                version: version.to_string(),
            }),
        ));
    }

    // 3. Autoremove
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        safe_command_unsandboxed("bash", &[])
            .args(["-c", "apt-get autoremove -y 2>&1"])
            .output(),
    )
    .await;

    tracing::info!("PHP {version} uninstalled");

    Ok(Json(InstallResponse {
        success: true,
        message: format!("PHP {version} has been uninstalled"),
        version: version.to_string(),
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/php/versions", get(list_versions))
        .route("/php/install", post(install_version))
        .route("/php/uninstall", post(uninstall_version))
        // PHP Extensions
        .route("/php/extensions/{version}", get(list_extensions))
        .route("/php/extensions/install", post(install_extension))
}
