//! Safe command execution helpers.
//!
//! Every child process spawned by the agent MUST use these helpers instead of
//! raw `Command::new()`.  They call `.env_clear()` and set a minimal, safe
//! environment so that inherited variables like `LD_PRELOAD`, `LD_LIBRARY_PATH`,
//! or a tampered `PATH` cannot be used to hijack child processes.

/// Minimal safe PATH containing only system directories.
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Config directory handed to every docker CLI invocation.
///
/// The agent unit runs `ProtectHome=yes`, so the `HOME=/root` these helpers set
/// is an empty read-only mount inside the sandbox. The docker CLI creates
/// `$HOME/.docker` on first use, and `docker build` does not tolerate failing to
/// — it aborts with `mkdir /root/.docker: read-only file system`. That took down
/// every Dockerfile-based git deploy on every hardened install (s261): the clone
/// succeeded, the build never ran once. Point the CLI at a directory that IS in
/// the unit's `ReadWritePaths` instead of widening the sandbox. Set here rather
/// than at a call site because `env_clear()` means a unit-level `Environment=`
/// would never reach the child, and because ~77 docker invocations share these
/// helpers — one of them silently missing it is exactly the drift that hid this.
const DOCKER_CONFIG_DIR: &str = "/var/lib/dockpanel/docker";

/// Create an async `tokio::process::Command` with a sanitized environment.
///
/// The child process starts with an **empty** environment and only receives:
/// - `PATH`  – system directories only
/// - `HOME`  – `/root`
/// - `LANG`  – `C.UTF-8`
/// - `LC_ALL` – `C.UTF-8`
/// - `DOCKER_CONFIG` – a writable dir, since `HOME` is not one under the sandbox
///
/// Callers that need additional env vars (e.g. `PGPASSWORD`) should add them
/// via `.env("KEY", "value")` **after** calling this function.
pub fn safe_command(binary: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(binary);
    cmd.env_clear();
    cmd.env("PATH", SAFE_PATH);
    cmd.env("HOME", "/root");
    cmd.env("LANG", "C.UTF-8");
    cmd.env("LC_ALL", "C.UTF-8");
    cmd.env("DOCKER_CONFIG", DOCKER_CONFIG_DIR);
    cmd
}

/// Create a synchronous `std::process::Command` with a sanitized environment.
///
/// Same safety guarantees as [`safe_command`] but for blocking contexts
/// (e.g. `app_process.rs` which writes systemd units synchronously).
pub fn safe_command_sync(binary: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(binary);
    cmd.env_clear();
    cmd.env("PATH", SAFE_PATH);
    cmd.env("HOME", "/root");
    cmd.env("LANG", "C.UTF-8");
    cmd.env("LC_ALL", "C.UTF-8");
    cmd.env("DOCKER_CONFIG", DOCKER_CONFIG_DIR);
    cmd
}

/// Run a binary outside the agent's `ProtectSystem=strict` sandbox via
/// `systemd-run`. PID1 spawns the transient unit in its own mount namespace,
/// so the inner binary sees the full filesystem read-write — necessary for
/// commands like `apt-get update/install/upgrade` that must write to
/// `/var/cache/apt`, `/var/lib/apt/lists`, `/var/lib/dpkg`, and `/usr`,
/// none of which are in the agent unit's `ReadWritePaths`.
///
/// Use sparingly: every call escapes the sandbox, so reserve this for
/// commands that genuinely cannot run sandboxed (apt/dpkg/etc.). Read-only
/// commands like `apt list --upgradable` work fine under the sandbox and
/// should keep using [`safe_command`].
///
/// Env vars passed via `extra_env` are forwarded to the inner binary using
/// `--setenv=KEY=value`. The defaults (PATH, HOME, LANG, LC_ALL,
/// DEBIAN_FRONTEND) are always set so the inner binary doesn't inherit
/// PID1's wider environment. **`.env()` on the returned Command applies to
/// `systemd-run` itself, not the inner binary** — pass extra inner-binary
/// env via `extra_env`.
pub fn safe_command_unsandboxed(
    binary: &str,
    extra_env: &[(&str, &str)],
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("systemd-run");
    cmd.env_clear();
    cmd.env("PATH", SAFE_PATH);
    cmd.args(["--quiet", "--pipe", "--wait", "--collect"]);
    cmd.arg(format!("--setenv=PATH={SAFE_PATH}"));
    cmd.arg("--setenv=HOME=/root");
    cmd.arg("--setenv=LANG=C.UTF-8");
    cmd.arg("--setenv=LC_ALL=C.UTF-8");
    cmd.arg("--setenv=DEBIAN_FRONTEND=noninteractive");
    cmd.arg(format!("--setenv=DOCKER_CONFIG={DOCKER_CONFIG_DIR}"));
    for (k, v) in extra_env {
        cmd.arg(format!("--setenv={k}={v}"));
    }
    cmd.arg("--");
    cmd.arg(binary);
    cmd
}

/// Synchronous sibling of [`safe_command_unsandboxed`] for blocking contexts
/// (e.g. `services/smtp.rs::ensure_msmtp` which installs msmtp via apt).
pub fn safe_command_sync_unsandboxed(
    binary: &str,
    extra_env: &[(&str, &str)],
) -> std::process::Command {
    let mut cmd = std::process::Command::new("systemd-run");
    cmd.env_clear();
    cmd.env("PATH", SAFE_PATH);
    cmd.args(["--quiet", "--pipe", "--wait", "--collect"]);
    cmd.arg(format!("--setenv=PATH={SAFE_PATH}"));
    cmd.arg("--setenv=HOME=/root");
    cmd.arg("--setenv=LANG=C.UTF-8");
    cmd.arg("--setenv=LC_ALL=C.UTF-8");
    cmd.arg("--setenv=DEBIAN_FRONTEND=noninteractive");
    cmd.arg(format!("--setenv=DOCKER_CONFIG={DOCKER_CONFIG_DIR}"));
    for (k, v) in extra_env {
        cmd.arg(format!("--setenv={k}={v}"));
    }
    cmd.arg("--");
    cmd.arg(binary);
    cmd
}
