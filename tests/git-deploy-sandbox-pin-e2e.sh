#!/usr/bin/env bash
# Regression pins for s261 — the update path, and what driving it exposed.
#
# s260 shipped databases-in-backups. s261 asked the next question: does any of
# that reach the installs people already run? Driving a real v2.31.2 box up to
# v2.34.2 said yes — and the same box showed that git deploy had never worked
# on ANY hardened install, in three separate places, all the same shape: the
# agent runs ProtectSystem=strict + ProtectHome=yes, and the build path writes
# outside ReadWritePaths.
#
#   A. THE AGENT CAN WRITE WHAT ITS BUILD TOOLS NEED. `docker build` creates
#      $HOME/.docker and refuses to run without it; HOME=/root is an empty
#      read-only mount under the sandbox, so every Dockerfile deploy died at
#      "mkdir /root/.docker: read-only file system". The fix is one env var in
#      the shared helper, NOT a per-call-site patch — ~77 docker invocations go
#      through it and the one that got missed is how this stayed hidden.
#      Same shape twice more: nixpacks installed itself into /usr/local/bin and
#      cached into /var/cache/dockpanel, neither writable.
#   B. THE UPDATE'S AGENT CHECK ASKS THE AGENT. It curled an AUTHENTICATED
#      panel endpoint with no token, so it returned 401 and warned on every
#      update on every install — identically whether the agent was alive or
#      dead. A check that cannot distinguish those two states is not a check.
#   C. THE INSTALLER INSTALLS THE VERSION IT WAS GIVEN. install.sh reads
#      DOCKPANEL_VERSION and clones that ref; setup.sh, its only consumer,
#      always fetched releases/latest. `DOCKPANEL_VERSION=v2.31.2 install.sh`
#      built a v2.31.2 tree around v2.34.2 binaries and printed "v2.34.2".
#
# These are SOURCE pins and need no running panel. The behavioural proof is in
# /home/ovidiu/dockpanel-update-path-drill-s261.md.
#   run: bash tests/git-deploy-sandbox-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAFECMD="$REPO/panel/agent/src/safe_cmd.rs"
GITBUILD="$REPO/panel/agent/src/services/git_build.rs"
UNIT="$REPO/panel/agent/dockpanel-agent.service"
UPDATE="$REPO/scripts/update.sh"
SETUP="$REPO/scripts/setup.sh"
INSTALL="$REPO/scripts/install.sh"
WEBINSTALL="$REPO/website/client/public/install.sh"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
has()  { grep -q  -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
hasE() { grep -qE -- "$2" "$1" 2>/dev/null && ok "$3" || bad "$3"; }
# Comment-blind variants. These pins describe the defects BY NAME in the
# comments that document each fix, so a raw grep would match the prose
# explaining the bug and pass while the code itself regressed.
#
# The comment marker is per-language: stripping `//` from a shell script would
# also eat every `http://` URL — which is exactly how the first draft of this
# file reported two false failures against correct code.
strip_comments() {
    case "$1" in
        *.rs) sed -E 's|[[:space:]]*//.*$||' "$1" ;;
        *)    sed -E 's|[[:space:]]*#.*$||'  "$1" ;;
    esac
}
code()   { strip_comments "$1" | grep -qE -- "$2" && ok "$3" || bad "$3"; }
nocode() { strip_comments "$1" | grep -qE -- "$2" && bad "$3" || ok "$3"; }

echo
echo "A. The agent can write what its build tools need"
has  "$SAFECMD" 'DOCKER_CONFIG_DIR: &str = "/var/lib/dockpanel/docker"' \
     "the docker CLI config dir is a fixed path under /var/lib/dockpanel"
code "$SAFECMD" 'cmd\.env\("DOCKER_CONFIG", DOCKER_CONFIG_DIR\)' \
     "safe_command sets DOCKER_CONFIG (env_clear means a unit Environment= cannot)"
[ "$(sed -E 's/[[:space:]]*\/\/.*$//' "$SAFECMD" | grep -c 'DOCKER_CONFIG')" -ge 4 ] \
     && ok "every helper family sets it — async, sync, and both unsandboxed" \
     || bad "every helper family sets it — async, sync, and both unsandboxed"
hasE "$UNIT" 'ReadWritePaths=.*/var/lib/dockpanel' \
     "and /var/lib/dockpanel really is writable under the unit's sandbox"
nocode "$UNIT" 'ReadWritePaths=.*(/root|/usr/local/bin)' \
     "the fix did NOT widen the sandbox to /root or /usr/local/bin"

has  "$GITBUILD" 'NIXPACKS_BIN: &str = "/var/lib/dockpanel/bin/nixpacks"' \
     "nixpacks installs inside ReadWritePaths, not /usr/local/bin"
has  "$GITBUILD" 'NIXPACKS_CACHE_ROOT: &str = "/var/lib/dockpanel/nixpacks-cache"' \
     "its build cache too (/var/cache/dockpanel was never in ReadWritePaths)"
nocode "$GITBUILD" 'mv /tmp/nixpacks /usr/local/bin' \
     "the download no longer moves the binary into a read-only prefix"
nocode "$GITBUILD" '/var/cache/dockpanel/nixpacks' \
     "no code path still points the cache at the unwritable location"
code "$GITBUILD" 'Path::new\(NIXPACKS_BIN\)\.is_file\(\)' \
     "an already-downloaded nixpacks is found again (it is off the agent's PATH)"

echo
echo "B. The update's agent check asks the agent"
code "$UPDATE" 'curl .*--unix-socket .*AGENT_SOCK.*localhost/health' \
     "the check probes the agent's own socket"
nocode "$UPDATE" 'curl.*api/system/info' \
     "it no longer curls an authenticated panel endpoint with no token"
has  "$UPDATE" 'AGENT_SOCK=/run/dockpanel/agent.sock' \
     "the modern socket path is tried first"
has  "$UPDATE" 'AGENT_SOCK=/var/run/dockpanel/agent.sock' \
     "with the legacy path as fallback, so older boxes still probe correctly"
has  "$REPO/panel/agent/src/routes/mod.rs" 'if request.uri().path() == "/health"' \
     "and /health is genuinely exempt from the agent's auth middleware"

echo
echo "C. The installer installs the version it was given"
code "$SETUP" 'DOCKPANEL_VERSION' \
     "download_binaries reads the pin instead of ignoring it"
code "$SETUP" 'Pinned release' \
     "and says so, rather than printing a version it did not install"
code "$SETUP" 'releases/latest' \
     "unpinned installs still resolve the latest release"
code "$INSTALL" 'git clone .*-b "\$VERSION"' \
     "install.sh still selects the tree by the same variable"
[ -n "$(diff "$INSTALL" "$WEBINSTALL" 2>&1)" ] \
     && bad "the advertised website copy of install.sh matches scripts/install.sh" \
     || ok "the advertised website copy of install.sh matches scripts/install.sh"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
