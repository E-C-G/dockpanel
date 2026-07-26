#!/usr/bin/env bash
# Regression pins for s264 — the RPM-family install path.
#
# README, docs/getting-started.md, docs/guides/multi-server.md and the marketing
# site all promised CentOS 9+, Rocky 9+, Fedora 39+ and Amazon Linux 2023. Nobody
# had ever run the installer on any of them. Driving all four on real boxes found
# that ALL FOUR failed, at three different places:
#
#   Rocky 9      — download.docker.com/linux/rocky/9 exists but publishes no
#                  docker-ce, so `dnf install docker-ce` died at step 3 of 15.
#   AlmaLinux 9  — get.docker.com refuses it outright ("Unsupported distribution
#                  'almalinux'"), though detect_os prints "Detected: AlmaLinux".
#   CentOS 9     — the sed that strips nginx's default server block ended its
#                  range at the first `}`, which is a nested location's brace, so
#                  it corrupted nginx.conf and nginx -t failed.
#   Fedora 43    — the agent unit listed /etc/apt in ReadWritePaths. On an RPM
#                  box that path does not exist, systemd refuses to build the
#                  mount namespace, and the agent could not start AT ALL.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

UNIT=panel/agent/dockpanel-agent.service
SETUP=scripts/setup.sh

echo "── 1. No sandbox path can make the agent unstartable on a distro that lacks it ──"

# THE DURABLE PIN. /etc/apt was not a typo — it was an allow-list entry nobody
# re-checked against a non-Debian box, and two hand-maintained mirrors of this
# same list (in setup.sh and update.sh, both commented "pre-create everything the
# canonical unit lists") had missed it for as long as it existed. So rather than
# pinning that one path, require every entry to be EITHER optional-by-prefix or
# demonstrably created before the unit starts. A future entry cannot repeat this.
RWP=$(grep -m1 '^ReadWritePaths=' "$UNIT" | sed 's/^ReadWritePaths=//')

if [ -z "$RWP" ]; then
  bad "$UNIT has no ReadWritePaths= line — this check cannot see the sandbox at all"
else
  # Paths present on any Linux box before DockPanel touches it, or created by
  # the package manager as a dependency of a step that must already have run.
  ALWAYS='/var/www /var/log /opt /etc/systemd/system /etc/nginx'
  unguarded=""
  for p in $RWP; do
    case "$p" in -*) continue ;; esac            # optional: systemd skips if absent
    case " $ALWAYS " in *" $p "*) continue ;; esac
    # Created up-front by the installer? Match a real mkdir, not a passing mention.
    if grep -qE "mkdir -p( -m [0-7]+)? [^#]*(^| )${p}( |$)" "$SETUP"; then continue; fi
    case "$p" in
      /etc/dockpanel|/var/run/dockpanel|/var/backups/dockpanel|/var/lib/dockpanel) continue ;;
    esac
    unguarded="$unguarded $p"
  done

  if [ -n "$unguarded" ]; then
    bad "ReadWritePaths lists${unguarded} with no '-' prefix and no mkdir in $SETUP — systemd fails the whole namespace mount if any one is missing, and the agent will not start"
  else
    ok "every ReadWritePaths entry is either optional ('-' prefix) or created before the unit starts"
  fi

  # The specific entry that did it, kept as a named regression.
  if grep -qE '^ReadWritePaths=.* /etc/apt( |$)' "$UNIT"; then
    bad "/etc/apt is back in ReadWritePaths unprefixed — that is the exact entry that made the agent unstartable on every RPM box"
  else
    ok "/etc/apt is not listed unprefixed"
  fi
fi

echo
echo "── 2. The nginx default-server strip counts braces ──"

# The sed range `/server {/,/^[[:space:]]*}/` looks right and is wrong: it stops
# at the first line that is only a closing brace, which inside a server block
# belongs to a nested location. It commented the opening of the block and left
# the rest at http level. Reproduced in a rockylinux:9 container against the
# stock config: `"location" directive is not allowed here in nginx.conf:52`.
if grep -qE "sed -i '/\^?\[\[:space:\]\]\*server \{/,/" "$SETUP"; then
  bad "the default-server strip is a sed range again — it ends at the first nested closing brace and corrupts nginx.conf"
else
  ok "no sed-range default-server strip in $SETUP"
fi

if grep -q 'gsub(/\\{/, "{") - gsub(/\\}/, "}")' "$SETUP"; then
  ok "the strip counts braces to find the block's real end"
else
  bad "the brace-counting default-server strip is gone from $SETUP — whatever replaced it must find the block end, not the first '}'"
fi

echo
echo "── 3. RHEL rebuilds do not depend on a repo upstream leaves empty ──"

if grep -q 'docker_repo_rhel_clone' "$SETUP"; then
  ok "an explicit Docker repo is written for the RHEL rebuilds"
else
  bad "docker_repo_rhel_clone is gone — Rocky/Alma fall back to get.docker.com, whose rocky path serves no docker-ce and whose distro list has no almalinux"
fi

if grep -q 'download.docker.com/linux/centos/\$releasever' "$SETUP"; then
  ok "that repo points at the centos path, which upstream actually fills"
else
  bad "the RHEL-rebuild Docker repo no longer points at the centos path — linux/rocky/ has metadata but no docker-ce packages"
fi

# rocky and almalinux must both reach that branch. almalinux especially: detect_os
# greets it by name, so a user has every reason to expect the install to work.
if grep -qE '^ *rocky\|almalinux\|centos\|rhel' "$SETUP"; then
  ok "rocky and almalinux are routed to the explicit repo"
else
  bad "the case that routes rocky/almalinux to the explicit Docker repo has changed shape — check both still reach it"
fi

echo
echo "── 4. The box is configured for the firewall it is actually running ──"

# s265: install succeeded on all four RPM families and the panel was still
# unreachable, because setup.sh installed UFW next to the firewalld the distro
# already had running and then opened 80/443 in UFW only. Let's Encrypt could
# not fetch the ACME challenge, so there was no certificate either — while the
# installer printed "installed successfully" and an https:// URL.

# The detector must exist AND be called from main() — a definition nothing
# invokes leaves FW_MGR at its "none" default, which silently disables every
# fw_allow below. (The first version of this pin only checked the definition
# and passed happily when the call site was removed.)
if grep -qE '^detect_firewall\(\) \{' "$SETUP" && \
   grep -qE '^[[:space:]]+detect_firewall$' "$SETUP"; then
  ok "setup.sh detects the enforcing firewall (FW_MGR) and calls the detector from main()"
else
  bad "detect_firewall is missing or never called in $SETUP — FW_MGR stays 'none', fw_allow becomes a no-op, and the installer is back to assuming UFW"
fi

# THE DURABLE PIN for this class, same shape as §1: rather than pinning one
# call site, require every `pkg_install ufw` to sit on the branch taken only
# when no firewall is running. Checked positionally, because a textual search
# for "is it inside the case" passes for a `none)` branch that no longer exists.
ufw_installs=$(grep -cE '^[[:space:]]*(if run .*)?pkg_install ufw|pkg_install ufw' "$SETUP" || true)
guarded_installs=$(awk '
  /^[[:space:]]*case "\$FW_MGR" in/ { in_case=1 }
  in_case && /^[[:space:]]*none\)/  { in_none=1 }
  in_none && /pkg_install ufw/      { n++ }
  in_none && /^[[:space:]]*;;/      { in_none=0 }
  in_case && /^[[:space:]]*esac/    { in_case=0 }
  END { print n+0 }
' "$SETUP")
if [ "$ufw_installs" -gt 0 ] && [ "$guarded_installs" -eq "$ufw_installs" ]; then
  ok "every 'pkg_install ufw' sits on the FW_MGR=none branch ($guarded_installs/$ufw_installs)"
elif [ "$ufw_installs" -eq 0 ]; then
  ok "setup.sh never installs UFW"
else
  bad "$ufw_installs 'pkg_install ufw' in $SETUP but only $guarded_installs on the FW_MGR=none branch — installing UFW next to a running firewalld is what left the panel unreachable on every RHEL-family box"
fi

if grep -q 'firewall-cmd' "$SETUP"; then
  ok "setup.sh knows how to open a port in firewalld"
else
  bad "$SETUP never mentions firewall-cmd — ports opened only in UFW are dropped by firewalld on Rocky/Alma/CentOS/Fedora"
fi

# The agent had the same defect one layer in: open_mail_ports() shelled out to
# ufw, discarded every result, and logged success unconditionally.
#
# Two kinds of ufw call are legitimate and must stay allowed: the ufw installer
# itself (`install_ufw`/`uninstall_ufw`, which now refuse on non-apt boxes) and
# ufw-specific rule CRUD. What must NOT come back is code that *opens a port*
# or *reports firewall state* through ufw alone — those are the ones that were
# wrong on every RHEL-family box. Anything matching below is that class.
# Opening a port through ufw alone is the defect. (Reading ufw's own status is
# fine where it sits behind the dispatch — see the next assertion.)
offenders=$(grep -rn 'safe_command("ufw")' panel/agent/src --include=*.rs \
  | grep -vE 'services/firewall\.rs' \
  | grep -vE 'routes/service_installer\.rs' \
  | grep -E '"allow"' || true)
if [ -n "$offenders" ]; then
  bad "code opens a port through ufw directly:
$offenders
    → use services::firewall::allow_tcp, which dispatches on the running firewall AND returns whether it worked"
else
  ok "port-opening goes through services/firewall.rs on every path"
fi

# Firewall STATUS must branch on the detected firewall rather than assuming ufw.
if grep -q 'firewalld_status' panel/agent/src/services/security.rs && \
   grep -q 'firewall::detect' panel/agent/src/services/security.rs; then
  ok "the Security page dispatches on the running firewall instead of calling a firewalld box unfirewalled"
else
  bad "security.rs no longer dispatches on the detected firewall — on the RHEL family the Security overview reports 'no firewall' for a box that is firewalled"
fi

if grep -q 'firewall::detect' panel/agent/src/services/diagnostics.rs; then
  ok "diagnostics raises 'no firewall' from the real firewall state, not from ufw's absence"
else
  bad "diagnostics.rs is back to asking ufw — it will warn 'Firewall (ufw) is not active' on every firewalld box and name a tool the operator does not have"
fi

echo
echo "── 5. Package queries work on both package databases ──"

# is_installed() ran `dpkg -l`. There is no dpkg on an RPM box, so it answered
# false for EVERY package: the Services page reported PHP and Fail2Ban as not
# installed while both were installed and running. There were four separate
# hand-rolled copies of it, which is how it stayed wrong in all of them.
if grep -rq 'safe_command("dpkg")' panel/agent/src --include=*.rs; then
  bad "an agent file calls dpkg directly — there is no dpkg on the RHEL family, so that query answers false for every package. Use services::pkg::is_installed"
else
  ok "no direct dpkg calls in the agent — package presence goes through services::pkg"
fi

if grep -q 'PkgMgr::Rpm' panel/agent/src/services/pkg.rs 2>/dev/null; then
  ok "services::pkg dispatches on the box's real package database"
else
  bad "services::pkg no longer handles rpm — every package query is Debian-only again"
fi

echo
echo "── 6. SELinux is accounted for, not discovered by the operator ──"

# With SELinux Enforcing (the RHEL-family default) nginx may not open a socket
# to the API, so every request answered 502 — including from the box itself.
# The denial is dontaudit'ed: nothing in the journal, nothing in ausearch.
if grep -q 'httpd_can_network_connect' "$SETUP"; then
  ok "setup.sh sets httpd_can_network_connect, without which the panel answers 502 on Enforcing systems"
else
  bad "$SETUP no longer sets httpd_can_network_connect — nginx cannot reach the API under Enforcing SELinux and every request 502s with no log line to explain it"
fi

# Existing broken boxes cannot be fixed from the panel, because the panel is
# what is unreachable. update.sh is the only path in.
if grep -q 'httpd_can_network_connect' scripts/update.sh && \
   grep -q 'firewall-cmd' scripts/update.sh; then
  ok "update.sh heals both defects on installs that already exist"
else
  bad "update.sh no longer repairs the firewall/SELinux state — boxes installed before v2.38.0 stay unreachable, and they cannot be fixed from a panel they cannot reach"
fi

echo
echo "── 7. An apt-only installer says so ──"

if grep -q 'apt_only_reason' panel/agent/src/services/pkg.rs 2>/dev/null && \
   grep -q 'apt_only_reason' panel/agent/src/routes/service_installer.rs; then
  ok "optional-service installers refuse with a stated limitation on non-apt boxes"
else
  bad "the apt-only guard is gone — on the RHEL family these endpoints fail with 'Failed to find executable apt-get', which tells the operator nothing"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
