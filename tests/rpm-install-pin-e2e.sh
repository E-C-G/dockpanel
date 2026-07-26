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
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
