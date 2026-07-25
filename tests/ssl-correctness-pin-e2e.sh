#!/usr/bin/env bash
# Regression pins for the s258 SSL-correctness ship.
#
# Two independent things are pinned here, both of which had already shipped
# broken once in a way a green unit suite could not see:
#
#   A. The npm audit gate. It must WAIVE the reviewed advisory and still FAIL on
#      anything else. An always-red gate and an always-green gate fail the same
#      way — neither can report a new advisory — so both directions are pinned.
#   B. A site is installed at the scheme it can actually serve. Before this ship
#      WordPress was installed at the secure URL even when the certificate step
#      had already failed, leaving the site dead on both schemes.
#
# No running panel needed.
#   run: bash tests/ssl-correctness-pin-e2e.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$REPO/scripts/npm-audit-gate.mjs"
SITES="$REPO/panel/backend/src/routes/sites.rs"
WP="$REPO/panel/agent/src/services/wordpress.rs"
AGENT_SSL="$REPO/panel/agent/src/services/ssl.rs"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected [$3], got [$2])"; fi; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# Build an npm-audit-shaped report for one advisory.
mkreport() { # $1=ghsa $2=severity $3=package
  cat > "$TMP/report.json" <<EOF
{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "$3": {
      "name": "$3",
      "severity": "$2",
      "via": [
        {
          "source": 1234567,
          "name": "$3",
          "title": "Synthetic advisory for the gate's own test",
          "url": "https://github.com/advisories/$1",
          "severity": "$2"
        }
      ]
    }
  },
  "metadata": { "vulnerabilities": { "total": 1 } }
}
EOF
}

run_gate() { node "$GATE" --input "$TMP/report.json" >"$TMP/out" 2>&1; echo $?; }

echo "── A: the npm audit gate waives what was reviewed and blocks what was not ──"

mkreport "GHSA-qwww-vcr4-c8h2" "high" "react-router"
check "reviewed advisory passes"                "$(run_gate)" "0"
grep -q "waived" "$TMP/out" \
  && ok "…and says out loud that it was waived, with the reason" \
  || bad "waiver is silent — a waiver nobody can see is indistinguishable from a missing check"

# The point of the whole exercise: it must still be able to fail.
mkreport "GHSA-0000-0000-0001" "high" "some-lib"
check "un-reviewed HIGH advisory fails the build"     "$(run_gate)" "1"
mkreport "GHSA-0000-0000-0002" "critical" "some-lib"
check "un-reviewed CRITICAL advisory fails the build" "$(run_gate)" "1"

# Below the threshold is not a silent pass by accident — it is the same
# --audit-level=high contract the job had before.
mkreport "GHSA-0000-0000-0003" "moderate" "some-lib"
check "moderate advisory does not fail at --level high" "$(run_gate)" "0"

echo '{"vulnerabilities":{},"metadata":{"vulnerabilities":{"total":0}}}' > "$TMP/report.json"
check "a clean report passes" "$(run_gate)" "0"
grep -q "stale" "$TMP/out" \
  && ok "…and flags the now-unmatched allowlist entry instead of keeping it forever" \
  || bad "an allowlist entry matching nothing is reported by nothing"

# A gate that cannot parse its input must not report success.
echo 'not json at all' > "$TMP/report.json"
check "unparseable audit output is an error, not a pass" "$(run_gate)" "2"
printf '{"error":{"summary":"registry unreachable"}}' > "$TMP/report.json"
check "a failed audit run is an error, not a pass"       "$(run_gate)" "2"

echo
echo "── B: a site is installed at the scheme it can actually serve ──"

# The install runs in a task beside auto-SSL, which may still fail. Pinning the
# literal here is the point: this is the line that decided a brand-new site was
# unreachable on both schemes.
grep -q '"url": format!("http://{cms_domain}")' "$SITES" \
  && ok "the CMS installer is handed the plain-HTTP URL" \
  || bad "the CMS installer no longer installs at the plain-HTTP URL"

grep -q '"url": format!("https' "$SITES" \
  && bad "an unconditional secure install URL is back in sites.rs" \
  || ok "no unconditional secure install URL remains"

grep -q 'promote-https' "$SITES" \
  && ok "the panel promotes the canonical URL once the certificate lands" \
  || bad "nothing promotes the canonical URL after a late certificate"

echo
echo "── C: the promotion only ever touches the URL DockPanel itself set ──"

# Extracted so it can be tested at all — the surrounding function shells out to
# wp-cli. A settable canonical URL is a site-takeover primitive, so the guard
# matters more than the rewrite.
grep -q 'fn https_promotion_target' "$WP" \
  && ok "the promotion decision is a separate, testable function" \
  || bad "the promotion decision is not extracted"

grep -q 'eq_ignore_ascii_case' "$WP" \
  && ok "…and compares the stored URL against this vhost's own plain-HTTP form" \
  || bad "the promotion no longer pins the comparison to this vhost's own domain"

grep -q 'promote_site_url_to_https(domain)' "$AGENT_SSL" \
  && ok "every path that enables SSL runs the promotion (single choke point)" \
  || bad "enabling SSL no longer promotes the canonical URL"

echo
echo "── D: a certificate that stops renewing is announced, not just logged ──"

HEALER="$REPO/panel/backend/src/services/auto_healer.rs"
SCAN="$REPO/panel/backend/src/services/security_scanner.rs"
NOTIF="$REPO/panel/backend/src/services/notifications.rs"

grep -q 'fn fire_alert_deduped' "$NOTIF" \
  && ok "there is a deduped alert path" \
  || bad "no deduped alert path — an alert from a 120s loop is a flood"

# The bail-outs. These run BEFORE any attempt is made, which is exactly the
# case F6 named: issuance is rescued by the fallback contact, renewal is not
# even tried, and sixty days later the certificate expires on a live server.
check "auto-healer alerts when a renewal cannot be attempted" \
  "$(grep -c 'ssl_renewal_blocked(' "$HEALER")" "3"
check "the scanner alerts on every renewal outcome it can see" \
  "$(grep -c 'ssl_renewal_alert(' "$SCAN")" "4"

# Both loops touch the same certificate; neither may alert unconditionally.
grep -q 'fire_alert_deduped' "$HEALER" && grep -q 'fire_alert_deduped' "$SCAN" \
  && ok "both loops dedupe, so one stuck certificate is one alert" \
  || bad "a loop still alerts unconditionally"

grep -q 'fire_alert(' "$SCAN" && grep -q 'ssl_renewal' "$SCAN" \
  && ok "the scanner's renewal path reaches the alert system at all" \
  || bad "the scanner's renewal failure is still log-only"

echo
echo "──────────────────────────────────────────"
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
