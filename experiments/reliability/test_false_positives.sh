#!/bin/bash
# Negative-control suite: run benign actions and check the pipeline does NOT
# respond. Categories: A true negative, B boundary, C known limitation (expected FP).
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
WAIT=30

CTRL="$SSH_CONTROLLER"
WS="$SSH_WORKSTATION"
WEB="$SSH_WEBSERVER"
RESULTS_FILE="$(pwd)/false_positive_results.txt"

PASS=0
FAIL=0
EXPECTED_FP=0

> "$RESULTS_FILE"

check_log() {
    local t_start="$1"
    local matches
    matches=$($CTRL "sudo python3 -c \"
import json
start = '$t_start'
found = []
with open('/var/log/ti-pipeline/integrator.log') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        if d.get('t','') > start and d.get('matched') is not None:
            found.append(d.get('matched') + ':' + d.get('playbook',''))
if found:
    print(','.join(found))
\"" 2>/dev/null)
    echo "$matches"
}

get_start_time() {
    $CTRL "date -Iseconds" 2>/dev/null
}

report() {
    local num="$1"
    local name="$2"
    local category="$3"
    local expected="$4"
    local result="$5"
    local triggered="$6"

    if [ "$result" = "$expected" ]; then
        local status="PASS"
        if [ "$expected" = "TRIGGER" ]; then
            EXPECTED_FP=$((EXPECTED_FP + 1))
        else
            PASS=$((PASS + 1))
        fi
    else
        local status="FAIL"
        FAIL=$((FAIL + 1))
    fi

    local line="N${num} | ${status} | ${category} | ${name}"
    if [ -n "$triggered" ]; then
        line="$line | triggered: ${triggered}"
    fi
    echo "  $line"
    echo "$line" >> "$RESULTS_FILE"
}

echo "============================================"
echo "  False Positive Testing Suite"
echo "  $(date)"
echo "============================================"
echo ""

# ─────────────────────────────────────────────
# N1: Normal SSH login (Category A)
# Rule tested: 5712/5758 (SSH brute force)
# Expected: no trigger (single successful login)
# ─────────────────────────────────────────────
echo "N1: Normal SSH login with correct password..."
T_START=$(get_start_time)
$WS "echo 'logged in successfully'" > /dev/null 2>&1
sleep "$WAIT"
MATCHES=$(check_log "$T_START")
if [ -z "$MATCHES" ]; then
    report 1 "SSH login (correct password)" "A" "NO_TRIGGER" "NO_TRIGGER" ""
else
    report 1 "SSH login (correct password)" "A" "NO_TRIGGER" "TRIGGER" "$MATCHES"
fi

# ─────────────────────────────────────────────
# N2: 15 TCP connections in 20s (Category B)
# Rule tested: 100501 (port scan, threshold=20)
# Expected: no trigger (below threshold)
# ─────────────────────────────────────────────
echo "N2: 15 TCP connections in 20s (threshold is 20)..."
T_START=$(get_start_time)
$WS "for i in \$(seq 1 15); do \
  curl -s -o /dev/null --connect-timeout 2 http://$WEBSERVER_IP/ & \
done; wait" > /dev/null 2>&1
sleep "$WAIT"
MATCHES=$(check_log "$T_START")
if [ -z "$MATCHES" ]; then
    report 2 "15 connections in 20s" "B" "NO_TRIGGER" "NO_TRIGGER" ""
else
    report 2 "15 connections in 20s" "B" "NO_TRIGGER" "TRIGGER" "$MATCHES"
fi

# ─────────────────────────────────────────────
# N4: echo hello | base64 (Category A)
# Rule tested: 100300 (base64 exec)
# Expected: may trigger (auditd sees bash + base64)
# ─────────────────────────────────────────────
echo "N4: Legitimate base64 encoding (echo hello | base64)..."
T_START=$(get_start_time)
$WS "echo hello | base64 > /dev/null" > /dev/null 2>&1
sleep "$WAIT"
MATCHES=$(check_log "$T_START")
if [ -z "$MATCHES" ]; then
    report 4 "Legitimate base64 usage" "A" "NO_TRIGGER" "NO_TRIGGER" ""
else
    # Check if base64_exec specifically triggered
    if echo "$MATCHES" | grep -q "base64_exec"; then
        report 4 "Legitimate base64 usage" "C" "TRIGGER" "TRIGGER" "$MATCHES"
    else
        report 4 "Legitimate base64 usage" "A" "NO_TRIGGER" "TRIGGER" "$MATCHES"
    fi
fi

# ─────────────────────────────────────────────
# N5: Bash session with no network (Category A)
# Rule tested: 100520 (reverse shell)
# Expected: no trigger (no established TCP)
# ─────────────────────────────────────────────
echo "N5: Bash session with no network connections..."
T_START=$(get_start_time)
$WS "bash -c 'ls /tmp > /dev/null; sleep 2; echo done'" > /dev/null 2>&1
sleep "$WAIT"
MATCHES=$(check_log "$T_START")
if [ -z "$MATCHES" ]; then
    report 5 "Bash with no network" "A" "NO_TRIGGER" "NO_TRIGGER" ""
else
    report 5 "Bash with no network" "A" "NO_TRIGGER" "TRIGGER" "$MATCHES"
fi

# ─────────────────────────────────────────────
# N7: Upload index.html to web root (Category C)
# Rule tested: 100530 (web shell)
# Expected: WILL trigger (known limitation - FIM
# cannot distinguish legitimate files from web shells)
# ─────────────────────────────────────────────
echo "N7: Upload legitimate index.html to web root..."
T_START=$(get_start_time)
$WEB "echo '<html><body>Hello</body></html>' | \
  sudo tee /var/www/html/test_legitimate.html > /dev/null"
sleep "$WAIT"
MATCHES=$(check_log "$T_START")
# Cleanup
$WEB "sudo rm -f /var/www/html/test_legitimate.html" > /dev/null 2>&1
$WEB "sudo rm -f /var/quarantine/*test_legitimate*" > /dev/null 2>&1
if [ -z "$MATCHES" ]; then
    report 7 "Legitimate HTML in web root" "C" "TRIGGER" "NO_TRIGGER" ""
else
    report 7 "Legitimate HTML in web root" "C" "TRIGGER" "TRIGGER" "$MATCHES"
fi

# ─────────────────────────────────────────────
# N8: Install legitimate cron job (Category C)
# Rule tested: 100510 (cron persistence)
# Expected: WILL trigger (known limitation - FIM
# cannot distinguish legitimate cron from persistence)
# ─────────────────────────────────────────────
echo "N8: Create legitimate cron job in /etc/cron.d/..."
T_START=$(get_start_time)
$WS "echo '0 3 * * * root /usr/bin/apt-get update -q' | \
  sudo tee /etc/cron.d/test-apt-update > /dev/null"
sleep "$WAIT"
MATCHES=$(check_log "$T_START")
# Cleanup (if pipeline didn't already delete it)
$WS "sudo rm -f /etc/cron.d/test-apt-update" > /dev/null 2>&1
if [ -z "$MATCHES" ]; then
    report 8 "Legitimate cron job" "C" "TRIGGER" "NO_TRIGGER" ""
else
    report 8 "Legitimate cron job" "C" "TRIGGER" "TRIGGER" "$MATCHES"
fi

# ─────────────────────────────────────────────
# N9: 5 SSH connections in 20s (Category B)
# Rule tested: 100501 (port scan, threshold=20)
# Expected: no trigger (well below threshold)
# ─────────────────────────────────────────────
echo "N9: 5 SSH connections in 20s (threshold is 20)..."
T_START=$(get_start_time)
$WS "for i in 1 2 3 4 5; do \
  ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
    $WEBSERVER_IP 'true' 2>/dev/null || true; \
done" > /dev/null 2>&1
sleep "$WAIT"
MATCHES=$(check_log "$T_START")
if [ -z "$MATCHES" ]; then
    report 9 "5 SSH connections in 20s" "B" "NO_TRIGGER" "NO_TRIGGER" ""
else
    report 9 "5 SSH connections in 20s" "B" "NO_TRIGGER" "TRIGGER" "$MATCHES"
fi

# ─────────────────────────────────────────────
# N10: Bash SSH port-forward (Category A - distinguishable benign)
# Rule tested: 100520 (reverse shell)
# Expected: no trigger. The rule keys on a bash-OWNED established TCP
# connection; an SSH port-forward's socket belongs to ssh/sshd, not bash,
# so it is distinguishable from a reverse shell and must not trigger.
# ─────────────────────────────────────────────
echo "N10: Bash with SSH port-forward (legitimate TCP)..."
T_START=$(get_start_time)
$WS "ssh -o StrictHostKeyChecking=no -f -N \
  -L 18080:localhost:80 $WEBSERVER_IP \
  sleep 10 2>/dev/null || true"
sleep "$WAIT"
# Cleanup: kill the port-forward
$WS "pkill -f 'ssh.*18080.*localhost' 2>/dev/null || true"
MATCHES=$(check_log "$T_START")
if [ -z "$MATCHES" ]; then
    report 10 "SSH port-forward" "A" "NO_TRIGGER" "NO_TRIGGER" ""
else
    if echo "$MATCHES" | grep -q "reverse_shell"; then
        report 10 "SSH port-forward" "A" "NO_TRIGGER" "TRIGGER" "$MATCHES"
    else
        report 10 "SSH port-forward" "A" "NO_TRIGGER" "NO_TRIGGER" ""
    fi
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "============================================"
echo "  RESULTS SUMMARY"
echo "============================================"
echo "  True negatives (PASS):           $PASS / 5"
echo "  Known false positives (expected): $EXPECTED_FP / 3"
echo "  Unexpected results (FAIL):        $FAIL"
echo ""
echo "  Category A (clearly different):   N1, N5, N10"
echo "  Category B (boundary tests):      N2, N9"
echo "  Category C (known limitations):   N4, N7, N8"
echo ""
echo "  Full results: $RESULTS_FILE"
echo "============================================"

if [ "$FAIL" -eq 0 ]; then
    echo ""
    echo "  All tests behaved as expected."
fi
