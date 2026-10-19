#!/bin/bash
# Cron persistence response time (T1053.003): plant a file in /etc/cron.d/, time
# until remove_persistence.yml completes (rc==0). End point matches the others.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
CRON_FILE="/etc/cron.d/backdoor"
RUNS=10
COOLDOWN=15            # let Wazuh FIM settle between trials
WAIT_MAX=60

CTRL="$SSH_CONTROLLER"
WS="$SSH_WORKSTATION"
RESULTS_FILE="$(pwd)/cron_results.txt"

echo "End point : playbook finished, rc==0 (integrator log)"
echo ""

> "$RESULTS_FILE"

for i in $(seq 1 "$RUNS"); do
    echo "===== Run $i / $RUNS ====="

    $WS "sudo rm -f $CRON_FILE" 2>/dev/null || true
    sleep 3

    t_start=$(python3 -c "import time; print(time.time())")
    t_start_iso=$(python3 -c \
      "from datetime import datetime; print(datetime.now().isoformat())")
    echo "  planting $CRON_FILE at $(date +%H:%M:%S)"
    $WS "echo '* * * * * root /tmp/backdoor.sh' | sudo tee $CRON_FILE > /dev/null"

    DONE_TIME=""
    elapsed=0
    while [ $elapsed -lt $WAIT_MAX ]; do
        DONE_TIME=$($CTRL "sudo python3 -c \"
import json
start = '$t_start_iso'
with open('/var/log/ti-pipeline/integrator.log') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        if d.get('t','') > start \
          and 'cron_persistence' in str(d.get('matched','')) \
          and d.get('outcome',{}).get('rc') == 0:
            print(d['t'])
            break
\"" 2>/dev/null)
        if [ -n "$DONE_TIME" ]; then
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo ""

    if [ -z "$DONE_TIME" ]; then
        echo "  TIMEOUT: no rc==0 remediation in ${WAIT_MAX}s"
        $WS "sudo rm -f $CRON_FILE" 2>/dev/null || true
        sleep "$COOLDOWN"
        continue
    fi

    delta=$(python3 -c "
from datetime import datetime
t_start = $t_start
done_epoch = datetime.fromisoformat('$DONE_TIME').timestamp()
print(round(done_epoch - t_start, 3))
")
    echo "  remediated at $DONE_TIME"
    echo "  $delta s"
    echo "$delta" >> "$RESULTS_FILE"

    if $WS "sudo test -f $CRON_FILE" 2>/dev/null; then
        echo "  WARNING: cron file still present"
        $WS "sudo rm -f $CRON_FILE" 2>/dev/null || true
    fi

    sleep "$COOLDOWN"
done

echo ""
echo "===== Summary ====="
python3 "$(dirname "${BASH_SOURCE[0]}")/latency_stats.py" "$RESULTS_FILE"
