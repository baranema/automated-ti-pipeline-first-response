#!/bin/bash
# Web shell response time (T1505.003): drop a .php in the web root, time until
# quarantine_file.yml completes. Run from a machine that can SSH to the lab.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
RUNS=10
COOLDOWN=30
WAIT_MAX=60

CTRL="$SSH_CONTROLLER"
WEB="$SSH_WEBSERVER"
RESULTS_FILE="$(pwd)/webshell_results.txt"

echo ""

> "$RESULTS_FILE"

for i in $(seq 1 "$RUNS"); do
    echo "===== Run $i / $RUNS ====="

    $WEB "sudo rm -f /var/www/html/testshell_*.php" 2>/dev/null || true
    $WEB "sudo rm -f /var/quarantine/*testshell_*" 2>/dev/null || true
    sleep 3

    t_start=$(python3 -c "import time; print(time.time())")
    t_start_iso=$(python3 -c \
      "from datetime import datetime; print(datetime.now().isoformat())")
    FILENAME="testshell_${i}.php"
    $WEB "echo '<?php echo 1; ?>' | sudo tee \
      /var/www/html/$FILENAME > /dev/null"

    BLOCK_TIME=""
    elapsed=0
    while [ $elapsed -lt $WAIT_MAX ]; do
        BLOCK_TIME=$($CTRL "sudo python3 -c \"
import json
start = '$t_start_iso'
with open('/var/log/ti-pipeline/integrator.log') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        if d.get('t','') > start \
          and 'web_shell' in str(d.get('matched','')) \
          and d.get('outcome',{}).get('rc') == 0:
            print(d['t'])
            break
\"" 2>/dev/null)
        if [ -n "$BLOCK_TIME" ]; then
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo ""

    if [ -z "$BLOCK_TIME" ]; then
        echo "  TIMEOUT: no quarantine in ${WAIT_MAX}s"
        sleep "$COOLDOWN"
        continue
    fi

    delta=$(python3 -c "
from datetime import datetime
t_start = $t_start
block_str = '$BLOCK_TIME'
block_dt = datetime.fromisoformat(block_str)
block_epoch = block_dt.timestamp()
print(round(block_epoch - t_start, 3))
")
    echo "  $delta s"
    echo "$delta" >> "$RESULTS_FILE"

    if $WEB "test -f /var/www/html/$FILENAME" 2>/dev/null; then
        echo "  WARNING: file still in web root"
    fi

    sleep "$COOLDOWN"
done

echo ""
echo "===== Summary ====="
python3 "$(dirname "${BASH_SOURCE[0]}")/latency_stats.py" "$RESULTS_FILE"
