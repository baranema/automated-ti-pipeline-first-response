#!/bin/bash
# Port scan response time (T1046): run nmap from the attacker, time until
# block_ip.yml completes. The attacker IP must NOT be in the allowlist.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
RUNS=10
COOLDOWN=75
WAIT_MAX=60

CTRL="$SSH_CONTROLLER"
ATK="$SSH_ATTACKER"
RESULTS_FILE="$(pwd)/portscan_results.txt"

echo ""

> "$RESULTS_FILE"

reset_state() {
    # remove any standing block on the attacker + clear the 24h dedup record
    $CTRL "cd /opt/automated-ti-pipeline && \
      sudo ansible endpoints -i $INVENTORY -m shell \
      -a 'iptables -D INPUT -s $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
          iptables -D OUTPUT -d $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
          true' -b" 2>/dev/null || true

    $CTRL "sudo python3 -c \"import json,pathlib; \
      p=pathlib.Path('/var/log/ti-pipeline/blocked.json'); \
      d=json.loads(p.read_text()) if p.exists() else {}; \
      d.pop('$ATTACKER_IP',None); \
      p.write_text(json.dumps(d,indent=2))\"" 2>/dev/null || true
}

for i in $(seq 1 "$RUNS"); do
    echo "===== Run $i / $RUNS ====="

    reset_state
    $ATK "sudo pkill -f nmap" 2>/dev/null || true
    sleep 3

    t_start=$(python3 -c "import time; print(time.time())")
    t_start_iso=$(python3 -c "from datetime import datetime; print(datetime.now().isoformat())")
    echo "  scan started at $(date +%H:%M:%S)"
    $ATK "sudo nohup nmap -sS -p 1-1000 -T4 $WEBSERVER_IP >/dev/null 2>&1 &" 2>/dev/null

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
          and 'port_scan' in str(d.get('matched','')) \
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

    $ATK "sudo pkill -f nmap" 2>/dev/null || true

    if [ -z "$BLOCK_TIME" ]; then
        echo "  TIMEOUT: no block in ${WAIT_MAX}s"
        sleep "$COOLDOWN"
        continue
    fi

    delta=$(python3 -c "
from datetime import datetime
t_start = $t_start
block_dt = datetime.fromisoformat('$BLOCK_TIME')
print(round(block_dt.timestamp() - t_start, 3))
")
    echo "  $delta s"
    echo "$delta" >> "$RESULTS_FILE"

    reset_state
    sleep "$COOLDOWN"
done

echo ""
echo "===== Summary ====="
python3 "$(dirname "${BASH_SOURCE[0]}")/latency_stats.py" "$RESULTS_FILE"
