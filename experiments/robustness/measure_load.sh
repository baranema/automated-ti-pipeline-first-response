#!/bin/bash
# Pipeline capacity: feed synthetic port-scan alerts at rising arrival rates (using
# distinct TEST-NET IPs, since the integrator dedups a target for 24h) and find the
# saturation knee. Env: TP_M (alerts/rate), TP_RATES (comma list).
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
CONTROLLER="$SSH_CONTROLLER"     # INVENTORY also comes from experiments.env
RESULTS_DIR="$(pwd)/results/load_test"
DRIVER_REMOTE="/tmp/load_driver.py"
RESULT_REMOTE="/tmp/load_result.json"
TP_M="${TP_M:-20}"
TP_RATES="${TP_RATES:-0.1,0.25,0.5,1.0,2.0,4.0}"
mkdir -p "$RESULTS_DIR"

$CONTROLLER "cat > $DRIVER_REMOTE" <<'PYEOF'
#!/usr/bin/env python3
"""Run on the controller as root. Sweeps arrival rate lambda; per rate, sends M
synthetic alerts through the real integration wrapper and measures latency."""
import json, subprocess, sys, time
from datetime import datetime
from pathlib import Path

WRAPPER = "/var/ossec/integrations/custom-ti-pipeline"
LOG = Path("/var/log/ti-pipeline/integrator.log")
ALERT_DIR = Path("/tmp/load_alerts")
M = int(sys.argv[1]) if len(sys.argv) > 1 else 20
RATES = [float(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else [0.1, 0.25, 0.5, 1.0, 2.0, 4.0]

ALERT_DIR.mkdir(parents=True, exist_ok=True)

def done_epoch(target, after):
    for raw in LOG.read_text().splitlines():
        raw = raw.strip()
        if not raw:
            continue
        d = json.loads(raw)
        if d.get("target") == target and d.get("outcome", {}).get("rc") == 0:
            t = datetime.fromisoformat(d["t"]).timestamp()
            if t >= after:
                return t
    return None

ip_index = 0
results = []
for rate in RATES:
    targets, submits = [], {}
    interval = 1.0 / rate
    for _ in range(M):
        ip_index += 1
        target = f"192.0.2.{ip_index}"
        alert = ALERT_DIR / f"alert_{ip_index}.json"
        alert.write_text(json.dumps({"rule": {"id": "100501"}, "data": {"srcip": target}}))
        alert.chmod(0o644)
        submits[target] = time.time()
        subprocess.Popen(["/usr/bin/sudo", "-u", "wazuh", WRAPPER, str(alert)])
        targets.append(target)
        time.sleep(interval)
    deadline = time.time() + M * 8 + 60
    latencies, done = {}, 0
    while time.time() < deadline and done < M:
        time.sleep(2)
        done = 0
        for target in targets:
            end = done_epoch(target, submits[target])
            if end is not None:
                latencies[target] = round(end - submits[target], 3)
                done += 1
    lat = sorted(latencies.values())
    results.append({
        "rate_per_s": rate, "sent": M, "completed": len(lat),
        "completion": round(len(lat) / M, 3),
        "mean_latency_s": round(sum(lat) / len(lat), 3) if lat else None,
        "p95_latency_s": lat[int((len(lat) - 1) * 0.95)] if lat else None,
        "max_latency_s": lat[-1] if lat else None,
    })
    print(f"  lambda={rate}/s -> completed {len(lat)}/{M}, "
          f"mean_latency={results[-1]['mean_latency_s']}s")

Path("/tmp/load_result.json").write_text(json.dumps({"ip_count": ip_index, "sweep": results}, indent=2))
PYEOF

echo "Running load test on the controller (M=$TP_M, rates=$TP_RATES)..."
$CONTROLLER "sudo python3 $DRIVER_REMOTE $TP_M '$TP_RATES'"

$CONTROLLER "cat $RESULT_REMOTE" > "$RESULTS_DIR/alert_rate_vs_latency.json"
echo "Wrote $RESULTS_DIR/alert_rate_vs_latency.json"

echo "Cleaning up synthetic blocks..."
COUNT=$($CONTROLLER "python3 -c \"import json;print(json.load(open('$RESULT_REMOTE'))['ip_count'])\"" 2>/dev/null || echo 130)
$CONTROLLER "cd /opt/automated-ti-pipeline && sudo ansible endpoints -i $INVENTORY -m shell \
  -a 'for n in \$(seq 1 $COUNT); do \
        iptables -D INPUT -s 192.0.2.\$n -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
        iptables -D OUTPUT -d 192.0.2.\$n -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
      done; true' -b" >/dev/null 2>&1 || true
$CONTROLLER "sudo python3 -c \"import json,pathlib; p=pathlib.Path('/var/log/ti-pipeline/blocked.json'); \
  d=json.loads(p.read_text()) if p.exists() else {}; \
  d={k:v for k,v in d.items() if not k.startswith('192.0.2.')}; \
  p.write_text(json.dumps(d,indent=2))\"" 2>/dev/null || true
$CONTROLLER "rm -rf /tmp/load_alerts $DRIVER_REMOTE $RESULT_REMOTE" 2>/dev/null || true
echo "Cleanup done. Verify: blocked.json should be {} (or free of 192.0.2.x)."
