#!/usr/bin/env bash
# Reset lab state: remove an IP's DROP rules on all endpoints and clear
# blocked.json. Usage: bash experiments/unblock_attacker.sh 10.1.1.64
set -euo pipefail

TARGET="${1:?usage: $0 <ip>}"
ROOT=/opt/automated-ti-pipeline

sudo -u wazuh env HOME="$ROOT/runtime" \
  ansible-playbook -i "$ROOT/response/inventory.yml" \
  "$ROOT/response/playbooks/unblock_ip.yml" -e "target=$TARGET"

sudo rm -f /var/log/ti-pipeline/blocked.json
echo "unblocked $TARGET and cleared blocked.json"
