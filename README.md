# Automated Threat-Intelligence Pipeline for First Response

This project is an automated first-response pipeline: Wazuh detects an attack, a small Python script picks the response, and Ansible applies it over SSH - with no human in the loop. It covers six attack scenarios, each detected and remediated in seconds.

The full thesis report is in [`report/Emilija_Baranauskaite_Automated_TI_Pipeline_for_First_Response.pdf`](report/Emilija_Baranauskaite_Automated_TI_Pipeline_for_First_Response.pdf).

## How it works

1. Each endpoint runs a Wazuh agent that ships logs, command records, and file-integrity events to the manager.
2. The manager raises an alert; those at level >= 6 are sent to the decision script.
3. `decision/integrator.py` maps the alert to a playbook (checking an allowlist and a 24-hour recent-block record before any IP block).
4. Ansible applies the fix on the affected endpoint over SSH.

| Attack scenario  | MITRE     | Detected by              | Response             |
| ---------------- | --------- | ------------------------ | -------------------- |
| Port scan        | T1046     | iptables connection log  | `block_ip`           |
| SSH brute force  | T1110.001 | Wazuh built-in rules     | `block_ip`           |
| Web shell upload | T1505.003 | file-integrity monitor   | `quarantine_file`    |
| Reverse shell    | T1059.004 | command check (every 5s) | `kill_process`       |
| Base64 execution | T1059.004 | auditd command log       | `kill_process`       |
| Cron persistence | T1053.003 | file-integrity monitor   | `remove_persistence` |

## What is in this repo

```
detection/                 how attacks are spotted
  rules/                   Wazuh detection rules, one per scenario (XML)
  sigma/                   the base64 rule in vendor-neutral Sigma form
  setup/                   playbooks that deploy the sensors to endpoints
decision/                  the decision logic
  integrator.py            reads an alert, runs the mapped playbook
  alert_actions.yml        which alert triggers which playbook
  allowlist.yml            IPs that must never be blocked
response/                  how attacks are answered
  playbooks/               block_ip, kill_process, quarantine_file, remove_persistence
  inventory.yml            the endpoints responses act on
experiments/               scripts that measure the pipeline (speed/, reliability/, robustness/)
  experiments.env          hosts/ports/user for the scripts (edit this)
results/                   measurement data, JSON + text
install_on_controller.sh   wires the pipeline into Wazuh (run on the controller)
ansible.cfg                Ansible defaults (SSH handling, inventory path)
requirements.txt           the one Python dependency (PyYAML)
report/                    the thesis report (PDF)
```

---

## Running it

To set up and run the pipeline on a clean VM - prerequisites, deployment, verification, and reproducing the experiments - see **[INSTRUCTIONS.md](INSTRUCTIONS.md)**.
