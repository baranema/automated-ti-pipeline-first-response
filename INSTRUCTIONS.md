# Running it on a clean VM

How to set up and run the pipeline from scratch. See `README.md` for what the project is and what each folder contains.

Tested on **Ubuntu 22.04**. You need Linux machines on one private network:

| Role                   | Example IP | What it runs                              |
| ---------------------- | ---------- | ----------------------------------------- |
| Controller             | 10.0.0.116 | Wazuh manager + `integrator.py` + Ansible |
| Endpoint - webserver   | 10.1.1.62  | Wazuh agent + Apache                      |
| Endpoint - workstation | 10.1.1.56  | Wazuh agent                               |
| Attacker               | 10.1.1.64  | nmap, hydra (runs the test attacks)       |

A minimal run needs three machines: controller, the webserver endpoint, and the attacker. The IPs above are examples; set your own in Step 3.

## Step 1 - Install prerequisites (downloaded from official sources)

**On the controller** - Wazuh manager (guide: <https://documentation.wazuh.com/current/quickstart.html>):

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

**On the controller** - Ansible, Python, and Git:

```bash
sudo apt update && sudo apt install -y ansible python3 python3-pip git
```

**On each endpoint** - Wazuh agent, pointed at the controller's IP (guide: <https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html>). Add the Wazuh repository first, then install:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER="10.0.0.116" apt install -y wazuh-agent
sudo systemctl enable --now wazuh-agent
```

**On the webserver endpoint** - Apache (serves the web-shell target directory):

```bash
sudo apt install -y apache2
```

**On the attacker** - the attack tools:

```bash
sudo apt update && sudo apt install -y nmap hydra python3
```

auditd and the per-scenario sensors are installed for you in Step 4.

## Step 2 - Get the code

The pipeline expects the fixed path `/opt/automated-ti-pipeline` (hard-coded in `integrator.py` and `ansible.cfg`). On the controller, unzip this submission - or clone the repo - to that path, then install the one Python dependency:

```bash
sudo unzip automated-ti-pipeline.zip -d /opt/
sudo mv /opt/automated-ti-pipeline-gitlab /opt/automated-ti-pipeline
cd /opt/automated-ti-pipeline
pip3 install -r requirements.txt
```

## Step 3 - Configure for your machines

Edit four files to match your lab:

- `response/inventory.yml` - endpoint IPs, SSH user, and SSH key path
- `decision/allowlist.yml` - IPs the pipeline must never block (controller, endpoints, your admin machine)
- `decision/alert_actions.yml` - the alert-to-playbook map (leave as-is to reproduce the six scenarios)
- `experiments/experiments.env` - hosts/ports/user, only needed for Step 6

Ansible reaches the endpoints over SSH, so set up key-based SSH from the controller to each endpoint, and give that user passwordless `sudo` (the playbooks use `become`).

## Step 4 - Deploy

Install the per-scenario sensors on the endpoints, then wire the pipeline into Wazuh on the controller:

```bash
for p in setup_auditd setup_fim_cron setup_iptables_log \
         setup_reverse_shell_detection setup_webshell_detection; do
  ansible-playbook detection/setup/$p.yml
done

sudo bash install_on_controller.sh
```

`install_on_controller.sh` installs the integration, deploys the detection rules, creates the log directories, and restarts the manager. It should end with:

```
wazuh-manager: active
integratord: running
```

## Step 5 - Verify it works

Trigger the fastest scenario from a webserver endpoint:

```bash
echo '<?php echo 1; ?>' | sudo tee /var/www/html/test.php
```

Within a few seconds the file is gone (quarantined) and the controller log shows the match and the response:

```bash
tail -n 5 /var/log/ti-pipeline/integrator.log
```

## Step 6 - Reproduce the experiments from the report

Each command below runs one of the experiments reported in the thesis. Run them from a machine that can SSH to the lab (not from a host being measured); they read their hosts from `experiments/experiments.env` and write results under `results/`.

```bash
bash experiments/speed/measure_webshell.sh           # response time, one scenario
bash experiments/robustness/measure_chain.sh         # four-stage attack chain
bash experiments/reliability/test_false_positives.sh # benign-traffic suite
RUNS=10 bash experiments/reliability/eval_confusion.sh  # detection correctness
bash experiments/robustness/measure_load.sh          # behaviour under load
```

Reset the lab between runs with `bash experiments/unblock_attacker.sh <attacker-ip>`.

The committed `results/` folder already holds the data behind the report's figures: per-scenario response times, the response-time breakdown, the confusion matrix, and the load test.
