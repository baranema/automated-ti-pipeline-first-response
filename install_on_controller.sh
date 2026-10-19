#!/usr/bin/env bash
# Wire the pipeline into Wazuh on the controller: install the integration wrapper,
# register it in ossec.conf (alerts >= level 6), deploy the detection rules, and
# restart the manager. Idempotent. Run after cloning to /opt/automated-ti-pipeline:
#   sudo bash install_on_controller.sh
set -euo pipefail

REPO=/opt/automated-ti-pipeline
WRAPPER=/var/ossec/integrations/custom-ti-pipeline
OSSEC=/var/ossec/etc/ossec.conf
LEVEL=6

echo "Creating runtime and log directories..."
sudo mkdir -p /var/log/ti-pipeline "$REPO/runtime/.ssh"
sudo chown -R wazuh:wazuh /var/log/ti-pipeline "$REPO/runtime"

echo "Installing the integration wrapper..."
# Runs as the wazuh user; HOME points at runtime/ because /var/ossec is locked.
sudo install -o root -g wazuh -m 750 /dev/stdin "$WRAPPER" <<'EOF'
#!/usr/bin/env bash
export HOME=/opt/automated-ti-pipeline/runtime
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export ANSIBLE_HOST_KEY_CHECKING=False
exec /usr/bin/python3 /opt/automated-ti-pipeline/decision/integrator.py "$@"
EOF

echo "Registering the integration in ossec.conf..."
sudo grep -q '<name>custom-ti-pipeline</name>' "$OSSEC" || {
  sudo cp "$OSSEC" "$OSSEC.bak.$(date +%s)"
  sudo python3 - <<EOF
from pathlib import Path
block = """
  <integration>
    <name>custom-ti-pipeline</name>
    <level>$LEVEL</level>
    <hook_url>http://localhost</hook_url>
    <alert_format>json</alert_format>
  </integration>
"""
p = Path("$OSSEC")
p.write_text(p.read_text().replace("</ossec_config>", block + "</ossec_config>", 1))
EOF
}

echo "Deploying the detection rules..."
sudo cp "$REPO"/detection/rules/*.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/ti_pipeline_*.xml
sudo chmod 660 /var/ossec/etc/rules/ti_pipeline_*.xml

echo "Restarting Wazuh..."
sudo systemctl restart wazuh-manager
sleep 2

echo "Verifying..."
sudo systemctl is-active --quiet wazuh-manager && echo "  wazuh-manager: active"
sudo /var/ossec/bin/wazuh-control status | grep -q integratord && echo "  integratord: running"
echo "Done."
