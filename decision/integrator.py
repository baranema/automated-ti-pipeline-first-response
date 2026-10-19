"""Wazuh integration: turn one alert into one enforcement action.

Usage: python3 integrator.py /tmp/alert.json

Walks alert_actions.yml in order and runs the first matching rule's playbook,
once the allowlist and recent-blocks checks pass.
"""

import sys
import os
import json
import re
import ipaddress
import subprocess
import fcntl
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import yaml

ROOT = Path("/opt/automated-ti-pipeline")
CONFIG_FILE = ROOT / "decision" / "alert_actions.yml"
ALLOWLIST_FILE = ROOT / "decision" / "allowlist.yml"
RESPONSE_DIR = ROOT / "response"
LOG_FILE = Path("/var/log/ti-pipeline/integrator.log")
STATE_FILE = Path("/var/log/ti-pipeline/blocked.json")
LOCK_FILE = Path("/var/log/ti-pipeline/blocked.lock")
STATE_TTL_HOURS = 24


def load_yaml(path, default):
    """Parse a YAML file, returning `default` when it is missing or empty."""
    if not path.exists():
        return default
    return yaml.safe_load(path.read_text()) or default


def get_value(alert, path):
    """Resolve a dotted path: 'rule.id' -> alert['rule']['id'], or None."""
    value = alert
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def rule_matches(rule, alert):
    """True when every field in rule['match'] satisfies its expected value."""
    for field, expected in rule.get("match", {}).items():
        actual = get_value(alert, field)
        if isinstance(expected, list) and actual not in expected:
            return False
        if isinstance(expected, str) and not re.fullmatch(expected, str(actual or "")):
            return False
        if not isinstance(expected, (list, str)) and actual != expected:
            return False
    return True


def render_template(text, alert):
    """Substitute {{ field.path }} placeholders with values from the alert."""
    def replace(match):
        return str(get_value(alert, match.group(1)) or "")
    return re.sub(r"\{\{\s*([\w.]+)\s*\}\}", replace, text)


def is_allowed_ip(ip, allowlist):
    """True when `ip` falls inside any IP or CIDR in allowlist['allowed_srcips']."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowlist.get("allowed_srcips", []):
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def read_state():
    """Return the blocked-target map, or empty when missing or corrupt."""
    try:
        return json.loads(STATE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_state(state):
    """Write the state file atomically so it is never left half-written."""
    temp = STATE_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2))
    os.replace(temp, STATE_FILE)


def is_recently_blocked(target, now):
    """True when `target` was blocked within the last STATE_TTL_HOURS."""
    when = read_state().get(target)
    if not when:
        return False
    age_hours = (now - datetime.fromisoformat(when)).total_seconds() / 3600
    return age_hours < STATE_TTL_HOURS


def mark_blocked(target, now):
    """Record that `target` was blocked at `now`; caller holds the state lock."""
    state = read_state()
    state[target] = now.isoformat()
    write_state(state)


@contextmanager
def state_lock():
    """Hold an exclusive lock so only one IP response edits blocked.json at a time."""
    descriptor = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def run_playbook(playbook, params):
    """Run one Ansible playbook; return its code, duration, and stderr tail."""
    command = [
        "/usr/bin/ansible-playbook",
        "-i", str(RESPONSE_DIR / "inventory.yml"),
        str(RESPONSE_DIR / "playbooks" / playbook),
    ]
    for key, value in params.items():
        command += ["-e", f"{key}={value}"]
    started = datetime.now()
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=120, cwd=str(ROOT)
    )
    return {
        "rc": result.returncode,
        "duration_ms": int((datetime.now() - started).total_seconds() * 1000),
        "stderr_tail": (result.stderr or "")[-400:],
    }


def write_log(entry):
    """Append one timestamped JSON line to the integrator log."""
    entry["t"] = datetime.now().isoformat()
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(entry) + "\n")


def dispatch_ip_block(action, params, base, now):
    """Run an IP-blocking playbook under the state lock, deduping recent blocks."""
    target = params["target"]
    with state_lock():
        if is_recently_blocked(target, now):
            write_log({**base, "suppressed": "already_blocked"})
            return
        outcome = run_playbook(action["playbook"], params)
        if outcome["rc"] == 0:
            mark_blocked(target, now)
        write_log({**base, "params": params, "outcome": outcome})


def dispatch(rule, alert, allowlist, now):
    """Handle one rule; return True if it matched (action taken or suppressed)."""
    if not rule_matches(rule, alert):
        return False
    action = rule["action"]
    params = {key: render_template(value, alert)
              for key, value in action.get("params", {}).items()}
    target = params.get("target")
    base = {"matched": rule["name"], "playbook": action["playbook"], "target": target}
    if target and is_allowed_ip(target, allowlist):
        write_log({**base, "suppressed": "allowlist"})
        return True
    if target:
        dispatch_ip_block(action, params, base, now)
        return True
    outcome = run_playbook(action["playbook"], params)
    write_log({**base, "params": params, "outcome": outcome})
    return True


def main():
    alert = json.loads(Path(sys.argv[1]).read_text())
    rules = load_yaml(CONFIG_FILE, [])
    allowlist = load_yaml(ALLOWLIST_FILE, {})
    now = datetime.now()
    for rule in rules:
        if dispatch(rule, alert, allowlist, now):
            return
    write_log({"matched": None, "rule_id": get_value(alert, "rule.id")})


if __name__ == "__main__":
    main()
