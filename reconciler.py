"""
Continuous Discovery & State Drift Reconciler.
Maintains desired_state vs observed_state in gateway_assets.
"""

import json
import subprocess
import time
from typing import Any, Dict, List, Optional
from db import get_db_connection


def scan_observed_docker() -> Dict[str, str]:
    """Scans running Docker containers using docker CLI."""
    result = {}
    try:
        proc = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().splitlines():
                if "\t" in line:
                    name, status = line.split("\t", 1)
                    state = "RUNNING" if status.startswith("Up") else "STOPPED"
                    result[f"docker:{name}"] = state
    except Exception:
        pass
    return result


def scan_observed_systemd() -> Dict[str, str]:
    """Scans systemd units registered in assets."""
    result = {}
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, name FROM gateway_assets WHERE category = 'systemd';")
        units = cursor.fetchall()

    for u in units:
        unit_name = u["name"]
        if not unit_name.endswith(".service"):
            unit_name += ".service"
        try:
            proc = subprocess.run(
                ["systemctl", "is-active", unit_name],
                capture_output=True,
                text=True,
                timeout=3,
            )
            state = "RUNNING" if proc.stdout.strip() == "active" else "STOPPED"
            result[u["key"]] = state
        except Exception:
            result[u["key"]] = "UNKNOWN"
    return result


def scan_system_snapshot() -> Dict[str, Any]:
    """Collects quick memory, cpu and disk stats."""
    snapshot = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    # Disk
    try:
        proc = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=2)
        lines = proc.stdout.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            snapshot["disk"] = {"total": parts[1], "used": parts[2], "avail": parts[3], "pct": parts[4]}
    except Exception:
        snapshot["disk"] = "unknown"

    # Memory
    try:
        proc = subprocess.run(["free", "-m"], capture_output=True, text=True, timeout=2)
        lines = proc.stdout.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            snapshot["memory_mb"] = {"total": parts[1], "used": parts[2], "free": parts[3]}
    except Exception:
        snapshot["memory_mb"] = "unknown"

    return snapshot


def reconcile_observed_state() -> List[Dict[str, str]]:
    """
    Core Reconciler:
    Scans host reality and updates gateway_assets.observed_state.
    Calculates drift_status = IN_SYNC if desired_state == observed_state else DRIFTED.
    Returns list of assets with detected drift.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    detected_drifts = []

    docker_states = scan_observed_docker()
    systemd_states = scan_observed_systemd()
    observed_map = {**docker_states, **systemd_states}

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, desired_state, observed_state, drift_status FROM gateway_assets;")
        assets = cursor.fetchall()

        for a in assets:
            key = a["key"]
            desired = a["desired_state"]
            old_observed = a["observed_state"]

            # If probed, update observed state
            if key in observed_map:
                new_observed = observed_map[key]
                new_drift = "IN_SYNC" if desired == new_observed else "DRIFTED"

                if new_drift == "DRIFTED":
                    detected_drifts.append({"key": key, "desired": desired, "observed": new_observed})

                conn.execute(
                    """
                    UPDATE gateway_assets
                    SET observed_state = ?, drift_status = ?, last_discovered_at = ?, updated_at = ?
                    WHERE key = ?;
                    """,
                    (new_observed, new_drift, now_iso, now_iso, key),
                )
        conn.commit()

    return detected_drifts