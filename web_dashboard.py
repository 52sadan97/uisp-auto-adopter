#!/usr/bin/env python3
"""
UISP Auto-Adopter — Web Dashboard
A Flask-based web interface for monitoring and controlling device adoption.
"""

import os
import sys
import json
import time
import threading
import logging
import ipaddress
from datetime import datetime
from flask import Flask, render_template, jsonify, request

from config_manager import (
    load_config, save_config, validate_config,
    validate_network_range, validate_ip, get_settings
)

# Import scanner functions (with reload support)
import uisptara
from uisptara import (
    scan_all_networks, adopt_device, load_history, save_to_history,
    check_port, reload_config as reload_scanner_config,
    __version__
)

app = Flask(__name__, template_folder='templates', static_folder='static')

# ================= SCAN STATE =================
scan_state = {
    "is_running": False,
    "progress": 0,
    "total_ips": 0,
    "scanned_ips": 0,
    "current_network": "",
    "current_ip": "",
    "start_time": None,
    "results": [],
    "live_log": [],
    "dry_run": False
}
scan_lock = threading.Lock()


class WebLogHandler(logging.Handler):
    """Custom log handler that captures logs for the web dashboard."""
    def __init__(self, max_entries=500):
        super().__init__()
        self.max_entries = max_entries

    def emit(self, record):
        try:
            msg = self.format(record)
            with scan_lock:
                scan_state["live_log"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "level": record.levelname,
                    "message": msg
                })
                if len(scan_state["live_log"]) > self.max_entries:
                    scan_state["live_log"] = scan_state["live_log"][-self.max_entries:]
        except Exception:
            pass


# Add web log handler
web_handler = WebLogHandler()
web_handler.setFormatter(logging.Formatter('%(message)s'))
logging.getLogger().addHandler(web_handler)


# ================= ROUTES =================

@app.route('/')
def dashboard():
    """Serve the main dashboard page."""
    return render_template('dashboard.html', version=__version__)


# ================= API: STATS =================

@app.route('/api/stats')
def api_stats():
    """Return current scan statistics."""
    config = load_config()
    settings = config.get("settings", {})
    stats_file = settings.get("stats_filename", "scan_stats.json")
    history_file = settings.get("history_filename", "basarili_cihazlar.txt")

    stats = {}
    if os.path.exists(stats_file):
        try:
            with open(stats_file, 'r', encoding='utf-8') as f:
                stats = json.load(f)
        except Exception:
            pass

    history = load_history()
    stats["total_adopted_all_time"] = len(history)
    stats["is_configured"] = bool(
        config.get("network_ranges") and
        config.get("credentials") and
        config.get("uisp_connection_string")
    )
    stats["network_count"] = len(config.get("network_ranges", []))
    stats["networks"] = config.get("network_ranges", [])
    return jsonify(stats)


# ================= API: DEVICES =================

@app.route('/api/devices')
def api_devices():
    """Return list of adopted devices."""
    history = load_history()
    devices = []
    for ip in sorted(history, key=lambda x: list(map(int, x.split('.')))):
        parts = ip.split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        devices.append({
            "ip": ip,
            "subnet": subnet,
            "status": "adopted"
        })
    return jsonify({"devices": devices, "total": len(devices)})


@app.route('/api/devices/check', methods=['POST'])
def api_check_device():
    """Check if a single device is reachable."""
    data = request.get_json()
    ip = data.get("ip", "")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    reachable = check_port(ip)
    return jsonify({"ip": ip, "reachable": reachable})


# ================= API: SCAN =================

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    """Start a network scan in the background."""
    with scan_lock:
        if scan_state["is_running"]:
            return jsonify({"error": "Scan already in progress"}), 409

    data = request.get_json() or {}
    dry_run = data.get("dry_run", False)
    config = load_config()
    threads = data.get("threads", config.get("settings", {}).get("max_threads", 10))

    def run_scan():
        # Reload config before each scan
        reload_scanner_config()

        with scan_lock:
            scan_state["is_running"] = True
            scan_state["progress"] = 0
            scan_state["scanned_ips"] = 0
            scan_state["start_time"] = time.time()
            scan_state["results"] = []
            scan_state["live_log"] = []
            scan_state["dry_run"] = dry_run

        try:
            results = scan_all_networks(dry_run=dry_run, max_threads=threads)
            with scan_lock:
                scan_state["results"] = results
                scan_state["progress"] = 100
        except Exception as e:
            logging.error(f"Scan error: {e}")
        finally:
            with scan_lock:
                scan_state["is_running"] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return jsonify({"status": "started", "dry_run": dry_run})


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    """Stop current scan."""
    with scan_lock:
        scan_state["is_running"] = False
    return jsonify({"status": "stop_requested"})


@app.route('/api/scan/status')
def api_scan_status():
    """Return current scan status and live log."""
    with scan_lock:
        elapsed = 0
        if scan_state["start_time"] and scan_state["is_running"]:
            elapsed = time.time() - scan_state["start_time"]

        adopted = sum(1 for r in scan_state["results"] if r.get("status") == "adopted")
        failed = sum(1 for r in scan_state["results"] if r.get("status") == "failed")

        return jsonify({
            "is_running": scan_state["is_running"],
            "progress": scan_state["progress"],
            "elapsed_seconds": round(elapsed, 1),
            "results_count": len(scan_state["results"]),
            "adopted": adopted,
            "failed": failed,
            "dry_run": scan_state["dry_run"],
            "live_log": scan_state["live_log"][-50:]
        })


@app.route('/api/scan/adopt-single', methods=['POST'])
def api_adopt_single():
    """Adopt a single device."""
    reload_scanner_config()  # Fresh config
    data = request.get_json()
    ip = data.get("ip", "")
    dry_run = data.get("dry_run", False)

    if not ip:
        return jsonify({"error": "IP required"}), 400

    result = adopt_device(ip, dry_run=dry_run)
    if result["status"] == "adopted" and not dry_run:
        save_to_history(ip)
    return jsonify(result)


# ================= API: LOGS =================

@app.route('/api/logs')
def api_logs():
    """Return recent log entries from the log file."""
    config = load_config()
    log_file = config.get("settings", {}).get("log_filename", "uisp_scan_results.log")
    lines = []
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                lines = [l.strip() for l in all_lines[-100:]]
        except Exception:
            pass
    return jsonify({"logs": lines})


# ================= API: SUBNET STATS =================

@app.route('/api/subnet-stats')
def api_subnet_stats():
    """Return device count per subnet."""
    history = load_history()
    subnet_counts = {}
    for ip in history:
        parts = ip.split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

    subnets = [{"subnet": k, "count": v} for k, v in sorted(subnet_counts.items(), key=lambda x: -x[1])]
    return jsonify({"subnets": subnets})


# ================================================================
# API: CONFIGURATION (FULL CRUD)
# ================================================================

@app.route('/api/config')
def api_config():
    """Return full configuration (credentials are masked)."""
    config = load_config()
    # Mask passwords for display
    safe_config = {
        "uisp_connection_string": config.get("uisp_connection_string", ""),
        "credentials": [
            {
                "username": c.get("username", ""),
                "password": c.get("password", "")
            }
            for c in config.get("credentials", [])
        ],
        "network_ranges": config.get("network_ranges", []),
        "settings": config.get("settings", {})
    }
    return jsonify(safe_config)


@app.route('/api/config', methods=['POST'])
def api_config_save():
    """Save the entire configuration."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Validate
    is_valid, errors = validate_config(data)
    if not is_valid:
        return jsonify({"error": "Validation failed", "errors": errors}), 400

    # Save
    if save_config(data):
        reload_scanner_config()
        return jsonify({"status": "saved", "message": "Yapılandırma başarıyla kaydedildi!"})
    else:
        return jsonify({"error": "Kaydetme başarısız!"}), 500


# ── Network Ranges ──

@app.route('/api/config/networks', methods=['GET'])
def api_get_networks():
    """Return all network ranges."""
    config = load_config()
    return jsonify({"network_ranges": config.get("network_ranges", [])})


@app.route('/api/config/networks', methods=['POST'])
def api_add_network():
    """Add a new network range."""
    data = request.get_json()
    network = data.get("network", "").strip()

    if not network:
        return jsonify({"error": "Ağ aralığı boş olamaz"}), 400

    valid, err = validate_network_range(network)
    if not valid:
        return jsonify({"error": f"Geçersiz ağ aralığı: {err}"}), 400

    # Normalize
    normalized = str(ipaddress.ip_network(network, strict=False))

    config = load_config()
    networks = config.get("network_ranges", [])

    if normalized in networks:
        return jsonify({"error": f"{normalized} zaten mevcut"}), 409

    networks.append(normalized)
    config["network_ranges"] = networks
    save_config(config)
    reload_scanner_config()

    return jsonify({"status": "added", "network": normalized, "total": len(networks)})


@app.route('/api/config/networks', methods=['DELETE'])
def api_remove_network():
    """Remove a network range."""
    data = request.get_json()
    network = data.get("network", "").strip()

    config = load_config()
    networks = config.get("network_ranges", [])

    if network in networks:
        networks.remove(network)
        config["network_ranges"] = networks
        save_config(config)
        reload_scanner_config()
        return jsonify({"status": "removed", "network": network, "total": len(networks)})
    else:
        return jsonify({"error": f"{network} bulunamadı"}), 404


# ── Credentials ──

@app.route('/api/config/credentials', methods=['GET'])
def api_get_credentials():
    """Return all credentials."""
    config = load_config()
    return jsonify({"credentials": config.get("credentials", [])})


@app.route('/api/config/credentials', methods=['POST'])
def api_add_credential():
    """Add a new credential pair."""
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Kullanıcı adı ve şifre gerekli"}), 400

    config = load_config()
    creds = config.get("credentials", [])

    # Check duplicate
    for c in creds:
        if c["username"] == username and c["password"] == password:
            return jsonify({"error": "Bu kimlik bilgisi zaten mevcut"}), 409

    creds.append({"username": username, "password": password})
    config["credentials"] = creds
    save_config(config)
    reload_scanner_config()

    return jsonify({"status": "added", "username": username, "total": len(creds)})


@app.route('/api/config/credentials', methods=['DELETE'])
def api_remove_credential():
    """Remove a credential pair by index."""
    data = request.get_json()
    index = data.get("index")

    if index is None:
        return jsonify({"error": "Index gerekli"}), 400

    config = load_config()
    creds = config.get("credentials", [])

    if 0 <= index < len(creds):
        removed = creds.pop(index)
        config["credentials"] = creds
        save_config(config)
        reload_scanner_config()
        return jsonify({"status": "removed", "username": removed["username"], "total": len(creds)})
    else:
        return jsonify({"error": "Geçersiz index"}), 400


# ── UISP Connection String ──

@app.route('/api/config/uisp', methods=['POST'])
def api_update_uisp():
    """Update the UISP connection string."""
    data = request.get_json()
    uisp_string = data.get("uisp_connection_string", "").strip()

    if not uisp_string:
        return jsonify({"error": "UISP bağlantı dizesi boş olamaz"}), 400

    config = load_config()
    config["uisp_connection_string"] = uisp_string
    save_config(config)
    reload_scanner_config()

    return jsonify({"status": "updated"})


# ── Settings ──

@app.route('/api/config/settings', methods=['POST'])
def api_update_settings():
    """Update scanning settings."""
    data = request.get_json()

    config = load_config()
    settings = config.get("settings", {})

    # Update only provided fields with validation
    if "max_threads" in data:
        val = int(data["max_threads"])
        if 1 <= val <= 100:
            settings["max_threads"] = val
        else:
            return jsonify({"error": "Thread sayısı 1-100 arasında olmalı"}), 400

    if "ssh_timeout" in data:
        val = float(data["ssh_timeout"])
        if 1 <= val <= 60:
            settings["ssh_timeout"] = val
        else:
            return jsonify({"error": "SSH timeout 1-60 arasında olmalı"}), 400

    if "port_scan_timeout" in data:
        val = float(data["port_scan_timeout"])
        if 0.1 <= val <= 10:
            settings["port_scan_timeout"] = val
        else:
            return jsonify({"error": "Port tarama timeout 0.1-10 arasında olmalı"}), 400

    if "dashboard_port" in data:
        val = int(data["dashboard_port"])
        if 1024 <= val <= 65535:
            settings["dashboard_port"] = val
        else:
            return jsonify({"error": "Port 1024-65535 arasında olmalı"}), 400

    config["settings"] = settings
    save_config(config)
    reload_scanner_config()

    return jsonify({"status": "updated", "settings": settings})


# ================= MAIN =================

if __name__ == '__main__':
    config = load_config()
    port = config.get("settings", {}).get("dashboard_port", 5050)
    debug = os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"

    print(f"""
╔══════════════════════════════════════════════════╗
║        📡 UISP Auto-Adopter Dashboard           ║
║        Version: {__version__:<33s}║
║        URL: http://localhost:{port:<21d}║
╚══════════════════════════════════════════════════╝
    """)

    app.run(host='0.0.0.0', port=port, debug=debug)
