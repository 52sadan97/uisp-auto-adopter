#!/usr/bin/env python3
"""
UISP Auto-Adopter — Bulk Ubiquiti device adoption tool for UISP/UNMS.

Scans specified network ranges for Ubiquiti devices (AirOS antennas and
UBIOS routers) via SSH, then automatically configures them to connect
to your UISP server.

Author: SdnNET
License: MIT
"""

import paramiko
import socket
import ipaddress
import time
import logging
import os
import sys
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from config_manager import (
    load_config, get_credentials, get_uisp_string,
    get_network_ranges, get_settings, get_setting,
    get_data_path
)

# ================= VERSION =================
__version__ = "2.1.2"


# ================= CONFIGURATION (from config.json) =================
def _cfg():
    """Reload config from disk for every scan (allows live changes)."""
    return load_config()

# Module-level accessors (for backward compat with imports)
@property
def _lazy():
    pass

def _get_credentials():
    return get_credentials()

def _get_uisp_string():
    return get_uisp_string()

def _get_network_ranges():
    return get_network_ranges()

# Expose module-level variables that auto-reload from config.json
# These are read at import time but also refreshed when functions run.
_initial = load_config()
_settings = _initial.get("settings", {})
LOG_FILENAME = get_data_path(_settings.get("log_filename", "uisp_scan_results.log"))
HISTORY_FILENAME = get_data_path(_settings.get("history_filename", "basarili_cihazlar.txt"))
STATS_FILENAME = get_data_path(_settings.get("stats_filename", "scan_stats.json"))
CREDENTIALS_LIST = get_credentials()
UISP_STRING = get_uisp_string()
NETWORK_RANGES = get_network_ranges()
MAX_THREADS = _settings.get("max_threads", 10)
SSH_TIMEOUT = _settings.get("ssh_timeout", 5)
PORT_SCAN_TIMEOUT = _settings.get("port_scan_timeout", 0.3)


def reload_config():
    """Reload all module-level config variables from config.json."""
    global LOG_FILENAME, HISTORY_FILENAME, STATS_FILENAME
    global CREDENTIALS_LIST, UISP_STRING, NETWORK_RANGES
    global MAX_THREADS, SSH_TIMEOUT, PORT_SCAN_TIMEOUT

    cfg = load_config()
    s = cfg.get("settings", {})
    LOG_FILENAME = get_data_path(s.get("log_filename", "uisp_scan_results.log"))
    HISTORY_FILENAME = get_data_path(s.get("history_filename", "basarili_cihazlar.txt"))
    STATS_FILENAME = get_data_path(s.get("stats_filename", "scan_stats.json"))
    CREDENTIALS_LIST = get_credentials()
    UISP_STRING = get_uisp_string()
    NETWORK_RANGES = get_network_ranges()
    MAX_THREADS = s.get("max_threads", 10)
    SSH_TIMEOUT = s.get("ssh_timeout", 5)
    PORT_SCAN_TIMEOUT = s.get("port_scan_timeout", 0.3)


# Suppress paramiko logging
logging.getLogger("paramiko").setLevel(logging.WARNING)


def setup_logging(verbose=False):
    """Configure logging with file and console handlers."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(LOG_FILENAME, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )


# ================= HELPER FUNCTIONS =================

def load_history():
    """Load previously adopted device IPs from history file."""
    processed_ips = set()
    if os.path.exists(HISTORY_FILENAME):
        with open(HISTORY_FILENAME, "r") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    processed_ips.add(ip)
    return processed_ips


def save_to_history(ip):
    """Append a successfully adopted device IP to history file."""
    with open(HISTORY_FILENAME, "a") as f:
        f.write(f"{ip}\n")


def save_stats(stats):
    """Save scan statistics to a JSON file."""
    with open(STATS_FILENAME, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)


def check_port(ip, port=22, timeout=None):
    """Quick TCP port check to see if a host is reachable on given port."""
    if timeout is None:
        timeout = PORT_SCAN_TIMEOUT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        sock.close()


# ================= DEVICE OPERATIONS =================

def detect_device_type(client, ip):
    """Detect whether the device is UBIOS (Router) or AirOS (Antenna)."""
    # Check for UBIOS
    stdin, stdout, stderr = client.exec_command("test -f /usr/bin/ubios-udapi-client")
    if stdout.channel.recv_exit_status() == 0:
        return "ubios"

    # Check for AirOS
    stdin, stdout, stderr = client.exec_command("test -f /tmp/system.cfg")
    if stdout.channel.recv_exit_status() == 0:
        return "airos"

    return "unknown"


def adopt_ubios(client, ip, dry_run=False):
    """Adopt a UBIOS router device."""
    logging.info(f"🤖 {ip}: UBIOS Router detected. Sending adoption command...")
    if dry_run:
        logging.info(f"🔍 {ip}: [DRY-RUN] Would send UBIOS adoption command.")
        return True

    cmd = (
        f"/usr/bin/ubios-udapi-client -X PUT "
        f"-d '{{\"connectionString\": \"{UISP_STRING}\"}}' "
        f"/v2.1/nms/connection"
    )
    stdin, stdout, stderr = client.exec_command(cmd)
    if stdout.channel.recv_exit_status() == 0:
        logging.info(f"✅ {ip}: SUCCESS — Router adopted!")
        return True
    else:
        error_output = stderr.read().decode('utf-8', errors='ignore').strip()
        logging.error(f"❌ {ip}: UBIOS command failed. {error_output}")
        return False


def adopt_airos(client, ip, dry_run=False):
    """Adopt an AirOS antenna device by modifying the config file."""
    logging.info(f"📡 {ip}: AirOS Antenna detected. Starting configuration...")

    # 1. Read current config
    stdin, stdout, stderr = client.exec_command("cat /tmp/system.cfg")
    config_content = stdout.read().decode('utf-8', errors='ignore')

    if not config_content:
        logging.error(f"❌ {ip}: Config file is empty or unreadable!")
        return False

    # 2. Modify config (update or add UISP URI)
    new_lines = []
    uri_updated = False
    for line in config_content.splitlines():
        if line.strip().startswith("unms.uri="):
            new_lines.append(f"unms.uri={UISP_STRING}")
            uri_updated = True
        else:
            new_lines.append(line)

    if not uri_updated:
        new_lines.append(f"unms.uri={UISP_STRING}")

    new_config_str = "\n".join(new_lines) + "\n"

    if dry_run:
        logging.info(f"🔍 {ip}: [DRY-RUN] Would update system.cfg with UISP URI.")
        return True

    # 3. Write updated config back
    try:
        stdin, stdout, stderr = client.exec_command("cat > /tmp/system.cfg")
        stdin.write(new_config_str)
        stdin.close()

        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0:
            logging.info(f"💾 {ip}: Config updated. Saving and restarting...")
            client.exec_command("save && /usr/etc/rc.d/rc.softrestart")
            logging.info(f"✅ {ip}: SUCCESS — Antenna adopted!")
            return True
        else:
            logging.error(f"❌ {ip}: Config write failed (exit code: {exit_status})")
            return False

    except Exception as write_error:
        logging.error(f"❌ {ip}: Write error: {write_error}")
        return False


def adopt_device(ip, dry_run=False):
    """
    Attempt to adopt a single device at the given IP address.
    Tries all credential pairs. Returns a dict with adoption result.
    """
    result = {
        "ip": ip,
        "status": "failed",
        "device_type": "unknown",
        "username": None,
        "error": None,
        "timestamp": datetime.now().isoformat()
    }

    if not CREDENTIALS_LIST:
        logging.error("No SSH credentials configured! Set SSH_CREDENTIALS env var.")
        result["error"] = "No credentials"
        return result

    if not UISP_STRING:
        logging.error("No UISP connection string configured! Set UISP_CONNECTION_STRING env var.")
        result["error"] = "No UISP string"
        return result

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connected = False
    for username, password in CREDENTIALS_LIST:
        try:
            client.connect(
                ip,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT,
                banner_timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False
            )
            logging.info(f"🔑 {ip}: SSH login successful ({username})")
            connected = True
            result["username"] = username
            break
        except paramiko.AuthenticationException:
            logging.debug(f"🔒 {ip}: Auth failed for {username}")
            continue
        except Exception as e:
            logging.debug(f"⚠️ {ip}: Connection error with {username}: {e}")
            continue

    if not connected:
        logging.warning(f"⛔ {ip}: All credentials failed.")
        result["error"] = "Authentication failed"
        client.close()
        return result

    try:
        device_type = detect_device_type(client, ip)
        result["device_type"] = device_type

        if device_type == "ubios":
            success = adopt_ubios(client, ip, dry_run)
        elif device_type == "airos":
            success = adopt_airos(client, ip, dry_run)
        else:
            logging.warning(f"❓ {ip}: Unknown device type. Skipping.")
            result["error"] = "Unknown device type"
            return result

        if success:
            result["status"] = "adopted"

    except Exception as e:
        logging.error(f"❌ {ip}: Error during adoption: {e}")
        result["error"] = str(e)
    finally:
        client.close()

    return result


# ================= SCANNING =================

def scan_network(network_range, history, dry_run=False, max_threads=None):
    """Scan a single network range and adopt discovered devices."""
    if max_threads is None:
        max_threads = MAX_THREADS

    results = []

    try:
        net = ipaddress.ip_network(network_range, strict=False)
    except ValueError as e:
        logging.error(f"Invalid network range '{network_range}': {e}")
        return results

    # Collect IPs to scan
    ips_to_scan = []
    for ip in net:
        ip_str = str(ip)
        if ip_str.endswith(".0") or ip_str.endswith(".255"):
            continue
        if ip_str in history:
            continue
        ips_to_scan.append(ip_str)

    if not ips_to_scan:
        logging.info(f"📂 {network_range}: No new IPs to scan.")
        return results

    logging.info(f"🔎 {network_range}: Scanning {len(ips_to_scan)} IPs...")

    # Phase 1: Port scan (fast)
    reachable_ips = []
    for ip_str in ips_to_scan:
        if check_port(ip_str):
            reachable_ips.append(ip_str)

    logging.info(f"📡 {network_range}: {len(reachable_ips)} devices reachable on SSH.")

    if not reachable_ips:
        return results

    # Phase 2: Adopt devices (threaded)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(adopt_device, ip, dry_run): ip
            for ip in reachable_ips
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                results.append(result)
                if result["status"] == "adopted" and not dry_run:
                    save_to_history(ip)
                    history.add(ip)
            except Exception as e:
                logging.error(f"❌ {ip}: Unexpected error: {e}")
                results.append({
                    "ip": ip, "status": "error",
                    "error": str(e), "timestamp": datetime.now().isoformat()
                })

    return results


def scan_all_networks(dry_run=False, max_threads=None):
    """Scan all configured network ranges and return aggregated results."""
    if not NETWORK_RANGES:
        logging.error("❌ No network ranges configured! Set NETWORK_RANGES env var.")
        logging.error("   Example: NETWORK_RANGES=10.0.0.0/24,10.0.1.0/24")
        return []

    history = load_history()
    all_results = []

    start_time = time.time()
    logging.info(f"{'='*60}")
    logging.info(f"🚀 UISP AUTO-ADOPTER v{__version__}")
    logging.info(f"   Networks: {len(NETWORK_RANGES)} ranges")
    logging.info(f"   Previously adopted: {len(history)} devices")
    logging.info(f"   Threads: {max_threads or MAX_THREADS}")
    if dry_run:
        logging.info(f"   ⚠️  DRY-RUN MODE — No changes will be made!")
    logging.info(f"{'='*60}")

    for net_range in NETWORK_RANGES:
        logging.info(f"\n--- Scanning: {net_range} ---")
        results = scan_network(net_range, history, dry_run, max_threads)
        all_results.extend(results)

    elapsed = time.time() - start_time

    # Statistics
    adopted = sum(1 for r in all_results if r["status"] == "adopted")
    failed = sum(1 for r in all_results if r["status"] == "failed")
    errors = sum(1 for r in all_results if r["status"] == "error")
    ubios_count = sum(1 for r in all_results if r.get("device_type") == "ubios" and r["status"] == "adopted")
    airos_count = sum(1 for r in all_results if r.get("device_type") == "airos" and r["status"] == "adopted")

    stats = {
        "scan_date": datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 2),
        "networks_scanned": len(NETWORK_RANGES),
        "total_devices_found": len(all_results),
        "adopted": adopted,
        "failed": failed,
        "errors": errors,
        "ubios_adopted": ubios_count,
        "airos_adopted": airos_count,
        "total_adopted_all_time": len(history)
    }
    save_stats(stats)

    logging.info(f"\n{'='*60}")
    logging.info(f"📊 SCAN COMPLETE")
    logging.info(f"   Duration: {elapsed:.1f}s")
    logging.info(f"   Devices found: {len(all_results)}")
    logging.info(f"   ✅ Adopted: {adopted} (UBIOS: {ubios_count}, AirOS: {airos_count})")
    logging.info(f"   ❌ Failed: {failed}")
    logging.info(f"   ⚠️  Errors: {errors}")
    logging.info(f"   📁 Total adopted (all-time): {len(history)}")
    logging.info(f"{'='*60}")

    return all_results


# ================= CLI =================

def main():
    parser = argparse.ArgumentParser(
        prog="uisp-auto-adopter",
        description="🚀 Automatically scan and adopt Ubiquiti devices into UISP/UNMS.",
        epilog="Example: python uisptara.py --dry-run --threads 20"
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Simulate adoption without making any changes"
    )
    parser.add_argument(
        "--threads", type=int, default=None,
        help=f"Number of concurrent threads (default: {MAX_THREADS})"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose/debug logging"
    )
    parser.add_argument(
        "--single", type=str, default=None,
        help="Adopt a single device by IP address"
    )

    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    if args.single:
        logging.info(f"🎯 Single device mode: {args.single}")
        result = adopt_device(args.single, dry_run=args.dry_run)
        if result["status"] == "adopted" and not args.dry_run:
            save_to_history(args.single)
        logging.info(f"Result: {json.dumps(result, indent=2, ensure_ascii=False)}")
    else:
        scan_all_networks(dry_run=args.dry_run, max_threads=args.threads)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\n🛑 Scan interrupted by user.")
        sys.exit(0)