#!/usr/bin/env python3
"""
UISP Auto-Adopter — Configuration Manager
Handles reading and writing config.json with validation.
"""

import json
import os
import ipaddress
import copy
import logging
from datetime import datetime

# Determine data directory (default to current directory for backward compat)
DATA_DIR = os.getenv("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

# Helper to resolve paths relative to DATA_DIR
def get_data_path(filename):
    if os.path.isabs(filename):
        return filename
    return os.path.join(DATA_DIR, filename)

DEFAULT_CONFIG = {
    "uisp_connection_string": "",
    "credentials": [],
    "network_ranges": [],
    "settings": {
        "max_threads": 10,
        "ssh_timeout": 5,
        "port_scan_timeout": 0.3,
        "log_filename": "uisp_scan_results.log",
        "history_filename": "adopted_devices.txt",
        "stats_filename": "scan_stats.json",
        "dashboard_port": 5050
    }
}


def load_config():
    """Load configuration from config.json. Creates default if not found."""
    # Ensure data dir exists
    if not os.path.exists(DATA_DIR):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except Exception as e:
            logging.error(f"Failed to create data dir {DATA_DIR}: {e}")

    if not os.path.exists(CONFIG_FILE):
        # Try to load from example config if available (in code directory)
        code_dir = os.path.dirname(os.path.abspath(__file__))
        example_file = os.path.join(code_dir, "config.example.json")
        if os.path.exists(example_file):
            try:
                with open(example_file, 'r', encoding='utf-8') as f:
                    example_config = json.load(f)
                save_config(example_config)
                return example_config
            except Exception as e:
                logging.error(f"Failed to load/copy example config: {e}")

        # Fallback to hardcoded default
        save_config(DEFAULT_CONFIG)
        return copy.deepcopy(DEFAULT_CONFIG)

    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # Ensure all keys exist (merge with defaults)
        merged = copy.deepcopy(DEFAULT_CONFIG)
        merged.update(config)
        if "settings" in config:
            merged["settings"] = {**DEFAULT_CONFIG["settings"], **config["settings"]}

        return merged
    except Exception as e:
        logging.error(f"Config read error: {e}")
        return copy.deepcopy(DEFAULT_CONFIG)


def save_config(config):
    """Save configuration to config.json with backup."""
    # Backup existing config
    if os.path.exists(CONFIG_FILE):
        backup_file = CONFIG_FILE + ".backup"
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                backup_data = f.read()
            with open(backup_file, 'w', encoding='utf-8') as f:
                f.write(backup_data)
        except Exception:
            pass

    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logging.error(f"Config write error: {e}")
        return False


def validate_network_range(network):
    """Validate a CIDR network range. Returns (is_valid, error_message)."""
    try:
        net = ipaddress.ip_network(network.strip(), strict=False)
        return True, None
    except ValueError as e:
        return False, str(e)


def validate_ip(ip):
    """Validate an IP address. Returns (is_valid, error_message)."""
    try:
        ipaddress.ip_address(ip.strip())
        return True, None
    except ValueError as e:
        return False, str(e)


def validate_config(config):
    """
    Validate the entire config. Returns (is_valid, errors_list).
    """
    errors = []

    # Check UISP string
    uisp = config.get("uisp_connection_string", "")
    if not uisp:
        errors.append("UISP bağlantı dizesi boş")
    elif not uisp.startswith("wss://"):
        errors.append("UISP bağlantı dizesi 'wss://' ile başlamalı")

    # Check credentials
    creds = config.get("credentials", [])
    if not creds:
        errors.append("En az bir SSH kimlik bilgisi gerekli")
    for i, cred in enumerate(creds):
        if not cred.get("username"):
            errors.append(f"Kimlik {i+1}: Kullanıcı adı boş")
        if not cred.get("password"):
            errors.append(f"Kimlik {i+1}: Şifre boş")

    # Check network ranges
    networks = config.get("network_ranges", [])
    if not networks:
        errors.append("En az bir ağ aralığı gerekli")
    for net in networks:
        valid, err = validate_network_range(net)
        if not valid:
            errors.append(f"Geçersiz ağ: {net} — {err}")

    # Check settings
    settings = config.get("settings", {})
    threads = settings.get("max_threads", 10)
    if not isinstance(threads, int) or threads < 1 or threads > 100:
        errors.append("Thread sayısı 1-100 arasında olmalı")

    ssh_timeout = settings.get("ssh_timeout", 5)
    if not isinstance(ssh_timeout, (int, float)) or ssh_timeout < 1 or ssh_timeout > 60:
        errors.append("SSH timeout 1-60 saniye arasında olmalı")

    port_timeout = settings.get("port_scan_timeout", 0.3)
    if not isinstance(port_timeout, (int, float)) or port_timeout < 0.1 or port_timeout > 10:
        errors.append("Port tarama timeout 0.1-10 saniye arasında olmalı")

    return len(errors) == 0, errors


# ================= CONVENIENCE GETTERS =================

def get_credentials():
    """Return credentials as list of (username, password) tuples."""
    config = load_config()
    return [(c["username"], c["password"]) for c in config.get("credentials", [])]


def get_uisp_string():
    """Return the UISP connection string."""
    config = load_config()
    return config.get("uisp_connection_string", "")


def get_network_ranges():
    """Return list of network ranges."""
    config = load_config()
    return config.get("network_ranges", [])


def get_settings():
    """Return settings dict."""
    config = load_config()
    return config.get("settings", DEFAULT_CONFIG["settings"])


def get_setting(key, default=None):
    """Return a specific setting value."""
    settings = get_settings()
    return settings.get(key, default)
