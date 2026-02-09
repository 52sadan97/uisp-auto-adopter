<p align="center">
  <img src="https://img.shields.io/badge/UISP-Auto%20Adopter-blueviolet?style=for-the-badge&logo=ubiquiti&logoColor=white" alt="UISP Auto-Adopter">
  <br>
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey?style=flat-square" alt="Platform">
</p>

# 📡 UISP Auto-Adopter

**Bulk Ubiquiti device adoption tool for UISP/UNMS — Scan your network, adopt all devices automatically.**

UISP Auto-Adopter scans your local network ranges for Ubiquiti devices (AirOS antennas and UBIOS routers) via SSH and automatically configures them to connect to your UISP server. It's designed for ISPs and network operators who manage hundreds of Ubiquiti devices across multiple subnets.

> 🇹🇷 Türkçe açıklama için [aşağıya bakın](#-türkçe).

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔎 **Multi-Subnet Scanning** | Scan multiple CIDR ranges simultaneously |
| 📡 **AirOS Support** | Auto-adopt airMAX antennas (Rocket, LiteBeam, NanoStation, etc.) |
| 🤖 **UBIOS Support** | Auto-adopt UniFi OS routers and gateways |
| ⚡ **Multi-Threaded** | Concurrent SSH connections for fast scanning |
| 🔄 **Idempotent** | Tracks adopted devices — never processes the same device twice |
| 🧪 **Dry-Run Mode** | Preview what would happen without making changes |
| 🎯 **Single Device Mode** | Adopt a specific device by IP |
| 🔑 **Multiple Credentials** | Try multiple SSH username/password pairs |
| 📊 **Statistics** | JSON scan reports with success/failure counts |
| 🔒 **Secure** | Credentials stored in `config.json`, never hardcoded |
| 🌐 **Web Dashboard** | Real-time monitoring with live config editor |

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/uisp-auto-adopter.git
cd uisp-auto-adopter
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure

```bash
cp config.example.json config.json
```

Edit `config.json` with your actual values:

```json
{
    "uisp_connection_string": "wss://uisp.example.com:8443+YourTokenHere+allowSelfSignedCertificate",
    "credentials": [
        { "username": "admin", "password": "mypassword" },
        { "username": "ubnt", "password": "ubnt" }
    ],
    "network_ranges": [
        "10.0.0.0/24",
        "192.168.1.0/24"
    ],
    "settings": {
        "max_threads": 10,
        "ssh_timeout": 5,
        "port_scan_timeout": 0.3
    }
}
```

> 💡 **Or configure via web dashboard** — Start the dashboard and edit everything from the browser!

### 4. Run

```bash
# Full scan
python uisptara.py

# Dry-run (preview only)
python uisptara.py --dry-run

# Single device
python uisptara.py --single 10.0.0.50

# With more threads
python uisptara.py --threads 20

# Verbose logging
python uisptara.py -v
```

---

## 🌐 Web Dashboard

UISP Auto-Adopter includes a built-in web dashboard for real-time monitoring and control.

```bash
# Install dependencies
pip install -r requirements.txt

# Start the dashboard
python web_dashboard.py
```

Then open **http://localhost:5050** in your browser.

### Dashboard Features
- 📊 **Overview** — Total devices, network stats, last scan summary
- 🔎 **Scan Control** — Start/stop scans, dry-run mode, live progress bar
- 📡 **Device List** — Searchable & filterable table of all adopted devices
- 🌐 **Subnet Distribution** — Visual breakdown of devices per subnet
- ⚙️ **Live Config Editor** — Add/remove networks, manage credentials, update settings (no restart needed!)
- 📋 **Live Logs** — Real-time log viewer during scans
- 🎯 **Single Device Adopt** — Adopt individual devices by IP

---

## 📖 How It Works

```
┌─────────────────────────────────────────────────────────┐
│                  UISP Auto-Adopter                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. 🔎 Port Scan (TCP 22)                               │
│     └─ Fast check across all IPs in configured ranges   │
│                                                         │
│  2. 🔑 SSH Authentication                               │
│     └─ Try each credential pair until one works         │
│                                                         │
│  3. 🔍 Device Detection                                 │
│     ├─ UBIOS? → /usr/bin/ubios-udapi-client exists      │
│     └─ AirOS? → /tmp/system.cfg exists                  │
│                                                         │
│  4. ⚙️ Adoption                                         │
│     ├─ UBIOS → API call via ubios-udapi-client          │
│     └─ AirOS → Update system.cfg + save + restart       │
│                                                         │
│  5. 💾 Record                                           │
│     └─ Save adopted IP to history (skip on next run)    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration Reference

All settings are stored in `config.json`. You can edit this file manually or use the web dashboard.

| Setting | Default | Description |
|---|---|---|
| `uisp_connection_string` | *(required)* | UISP WebSocket connection string |
| `credentials` | *(required)* | Array of `{username, password}` SSH credential pairs |
| `network_ranges` | *(required)* | Array of CIDR ranges to scan |
| `settings.max_threads` | `10` | Max concurrent SSH connections |
| `settings.ssh_timeout` | `5` | SSH connection timeout (seconds) |
| `settings.port_scan_timeout` | `0.3` | TCP port scan timeout (seconds) |
| `settings.dashboard_port` | `5050` | Web dashboard port |
| `settings.log_filename` | `uisp_scan_results.log` | Log file path |
| `settings.history_filename` | `adopted_devices.txt` | Adopted devices history file |
| `settings.stats_filename` | `scan_stats.json` | Scan statistics JSON file |

---

## 📊 Output Files

| File | Description |
|---|---|
| `uisp_scan_results.log` | Detailed log of all scan activity |
| `adopted_devices.txt` | List of successfully adopted device IPs (one per line) |
| `scan_stats.json` | JSON statistics from the latest scan |

Example `scan_stats.json`:
```json
{
  "scan_date": "2026-02-10T00:30:00",
  "duration_seconds": 45.2,
  "networks_scanned": 5,
  "total_devices_found": 120,
  "adopted": 95,
  "failed": 20,
  "errors": 5,
  "ubios_adopted": 10,
  "airos_adopted": 85,
  "total_adopted_all_time": 293
}
```

---

## 🛡️ Security

- **Never commit `config.json`** — it contains your SSH credentials and UISP token
- The `.gitignore` file is pre-configured to exclude `config.json`, log files, and device history
- SSH uses `AutoAddPolicy` for host key verification — suitable for managed ISP networks
- All credentials are loaded from `config.json`, never hardcoded
- Automatic backup (`config.json.backup`) is created before every save

---

## 🗺️ Roadmap

- [x] 🌐 **Web Dashboard** — Real-time scan progress, live config editor, and statistics
- [ ] 📧 **Notifications** — Email/Telegram/Slack alerts on scan completion
- [ ] 📋 **UISP API Integration** — Verify adoption status via UISP REST API
- [ ] 🗺️ **Network Map** — Visual map of adopted devices by subnet
- [ ] 🐳 **Docker Support** — Containerized deployment with scheduled scans
- [ ] ⏰ **Scheduled Scans** — Cron-compatible scheduling with configurable intervals
- [ ] 📈 **Historical Trends** — Track adoption rates over time
- [ ] 🔐 **SSH Key Auth** — Support for key-based authentication

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool modifies device configurations over SSH. **Use at your own risk.** Always test with `--dry-run` first. The authors are not responsible for any network disruptions caused by improper use.

---

---

<a name="-türkçe"></a>
## 🇹🇷 Türkçe

### UISP Auto-Adopter Nedir?

UISP Auto-Adopter, yerel ağınızdaki Ubiquiti cihazlarını (AirOS antenleri ve UBIOS router'lar) otomatik olarak tarayıp UISP sunucunuza bağlayan bir araçtır. İSS'ler (İnternet Servis Sağlayıcıları) ve birden fazla alt ağda yüzlerce Ubiquiti cihazı yöneten ağ operatörleri için tasarlanmıştır.

### Özellikler

- 🔎 **Çoklu Alt Ağ Tarama** — Birden fazla CIDR aralığını eş zamanlı tarar
- 📡 **AirOS Desteği** — airMAX antenleri (Rocket, LiteBeam, NanoStation, vb.) otomatik bağlar
- 🤖 **UBIOS Desteği** — UniFi OS router ve gateway'leri otomatik bağlar
- ⚡ **Çoklu İş Parçacığı** — Hızlı tarama için eş zamanlı SSH bağlantıları
- 🔄 **Tekrarsız** — Daha önce bağlanan cihazları atlar
- 🧪 **Deneme Modu** — Değişiklik yapmadan önce ne olacağını görün (`--dry-run`)
- 🎯 **Tekli Cihaz Modu** — IP adresine göre tek bir cihaz bağlayın
- 📊 **İstatistikler** — JSON formatında tarama raporları

### Hızlı Başlangıç

```bash
# Repository'yi klonlayın
git clone https://github.com/YOUR_USERNAME/uisp-auto-adopter.git
cd uisp-auto-adopter

# Bağımlılıkları yükleyin
pip install -r requirements.txt

# Yapılandırma dosyasını oluşturun
cp config.example.json config.json
# config.json dosyasını kendi bilgilerinizle düzenleyin veya web panelden yapın

# Taramayı başlatın
python uisptara.py

# Deneme modu (değişiklik yapmaz)
python uisptara.py --dry-run
```

### Nasıl Çalışır?

1. Belirtilen ağ aralıklarındaki tüm IP'leri tarar (port 22/SSH)
2. Erişilebilir cihazlara SSH ile bağlanır (birden fazla şifre dener)
3. Cihaz tipini tespit eder (AirOS anten mi, UBIOS router mı?)
4. Cihazın yapılandırmasını UISP bağlantı bilgileriyle günceller
5. Başarılı cihazları kaydeder (tekrar taranmaz)

---

<p align="center">
  Made with ❤️ by <strong>SdnNET</strong>
</p>
