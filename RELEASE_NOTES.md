# UISP Auto-Adopter v2.1.0 (Release Notes)

We are excited to announce the release of **UISP Auto-Adopter v2.1.0**! 🚀

This version brings significant improvements to scanning speed, device support, and user experience with a brand new Web Dashboard.

## 🌟 What's New in v2.1.0

### 🚀 Major Features
- **Web Dashboard**: A real-time web interface to monitor scans, edit configurations, and view stats.
- **Multi-Subnet Scanning**: Simultaneously scan multiple network ranges (CIDR).
- **Expanded Device Support**: Now supports both **AirOS** (antennas) and **UBIOS** (routers/gateways).
- **Performance Boost**: Multi-threaded SSH connections for lightning-fast network discovery.

### 🛠️ Improvements
- **Dry-Run Mode**: Test your configuration safely without modifying devices.
- **Smart Adoption**: Tracks adopted devices to avoid redundant processing.
- ** Enhanced Logging**: Detailed logs and JSON statistics for every scan.

---

## 🇹🇷 Sürüm Notları (Türkçe)

**UISP Auto-Adopter v2.1.0** sürümünü duyurmaktan heyecan duyuyoruz! 🚀

Bu sürüm, tarama hızında, cihaz desteğinde ve kullanıcı deneyiminde (yeni Web Paneli ile) önemli iyileştirmeler getiriyor.

### 🌟 Yenilikler

- **Web Paneli**: Taramaları izlemek, ayarları düzenlemek ve istatistikleri görmek için gerçek zamanlı web arayüzü.
- **Çoklu Ağ Tarama**: Birden fazla ağ aralığını (CIDR) aynı anda tarayın.
- **Genişletilmiş Cihaz Desteği**: Artık hem **AirOS** (antenler) hem de **UBIOS** (router/gateway) cihazlarını destekliyor.
- **Performans Artışı**: Çok iş parçacıklı SSH bağlantıları ile çok daha hızlı ağ keşfi.
- **Güvenli Deneme Modu**: Cihazlarda değişiklik yapmadan önce `--dry-run` modu ile test edin.

---

## 📦 Installation / Kurulum

```bash
git clone https://github.com/52sadan97/uisp-auto-adopter.git
cd uisp-auto-adopter
pip install -r requirements.txt
cp config.example.json config.json
# Edit config.json with your details
python uisptara.py
```

## 🤝 Contributors

Special thanks to **Ertuğrul SADAN** for the development of this tool.
