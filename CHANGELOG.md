# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.2] - 2026-02-10

### Fixed
- **Docker Integration**: Fixed a critical issue where configuration files (like `config.json`) were being created as directories by Docker volume mounts.
- **Data Persistence**: Introduced `DATA_DIR` environment variable support. Docker now mounts a single `data` volume instead of individual files, ensuring proper file creation and persistence.
- **Configuration Loading**: Enhanced config manager to look for `config.json` in `DATA_DIR` if specified, falling back to the application directory.

## [2.1.1] - 2026-02-10

### Fixed
- **Configuration**: Automatically create `config.json` from `config.example.json` if missing.
- **Docker**: Added `docker-compose.yml` for simplified deployment.
- **CI/CD**: Fixed GitHub Actions workflow not triggering correctly on pushes.

## [2.1.0] - 2026-02-10

### Added
- **Multi-Subnet Scanning**: Scan multiple CIDR ranges simultaneously.
- **AirOS Support**: Automatic adoption for airMAX antennas (Rocket, LiteBeam, NanoStation, etc.).
- **UBIOS Support**: Automatic adoption for UniFi OS routers and gateways.
- **Web Dashboard**: Real-time monitoring with live config editor.
- **Multi-Threaded**: Concurrent SSH connections for faster scanning.
- **Idempotency**: Preventing duplicate processing of already adopted devices.
- **Dry-Run Mode**: Preview changes without applying them.
- **Single Device Mode**: Adopt specific devices by IP.
- **Multiple Credentials**: Support for trying multiple SSH username/password pairs.
- **Statistics**: Detailed JSON scan reports.
- **Secure Configuration**: Credentials stored securely in `config.json`.

### Changed
- Improved error handling for SSH connections.
- Optimized scanning performance.

## [1.0.0] - 2025-01-01

### Initial Release
- Basic scanning functionality.
- Initial support for Ubiquiti devices.
