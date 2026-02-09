# UISP Auto-Adopter v2.1.3 (Release Notes)

This release focuses on improving the dashboard experience by reducing log noise.

## 🛠️ Fixes
- **Dashboard Logs**: The "Live Log" view in the dashboard no longer displays internal HTTP request logs (e.g., `GET /api/stats`). It now only shows relevant scanning activities and errors, making it much easier to read and debug.

---

## 📦 Installation / Update

Stop any existing containers:
```bash
docker-compose down
```

Pull the latest image:
```bash
docker-compose pull
```

Start the application:
```bash
docker-compose up -d
```
