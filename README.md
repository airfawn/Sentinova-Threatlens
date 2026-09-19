# Sentinova ThreatLens

Sentinova ThreatLens is a PostgreSQL-backed cyber threat intelligence dashboard. It ingests indicators from public threat feeds, normalizes and scores them, enriches indicators, manages incidents, and exposes a local FastAPI integration service alongside the PySide6 desktop interface.

## Requirements

- macOS, Linux, or Windows
- Python 3.11 or newer
- PostgreSQL 14 or newer
- Redis 6 or newer for caching and event fan-out (optional for offline development)

The desktop application can start without Redis. PostgreSQL is required for ingestion and persistent IOC data.

## Setup

From the project root:

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt
```

Configure PostgreSQL with a database named `sentinova` and a user that can create the `cti_iocs` schema. Then create a `.env` file in the project root. A minimal local configuration is:

```env
CTI_DB_HOST=localhost
CTI_DB_PORT=5432
CTI_DB_NAME=sentinova
CTI_DB_USER=cti_user
CTI_DB_PASSWORD=your-password
CTI_DB_CONNECT_TIMEOUT=5

CTI_REDIS_ENABLED=0
CTI_API_TOKEN_SECRET=replace-with-a-long-random-secret
```

The application applies the base schema and additive compliance migrations during startup. The migration adds feed, provenance, relationship, event, alert, incident, audit, user, dashboard, report, and integration tables.

## Run the Desktop Application

The default application starts the ingestion splash screen and then opens the dark SOC-style PySide6 dashboard:

```bash
venv/bin/python -m sentinova_threatlens.main
```

The GUI includes the database, dashboard, threats, incidents, sources, and settings views. The first launch may take time while feeds are collected. External feed failures are logged and skipped where possible.

For headless ingestion without the GUI:

```bash
venv/bin/python -m sentinova_threatlens.main --headless
```

To perform inline CVE/CVSS enrichment during headless ingestion:

```bash
venv/bin/python -m sentinova_threatlens.main --headless --enrich-cvss
```

## Run the API

Start the local REST and WebSocket service in a second terminal:

```bash
venv/bin/python -m sentinova_threatlens.api
```

By default it listens on `http://127.0.0.1:8765`.

Useful configuration:

```env
CTI_API_HOST=127.0.0.1
CTI_API_PORT=8765
CTI_API_RATE_LIMIT=120
CTI_API_TOKEN_SECRET=replace-with-a-long-random-secret
CTI_BOOTSTRAP_ADMIN=admin
CTI_BOOTSTRAP_PASSWORD=replace-with-a-strong-password
CTI_WEBHOOK_SECRET=replace-with-a-webhook-secret
```

When bootstrap credentials are configured, the API creates the first Admin user during startup. Obtain a bearer token through:

```bash
curl -X POST http://127.0.0.1:8765/api/v1/auth/token \
	-H 'Content-Type: application/json' \
	-d '{"username":"admin","password":"replace-with-a-strong-password"}'
```

The API provides IOC queries, feed management, event ingestion, incident lifecycle routes, alert rules, analytics, map data, CSV/STIX exports, reports, integrations, and `/api/v1/alerts.stream` WebSocket updates.

## Feed and Enrichment Configuration

The default feed registry includes MalwareBazaar, AbuseIPDB, ThreatFox, GreyNoise, CISA KEV, and OpenPhish. Optional provider settings include:

```env
ABUSE_CH_API_KEY=...
ABUSEIPDB_API_KEY=...
GREYNOISE_API_KEY=...
VIRUSTOTAL_API_KEY=...
CTI_REQUEST_TIMEOUT=30
CTI_CVSS_ENABLED=1
```

Without provider keys, supported adapters use safe fallback behavior where available. Do not commit `.env` files or API keys.

## Redis

Redis is used for enrichment caching and pub/sub. Enable it with:

```env
CTI_REDIS_ENABLED=1
CTI_REDIS_URL=redis://localhost:6379/0
```

For offline development:

```env
CTI_REDIS_ENABLED=0
```

The application uses an in-process fallback cache when Redis is disabled or unavailable.

## Tests and Validation

Run the complete repository test suite:

```bash
venv/bin/python -m pytest -q
```

Compile the application and tests:

```bash
venv/bin/python -m compileall -q sentinova_threatlens tests test_gui.py
```

Run the offscreen GUI smoke test:

```bash
QT_QPA_PLATFORM=offscreen venv/bin/python test_gui.py
```

The GUI smoke test does not require a visible display. It handles an unavailable compliance migration gracefully, but a working PostgreSQL database is needed to display stored data.

## Troubleshooting

### PostgreSQL connection failures

Check that PostgreSQL is running and that the `.env` credentials match the database:

```bash
psql -h localhost -U cti_user -d sentinova
```

The connection timeout is controlled by `CTI_DB_CONNECT_TIMEOUT` and defaults to five seconds.

### Missing Python packages

Reinstall the project dependencies:

```bash
venv/bin/python -m pip install -r requirements.txt
```

### API port already in use

Use another port:

```bash
CTI_API_PORT=8877 venv/bin/python -m sentinova_threatlens.api
```

### Offline or restricted networks

Set `CTI_REDIS_ENABLED=0`, omit external API keys, and use the desktop application with existing database records. Feed and enrichment calls may be skipped or use mock fallback responses.
