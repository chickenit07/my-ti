# my-ti (Threat Intelligence Toolkit)

A small end-to-end toolkit to collect, normalize and explore leaked credential data and IoCs.

- Collect raw logs (e.g., from Telegram dumps)
- Normalize and convert to clean JSON
- Ship to ELK for storage and analytics
- Explore via a modern Web UI (credential search, IoC search, saved items, etc.)

Repo: https://github.com/chickenit07/my-ti

## Repository Structure

- `web-ui/` — Flask/Bootstrap Web UI for credential search, IoC search, saved items, admin
- `convert-to-json.py` — Convert raw log lines to clean JSON; drops bad formats
- `logstash_pushLog.conf` — Logstash pipeline to ingest JSON into Elasticsearch
- `docker-compose.yml` — ELK stack (Elasticsearch + Kibana + Logstash)
- `Old_Archive/` — Archived assets (not used by the current app)

Note: keep local artifacts out of git (`esdata/`, `.venv/`, `users.db`, `__pycache__/`).

## Prerequisites

- Docker + Docker Compose (for ELK)
- Python 3.10+ (for web-ui and conversion)
- Git

## Quick Start

### 1) Start ELK
From the repo root:
```bash
docker compose up -d
# or: docker-compose up -d
```
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601

Data persists in `esdata/` (ignored by git).

### 2) Convert raw logs to JSON
```bash
python3 convert-to-json.py \
  --input path/to/raw_logs.txt \
  --output path/to/converted.jsonl
```
What it does:
- trims/normalizes messy lines
- filters obviously broken rows
- emits one JSON object per line (JSONL) ready for Logstash

### 3) Ingest JSON via Logstash
Edit `logstash_pushLog.conf` to point to your JSONL, then:
```bash
docker compose restart logstash
```
(Or run a local Logstash: `logstash -f logstash_pushLog.conf`.)

### 4) Initialize the Web UI database
The UI uses SQLite (`users.db`). Run once:
```bash
cd web-ui
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt

# Initialize DB with default users (admin/guest) and tables
python -c "from app import init_db; init_db(); print('DB initialized')"
```
Default admin/guest credentials and token settings live in `web-ui/app.py`. Update secrets and passwords before deploying.

### 5) Run the Web UI
```bash
# still inside web-ui and venv
python app.py
```
Open http://localhost:8000.

## Configuration

- ELK versions/resources: `docker-compose.yml`
- Logstash inputs/filters/outputs: `logstash_pushLog.conf`
- UI (roles, tokens, endpoints): `web-ui/app.py` and templates under `web-ui/templates/`

Suggested env file (do not commit):
```
web-ui/.env
  ELASTICSEARCH_URL=http://localhost:9200
  SECRET_KEY=change-me
  ES_USERNAME=elastic
  ES_PASSWORD=your-password
```

## Operational Tips

- Use consistent index patterns (e.g., `credentials-*`, `ioc-*`)
- Consider explicit mappings/templates for keyword vs analyzed fields
- Stage converted files for Logstash to tail
- Snapshot Elasticsearch indices for backups

## Roadmap

- Expand IoC search (URL, hash, ASN, WHOIS pivots)
- Saved queries and sharing
- Alerting/exports (CSV/JSON)
- RBAC and audit logging
