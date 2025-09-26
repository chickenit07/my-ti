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
- `.env.sample` — Example environment file (copy to `.env`)

Note: local artifacts are ignored by git (`esdata/`, `.venv/`, `users.db`, `__pycache__/`, `.env`).

## Prerequisites

- Docker + Docker Compose (for ELK)
- Python 3.10+ (for web-ui and conversion)
- Git

## Configuration (.env)

Create `.env` from `.env.sample` in the repo root:
```
cp .env.sample .env
```
Variables:
- `SECRET_KEY` — Flask secret key
- `ELASTICSEARCH_URL`, `ES_USERNAME`, `ES_PASSWORD` — ELK connection
- `ADMIN_PASSWORD`, `GUEST_PASSWORD` — initial credentials seeded into SQLite if users don’t exist
- `SECURITY_PASSPHRASE` — passphrase required to earn tokens on the UI security question

## Quick Start

### 1) Start ELK
```bash
docker compose up -d
# or: docker-compose up -d
```
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601

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
# or run: logstash -f logstash_pushLog.conf
```

### 4) Initialize the Web UI DB and run
```bash
cd web-ui
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Initialize DB tables and seed admin/guest users using env variables
python -c "from app import init_db; init_db(); print('DB initialized')"

# Run UI
python app.py
```
Open http://localhost:5000.

## Operational Tips

- Use consistent index patterns (e.g., `credentials-*`, `ioc-*`)
- Consider explicit mappings/templates for keyword vs analyzed fields
- Stage converted files for Logstash to tail
- Snapshot Elasticsearch indices for backups

## Development

Recommended excludes are already in `.gitignore`: `esdata/`, `.venv/`, `__pycache__/`, `users.db`, `*.sqlite*`, `.push_tmp/`, `.env`.

## Roadmap

- Expand IoC search (URL, hash, ASN, WHOIS pivots)
- Saved queries and sharing
- Alerting/exports (CSV/JSON)
- RBAC and audit logging
