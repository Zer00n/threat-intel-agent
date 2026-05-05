# Threat Intelligence Deep Research Agent v2.0

Enterprise SOC threat intelligence research assistant. Combines authoritative data sources (NVD, CISA KEV, EPSS, MITRE ATT&CK) with AI to generate structured threat intelligence reports.

## Quick Start

```bash
# Setup
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY

# Initialize (creates DB + downloads ATT&CK data)
python -m app.scripts.init

# Run
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 in your browser.

## Features

- **Intent Classification**: Regex-first + LLM fallback for CVE, ATT&CK, APT, IOC queries
- **Authoritative Sources**: NVD, CISA KEV, EPSS, MITRE ATT&CK, GitHub Advisory
- **7-Agent Pipeline**: IntentClassifier → Planner → Enrichment → Research × N → IOC Extractor → Critic → Synthesis
- **Structured Outputs**: Markdown report, STIX 2.1 bundle, IOC CSV, Sigma rules, PDF
- **Real-time Streaming**: SSE with Last-Event-ID reconnection
- **Token Budget**: Monthly and per-task limits with tracking

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /analyze | Start analysis |
| GET | /stream/{task_id} | SSE event stream |
| POST | /analyze/{id}/stop | Stop analysis |
| GET | /history | List analyses |
| GET | /history/{id} | Analysis detail |
| GET | /export/{format}/{id} | Export (md/pdf/stix/iocs/sigma/zip) |
| GET | /sources/health | Data source status |
| GET | /settings | Get settings |
| PUT | /settings | Update settings |
| GET | /health | Health check |

## Tech Stack

- **Backend**: FastAPI + Python 3.11+ + SQLAlchemy async + SQLite WAL
- **AI**: Anthropic Claude API with tool_use for structured output
- **Frontend**: Native HTML/CSS/JS with Web Components
- **PDF**: WeasyPrint with Noto CJK fonts

## Testing

```bash
pytest tests/ -v
```

## Project Structure

```
app/
  agents/          # 7-agent pipeline
  db/              # Models, engine, repositories
  exporters/       # MD, PDF, STIX, CSV, Sigma, ZIP
  routers/         # FastAPI routes
  utils/           # IOC regex, defang, slug, crypto
  workers/         # Background tasks (health check, sync)
static/            # Frontend SPA
templates/pdf/     # PDF HTML template
tests/             # Unit, agent, integration tests
```
