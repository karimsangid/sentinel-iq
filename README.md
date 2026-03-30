# SentinelIQ

AI-powered security log analyzer. Ingest logs from multiple sources, detect anomalies with embeddings and statistical methods, summarize incidents with LLMs, and query your logs in plain English.

## Features

- **Multi-format ingestion** -- syslog (RFC 3164/5424), Windows Event Logs, JSON, CSV, CEF
- **Auto-detection** -- automatically identifies log format and parses accordingly
- **AI-powered analysis** -- uses Ollama LLMs + embeddings for anomaly detection and incident summarization
- **Natural language queries** -- ask questions like "show failed SSH logins from last hour"
- **Real-time streaming** -- WebSocket-based live log feed with severity filtering
- **Dark-themed dashboard** -- React + Recharts with severity charts, threat timeline, and chat interface
- **Vector similarity search** -- ChromaDB embeddings for semantic log search
- **Three anomaly detection methods** -- vector distance, frequency z-score, severity escalation

## Architecture

```
                         +-------------------+
                         |   React Frontend  |
                         |  (Vite + Recharts)|
                         +--------+----------+
                                  |
                          REST / WebSocket
                                  |
                         +--------v----------+
                         |   FastAPI Backend  |
                         +---+----+----+-----+
                             |    |    |
                +------------+    |    +------------+
                |                 |                  |
        +-------v------+  +------v-------+  +-------v------+
        |   Ingestion   |  |   Analysis   |  |    Query     |
        |   Pipeline    |  | Embeddings   |  |  NL -> SQL   |
        | (parser.py)   |  | Anomaly Det  |  | (Ollama LLM) |
        +-------+------+  | Summarizer   |  +--------------+
                |          +------+-------+
                |                 |
         +------v------+  +------v-------+
         |   SQLite    |  |   ChromaDB   |
         | (logs table)|  | (embeddings) |
         +-------------+  +--------------+
                               |
                         +-----v-----+
                         |   Ollama   |
                         | (LLM host)|
                         +-----------+
```

## Tech Stack

| Layer     | Technology                       |
|-----------|----------------------------------|
| Backend   | Python 3.12, FastAPI, Pydantic   |
| Frontend  | React 18, Vite, Recharts         |
| AI/ML     | Ollama (llama3, nomic-embed-text) |
| Vector DB | ChromaDB                         |
| Database  | SQLite                           |
| Transport | WebSocket, REST                  |
| Deploy    | Docker, docker-compose           |

## Quickstart

### Prerequisites

- Python 3.11+
- Node.js 18+
- [Ollama](https://ollama.ai/) installed and running

### Local Development

```bash
# 1. Clone and install backend
cd sentinel-iq
pip install -r requirements.txt

# 2. Pull Ollama models
ollama pull llama3
ollama pull nomic-embed-text

# 3. Start the backend
python main.py

# 4. In another terminal, start the frontend
cd frontend
npm install
npm run dev
```

The backend runs at `http://localhost:8000` and the frontend dev server at `http://localhost:5173`.

### Docker

```bash
docker-compose up --build
```

This starts both the app and an Ollama instance. The dashboard is available at `http://localhost:8000`.

### Ingest Sample Logs

```bash
# Upload via API
curl -X POST http://localhost:8000/api/ingest/file \
  -F "file=@sample_logs/sample_syslog.log"

curl -X POST http://localhost:8000/api/ingest/file \
  -F "file=@sample_logs/sample_windows_events.json"

curl -X POST http://localhost:8000/api/ingest/file \
  -F "file=@sample_logs/sample_firewall.csv"
```

Or use the Upload panel in the dashboard.

## API Reference

| Method | Endpoint             | Description                        |
|--------|---------------------|------------------------------------|
| GET    | `/api/health`       | Health check                       |
| POST   | `/api/ingest/file`  | Upload and ingest a log file       |
| POST   | `/api/ingest/text`  | Ingest raw log text                |
| GET    | `/api/logs`         | Query logs (filters: severity, source, time range) |
| GET    | `/api/logs/{id}`    | Get a single log entry             |
| POST   | `/api/query`        | Natural language log query         |
| GET    | `/api/anomalies`    | Detect anomalies in recent logs    |
| POST   | `/api/summarize`    | LLM-powered incident summary      |
| GET    | `/api/stats`        | Dashboard statistics               |
| WS     | `/ws/logs`          | Real-time log stream (WebSocket)   |

## Running Tests

```bash
pytest tests/ -v
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a pull request

## License

MIT
