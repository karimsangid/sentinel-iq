"""SentinelIQ Configuration."""

import os
from pathlib import Path

# ── App ───────────────────────────────────────────────────────────────
APP_NAME = "SentinelIQ"
APP_VERSION = "0.1.0"
APP_DESCRIPTION = "AI-powered security log analyzer"
APP_AUTHOR = "Hummus Development LLC"

# ── Paths ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

SQLITE_DB_PATH = str(DATA_DIR / "sentinel.db")
CHROMADB_PATH = str(DATA_DIR / "chromadb_store")

# ── Ollama ────────────────────────────────────────────────────────────
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "llama3")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

# ── Ingestion ─────────────────────────────────────────────────────────
INGEST_BATCH_SIZE = int(os.getenv("INGEST_BATCH_SIZE", "100"))
INGEST_MAX_WORKERS = int(os.getenv("INGEST_MAX_WORKERS", "4"))

# ── Anomaly Detection ────────────────────────────────────────────────
ANOMALY_DISTANCE_THRESHOLD = float(os.getenv("ANOMALY_DISTANCE_THRESHOLD", "1.5"))
ANOMALY_FREQUENCY_ZSCORE = float(os.getenv("ANOMALY_FREQUENCY_ZSCORE", "2.0"))
ANOMALY_SEVERITY_WINDOW_MINUTES = int(os.getenv("ANOMALY_SEVERITY_WINDOW", "60"))

# ── Server ────────────────────────────────────────────────────────────
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))

# ── CORS (development) ───────────────────────────────────────────────
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
