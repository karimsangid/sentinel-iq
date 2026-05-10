"""SentinelIQ — Entry point. Starts the FastAPI server."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import config
from backend.api.routes import init_dependencies, router as api_router
from backend.api.websocket import websocket_endpoint
from backend.storage.database import LogDatabase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("Starting %s v%s", config.APP_NAME, config.APP_VERSION)

    # Initialize database
    db = LogDatabase(config.SQLITE_DB_PATH)
    logger.info("SQLite database ready at %s", config.SQLITE_DB_PATH)

    # Initialize vector store (best effort — ChromaDB may not be available)
    vector_store = None
    try:
        from backend.storage.vectors import VectorStore
        vector_store = VectorStore(config.CHROMADB_PATH)
        logger.info("ChromaDB vector store ready at %s", config.CHROMADB_PATH)
    except Exception as e:
        logger.warning("ChromaDB initialization failed (will run without embeddings): %s", e)

    # Wire up dependencies for routes
    init_dependencies(db, vector_store)
    logger.info("%s is ready", config.APP_NAME)

    yield

    logger.info("Shutting down %s", config.APP_NAME)


app = FastAPI(
    title=config.APP_NAME,
    description=config.APP_DESCRIPTION,
    version=config.APP_VERSION,
    lifespan=lifespan,
)

# CORS for frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(api_router)

# WebSocket
app.websocket("/ws/logs")(websocket_endpoint)

# Serve frontend static files if built
frontend_dist = Path(__file__).parent / "frontend" / "dist"
if frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")


def main():
    import uvicorn
    uvicorn.run(
        "main:app",
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
