"""Generate embeddings via Ollama and store in ChromaDB."""

from __future__ import annotations

import logging
from typing import Optional

import httpx

import config
from backend.models.log_entry import NormalizedLog

logger = logging.getLogger(__name__)

# Simple in-memory cache to avoid recomputing embeddings for identical text
_embedding_cache: dict[str, list[float]] = {}
_CACHE_MAX = 10_000


async def embed_text(text: str) -> list[float]:
    """Generate an embedding for a single text string using Ollama."""
    if text in _embedding_cache:
        return _embedding_cache[text]

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{config.OLLAMA_HOST}/api/embeddings",
            json={
                "model": config.OLLAMA_EMBED_MODEL,
                "prompt": text,
            },
        )
        response.raise_for_status()
        data = response.json()

    embedding = data.get("embedding", [])

    # Cache it
    if len(_embedding_cache) < _CACHE_MAX:
        _embedding_cache[text] = embedding

    return embedding


async def embed_texts(texts: list[str]) -> list[list[float]]:
    """Generate embeddings for multiple texts."""
    results: list[list[float]] = []
    for text in texts:
        emb = await embed_text(text)
        results.append(emb)
    return results


async def embed_logs(logs: list[NormalizedLog]) -> list[list[float]]:
    """Generate embeddings for a list of normalized logs."""
    texts = [log.to_embed_text() for log in logs]
    return await embed_texts(texts)


def clear_cache() -> None:
    """Clear the embedding cache."""
    _embedding_cache.clear()
