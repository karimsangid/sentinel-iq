"""ChromaDB vector store wrapper for log embeddings."""

from __future__ import annotations

import logging
from typing import Optional

import chromadb
from chromadb.config import Settings

from backend.models.log_entry import NormalizedLog

logger = logging.getLogger(__name__)

COLLECTION_NAME = "log_embeddings"


class VectorStore:
    """Wrapper around ChromaDB for storing and querying log embeddings."""

    def __init__(self, persist_directory: str):
        self.client = chromadb.Client(Settings(
            chroma_db_impl="duckdb+parquet",
            persist_directory=persist_directory,
            anonymized_telemetry=False,
        ))
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("VectorStore initialized at %s (count=%d)", persist_directory, self.collection.count())

    def store_embeddings(
        self,
        logs: list[NormalizedLog],
        embeddings: list[list[float]],
    ) -> int:
        """Store log embeddings in ChromaDB. Returns number stored."""
        if not logs or not embeddings:
            return 0

        ids = [log.id for log in logs]
        documents = [log.to_embed_text() for log in logs]
        metadatas = [
            {
                "severity": log.severity.value,
                "source": log.source,
                "hostname": log.hostname,
                "timestamp": log.timestamp.isoformat(),
                "log_type": log.log_type.value,
            }
            for log in logs
        ]

        self.collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
        )
        logger.info("Stored %d embeddings", len(ids))
        return len(ids)

    def search_similar(
        self,
        query_embedding: list[float],
        top_k: int = 10,
        severity_filter: Optional[str] = None,
    ) -> list[dict]:
        """Search for similar logs by embedding vector."""
        where = {"severity": severity_filter} if severity_filter else None
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        items = []
        if results and results["ids"]:
            for i, log_id in enumerate(results["ids"][0]):
                items.append({
                    "id": log_id,
                    "document": results["documents"][0][i] if results["documents"] else "",
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else 0.0,
                })
        return items

    def find_anomalies(self, threshold: float = 1.5) -> list[dict]:
        """Find logs whose embeddings are distant from the centroid (potential anomalies).

        Gets all embeddings, computes the mean, and returns any log whose distance
        from the mean exceeds the threshold.
        """
        count = self.collection.count()
        if count == 0:
            return []

        # Get all items
        all_data = self.collection.get(
            include=["embeddings", "documents", "metadatas"],
            limit=min(count, 5000),
        )

        if not all_data["embeddings"]:
            return []

        embeddings = all_data["embeddings"]
        n = len(embeddings)
        dim = len(embeddings[0])

        # Compute centroid
        centroid = [0.0] * dim
        for emb in embeddings:
            for j in range(dim):
                centroid[j] += emb[j]
        centroid = [c / n for c in centroid]

        # Compute distances
        anomalies = []
        for i, emb in enumerate(embeddings):
            dist = sum((a - b) ** 2 for a, b in zip(emb, centroid)) ** 0.5
            if dist > threshold:
                anomalies.append({
                    "id": all_data["ids"][i],
                    "document": all_data["documents"][i] if all_data["documents"] else "",
                    "metadata": all_data["metadatas"][i] if all_data["metadatas"] else {},
                    "distance": dist,
                })

        anomalies.sort(key=lambda x: x["distance"], reverse=True)
        return anomalies

    def get_count(self) -> int:
        return self.collection.count()

    def delete_collection(self) -> None:
        self.client.delete_collection(COLLECTION_NAME)
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
