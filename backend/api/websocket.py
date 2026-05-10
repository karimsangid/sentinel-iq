"""WebSocket endpoint for real-time log streaming."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from fastapi import WebSocket, WebSocketDisconnect

from backend.models.log_entry import NormalizedLog, Severity

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections and their filter subscriptions."""

    def __init__(self):
        self.active_connections: dict[WebSocket, set[str]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            # Default: subscribe to all severities
            self.active_connections[websocket] = {
                s.value for s in Severity
            }
        logger.info("WebSocket client connected (total=%d)", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.active_connections.pop(websocket, None)
        logger.info("WebSocket client disconnected (total=%d)", len(self.active_connections))

    async def update_filters(self, websocket: WebSocket, severities: list[str]) -> None:
        """Update severity filter subscription for a client."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections[websocket] = set(severities)

    async def broadcast_log(self, log: NormalizedLog) -> None:
        """Send a log entry to all subscribed clients."""
        message = json.dumps({
            "type": "log",
            "data": {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "source": log.source,
                "hostname": log.hostname,
                "severity": log.severity.value,
                "message": log.message,
                "log_type": log.log_type.value,
            },
        })

        async with self._lock:
            to_remove = []
            for ws, subscribed_severities in self.active_connections.items():
                if log.severity.value in subscribed_severities:
                    try:
                        await ws.send_text(message)
                    except Exception:
                        to_remove.append(ws)

            for ws in to_remove:
                self.active_connections.pop(ws, None)

    async def broadcast_stats(self, stats: dict[str, Any]) -> None:
        """Broadcast dashboard stats update to all clients."""
        message = json.dumps({"type": "stats", "data": stats})

        async with self._lock:
            to_remove = []
            for ws in self.active_connections:
                try:
                    await ws.send_text(message)
                except Exception:
                    to_remove.append(ws)

            for ws in to_remove:
                self.active_connections.pop(ws, None)

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


# Global connection manager instance
manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket) -> None:
    """Handle a WebSocket connection for real-time log streaming."""
    await manager.connect(websocket)
    try:
        while True:
            # Listen for filter updates from client
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "subscribe":
                    severities = msg.get("severities", [s.value for s in Severity])
                    await manager.update_filters(websocket, severities)
                    await websocket.send_text(json.dumps({
                        "type": "subscribed",
                        "severities": severities,
                    }))
                elif msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)
