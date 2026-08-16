import asyncio
import json
from typing import Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

import config
from engine import SIEMAnalyticsEngine
from generator import SecurityLogGenerator

app = FastAPI(title="Plaintext SIEM Stream Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = SIEMAnalyticsEngine()
generator = SecurityLogGenerator()


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def broadcast(self, data: dict) -> None:
        if not self.active_connections:
            return
        message = json.dumps(data)
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)
        for conn in disconnected:
            self.active_connections.discard(conn)


manager = ConnectionManager()


@app.on_event("startup")
async def startup_event() -> None:
    asyncio.create_task(background_telemetry_loop())


async def background_telemetry_loop() -> None:
    async for raw_event in generator.stream_events(delay=0.1):
        alert = engine.process_and_store_event(raw_event)

        payload = {
            "type": "TELEMETRY",
            "event": raw_event.to_dict(),
            "summary": engine.get_summary_metrics(),
        }

        if alert:
            payload["alert"] = alert.to_dict()

        await manager.broadcast(payload)


@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            if cmd.get("action") == "TRIGGER_ATTACK":
                attack_type = cmd.get("attack_type")
                if attack_type:
                    generator.trigger_attack(attack_type)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/api/attack/{attack_type}")
async def trigger_attack_endpoint(attack_type: str) -> dict:
    generator.trigger_attack(attack_type)
    return {"status": "success", "triggered_attack": attack_type}


@app.get("/api/metrics")
async def get_metrics_endpoint() -> dict:
    return engine.get_summary_metrics()


@app.get("/api/logs")
async def get_logs_endpoint(category: str = "all") -> list:
    if category != "all":
        query = f"SELECT event_id, timestamp, category, event_type, source_ip, destination_ip, user_name, status, is_malicious_ip FROM events WHERE category = '{category}' ORDER BY timestamp DESC LIMIT 25"
    else:
        query = "SELECT event_id, timestamp, category, event_type, source_ip, destination_ip, user_name, status, is_malicious_ip FROM events ORDER BY timestamp DESC LIMIT 25"

    df = engine.db.execute(query).df()
    return df.to_dict(orient="records")


@app.get("/api/alerts")
async def get_alerts_endpoint() -> list:
    return engine.get_recent_alerts(limit=20)


@app.get("/api/categories")
async def get_categories_endpoint() -> list:
    df = engine.get_category_distribution()
    return df.to_dict(orient="records")


@app.get("/api/threats")
async def get_threats_endpoint() -> list:
    df = engine.get_top_threat_sources()
    return df.to_dict(orient="records")


@app.get("/api/investigate/{source_ip}")
async def investigate_ip_endpoint(source_ip: str) -> dict:
    query_events = f"""
        SELECT event_id, timestamp, category, event_type, source_ip, destination_ip, destination_port, user_name, action, status, bytes_transferred
        FROM events 
        WHERE source_ip = '{source_ip}' 
        ORDER BY timestamp ASC
    """
    df_events = engine.db.execute(query_events).df()

    query_summary = f"""
        SELECT 
            COUNT(*) as total_actions,
            COUNT(DISTINCT destination_ip) as target_hosts,
            COUNT(DISTINCT user_name) as targeted_users,
            COALESCE(SUM(bytes_transferred), 0) as total_bytes
        FROM events 
        WHERE source_ip = '{source_ip}'
    """
    summary = engine.db.execute(query_summary).df().to_dict(orient="records")[0]

    return {
        "source_ip": source_ip,
        "summary": summary,
        "timeline": df_events.to_dict(orient="records"),
    }

@app.get("/api/timeline")
async def get_timeline_endpoint() -> list:
    query = """
        SELECT 
            time_bucket(INTERVAL '5 seconds', timestamp) AS time_window,
            category,
            COUNT(*) AS event_count
        FROM events
        GROUP BY time_window, category
        ORDER BY time_window ASC
    """
    df = engine.db.execute(query).df()
    return df.to_dict(orient="records")


if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host=config.HOST,
        port=config.PORT,
        reload=False,
        log_level="info",
    )