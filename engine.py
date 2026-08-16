import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import duckdb
import pandas as pd

import config
from correlation import StatefulCorrelationEngine
from schema import SecurityAlert, SecurityEvent
from threat_intel import ThreatIntelEngine


class SIEMAnalyticsEngine:
    def __init__(self) -> None:
        self.threat_intel = ThreatIntelEngine()
        self.correlation_engine = StatefulCorrelationEngine()

        self.db = duckdb.connect(database=":memory:")
        self._initialize_schema()

        self.alerts: List[SecurityAlert] = []

    def _initialize_schema(self) -> None:
        self.db.execute(
            """
            CREATE TABLE events (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP,
                category VARCHAR,
                event_type VARCHAR,
                source_ip VARCHAR,
                destination_ip VARCHAR,
                source_port INTEGER,
                destination_port INTEGER,
                user_name VARCHAR,
                action VARCHAR,
                status VARCHAR,
                bytes_transferred BIGINT,
                process_name VARCHAR,
                file_path VARCHAR,
                is_malicious_ip BOOLEAN,
                ip_reputation_score DOUBLE,
                known_threat_actor VARCHAR,
                is_known_bad_hash BOOLEAN
            )
        """
        )

    def process_and_store_event(self, raw_event: SecurityEvent) -> Optional[SecurityAlert]:
        enriched_event = self.threat_intel.enrich_event(raw_event)

        alert = self.correlation_engine.process_event(enriched_event)
        if alert:
            self.alerts.append(alert)

        dt = datetime.fromisoformat(enriched_event.timestamp)
        self.db.execute(
            """
            INSERT INTO events VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """,
            (
                enriched_event.event_id,
                dt,
                enriched_event.category.value,
                enriched_event.event_type,
                enriched_event.source_ip,
                enriched_event.destination_ip,
                enriched_event.source_port,
                enriched_event.destination_port,
                enriched_event.user,
                enriched_event.action,
                enriched_event.status,
                enriched_event.bytes_transferred,
                enriched_event.process_name or "",
                enriched_event.file_path or "",
                enriched_event.threat_intel.is_malicious_ip,
                enriched_event.threat_intel.ip_reputation_score,
                enriched_event.threat_intel.known_threat_actor or "",
                enriched_event.threat_intel.is_known_bad_hash,
            ),
        )

        self._prune_old_events()

        return alert

    def _prune_old_events(self) -> None:
        count = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count > config.BUFFER_MAX_SIZE:
            excess = count - config.BUFFER_MAX_SIZE
            self.db.execute(
                f"""
                DELETE FROM events 
                WHERE event_id IN (
                    SELECT event_id FROM events ORDER BY timestamp ASC LIMIT {excess}
                )
            """
            )

    def get_summary_metrics(self) -> Dict[str, Any]:
        total_events = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        malicious_events = self.db.execute(
            "SELECT COUNT(*) FROM events WHERE is_malicious_ip = True"
        ).fetchone()[0]
        total_bytes = self.db.execute(
            "SELECT COALESCE(SUM(bytes_transferred), 0) FROM events"
        ).fetchone()[0]

        return {
            "total_events": total_events,
            "malicious_events": malicious_events,
            "total_alerts": len(self.alerts),
            "total_bytes_transferred": total_bytes,
        }

    def get_category_distribution(self) -> pd.DataFrame:
        query = """
            SELECT category, COUNT(*) as count 
            FROM events 
            GROUP BY category 
            ORDER BY count DESC
        """
        return self.db.execute(query).df()

    def get_top_threat_sources(self) -> pd.DataFrame:
        query = """
            SELECT source_ip, COUNT(*) as attack_count, MAX(ip_reputation_score) as max_reputation
            FROM events 
            WHERE is_malicious_ip = True 
            GROUP BY source_ip 
            ORDER BY attack_count DESC 
            LIMIT 5
        """
        return self.db.execute(query).df()

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        recent = self.alerts[-limit:]
        return [alert.to_dict() for alert in reversed(recent)]


if __name__ == "__main__":
    async def main():
        from generator import SecurityLogGenerator

        engine = SIEMAnalyticsEngine()
        generator = SecurityLogGenerator()

        print("--- Ingesting Batch Telemetry into DuckDB Engine ---")
        generator.trigger_attack("BRUTE_FORCE")

        count = 0
        async for event in generator.stream_events(delay=0.001):
            engine.process_and_store_event(event)
            count += 1
            if count >= 20:
                break

        metrics = engine.get_summary_metrics()
        print("\n--- Summary Metrics ---")
        print(f"Total Ingested Events: {metrics['total_events']}")
        print(f"Malicious Events Flagged: {metrics['malicious_events']}")
        print(f"Total Alerts Triggered: {metrics['total_alerts']}")

        print("\n--- Category Breakdown ---")
        print(engine.get_category_distribution())

    asyncio.run(main())