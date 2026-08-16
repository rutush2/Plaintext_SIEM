import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
import config
from schema import SecurityAlert, SecurityEvent, SeverityLevel


class StatefulCorrelationEngine:
    def __init__(self) -> None:
        self._login_failures: Dict[str, List[datetime]] = defaultdict(list)
        self._port_scan_probes: Dict[str, Set[int]] = defaultdict(set)
        self._port_scan_timestamps: Dict[str, List[datetime]] = defaultdict(list)
        self._data_transfers: Dict[str, List[tuple[datetime, int]]] = defaultdict(list)

    def _parse_timestamp(self, ts_str: str) -> datetime:
        return datetime.fromisoformat(ts_str)

    def _prune_old_records(
        self, timestamps: List[datetime], window_seconds: float, current_time: datetime
    ) -> List[datetime]:
        cutoff = current_time.timestamp() - window_seconds
        return [ts for ts in timestamps if ts.timestamp() >= cutoff]

    def process_event(self, event: SecurityEvent) -> Optional[SecurityAlert]:
        now = self._parse_timestamp(event.timestamp)
        src_ip = event.source_ip

        if event.category.value == "authentication" and event.status == "FAILURE":
            self._login_failures[src_ip].append(now)
            self._login_failures[src_ip] = self._prune_old_records(
                self._login_failures[src_ip],
                config.BRUTE_FORCE_WINDOW_SEC,
                now,
            )

            if len(self._login_failures[src_ip]) >= config.BRUTE_FORCE_THRESHOLD:
                failure_count = len(self._login_failures[src_ip])
                self._login_failures[src_ip].clear()
                return SecurityAlert(
                    rule_name="AUTH_BRUTE_FORCE_DETECTED",
                    severity=SeverityLevel.HIGH,
                    description=f"Detected {failure_count} failed login attempts from IP {src_ip} within {config.BRUTE_FORCE_WINDOW_SEC}s.",
                    source_ip=src_ip,
                    target_user=event.user,
                    trigger_event_count=failure_count,
                    mitre_tactic="Credential Access",
                )

        if event.event_type in ["PORT_SCAN_PROBE", "NETWORK_FLOW"] and event.destination_port > 0:
            self._port_scan_timestamps[src_ip].append(now)
            self._port_scan_probes[src_ip].add(event.destination_port)

            valid_timestamps = self._prune_old_records(
                self._port_scan_timestamps[src_ip],
                config.PORT_SCAN_WINDOW_SEC,
                now,
            )
            self._port_scan_timestamps[src_ip] = valid_timestamps

            if not valid_timestamps:
                self._port_scan_probes[src_ip].clear()

            if len(self._port_scan_probes[src_ip]) >= config.PORT_SCAN_UNIQUE_PORTS_THRESHOLD:
                probed_count = len(self._port_scan_probes[src_ip])
                self._port_scan_probes[src_ip].clear()
                self._port_scan_timestamps[src_ip].clear()
                return SecurityAlert(
                    rule_name="PORT_SCAN_RECONNAISSANCE",
                    severity=SeverityLevel.MEDIUM,
                    description=f"IP {src_ip} probed {probed_count} unique destination ports within {config.PORT_SCAN_WINDOW_SEC}s.",
                    source_ip=src_ip,
                    trigger_event_count=probed_count,
                    mitre_tactic="Reconnaissance",
                )

        if event.bytes_transferred > 0:
            self._data_transfers[src_ip].append((now, event.bytes_transferred))

            cutoff = now.timestamp() - config.DATA_EXFIL_WINDOW_SEC
            self._data_transfers[src_ip] = [
                (ts, b) for ts, b in self._data_transfers[src_ip] if ts.timestamp() >= cutoff
            ]

            total_bytes = sum(b for _, b in self._data_transfers[src_ip])
            if total_bytes >= config.DATA_EXFIL_BYTES_THRESHOLD:
                event_count = len(self._data_transfers[src_ip])
                self._data_transfers[src_ip].clear()
                mb_transferred = round(total_bytes / (1024 * 1024), 2)
                return SecurityAlert(
                    rule_name="POTENTIAL_DATA_EXFILTRATION",
                    severity=SeverityLevel.CRITICAL,
                    description=f"High-volume outbound transfer ({mb_transferred} MB) detected from IP {src_ip} within {config.DATA_EXFIL_WINDOW_SEC}s.",
                    source_ip=src_ip,
                    target_user=event.user,
                    trigger_event_count=event_count,
                    mitre_tactic="Exfiltration",
                )

        return None


if __name__ == "__main__":
    async def main():
        from generator import SecurityLogGenerator

        engine = StatefulCorrelationEngine()
        generator = SecurityLogGenerator()

        print("--- Testing Stateful Brute Force Correlation ---")
        generator.trigger_attack("BRUTE_FORCE")

        alert_triggered = False
        async for event in generator.stream_events(delay=0.01):
            alert = engine.process_event(event)
            if alert:
                print(f"\n[ALERT TRIGGERED] Rule: {alert.rule_name}")
                print(f"Severity: {alert.severity.value} | Tactic: {alert.mitre_tactic}")
                print(f"Description: {alert.description}")
                alert_triggered = True
                break

        if not alert_triggered:
            print("No alert triggered.")

    asyncio.run(main())