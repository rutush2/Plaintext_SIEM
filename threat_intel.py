import asyncio
from typing import Dict, Set
from schema import SecurityEvent


class ThreatIntelEngine:
    def __init__(self) -> None:
        self._ip_overrides: Dict[str, Dict[str, str]] = {}
        self._bad_hashes: Set[str] = set()

    def add_override(self, ip: str, score: float, actor: str) -> None:
        self._ip_overrides[ip] = {
            "score": str(score),
            "actor": actor,
        }

    def _compute_automated_score(self, event: SecurityEvent) -> float:
        score = 0.0

        if event.destination_port in [22, 3389, 445]:
            score += 3.0

        if event.status == "FAILURE":
            score += 3.5
        elif event.status == "REJECTED":
            score += 2.5

        if not event.source_ip.startswith("192.168.") and not event.source_ip.startswith("10."):
            score += 3.0

        return min(score, 10.0)

    def enrich_event(self, event: SecurityEvent) -> SecurityEvent:
        if event.source_ip in self._ip_overrides:
            override = self._ip_overrides[event.source_ip]
            event.threat_intel.is_malicious_ip = True
            event.threat_intel.ip_reputation_score = float(override["score"])
            event.threat_intel.known_threat_actor = override["actor"]
        else:
            calculated_score = self._compute_automated_score(event)
            event.threat_intel.ip_reputation_score = calculated_score
            if calculated_score >= 7.0:
                event.threat_intel.is_malicious_ip = True
                event.threat_intel.known_threat_actor = "AUTOMATED_RISK_RULE"

        return event


if __name__ == "__main__":
    async def main():
        engine = ThreatIntelEngine()

        normal_event = SecurityEvent(
            source_ip="192.168.1.10",
            destination_port=80,
            status="SUCCESS",
        )
        print("--- Automated Clean Event ---")
        enriched_normal = engine.enrich_event(normal_event)
        print(f"IP: {enriched_normal.source_ip} | Score: {enriched_normal.threat_intel.ip_reputation_score} | Malicious: {enriched_normal.threat_intel.is_malicious_ip}")

        suspicious_event = SecurityEvent(
            source_ip="203.0.113.5",
            destination_port=22,
            status="FAILURE",
        )
        print("\n--- Automated Suspicious Event ---")
        enriched_suspicious = engine.enrich_event(suspicious_event)
        print(f"IP: {enriched_suspicious.source_ip} | Score: {enriched_suspicious.threat_intel.ip_reputation_score} | Malicious: {enriched_suspicious.threat_intel.is_malicious_ip}")

    asyncio.run(main())