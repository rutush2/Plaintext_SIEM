import asyncio
import random
from typing import AsyncGenerator, Dict, List, Optional
from schema import SecurityEvent, EventCategory, ThreatIntelAnnotation


class SecurityLogGenerator:
    def __init__(self) -> None:
        self.running: bool = False
        self._active_attack: Optional[str] = None

        self.internal_ips: List[str] = [
            f"192.168.1.{i}" for i in range(10, 50)
        ]
        self.external_ips: List[str] = [
            "203.0.113.5",
            "198.51.100.14",
            "198.51.100.88",
            "45.33.32.156",
        ]
        self.malicious_ips: List[str] = [
            "185.220.101.5",
            "193.27.228.27",
        ]
        self.system_users: List[str] = [
            "Colin",
            "Delson",
            "Shinoda",
            "Mr.han",
            "Phoenix",
            "Emily",
        ]

    def trigger_attack(self, attack_type: str) -> None:
        self._active_attack = attack_type

    def stop_attack(self) -> None:
        self._active_attack = None

    def _generate_normal_event(self) -> SecurityEvent:
        category = random.choice(list(EventCategory))
        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.internal_ips)
        user = random.choice(self.system_users)

        if category == EventCategory.AUTHENTICATION:
            return SecurityEvent(
                category=category,
                event_type="USER_LOGIN",
                source_ip=src_ip,
                destination_ip=dst_ip,
                destination_port=22,
                user=user,
                action="LOGIN",
                status=random.choices(["SUCCESS", "FAILURE"], weights=[0.9, 0.1])[0],
            )
        elif category == EventCategory.NETWORK:
            return SecurityEvent(
                category=category,
                event_type="NETWORK_FLOW",
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=random.randint(1024, 65535),
                destination_port=random.choice([80, 443, 8080, 5432]),
                user=user,
                action="CONNECTION",
                status="SUCCESS",
                bytes_transferred=random.randint(200, 15000),
            )
        elif category == EventCategory.FILE_SYSTEM:
            return SecurityEvent(
                category=category,
                event_type="FILE_ACCESS",
                source_ip=src_ip,
                user=user,
                action="READ",
                status="SUCCESS",
                file_path=f"/var/log/{random.choice(['app.log', 'syslog', 'auth.log'])}",
            )
        else:
            return SecurityEvent(
                category=category,
                event_type="PROCESS_START",
                source_ip=src_ip,
                user=user,
                action="EXECUTE",
                status="SUCCESS",
                process_name=random.choice(["python3", "nginx", "postgres", "bash"]),
            )

    def _generate_attack_events(self) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        attacker_ip = random.choice(self.malicious_ips)

        if self._active_attack == "BRUTE_FORCE":
            target_user = random.choice(self.system_users)
            target_ip = "192.168.1.10"
            for _ in range(8):
                events.append(
                    SecurityEvent(
                        category=EventCategory.AUTHENTICATION,
                        event_type="ATTACK_BRUTE_FORCE",
                        source_ip=attacker_ip,
                        destination_ip=target_ip,
                        destination_port=22,
                        user=target_user,
                        action="LOGIN_ATTACK",
                        status="FAILURE",
                        threat_intel=ThreatIntelAnnotation(
                            is_malicious_ip=True,
                            ip_reputation_score=9.5,
                            known_threat_actor="APT_SSH_Scanner",
                        ),
                    )
                )

        elif self._active_attack == "PORT_SCAN":
            target_ip = "192.168.1.1"
            ports = random.sample(range(20, 1024), 12)
            for port in ports:
                events.append(
                    SecurityEvent(
                        category=EventCategory.NETWORK,
                        event_type="ATTACK_PORT_SCAN",
                        source_ip=attacker_ip,
                        destination_ip=target_ip,
                        destination_port=port,
                        user=random.choice(self.system_users),
                        action="RECON_PROBE",
                        status="REJECTED",
                        threat_intel=ThreatIntelAnnotation(
                            is_malicious_ip=True,
                            ip_reputation_score=8.8,
                            known_threat_actor="Port_Scanner_Bot",
                        ),
                    )
                )

        elif self._active_attack == "DATA_EXFIL":
            target_ip = random.choice(self.external_ips)
            events.append(
                SecurityEvent(
                    category=EventCategory.NETWORK,
                    event_type="ATTACK_DATA_EXFIL",
                    source_ip="192.168.1.25",
                    destination_ip=target_ip,
                    destination_port=443,
                    user=random.choice(self.system_users),
                    action="HIGH_VOL_TRANSFER",
                    status="SUCCESS",
                    bytes_transferred=8_500_000,
                    threat_intel=ThreatIntelAnnotation(
                        is_malicious_ip=True,
                        ip_reputation_score=9.0,
                        known_threat_actor="Data_Exfil_Group",
                    ),
                )
            )

        self._active_attack = None
        return events

    async def stream_events(self, delay: float = 0.1) -> AsyncGenerator[SecurityEvent, None]:
        self.running = True
        while self.running:
            if self._active_attack:
                attack_batch = self._generate_attack_events()
                for event in attack_batch:
                    yield event
                    await asyncio.sleep(0.01)
            else:
                yield self._generate_normal_event()
                await asyncio.sleep(delay)

    def stop(self) -> None:
        self.running = False

if __name__ == "__main__":
    async def main():
        gen = SecurityLogGenerator()
        print("--- Testing Normal Stream (5 events) ---")
        count = 0
        async for event in gen.stream_events(delay=0.05):
            print(f"[{event.category.value}] {event.event_type} from {event.source_ip} (Status: {event.status})")
            count += 1
            if count == 5:
                break

        print("\n--- Triggering BRUTE_FORCE Attack ---")
        gen.trigger_attack("BRUTE_FORCE")
        async for event in gen.stream_events(delay=0.05):
            print(f"[{event.category.value}] {event.event_type} from {event.source_ip} (Threat: {event.threat_intel.is_malicious_ip})")
            count += 1
            if count == 12:
                break

    asyncio.run(main())