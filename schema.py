from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional
import uuid


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    PROCESS = "process"


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatIntelAnnotation:
    is_malicious_ip: bool = False
    ip_reputation_score: float = 0.0
    known_threat_actor: Optional[str] = None
    is_known_bad_hash: bool = False


@dataclass
class SecurityEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    category: EventCategory = EventCategory.NETWORK
    event_type: str = "GENERIC_LOG"
    source_ip: str = "127.0.0.1"
    destination_ip: str = "127.0.0.1"
    source_port: int = 0
    destination_port: int = 0
    user: str = "system"
    action: str = "UNKNOWN"
    status: str = "SUCCESS"
    bytes_transferred: int = 0
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    threat_intel: ThreatIntelAnnotation = field(
        default_factory=ThreatIntelAnnotation
    )
    extra_attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "category": self.category.value,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "user": self.user,
            "action": self.action,
            "status": self.status,
            "bytes_transferred": self.bytes_transferred,
            "process_name": self.process_name or "",
            "file_path": self.file_path or "",
            "is_malicious_ip": self.threat_intel.is_malicious_ip,
            "ip_reputation_score": self.threat_intel.ip_reputation_score,
            "known_threat_actor": self.threat_intel.known_threat_actor or "",
            "is_known_bad_hash": self.threat_intel.is_known_bad_hash,
        }


@dataclass
class SecurityAlert:
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    rule_name: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""
    source_ip: str = ""
    target_user: Optional[str] = None
    trigger_event_count: int = 1
    mitre_tactic: str = "Initial Access"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "source_ip": self.source_ip,
            "target_user": self.target_user or "",
            "trigger_event_count": self.trigger_event_count,
            "mitre_tactic": self.mitre_tactic,
        }