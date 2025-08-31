"""
Simple data models using dataclasses instead of Pydantic
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum


class EventType(str, Enum):
    NETWORK = "network"
    LOGIN = "login"
    FILE_ACCESS = "file_access"
    PROCESS = "process"
    API_CALL = "api_call"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NetworkEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration: float
    packet_count: int
    flags: Optional[str] = None
    source_host: Optional[str] = None
    destination_host: Optional[str] = None
    service: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'duration': self.duration,
            'packet_count': self.packet_count,
            'flags': self.flags,
            'source_host': self.source_host,
            'destination_host': self.destination_host,
            'service': self.service
        }


@dataclass
class UserBehaviorEvent:
    timestamp: datetime
    user_id: str
    entity_id: str
    event_type: EventType
    action: str
    resource: str
    user_name: Optional[str] = None
    location: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'user_name': self.user_name,
            'entity_id': self.entity_id,
            'event_type': self.event_type.value if isinstance(self.event_type, EventType) else self.event_type,
            'action': self.action,
            'resource': self.resource,
            'location': self.location,
            'device_id': self.device_id,
            'session_id': self.session_id,
            'metadata': self.metadata
        }


@dataclass
class AnomalyDetection:
    detection_id: str
    timestamp: datetime
    event_type: EventType
    threat_level: ThreatLevel
    confidence_score: float
    anomaly_score: float
    description: str
    affected_entities: List[str]
    indicators: List[str]
    raw_events: List[Dict[str, Any]]
    recommended_actions: List[str]
    false_positive_probability: float
    prioritized_recommendations: Optional[List[Tuple[int, str]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'detection_id': self.detection_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value if isinstance(self.event_type, EventType) else self.event_type,
            'threat_level': self.threat_level.value if isinstance(self.threat_level, ThreatLevel) else self.threat_level,
            'confidence_score': self.confidence_score,
            'anomaly_score': self.anomaly_score,
            'description': self.description,
            'affected_entities': self.affected_entities,
            'indicators': self.indicators,
            'raw_events': self.raw_events,
            'recommended_actions': self.recommended_actions,
            'false_positive_probability': self.false_positive_probability,
            'prioritized_recommendations': self.prioritized_recommendations
        }


@dataclass
class UserProfile:
    user_id: str
    normal_login_hours: List[int]
    typical_locations: List[str]
    common_resources: List[str]
    average_data_transfer: float
    baseline_activity_score: float
    risk_score: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)