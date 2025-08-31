from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pydantic import BaseModel, Field
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


class NetworkEvent(BaseModel):
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
    
    
class UserBehaviorEvent(BaseModel):
    timestamp: datetime
    user_id: str
    user_name: Optional[str] = None
    entity_id: str
    event_type: EventType
    action: str
    resource: str
    location: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnomalyDetection(BaseModel):
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


class UserProfile(BaseModel):
    user_id: str
    normal_login_hours: List[int]
    typical_locations: List[str]
    common_resources: List[str]
    average_data_transfer: float
    baseline_activity_score: float
    risk_score: float = 0.0
    last_updated: datetime