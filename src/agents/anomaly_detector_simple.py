"""
Simplified Anomaly Detection Agent without Pydantic
"""

import numpy as np
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import asyncio

# Use dataclasses instead of Pydantic
from src.models.data_models_simple import (
    NetworkEvent, UserBehaviorEvent, AnomalyDetection,
    ThreatLevel, EventType, UserProfile
)


class SimpleAnomalyDetector:
    """Simplified anomaly detector without Pydantic dependencies"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.baseline_stats = defaultdict(dict)
        self.user_profiles = {}
        self.false_positive_history = []
        self.detection_threshold = 0.65
        
    def extract_network_features(self, event: NetworkEvent) -> np.ndarray:
        """Extract features from network event"""
        features = [
            event.bytes_sent,
            event.bytes_received,
            event.duration,
            event.packet_count,
            event.source_port,
            event.destination_port,
            event.bytes_sent / (event.duration + 0.001),
            event.packet_count / (event.duration + 0.001),
            len(event.source_ip.split('.')),
            1 if event.protocol.upper() == 'TCP' else 0
        ]
        return np.array(features)
    
    def extract_behavior_features(self, event: UserBehaviorEvent) -> np.ndarray:
        """Extract features from behavior event"""
        hour = event.timestamp.hour
        day_of_week = event.timestamp.weekday()
        
        features = [
            hour,
            day_of_week,
            1 if event.event_type == EventType.LOGIN else 0,
            1 if event.event_type == EventType.FILE_ACCESS else 0,
            1 if event.event_type == EventType.PRIVILEGE_ESCALATION else 0,
            len(event.resource),
            hash(event.action) % 1000,
            hash(event.entity_id) % 1000,
        ]
        return np.array(features)
    
    def calculate_anomaly_score(self, features: np.ndarray, event_type: str) -> float:
        """Calculate anomaly score for features"""
        if event_type not in self.baseline_stats:
            return 0.5
            
        baseline = self.baseline_stats[event_type]
        if 'mean' not in baseline:
            return 0.5
            
        z_scores = np.abs((features - baseline['mean']) / (baseline['std'] + 0.001))
        anomaly_score = np.mean(z_scores) / 10.0
        return min(anomaly_score, 1.0)
    
    def update_baseline(self, features: np.ndarray, event_type: str):
        """Update baseline statistics"""
        if event_type not in self.baseline_stats:
            self.baseline_stats[event_type] = {
                'mean': features,
                'std': np.ones_like(features),
                'count': 1
            }
        else:
            stats = self.baseline_stats[event_type]
            stats['count'] += 1
            alpha = 1.0 / stats['count']
            stats['mean'] = (1 - alpha) * stats['mean'] + alpha * features
            variance = alpha * ((features - stats['mean']) ** 2)
            stats['std'] = np.sqrt((1 - alpha) * stats['std']**2 + variance)
    
    def detect_network_anomaly(self, event: NetworkEvent) -> Tuple[bool, float, str]:
        """Detect anomalies in network events"""
        features = self.extract_network_features(event)
        base_anomaly_score = self.calculate_anomaly_score(features, 'network')
        
        anomalies = []
        additional_score = 0
        
        # Check for suspicious patterns
        if event.bytes_sent > 10000000:
            anomalies.append("Unusually high data transfer")
            additional_score += 0.3
            
        # Check for suspicious IPs or hosts
        if event.source_host:
            suspicious_keywords = ['TOR', 'C2', 'SCANNER', 'MINER', 'ATTACKER', 'SUSPICIOUS']
            if any(keyword in str(event.source_host).upper() for keyword in suspicious_keywords):
                anomalies.append(f"Suspicious source: {event.source_host}")
                additional_score += 0.4
                
        if event.destination_port in [22, 3389, 445, 139]:
            if event.source_ip.startswith('10.') or event.source_ip.startswith('192.168'):
                anomalies.append(f"Sensitive port {event.destination_port} access")
                additional_score += 0.2
                
        if event.duration > 3600:
            anomalies.append("Long-duration connection")
            additional_score += 0.1
            
        # Calculate final score
        if anomalies:
            anomaly_score = min(base_anomaly_score + additional_score, 1.0)
            description = "; ".join(anomalies)
        else:
            anomaly_score = min(base_anomaly_score * 0.5, 0.5)
            description = "Normal network activity"
            
        is_anomaly = anomaly_score > self.detection_threshold
        
        # Don't flag normal activity as anomaly
        if description == "Normal network activity" and is_anomaly:
            is_anomaly = False
            
        return is_anomaly, anomaly_score, description
    
    def detect_behavior_anomaly(self, event: UserBehaviorEvent) -> Tuple[bool, float, str]:
        """Detect anomalies in user behavior"""
        features = self.extract_behavior_features(event)
        anomaly_score = self.calculate_anomaly_score(features, 'behavior')
        
        anomalies = []
        hour = event.timestamp.hour
        
        # Check for unusual patterns
        if event.user_id in self.user_profiles:
            profile = self.user_profiles[event.user_id]
            if hour not in profile.normal_login_hours:
                anomalies.append(f"Unusual login time: {hour:02d}:00")
                anomaly_score += 0.3
                
            if event.location and event.location not in profile.typical_locations:
                anomalies.append(f"Unusual location: {event.location}")
                anomaly_score += 0.25
                
        if event.event_type == EventType.PRIVILEGE_ESCALATION:
            anomalies.append("Privilege escalation detected")
            anomaly_score += 0.4
            
        if event.event_type == EventType.FILE_ACCESS:
            if 'sensitive' in event.resource.lower() or 'admin' in event.resource.lower():
                anomalies.append(f"Sensitive resource access: {event.resource}")
                anomaly_score += 0.3
                
        anomaly_score = min(anomaly_score, 1.0)
        is_anomaly = anomaly_score > self.detection_threshold
        
        description = "; ".join(anomalies) if anomalies else "Normal user behavior"
        return is_anomaly, anomaly_score, description
    
    def determine_threat_level(self, anomaly_score: float, confidence: float) -> ThreatLevel:
        """Determine threat level based on scores"""
        weighted_score = anomaly_score * confidence
        
        if weighted_score >= 0.8:
            return ThreatLevel.CRITICAL
        elif weighted_score >= 0.6:
            return ThreatLevel.HIGH
        elif weighted_score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def generate_recommendations(self, threat_level: ThreatLevel, event_type: EventType) -> List[str]:
        """Generate recommendations based on threat level"""
        recommendations = []
        
        if threat_level == ThreatLevel.CRITICAL:
            recommendations = [
                "🚨 Isolate affected systems immediately",
                "📞 Contact security team",
                "🔒 Disable compromised accounts",
                "📋 Initiate incident response"
            ]
        elif threat_level == ThreatLevel.HIGH:
            recommendations = [
                "⚠️ Investigate suspicious activity",
                "📊 Monitor for additional indicators",
                "🔐 Reset affected credentials"
            ]
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations = [
                "👀 Monitor closely",
                "📈 Check for patterns",
                "🔄 Review recent logs"
            ]
        else:
            recommendations = [
                "📊 Continue monitoring",
                "📝 Log for future reference"
            ]
            
        return recommendations
    
    async def process_event(self, event: Any) -> Optional[AnomalyDetection]:
        """Process an event and return detection if anomaly found"""
        
        if isinstance(event, NetworkEvent):
            is_anomaly, anomaly_score, description = self.detect_network_anomaly(event)
            event_type = EventType.NETWORK
            features = self.extract_network_features(event)
            affected_entities = [event.source_ip, event.destination_ip]
            
        elif isinstance(event, UserBehaviorEvent):
            is_anomaly, anomaly_score, description = self.detect_behavior_anomaly(event)
            event_type = event.event_type
            features = self.extract_behavior_features(event)
            affected_entities = [event.user_id, event.entity_id]
        else:
            return None
            
        # Update baseline
        self.update_baseline(features, event_type.value)
        
        if not is_anomaly:
            return None
            
        # Calculate confidence
        confidence = min(anomaly_score * 1.2, 0.99)
        
        # Determine threat level
        threat_level = self.determine_threat_level(anomaly_score, confidence)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(threat_level, event_type)
        
        # Create detection
        detection = AnomalyDetection(
            detection_id=f"DET-{datetime.now().timestamp()}",
            timestamp=datetime.now(),
            event_type=event_type,
            threat_level=threat_level,
            confidence_score=confidence,
            anomaly_score=anomaly_score,
            description=description,
            affected_entities=affected_entities,
            indicators=description.split("; "),
            raw_events=[event.to_dict()],
            recommended_actions=recommendations,
            false_positive_probability=0.2
        )
        
        return detection