import numpy as np
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from scipy import stats
import pandas as pd
from collections import defaultdict
import asyncio
from src.models.data_models import (
    NetworkEvent, UserBehaviorEvent, AnomalyDetection,
    ThreatLevel, EventType, UserProfile
)


class AnomalyDetectionAgent:
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
        self.detection_threshold = 0.65  # Balanced for catching real threats
        
    def extract_network_features(self, event: NetworkEvent) -> np.ndarray:
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
        if event_type not in self.baseline_stats:
            return 0.5
            
        baseline = self.baseline_stats[event_type]
        if 'mean' not in baseline:
            return 0.5
            
        z_scores = np.abs((features - baseline['mean']) / (baseline['std'] + 0.001))
        anomaly_score = np.mean(z_scores) / 10.0
        return min(anomaly_score, 1.0)
    
    def update_baseline(self, features: np.ndarray, event_type: str):
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
        features = self.extract_network_features(event)
        base_anomaly_score = self.calculate_anomaly_score(features, 'network')
        
        anomalies = []
        additional_score = 0
        
        # Check for suspicious patterns
        if event.bytes_sent > 10000000:
            anomalies.append("Unusually high data transfer")
            additional_score += 0.3
            
        # Check for suspicious IPs or hosts
        if hasattr(event, 'source_host'):
            suspicious_keywords = ['TOR', 'C2', 'SCANNER', 'MINER', 'ATTACKER', 'SUSPICIOUS']
            if any(keyword in str(event.source_host).upper() for keyword in suspicious_keywords):
                anomalies.append(f"Suspicious source: {event.source_host}")
                additional_score += 0.4
            if hasattr(event, 'destination_host') and any(keyword in str(event.destination_host).upper() for keyword in suspicious_keywords):
                anomalies.append(f"Suspicious destination: {event.destination_host}")
                additional_score += 0.4
                
        if event.destination_port in [22, 3389, 445, 139]:
            if event.source_ip.startswith('10.') or event.source_ip.startswith('192.168'):
                anomalies.append(f"Sensitive port {event.destination_port} access")
                additional_score += 0.2
                
        if event.duration > 3600:
            anomalies.append("Long-duration connection")
            additional_score += 0.1
            
        # Check for DDoS patterns
        if hasattr(event, 'service') and 'DDOS' in str(event.service).upper():
            anomalies.append("DDoS attack pattern detected")
            additional_score += 0.5
            
        # Only use the higher of base score or pattern-based score if patterns found
        if anomalies:
            anomaly_score = min(base_anomaly_score + additional_score, 1.0)
            description = "; ".join(anomalies)
        else:
            # For normal traffic, cap the score at 0.5 to avoid false positives
            anomaly_score = min(base_anomaly_score * 0.5, 0.5)
            description = "Normal network activity"
            
        is_anomaly = anomaly_score > self.detection_threshold
        
        # Don't flag normal activity as anomaly even if statistical score is high
        if description == "Normal network activity" and is_anomaly:
            is_anomaly = False
            
        return is_anomaly, anomaly_score, description
    
    def detect_behavior_anomaly(self, event: UserBehaviorEvent) -> Tuple[bool, float, str]:
        features = self.extract_behavior_features(event)
        anomaly_score = self.calculate_anomaly_score(features, 'behavior')
        
        anomalies = []
        hour = event.timestamp.hour
        
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
    
    def calculate_confidence_score(self, anomaly_score: float, event_count: int) -> float:
        base_confidence = anomaly_score * 0.7
        
        sample_size_factor = min(1.0, event_count / 100.0)
        confidence = base_confidence + (sample_size_factor * 0.3)
        
        if len(self.false_positive_history) > 10:
            recent_fp_rate = sum(self.false_positive_history[-10:]) / 10
            confidence *= (1 - recent_fp_rate * 0.5)
            
        return min(confidence, 0.99)
    
    def estimate_false_positive_probability(self, anomaly_score: float, confidence: float) -> float:
        if anomaly_score < 0.5:
            base_fp = 0.7
        elif anomaly_score < 0.7:
            base_fp = 0.4
        elif anomaly_score < 0.85:
            base_fp = 0.2
        else:
            base_fp = 0.1
            
        fp_probability = base_fp * (1 - confidence)
        return min(fp_probability, 1.0)
    
    def determine_threat_level(self, anomaly_score: float, confidence: float) -> ThreatLevel:
        weighted_score = anomaly_score * confidence
        
        if weighted_score >= 0.8:
            return ThreatLevel.CRITICAL
        elif weighted_score >= 0.6:
            return ThreatLevel.HIGH
        elif weighted_score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    async def process_event(self, event: Any, context: Dict[str, Any] = None) -> Optional[AnomalyDetection]:
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
            
        self.update_baseline(features, event_type.value)
        
        if not is_anomaly:
            return None
            
        confidence = self.calculate_confidence_score(anomaly_score, 1)
        fp_probability = self.estimate_false_positive_probability(anomaly_score, confidence)
        threat_level = self.determine_threat_level(anomaly_score, confidence)
        
        # Get prioritized recommendations
        prioritized_recs = self.generate_recommendations(threat_level, event_type, event)
        # Extract just the action strings for the model (keeping backward compatibility)
        action_strings = [action for _, action in prioritized_recs]
        
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
            raw_events=[event.model_dump()],
            recommended_actions=action_strings,
            false_positive_probability=fp_probability,
            prioritized_recommendations=prioritized_recs
        )
        
        return detection
    
    def generate_recommendations(self, threat_level: ThreatLevel, event_type: EventType, event: Any = None) -> List[Tuple[int, str]]:
        """Generate prioritized recommendations with priority scores (1=highest, 5=lowest)"""
        recommendations = []
        
        # Extract specific information from the event
        user_info = ""
        ip_info = ""
        system_info = ""
        
        if event:
            # Get user information from behavior events
            if hasattr(event, 'user_name'):
                user_info = f" ({event.user_name})"
            elif hasattr(event, 'user_id'):
                user_info = f" ({event.user_id})"
                
            # Get network information
            if hasattr(event, 'source_host') and hasattr(event, 'destination_host'):
                ip_info = f" ({event.source_host} → {event.destination_host})"
            elif hasattr(event, 'source_ip') and hasattr(event, 'destination_ip'):
                ip_info = f" ({event.source_ip} → {event.destination_ip})"
                
            # Get system information
            if hasattr(event, 'entity_id'):
                system_info = f" on {event.entity_id}"
        
        # Priority 1: CRITICAL immediate actions
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.append((1, f"🚨 IMMEDIATE ACTION: Isolate affected systems{system_info} and initiate incident response"))
            recommendations.append((1, "📞 Contact security team and management immediately"))
            if user_info:
                recommendations.append((1, f"🔒 Disable compromised user account{user_info} temporarily"))
            else:
                recommendations.append((1, "🔒 Disable compromised user accounts temporarily"))
            
        # Priority 2: HIGH priority actions
        elif threat_level == ThreatLevel.HIGH:
            recommendations.append((2, "⚠️ HIGH PRIORITY: Investigate suspicious activity within 15 minutes"))
            recommendations.append((2, "📋 Document all findings for incident report"))
            
        # Priority 3-4: Event-specific actions
        if event_type == EventType.NETWORK:
            if ip_info:
                recommendations.append((3, f"🌐 Block suspicious connection{ip_info} at firewall"))
            else:
                recommendations.append((3, "🌐 Block suspicious IP addresses at firewall level"))
            recommendations.append((4, "📊 Analyze network traffic for data exfiltration patterns"))
            recommendations.append((4, "🔍 Check for lateral movement between systems"))
            
        elif event_type == EventType.PRIVILEGE_ESCALATION:
            if user_info:
                recommendations.append((2, f"🔑 Review privilege escalation by{user_info} in last 24 hours"))
                recommendations.append((2, f"👤 Verify identity of{user_info} through secondary channel"))
            else:
                recommendations.append((2, "🔑 Review all privilege escalation attempts in last 24 hours"))
                recommendations.append((2, "👤 Verify user identity through secondary channel"))
            recommendations.append((3, "🛡️ Enable additional authentication for admin access"))
            recommendations.append((4, "📝 Audit all recent permission changes"))
            
        elif event_type == EventType.LOGIN:
            if user_info:
                recommendations.append((3, f"🔐 Force password reset for{user_info}"))
            else:
                recommendations.append((3, "🔐 Force password reset for affected accounts"))
            recommendations.append((3, "📍 Verify login location and device legitimacy"))
            recommendations.append((4, "⏰ Check for unusual login times or patterns"))
            
        elif event_type == EventType.FILE_ACCESS:
            recommendations.append((3, "💾 Monitor for bulk file downloads or copies"))
            recommendations.append((3, "🔒 Restrict access to sensitive directories"))
            recommendations.append((4, "📁 Enable file integrity monitoring"))
            
        # For Medium and Low threat levels, only adjust non-critical priorities
        # Keep IMMEDIATE actions at Priority 1 regardless of threat level
        if threat_level == ThreatLevel.MEDIUM:
            adjusted = []
            for p, r in recommendations:
                # Keep IMMEDIATE actions at Priority 1
                if '🚨 IMMEDIATE' in r:
                    adjusted.append((1, r))
                else:
                    adjusted.append((min(p+1, 5), r))
            recommendations = adjusted
        elif threat_level == ThreatLevel.LOW:
            adjusted = []
            for p, r in recommendations:
                # Keep IMMEDIATE actions at Priority 1
                if '🚨 IMMEDIATE' in r:
                    adjusted.append((1, r))
                else:
                    adjusted.append((min(p+2, 5), r))
            recommendations = adjusted
            
        return recommendations