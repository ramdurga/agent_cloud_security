"""
Simplified LangChain Security Agent that works with current versions
"""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from langchain.tools import Tool
from langchain_anthropic import ChatAnthropic
from langchain.schema import HumanMessage, SystemMessage

from src.models.data_models import (
    NetworkEvent, UserBehaviorEvent, AnomalyDetection,
    ThreatLevel, EventType
)
from src.agents.anomaly_detector import AnomalyDetectionAgent


class SimpleLangChainAgent:
    """Simplified security agent using LangChain and Claude"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the simplified LangChain agent"""
        
        # Set up Claude LLM with updated model
        self.llm = ChatAnthropic(
            anthropic_api_key=api_key or os.getenv('ANTHROPIC_API_KEY'),
            model='claude-3-5-sonnet-20241022',
            temperature=0.3,
            max_tokens=1000
        )
        
        # Initialize ML detector
        self.anomaly_detector = AnomalyDetectionAgent()
        
        # Simulated threat intelligence database
        self.known_threats = {
            'ips': ['185.220.101.45', '104.248.144.120', '192.241.220.147'],
            'domains': ['malicious.com', 'phishing-site.net', 'c2-server.org'],
            'users': ['compromised_user1', 'suspicious_account']
        }
        
        # Store recent detections
        self.recent_detections = []
        
    def check_threat_intelligence(self, query: str) -> str:
        """Check if an entity is in threat intelligence"""
        query = query.strip().lower()
        
        # Check IPs
        if query in [ip.lower() for ip in self.known_threats['ips']]:
            return f"⚠️ WARNING: {query} is a known malicious IP address"
        
        # Check domains
        if query in [domain.lower() for domain in self.known_threats['domains']]:
            return f"⚠️ WARNING: {query} is a known malicious domain"
        
        # Check users
        if query in [user.lower() for user in self.known_threats['users']]:
            return f"⚠️ WARNING: {query} is a compromised user account"
        
        # Check for suspicious patterns
        if 'tor' in query or 'c2' in query or 'scanner' in query:
            return f"⚠️ SUSPICIOUS: {query} matches suspicious patterns"
        
        return f"✅ {query} is not in threat intelligence databases"
    
    async def analyze_with_llm(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze event using Claude LLM"""
        
        # Check threat intelligence for IPs and users
        threat_intel_results = []
        
        if event.get('source_ip'):
            result = self.check_threat_intelligence(event['source_ip'])
            if '⚠️' in result:
                threat_intel_results.append(result)
        
        if event.get('user_id'):
            result = self.check_threat_intelligence(event['user_id'])
            if '⚠️' in result:
                threat_intel_results.append(result)
        
        # Prepare context for LLM
        system_prompt = """You are an expert cybersecurity analyst. Analyze the following security event and provide:
1. Threat level assessment (LOW, MEDIUM, HIGH, CRITICAL)
2. Confidence score (0.0 to 1.0)
3. Brief description of the threat
4. Recommended actions

Respond in JSON format."""
        
        event_context = f"""
Security Event:
{json.dumps(event, indent=2)}

Threat Intelligence Results:
{chr(10).join(threat_intel_results) if threat_intel_results else 'No matches found'}

Analyze this event for security threats.
"""
        
        try:
            # Get LLM analysis
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=event_context)
            ]
            
            response = self.llm.invoke(messages)
            
            # Parse response (simplified - in production would need better parsing)
            analysis = {
                'threat_level': ThreatLevel.MEDIUM,
                'confidence': 0.75,
                'description': response.content[:200] if len(response.content) > 200 else response.content,
                'has_threat_intel': len(threat_intel_results) > 0
            }
            
            # Extract threat level from response
            if 'CRITICAL' in response.content.upper():
                analysis['threat_level'] = ThreatLevel.CRITICAL
            elif 'HIGH' in response.content.upper():
                analysis['threat_level'] = ThreatLevel.HIGH
            elif 'LOW' in response.content.upper():
                analysis['threat_level'] = ThreatLevel.LOW
            
            return analysis
            
        except Exception as e:
            print(f"LLM analysis error: {e}")
            # Fallback to basic analysis
            return {
                'threat_level': ThreatLevel.HIGH if threat_intel_results else ThreatLevel.MEDIUM,
                'confidence': 0.8 if threat_intel_results else 0.6,
                'description': f"Threat intelligence matches found: {', '.join(threat_intel_results)}" if threat_intel_results else "Anomalous activity detected",
                'has_threat_intel': len(threat_intel_results) > 0
            }
    
    async def analyze_event(self, event: Dict[str, Any]) -> Optional[AnomalyDetection]:
        """Analyze a single event using both ML and LLM"""
        
        # First, use ML-based detection
        ml_detection = None
        
        if event.get('type') == 'network':
            network_event = NetworkEvent(
                timestamp=datetime.fromisoformat(event['timestamp']),
                source_ip=event.get('source_ip', '0.0.0.0'),
                destination_ip=event.get('destination_ip', '0.0.0.0'),
                source_port=event.get('source_port', 0),
                destination_port=event.get('destination_port', 0),
                protocol=event.get('protocol', 'TCP'),
                bytes_sent=event.get('bytes_sent', 0),
                bytes_received=event.get('bytes_received', 0),
                duration=event.get('duration', 0),
                packet_count=event.get('packet_count', 0)
            )
            ml_detection = await self.anomaly_detector.process_event(network_event)
        
        # Get LLM analysis
        llm_analysis = await self.analyze_with_llm(event)
        
        # Combine ML and LLM results
        if ml_detection:
            # Enhance ML detection with LLM insights
            ml_detection.description = f"{ml_detection.description} | LLM: {llm_analysis['description']}"
            if llm_analysis['has_threat_intel']:
                ml_detection.threat_level = max(ml_detection.threat_level, llm_analysis['threat_level'], key=lambda x: ['low', 'medium', 'high', 'critical'].index(x.value))
                ml_detection.confidence_score = min(ml_detection.confidence_score * 1.2, 0.99)
            
            self.recent_detections.append(ml_detection)
            return ml_detection
        elif llm_analysis['threat_level'] in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            # Create detection from LLM analysis alone
            detection = AnomalyDetection(
                detection_id=f"LLM-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                event_type=EventType.NETWORK if event.get('type') == 'network' else EventType.LOGIN,
                threat_level=llm_analysis['threat_level'],
                confidence_score=llm_analysis['confidence'],
                anomaly_score=0.8,
                description=llm_analysis['description'],
                affected_entities=[event.get('source_ip', ''), event.get('user_id', '')],
                indicators=['LLM Analysis', 'Threat Intelligence Match'] if llm_analysis['has_threat_intel'] else ['LLM Analysis'],
                raw_events=[event],
                recommended_actions=self.generate_recommendations(llm_analysis['threat_level']),
                false_positive_probability=0.2
            )
            
            self.recent_detections.append(detection)
            return detection
        
        return None
    
    def generate_recommendations(self, threat_level: ThreatLevel) -> List[str]:
        """Generate recommendations based on threat level"""
        
        if threat_level == ThreatLevel.CRITICAL:
            return [
                "🚨 Isolate affected systems immediately",
                "📞 Contact security team",
                "🔒 Disable compromised accounts",
                "📋 Initiate incident response procedure",
                "🔍 Perform forensic analysis"
            ]
        elif threat_level == ThreatLevel.HIGH:
            return [
                "⚠️ Investigate suspicious activity",
                "📊 Monitor for additional indicators",
                "🔐 Reset affected credentials",
                "📝 Document findings"
            ]
        elif threat_level == ThreatLevel.MEDIUM:
            return [
                "👀 Monitor closely",
                "📈 Check for patterns",
                "🔄 Review recent logs"
            ]
        else:
            return [
                "📊 Continue monitoring",
                "📝 Log for future reference"
            ]
    
    async def analyze_batch(self, events: List[Dict[str, Any]]) -> List[AnomalyDetection]:
        """Analyze a batch of events"""
        detections = []
        
        for event in events:
            detection = await self.analyze_event(event)
            if detection:
                detections.append(detection)
        
        return detections
    
    def get_agent_stats(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return {
            'total_detections': len(self.recent_detections),
            'recent_detections': self.recent_detections[-10:],
            'has_llm': True,
            'threat_intel_entries': sum(len(v) for v in self.known_threats.values())
        }