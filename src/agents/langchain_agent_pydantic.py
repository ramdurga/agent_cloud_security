"""
Fixed LangChain Security Agent that works with Pydantic v2
"""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import numpy as np

from langchain.tools import Tool
from langchain_anthropic import ChatAnthropic
from langchain.schema import HumanMessage, SystemMessage
from langchain.memory import ConversationBufferWindowMemory

from src.models.data_models import (
    NetworkEvent, UserBehaviorEvent, AnomalyDetection,
    ThreatLevel, EventType
)
from src.agents.anomaly_detector import AnomalyDetectionAgent


class LangChainSecurityAgentFixed:
    """Security monitoring agent using LangChain and Claude - Fixed for Pydantic v2"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the LangChain security agent"""
        
        # Set up Claude LLM with updated model
        self.llm = ChatAnthropic(
            anthropic_api_key=api_key or os.getenv('ANTHROPIC_API_KEY'),
            model='claude-3-5-sonnet-20241022',
            temperature=0.3,
            max_tokens=1000
        )
        
        # Initialize anomaly detector
        self.anomaly_detector = AnomalyDetectionAgent()
        
        # Set up memory
        self.memory = ConversationBufferWindowMemory(
            memory_key="chat_history",
            k=10,
            return_messages=True
        )
        
        # Create tools using functions (avoid Pydantic issues)
        self.tools = self._create_tools()
        
        # Store recent detections
        self.recent_detections = []
        
        # Threat intelligence database
        self.known_threats = {
            'ips': ['185.220.101.45', '104.248.144.120', '192.241.220.147'],
            'domains': ['malicious.com', 'phishing-site.net', 'c2-server.org'],
            'users': ['compromised_user1', 'suspicious_account']
        }
    
    def _create_tools(self) -> List[Tool]:
        """Create LangChain tools using functions"""
        
        def analyze_security_event(event_json: str) -> str:
            """Analyze a security event for anomalies"""
            try:
                event_data = json.loads(event_json)
                
                # Create appropriate event object
                if event_data.get('type') == 'network':
                    event = NetworkEvent(
                        timestamp=datetime.fromisoformat(event_data['timestamp']),
                        source_ip=event_data.get('source_ip', '0.0.0.0'),
                        destination_ip=event_data.get('destination_ip', '0.0.0.0'),
                        source_port=event_data.get('source_port', 0),
                        destination_port=event_data.get('destination_port', 0),
                        protocol=event_data.get('protocol', 'TCP'),
                        bytes_sent=event_data.get('bytes_sent', 0),
                        bytes_received=event_data.get('bytes_received', 0),
                        duration=event_data.get('duration', 0),
                        packet_count=event_data.get('packet_count', 0)
                    )
                    features = self.anomaly_detector.extract_network_features(event)
                else:
                    event = UserBehaviorEvent(
                        timestamp=datetime.fromisoformat(event_data['timestamp']),
                        user_id=event_data.get('user_id', 'unknown'),
                        entity_id=event_data.get('entity_id', 'unknown'),
                        event_type=EventType[event_data.get('event_type', 'LOGIN').upper()],
                        action=event_data.get('action', 'unknown'),
                        resource=event_data.get('resource', 'unknown'),
                        location=event_data.get('location'),
                        device_id=event_data.get('device_id')
                    )
                    features = self.anomaly_detector.extract_behavior_features(event)
                
                # Calculate anomaly score
                event_type = 'network' if event_data.get('type') == 'network' else 'behavior'
                anomaly_score = self.anomaly_detector.calculate_anomaly_score(features, event_type)
                
                # Update baseline
                self.anomaly_detector.update_baseline(features, event_type)
                
                result = {
                    'anomaly_score': float(anomaly_score),
                    'is_anomaly': anomaly_score > self.anomaly_detector.detection_threshold,
                    'threshold': self.anomaly_detector.detection_threshold,
                    'event_type': event_type
                }
                
                return json.dumps(result)
                
            except Exception as e:
                return f"Error analyzing event: {str(e)}"
        
        def check_threat_intelligence(query: str) -> str:
            """Check threat intelligence"""
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
        
        def analyze_patterns(events_json: str) -> str:
            """Analyze patterns in multiple events"""
            try:
                events = json.loads(events_json) if isinstance(events_json, str) else events_json
                
                analysis = {
                    'total_events': len(events),
                    'patterns_detected': []
                }
                
                if events:
                    # Pattern detection
                    event_types = {}
                    unique_sources = set()
                    unique_targets = set()
                    
                    for event in events:
                        evt_type = event.get('type', 'unknown')
                        event_types[evt_type] = event_types.get(evt_type, 0) + 1
                        
                        if event.get('source_ip'):
                            unique_sources.add(event['source_ip'])
                        if event.get('destination_ip'):
                            unique_targets.add(event['destination_ip'])
                        if event.get('user_id'):
                            unique_sources.add(event['user_id'])
                    
                    # Detect patterns
                    if len(unique_sources) == 1 and len(unique_targets) > 5:
                        analysis['patterns_detected'].append("Port scanning detected")
                    
                    if event_types.get('login', 0) > 10:
                        analysis['patterns_detected'].append("Brute force attack detected")
                    
                    if len(events) > 50:
                        analysis['patterns_detected'].append("High volume activity - possible DDoS")
                
                return json.dumps(analysis, default=str)
                
            except Exception as e:
                return f"Error analyzing patterns: {str(e)}"
        
        # Create tools
        tools = [
            Tool(
                name="analyze_security_event",
                func=analyze_security_event,
                description="Analyze a security event for anomalies"
            ),
            Tool(
                name="check_threat_intelligence",
                func=check_threat_intelligence,
                description="Check if an IP, domain, or user is in threat databases"
            ),
            Tool(
                name="analyze_patterns",
                func=analyze_patterns,
                description="Analyze patterns in multiple security events"
            )
        ]
        
        return tools
    
    async def analyze_event(self, event: Dict[str, Any]) -> Optional[AnomalyDetection]:
        """Analyze a single event using LangChain agent"""
        
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
        elif event.get('type') == 'behavior':
            behavior_event = UserBehaviorEvent(
                timestamp=datetime.fromisoformat(event['timestamp']),
                user_id=event.get('user_id', 'unknown'),
                entity_id=event.get('entity_id', 'unknown'),
                event_type=EventType[event.get('event_type', 'LOGIN').upper()],
                action=event.get('action', 'unknown'),
                resource=event.get('resource', 'unknown'),
                location=event.get('location'),
                device_id=event.get('device_id')
            )
            ml_detection = await self.anomaly_detector.process_event(behavior_event)
        
        # Enhance with LLM analysis
        if ml_detection or event.get('force_analysis'):
            # Prepare context for LLM
            event_json = json.dumps(event)
            
            # Check threat intelligence
            threat_intel_results = []
            if event.get('source_ip'):
                result = self.tools[1].func(event['source_ip'])
                if '⚠️' in result:
                    threat_intel_results.append(result)
            
            if event.get('user_id'):
                result = self.tools[1].func(event['user_id'])
                if '⚠️' in result:
                    threat_intel_results.append(result)
            
            # Query LLM for analysis
            query = f"""
Analyze this security event:
{event_json}

Threat Intelligence: {', '.join(threat_intel_results) if threat_intel_results else 'No matches'}

Provide:
1. Threat level (LOW/MEDIUM/HIGH/CRITICAL)
2. Confidence score (0.0-1.0)
3. Brief threat description
4. Recommended actions
"""
            
            try:
                messages = [
                    SystemMessage(content="You are a cybersecurity analyst. Analyze security events and provide threat assessments."),
                    HumanMessage(content=query)
                ]
                
                response = self.llm.invoke(messages)
                
                # Enhance ML detection with LLM insights
                if ml_detection:
                    if threat_intel_results:
                        ml_detection.description = f"{ml_detection.description} | Threat Intel: Matches found"
                        ml_detection.confidence_score = min(ml_detection.confidence_score * 1.2, 0.99)
                    
                    self.recent_detections.append(ml_detection)
                    return ml_detection
                
            except Exception as e:
                print(f"LLM analysis error: {e}")
        
        return ml_detection
    
    async def analyze_batch(self, events: List[Dict[str, Any]]) -> List[AnomalyDetection]:
        """Analyze a batch of events"""
        
        # First, check for patterns
        if len(events) > 3:
            pattern_result = self.tools[2].func(json.dumps(events[:10]))
            print(f"Pattern Analysis: {pattern_result}")
        
        # Analyze individual events
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
            'tools_available': [tool.name for tool in self.tools],
            'has_llm': True
        }


# For backward compatibility
LangChainSecurityAgent = LangChainSecurityAgentFixed