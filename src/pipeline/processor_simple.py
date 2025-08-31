"""
Real-time processor with LangChain agent integration
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
from collections import deque
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from src.models.data_models_simple import NetworkEvent, UserBehaviorEvent, AnomalyDetection
from src.agents.anomaly_detector_simple import AnomalyDetectionAgent
# Use the simple version
from src.agents.langchain_agent_simple import SimpleLangChainAgent as LangChainSecurityAgent


class LangChainRealTimeProcessor:
    """Real-time processor that can use either standard or LangChain agent"""
    
    def __init__(self, buffer_size: int = 1000, batch_size: int = 50, use_langchain: bool = True):
        self.event_buffer = deque(maxlen=buffer_size)
        self.detection_buffer = deque(maxlen=100)
        self.batch_size = batch_size
        self.use_langchain = use_langchain
        
        # Initialize agents
        self.anomaly_detector = AnomalyDetectionAgent()
        
        # Initialize LangChain agent if enabled and API key is available
        self.langchain_agent = None
        if use_langchain:
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if api_key:
                try:
                    self.langchain_agent = LangChainSecurityAgent(api_key)
                    print("✅ LangChain agent initialized with Claude LLM")
                except Exception as e:
                    print(f"⚠️ Failed to initialize LangChain agent: {e}")
                    print("Falling back to standard anomaly detector")
                    self.use_langchain = False
            else:
                print("⚠️ ANTHROPIC_API_KEY not found. Using standard anomaly detector.")
                self.use_langchain = False
        
        self.is_running = False
        self.stats = {
            'events_processed': 0,
            'anomalies_detected': 0,
            'false_positives_reduced': 0,
            'processing_time_avg': 0,
            'langchain_analyses': 0
        }
        self.correlation_window = timedelta(minutes=5)
        self.event_correlations = {}
        
    async def process_network_event(self, raw_event: Dict[str, Any]) -> Optional[NetworkEvent]:
        """Process raw network event into NetworkEvent object"""
        try:
            # Add host information if source/destination IPs match known patterns
            if 'source_host' not in raw_event:
                if 'TOR' in raw_event.get('service', ''):
                    raw_event['source_host'] = 'TOR-EXIT-NODE'
                elif 'C2' in raw_event.get('service', ''):
                    raw_event['source_host'] = 'C2-SERVER'
                    
            event = NetworkEvent(
                timestamp=datetime.fromisoformat(raw_event['timestamp']),
                source_ip=raw_event['source_ip'],
                destination_ip=raw_event['destination_ip'],
                source_port=raw_event['source_port'],
                destination_port=raw_event['destination_port'],
                protocol=raw_event['protocol'],
                bytes_sent=raw_event['bytes_sent'],
                bytes_received=raw_event['bytes_received'],
                duration=raw_event['duration'],
                packet_count=raw_event['packet_count'],
                flags=raw_event.get('flags'),
                source_host=raw_event.get('source_host'),
                destination_host=raw_event.get('destination_host'),
                service=raw_event.get('service')
            )
            return event
        except Exception as e:
            print(f"Error processing network event: {e}")
            return None
    
    async def process_behavior_event(self, raw_event: Dict[str, Any]) -> Optional[UserBehaviorEvent]:
        """Process raw behavior event into UserBehaviorEvent object"""
        try:
            # Add user name if available
            if 'user_name' not in raw_event and 'user_id' in raw_event:
                # Map user IDs to names for better identification
                user_names = {
                    'user_ram': 'Ram Katakam',
                    'user_pavan': 'Pavan Katakam',
                    'user_kittu': 'Kittu Katakam',
                    'user_jyothi': 'Jyothi Katakam',
                    'user_mani': 'Mani Katakam',
                    'user_venkat': 'Venkat Bezawada',
                    'user_ramakrishna': 'Ramakrishna Katakam'
                }
                raw_event['user_name'] = user_names.get(raw_event['user_id'], raw_event['user_id'])
                
            event = UserBehaviorEvent(
                timestamp=datetime.fromisoformat(raw_event['timestamp']),
                user_id=raw_event['user_id'],
                user_name=raw_event.get('user_name'),
                entity_id=raw_event['entity_id'],
                event_type=raw_event['event_type'],
                action=raw_event['action'],
                resource=raw_event['resource'],
                location=raw_event.get('location'),
                device_id=raw_event.get('device_id'),
                session_id=raw_event.get('session_id'),
                metadata=raw_event.get('metadata', {})
            )
            return event
        except Exception as e:
            print(f"Error processing behavior event: {e}")
            return None
    
    def correlate_events(self, detection: AnomalyDetection) -> bool:
        """Check if this detection correlates with recent events"""
        current_time = detection.timestamp
        correlation_key = tuple(sorted(detection.affected_entities))
        
        if correlation_key in self.event_correlations:
            previous_detections = self.event_correlations[correlation_key]
            recent_detections = [
                d for d in previous_detections
                if (current_time - d['timestamp']) <= self.correlation_window
            ]
            
            if len(recent_detections) >= 3:
                similar_patterns = sum(
                    1 for d in recent_detections
                    if abs(d['anomaly_score'] - detection.anomaly_score) < 0.1
                )
                if similar_patterns >= 2:
                    return False
                    
            recent_detections.append({
                'timestamp': current_time,
                'anomaly_score': detection.anomaly_score,
                'threat_level': detection.threat_level
            })
            self.event_correlations[correlation_key] = recent_detections[-10:]
        else:
            self.event_correlations[correlation_key] = [{
                'timestamp': current_time,
                'anomaly_score': detection.anomaly_score,
                'threat_level': detection.threat_level
            }]
        
        return True
    
    def apply_confidence_adjustment(self, detection: AnomalyDetection) -> Optional[AnomalyDetection]:
        """Apply confidence adjustments to reduce false positives"""
        if detection.confidence_score < 0.5 and detection.anomaly_score < 0.6:
            detection.confidence_score *= 0.8
            detection.false_positive_probability = min(
                detection.false_positive_probability * 1.2, 0.95
            )
            
        if detection.threat_level.value == 'low' and detection.confidence_score < 0.4:
            return None
            
        time_of_day = detection.timestamp.hour
        if 2 <= time_of_day <= 6:
            detection.confidence_score *= 1.1
            detection.confidence_score = min(detection.confidence_score, 0.99)
            
        return detection
    
    async def process_batch(self, events: List[Dict[str, Any]]):
        """Process a batch of events"""
        start_time = time.time()
        
        # If using LangChain and we have multiple events, analyze patterns first
        if self.use_langchain and self.langchain_agent and len(events) > 3:
            try:
                pattern_detections = await self.langchain_agent.analyze_batch(events)
                for detection in pattern_detections:
                    if detection and self.correlate_events(detection):
                        self.detection_buffer.append(detection)
                        self.stats['anomalies_detected'] += 1
                        self.stats['langchain_analyses'] += 1
                        print(f"\n🤖 LANGCHAIN DETECTION: {detection.description}")
                        print(f"   Threat Level: {detection.threat_level.value.upper()}")
                        print(f"   Confidence: {detection.confidence_score:.2%}")
            except Exception as e:
                print(f"LangChain batch analysis error: {e}")
        
        # Process individual events
        for raw_event in events:
            event = None
            if raw_event['type'] == 'network':
                event = await self.process_network_event(raw_event)
            elif raw_event['type'] == 'behavior':
                event = await self.process_behavior_event(raw_event)
                
            if event:
                # Use LangChain agent if available, otherwise use standard detector
                detection = None
                
                if self.use_langchain and self.langchain_agent:
                    try:
                        # Convert event to dict for LangChain agent
                        event_dict = {
                            'type': 'network' if isinstance(event, NetworkEvent) else 'behavior',
                            'timestamp': event.timestamp.isoformat(),
                            **event.model_dump()
                        }
                        detection = await self.langchain_agent.analyze_event(event_dict)
                        if detection:
                            self.stats['langchain_analyses'] += 1
                    except Exception as e:
                        print(f"LangChain analysis error: {e}")
                        # Fall back to standard detector
                        detection = await self.anomaly_detector.process_event(event)
                else:
                    # Use standard anomaly detector
                    detection = await self.anomaly_detector.process_event(event)
                
                if detection:
                    detection = self.apply_confidence_adjustment(detection)
                    
                    if detection and self.correlate_events(detection):
                        self.detection_buffer.append(detection)
                        self.stats['anomalies_detected'] += 1
                        
                        agent_type = "🤖 LANGCHAIN" if self.use_langchain else "🔍 STANDARD"
                        print(f"\n{agent_type} ANOMALY DETECTED: {detection.description}")
                        print(f"   Threat Level: {detection.threat_level.value.upper()}")
                        print(f"   Confidence: {detection.confidence_score:.2%}")
                        print(f"   False Positive Probability: {detection.false_positive_probability:.2%}")
                    else:
                        self.stats['false_positives_reduced'] += 1
                        
                self.stats['events_processed'] += 1
                
        processing_time = time.time() - start_time
        self.stats['processing_time_avg'] = (
            self.stats['processing_time_avg'] * 0.9 + processing_time * 0.1
        )
    
    async def run(self):
        """Main processing loop"""
        self.is_running = True
        agent_type = "LangChain + Claude" if self.use_langchain else "Standard ML"
        print(f"🚀 Real-time processor started with {agent_type} agent")
        
        while self.is_running:
            if len(self.event_buffer) >= self.batch_size:
                batch = []
                for _ in range(min(self.batch_size, len(self.event_buffer))):
                    if self.event_buffer:
                        batch.append(self.event_buffer.popleft())
                        
                if batch:
                    await self.process_batch(batch)
                    
            await asyncio.sleep(0.1)
    
    def add_event(self, event: Dict[str, Any]):
        """Add event to processing buffer"""
        self.event_buffer.append(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics"""
        return {
            **self.stats,
            'agent_type': 'LangChain + Claude' if self.use_langchain else 'Standard ML',
            'buffer_size': len(self.event_buffer),
            'detections_count': len(self.detection_buffer),
            'recent_detections': list(self.detection_buffer)[-5:] if self.detection_buffer else []
        }
    
    def stop(self):
        """Stop the processor"""
        self.is_running = False
        print("🛑 Real-time processor stopped")