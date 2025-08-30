#!/usr/bin/env python3
"""Test script to generate actual threats for the security system"""

import asyncio
from src.agents.anomaly_detector import AnomalyDetectionAgent
from src.pipeline.real_time_processor import RealTimeProcessor
from src.utils.data_generator import DataGenerator

async def test_threats():
    # Initialize components
    detector = AnomalyDetectionAgent()
    processor = RealTimeProcessor()
    generator = DataGenerator()
    
    print("🔍 Testing threat detection system...")
    print("-" * 50)
    
    # Test 1: Generate a data exfiltration attack
    print("\n📊 Test 1: Data Exfiltration Attack")
    attack_events = generator.generate_network_attack_scenario()
    for event in attack_events:
        processor.add_event(event)
    
    await processor.process_batch(attack_events)
    stats = processor.get_stats()
    print(f"   Detected: {stats['anomalies_detected']} anomalies")
    
    # Test 2: Generate privilege escalation
    print("\n🔑 Test 2: Privilege Escalation")
    priv_events = generator.generate_ueba_attack_scenario()
    for event in priv_events:
        processor.add_event(event)
    
    await processor.process_batch(priv_events)
    stats = processor.get_stats()
    print(f"   Detected: {stats['anomalies_detected']} anomalies")
    
    # Test 3: Critical combined attack
    print("\n🚨 Test 3: Critical Combined Attack")
    critical_events = []
    for _ in range(5):
        event = generator.generate_critical_threat_event()
        critical_events.append(event)
        processor.add_event(event)
    
    await processor.process_batch(critical_events)
    stats = processor.get_stats()
    print(f"   Detected: {stats['anomalies_detected']} anomalies")
    
    # Display summary
    print("\n" + "=" * 50)
    print("📈 FINAL STATISTICS")
    print("=" * 50)
    print(f"Total Events Processed: {stats['events_processed']}")
    print(f"Total Anomalies Detected: {stats['anomalies_detected']}")
    print(f"False Positives Reduced: {stats['false_positives_reduced']}")
    
    if stats['recent_detections']:
        print("\n🔴 Recent High/Critical Threats:")
        for detection in stats['recent_detections'][-5:]:
            if detection.threat_level.value in ['high', 'critical']:
                print(f"   - {detection.threat_level.value.upper()}: {detection.description}")
                print(f"     Confidence: {detection.confidence_score:.1%}")

if __name__ == "__main__":
    asyncio.run(test_threats())