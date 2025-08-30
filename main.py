import asyncio
import sys
from datetime import datetime
import json
from src.pipeline.real_time_processor import RealTimeProcessor
from src.utils.data_generator import DataGenerator
import time


async def simulate_real_time_monitoring():
    print("=" * 80)
    print("🛡️  AGENTIC AI SECURITY MONITORING SYSTEM")
    print("=" * 80)
    print("Real-time Network & UEBA Anomaly Detection")
    print("Features: Confidence Scoring | False Positive Reduction | Threat Classification")
    print("=" * 80)
    
    processor = RealTimeProcessor(buffer_size=1000, batch_size=10)
    generator = DataGenerator()
    
    processor_task = asyncio.create_task(processor.run())
    
    print("\n📊 Starting real-time monitoring...")
    print("Generating event stream with mixed normal and anomalous patterns\n")
    
    try:
        print("\n--- SCENARIO 1: Normal Traffic with Random Anomalies ---")
        events = generator.generate_event_stream(count=50, anomaly_rate=0.15)
        for event in events:
            processor.add_event(event)
            await asyncio.sleep(0.05)
        
        await asyncio.sleep(2)
        
        print("\n--- SCENARIO 2: Data Exfiltration Attack ---")
        attack_events = generator.generate_attack_scenario('data_exfiltration')
        for event in attack_events:
            processor.add_event(event)
            await asyncio.sleep(0.1)
        
        await asyncio.sleep(2)
        
        print("\n--- SCENARIO 3: Brute Force Attack ---")
        brute_force_events = generator.generate_attack_scenario('brute_force')
        for event in brute_force_events:
            processor.add_event(event)
            await asyncio.sleep(0.05)
        
        await asyncio.sleep(3)
        
        print("\n" + "=" * 80)
        print("📈 MONITORING STATISTICS")
        print("=" * 80)
        stats = processor.get_stats()
        print(f"Total Events Processed: {stats['events_processed']}")
        print(f"Anomalies Detected: {stats['anomalies_detected']}")
        print(f"False Positives Reduced: {stats['false_positives_reduced']}")
        print(f"Average Processing Time: {stats['processing_time_avg']*1000:.2f}ms")
        print(f"Current Buffer Size: {stats['buffer_size']}")
        
        if stats['anomalies_detected'] > 0:
            reduction_rate = stats['false_positives_reduced'] / (stats['anomalies_detected'] + stats['false_positives_reduced'])
            print(f"False Positive Reduction Rate: {reduction_rate:.1%}")
        
        print("\n📝 Recent Detections Summary:")
        if stats['recent_detections']:
            for detection in stats['recent_detections'][-3:]:
                print(f"\n  • Detection ID: {detection.detection_id}")
                print(f"    Threat Level: {detection.threat_level.value.upper()}")
                print(f"    Confidence: {detection.confidence_score:.2%}")
                print(f"    Description: {detection.description}")
                print(f"    False Positive Probability: {detection.false_positive_probability:.2%}")
                if detection.recommended_actions:
                    print(f"    Recommended Actions:")
                    for action in detection.recommended_actions[:2]:
                        print(f"      - {action}")
        else:
            print("  No recent anomalies detected")
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Monitoring interrupted by user")
    finally:
        processor.stop()
        processor_task.cancel()
        try:
            await processor_task
        except asyncio.CancelledError:
            pass
        
    print("\n" + "=" * 80)
    print("✅ Monitoring session completed")
    print("=" * 80)


async def run_continuous_monitoring():
    print("=" * 80)
    print("🛡️  CONTINUOUS MONITORING MODE")
    print("=" * 80)
    print("Press Ctrl+C to stop monitoring\n")
    
    processor = RealTimeProcessor(buffer_size=5000, batch_size=25)
    generator = DataGenerator()
    
    processor_task = asyncio.create_task(processor.run())
    
    try:
        event_count = 0
        while True:
            if event_count % 100 == 0 and event_count > 0:
                print(f"\n📊 Checkpoint - {event_count} events processed")
                stats = processor.get_stats()
                print(f"   Anomalies: {stats['anomalies_detected']} | FP Reduced: {stats['false_positives_reduced']}")
            
            anomaly_rate = 0.05 if event_count % 200 < 150 else 0.3
            events = generator.generate_event_stream(count=10, anomaly_rate=anomaly_rate)
            
            for event in events:
                processor.add_event(event)
                event_count += 1
                
            await asyncio.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Stopping continuous monitoring...")
    finally:
        processor.stop()
        processor_task.cancel()
        try:
            await processor_task
        except asyncio.CancelledError:
            pass
        
        print("\n📈 Final Statistics:")
        stats = processor.get_stats()
        print(f"Total Events: {stats['events_processed']}")
        print(f"Total Anomalies: {stats['anomalies_detected']}")
        print(f"False Positives Reduced: {stats['false_positives_reduced']}")


def main():
    print("\n🔐 Agentic AI Security System")
    print("Select monitoring mode:")
    print("1. Demo Mode (Simulated scenarios)")
    print("2. Continuous Monitoring Mode")
    print("3. Exit")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == "1":
        asyncio.run(simulate_real_time_monitoring())
    elif choice == "2":
        asyncio.run(run_continuous_monitoring())
    elif choice == "3":
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice. Please run again.")
        sys.exit(1)


if __name__ == "__main__":
    main()