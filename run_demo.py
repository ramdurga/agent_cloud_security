#!/usr/bin/env python3

import asyncio
from src.pipeline.real_time_processor import RealTimeProcessor
from src.utils.data_generator import DataGenerator

async def quick_demo():
    print("=" * 80)
    print("🛡️  AGENTIC AI SECURITY SYSTEM - QUICK DEMO")
    print("=" * 80)
    print("\nGenerating and processing security events...")
    print("-" * 80)
    
    processor = RealTimeProcessor(buffer_size=100, batch_size=5)
    generator = DataGenerator()
    
    processor_task = asyncio.create_task(processor.run())
    
    print("\n📌 Generating normal traffic...")
    normal_events = generator.generate_event_stream(count=20, anomaly_rate=0.05)
    for event in normal_events[:10]:
        processor.add_event(event)
    await asyncio.sleep(1)
    
    print("\n⚠️  Injecting suspicious activity...")
    suspicious_events = generator.generate_event_stream(count=10, anomaly_rate=0.8)
    for event in suspicious_events:
        processor.add_event(event)
    await asyncio.sleep(1)
    
    print("\n🚨 Simulating data exfiltration attack...")
    attack_events = generator.generate_attack_scenario('data_exfiltration')
    for event in attack_events:
        processor.add_event(event)
    await asyncio.sleep(2)
    
    processor.stop()
    processor_task.cancel()
    try:
        await processor_task
    except asyncio.CancelledError:
        pass
    
    print("\n" + "=" * 80)
    print("📊 DEMO RESULTS")
    print("=" * 80)
    
    stats = processor.get_stats()
    print(f"\n✅ Events Processed: {stats['events_processed']}")
    print(f"🔴 Anomalies Detected: {stats['anomalies_detected']}")
    print(f"🟢 False Positives Reduced: {stats['false_positives_reduced']}")
    
    if stats['anomalies_detected'] > 0:
        reduction_rate = stats['false_positives_reduced'] / (stats['anomalies_detected'] + stats['false_positives_reduced'])
        print(f"📈 False Positive Reduction Rate: {reduction_rate:.1%}")
    
    print(f"⚡ Average Processing Time: {stats['processing_time_avg']*1000:.2f}ms per batch")
    
    print("\n" + "=" * 80)
    print("✨ Demo completed successfully!")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(quick_demo())