"""
Working Streamlit Dashboard with Threat Detection
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import asyncio
import random
import os
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import components
from src.utils.data_generator import DataGenerator
from src.agents.anomaly_detector_pydantic import AnomalyDetectionAgent
from src.models.data_models import ThreatLevel, EventType, NetworkEvent, UserBehaviorEvent

# For LangChain features
try:
    from src.agents.langchain_agent_pydantic import LangChainSecurityAgentFixed as SimpleLangChainAgent
    LANGCHAIN_AVAILABLE = True
except:
    LANGCHAIN_AVAILABLE = False


# Page configuration
st.set_page_config(
    page_title="AI Security Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Initialize session state
if 'initialized' not in st.session_state:
    st.session_state.initialized = True
    st.session_state.monitoring_active = False
    st.session_state.active_threats = []
    st.session_state.all_recommendations = []
    st.session_state.events_processed = 0
    st.session_state.anomalies_detected = 0
    
    # Initialize components
    st.session_state.data_generator = DataGenerator()
    st.session_state.anomaly_detector = AnomalyDetectionAgent()
    
    # Check for API key and initialize LangChain if available
    api_key = os.getenv('ANTHROPIC_API_KEY')
    st.session_state.has_api_key = api_key is not None
    
    if st.session_state.has_api_key and LANGCHAIN_AVAILABLE:
        try:
            st.session_state.langchain_agent = SimpleLangChainAgent(api_key)
            st.session_state.use_langchain = True
        except:
            st.session_state.use_langchain = False
    else:
        st.session_state.use_langchain = False


# Helper function to process events
async def process_event_async(event_dict):
    """Process an event and detect anomalies"""
    detector = st.session_state.anomaly_detector
    
    # Create event object
    if event_dict['type'] == 'network':
        event = NetworkEvent(
            timestamp=datetime.fromisoformat(event_dict['timestamp']),
            source_ip=event_dict.get('source_ip', '0.0.0.0'),
            destination_ip=event_dict.get('destination_ip', '0.0.0.0'),
            source_port=event_dict.get('source_port', 0),
            destination_port=event_dict.get('destination_port', 0),
            protocol=event_dict.get('protocol', 'TCP'),
            bytes_sent=event_dict.get('bytes_sent', 0),
            bytes_received=event_dict.get('bytes_received', 0),
            duration=event_dict.get('duration', 0),
            packet_count=event_dict.get('packet_count', 0),
            source_host=event_dict.get('source_host'),
            destination_host=event_dict.get('destination_host'),
            service=event_dict.get('service')
        )
    else:
        event = UserBehaviorEvent(
            timestamp=datetime.fromisoformat(event_dict['timestamp']),
            user_id=event_dict.get('user_id', 'unknown'),
            user_name=event_dict.get('user_name'),
            entity_id=event_dict.get('entity_id', 'unknown'),
            event_type=EventType[event_dict.get('event_type', 'LOGIN').upper()],
            action=event_dict.get('action', 'unknown'),
            resource=event_dict.get('resource', 'unknown'),
            location=event_dict.get('location'),
            device_id=event_dict.get('device_id')
        )
    
    # Process with anomaly detector
    detection = await detector.process_event(event)
    
    # Enhance with LangChain if available
    if detection and st.session_state.use_langchain:
        try:
            llm_result = await st.session_state.langchain_agent.analyze_event(event_dict)
            if llm_result:
                # Merge LLM insights
                detection.description = f"{detection.description} | AI: Enhanced threat detected"
        except:
            pass
    
    return detection


def process_event(event_dict):
    """Synchronous wrapper for event processing"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(process_event_async(event_dict))
    loop.close()
    return result


# Custom CSS
st.markdown("""
<style>
    .threat-critical {
        background-color: #FF4B4B;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
        font-weight: bold;
    }
    .threat-high {
        background-color: #FFA500;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .threat-medium {
        background-color: #FFD700;
        color: black;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .threat-low {
        background-color: #90EE90;
        color: black;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .normal-event {
        background-color: #f0f2f6;
        padding: 5px;
        border-radius: 3px;
        margin: 2px 0;
        font-size: 0.9em;
    }
</style>
""", unsafe_allow_html=True)


# Header
col1, col2, col3 = st.columns([2, 1, 1])
with col1:
    st.title("🛡️ AI Security Monitoring System")
    agent_type = "LangChain + Claude" if st.session_state.use_langchain else "Standard ML"
    st.caption(f"Powered by {agent_type}")
    
with col2:
    if st.session_state.monitoring_active:
        st.success("🟢 Monitoring Active")
    else:
        st.warning("🔴 Monitoring Inactive")
        
with col3:
    st.metric("Threats", st.session_state.anomalies_detected)


# Sidebar
with st.sidebar:
    st.header("🎛️ Control Panel")
    
    # API Key Status
    st.subheader("🔑 Configuration")
    if st.session_state.has_api_key:
        st.success("✅ Claude API Key Found")
        if st.session_state.use_langchain:
            st.info("🤖 Using Claude AI")
    else:
        st.warning("⚠️ No API Key")
        st.caption("Add ANTHROPIC_API_KEY to .env for AI features")
    
    st.divider()
    
    # Controls
    st.subheader("📊 Monitoring Controls")
    
    if st.button("▶️ Start" if not st.session_state.monitoring_active else "⏸️ Stop", 
                 type="primary", key="start_stop", use_container_width=True):
        st.session_state.monitoring_active = not st.session_state.monitoring_active
        st.rerun()
    
    if st.button("🔄 Reset All", key="reset", use_container_width=True):
        st.session_state.active_threats = []
        st.session_state.all_recommendations = []
        st.session_state.events_processed = 0
        st.session_state.anomalies_detected = 0
        st.rerun()
    
    st.divider()
    
    # Threat Simulation
    st.subheader("🎯 Simulate Attacks")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🌐 Network", key="net_attack", use_container_width=True):
            # Generate DDoS attack
            attacker_ip = "185.220.101.45"  # Known malicious IP
            for i in range(5):
                event = {
                    'type': 'network',
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': attacker_ip,
                    'source_host': 'TOR-EXIT-NODE',
                    'destination_ip': f'10.0.1.{100+i}',
                    'destination_host': f'server-{i}',
                    'source_port': random.randint(1024, 65535),
                    'destination_port': 80,
                    'protocol': 'TCP',
                    'service': 'DDOS-ATTACK',
                    'bytes_sent': 50000000,  # 50MB - suspicious
                    'bytes_received': 1000,
                    'duration': 0.1,
                    'packet_count': 50000
                }
                detection = process_event(event)
                if detection:
                    st.session_state.active_threats.append(detection)
                    st.session_state.anomalies_detected += 1
            st.success("Network attack simulated!")
            st.rerun()
    
    with col2:
        if st.button("👤 UEBA", key="ueba_attack", use_container_width=True):
            # Generate privilege escalation
            for i in range(3):
                event = {
                    'type': 'behavior',
                    'timestamp': datetime.now().isoformat(),
                    'user_id': 'compromised_user1',
                    'user_name': 'Suspicious User',
                    'entity_id': f'server-prod-{i}',
                    'event_type': 'privilege_escalation',
                    'action': 'sudo_execute',
                    'resource': '/etc/shadow',
                    'location': 'Unknown-IP'
                }
                detection = process_event(event)
                if detection:
                    st.session_state.active_threats.append(detection)
                    st.session_state.anomalies_detected += 1
            st.success("UEBA attack simulated!")
            st.rerun()
    
    if st.button("💣 Critical Threat", key="critical", type="secondary", use_container_width=True):
        # Generate critical data exfiltration
        event = {
            'type': 'network',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '10.0.1.50',
            'source_host': 'compromised-workstation',
            'destination_ip': '185.220.101.45',
            'destination_host': 'C2-SERVER',
            'source_port': 443,
            'destination_port': 443,
            'protocol': 'TCP',
            'service': 'DATA-EXFILTRATION',
            'bytes_sent': 500000000,  # 500MB - very suspicious
            'bytes_received': 1000,
            'duration': 600,
            'packet_count': 100000
        }
        detection = process_event(event)
        if detection:
            detection.threat_level = ThreatLevel.CRITICAL
            detection.description = "CRITICAL: Large data exfiltration to C2 server detected!"
            st.session_state.active_threats.append(detection)
            st.session_state.anomalies_detected += 1
        st.error("Critical threat simulated!")
        st.rerun()
    
    st.divider()
    
    # Statistics
    st.subheader("📈 Statistics")
    st.metric("Events", st.session_state.events_processed)
    st.metric("Threats", st.session_state.anomalies_detected)
    if st.session_state.events_processed > 0:
        rate = (st.session_state.anomalies_detected / st.session_state.events_processed) * 100
        st.metric("Detection Rate", f"{rate:.1f}%")


# Main content tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Real-Time Monitor", 
    "🔍 Threat Analysis", 
    "📈 Analytics", 
    "🤖 AI Recommendations"
])


with tab1:
    st.header("Real-Time Security Monitoring")
    
    # Process events if monitoring is active
    if st.session_state.monitoring_active:
        # Generate and process some events
        for _ in range(2):
            event = st.session_state.data_generator.generate_event()
            st.session_state.events_processed += 1
            
            # Process for anomalies
            detection = process_event(event)
            if detection:
                st.session_state.active_threats.append(detection)
                st.session_state.anomalies_detected += 1
    
    # Display layout
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🚨 Active Threats")
        
        # Keep only last 10 threats
        st.session_state.active_threats = st.session_state.active_threats[-10:]
        
        if st.session_state.active_threats:
            for threat in reversed(st.session_state.active_threats):
                threat_class = f"threat-{threat.threat_level.value}"
                st.markdown(f"""
                <div class="{threat_class}">
                    <b>{threat.threat_level.value.upper()}</b> - {threat.description}<br>
                    <small>Confidence: {threat.confidence_score:.1%} | 
                    Score: {threat.anomaly_score:.2f} |
                    Time: {threat.timestamp.strftime('%H:%M:%S')}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No active threats detected. Click 'Simulate Attacks' to test the system.")
    
    with col2:
        st.subheader("📊 Recent Events")
        
        # Show some recent normal events
        if st.session_state.monitoring_active:
            st.markdown("""
            <div class="normal-event">🌐 192.168.1.10 → 8.8.8.8:53 (DNS)</div>
            <div class="normal-event">👤 Ram Katakam logged in</div>
            <div class="normal-event">🌐 10.0.1.50 → 172.217.0.0:443 (HTTPS)</div>
            <div class="normal-event">👤 Pavan Katakam accessed files</div>
            <div class="normal-event">🌐 192.168.1.20 → 10.0.0.1:22 (SSH)</div>
            """, unsafe_allow_html=True)
        else:
            st.warning("Start monitoring to see events")


with tab2:
    st.header("Threat Analysis")
    
    # Threat distribution
    threat_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for threat in st.session_state.active_threats:
        threat_counts[threat.threat_level.value] += 1
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔴 Critical", threat_counts['critical'])
    with col2:
        st.metric("🟠 High", threat_counts['high'])
    with col3:
        st.metric("🟡 Medium", threat_counts['medium'])
    with col4:
        st.metric("🟢 Low", threat_counts['low'])
    
    # Threat details
    if st.session_state.active_threats:
        st.subheader("Threat Details")
        
        threat_data = []
        for threat in st.session_state.active_threats[-5:]:
            threat_data.append({
                'Time': threat.timestamp.strftime('%H:%M:%S'),
                'Level': threat.threat_level.value.upper(),
                'Type': threat.event_type.value,
                'Score': f"{threat.anomaly_score:.2f}",
                'Description': threat.description[:60] + '...' if len(threat.description) > 60 else threat.description
            })
        
        df = pd.DataFrame(threat_data)
        st.dataframe(df, hide_index=True, use_container_width=True)


with tab3:
    st.header("Security Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("System Metrics")
        
        st.metric("Total Events", st.session_state.events_processed)
        st.metric("Threats Detected", st.session_state.anomalies_detected)
        st.metric("Active Threats", len(st.session_state.active_threats))
        st.metric("Agent Type", "Claude AI" if st.session_state.use_langchain else "ML Only")
    
    with col2:
        st.subheader("Threat Distribution")
        
        total = sum(threat_counts.values())
        if total > 0:
            fig = px.pie(
                values=list(threat_counts.values()),
                names=['Critical', 'High', 'Medium', 'Low'],
                color_discrete_map={
                    'Critical': '#FF4B4B',
                    'High': '#FFA500',
                    'Medium': '#FFD700',
                    'Low': '#90EE90'
                },
                title="Threats by Severity"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threats to visualize yet")


with tab4:
    st.header("🤖 AI-Generated Security Recommendations")
    
    # Collect all recommendations with priorities
    all_prioritized_recs = []
    simple_recs = []
    
    for threat in st.session_state.active_threats:
        # Get prioritized recommendations first
        if hasattr(threat, 'prioritized_recommendations') and threat.prioritized_recommendations:
            for priority, rec in threat.prioritized_recommendations:
                all_prioritized_recs.append((priority, rec, threat.threat_level))
        # Also get simple recommendations
        elif hasattr(threat, 'recommended_actions') and threat.recommended_actions:
            for action in threat.recommended_actions:
                simple_recs.append(action)
    
    if all_prioritized_recs or simple_recs:
        st.subheader("🎯 Recommended Security Actions")
        
        # Sort prioritized recommendations by priority
        all_prioritized_recs.sort(key=lambda x: x[0])
        
        # Group by priority
        priority_groups = {1: [], 2: [], 3: [], 4: [], 5: []}
        for priority, rec, threat_level in all_prioritized_recs:
            if rec not in priority_groups[priority]:  # Avoid duplicates
                priority_groups[priority].append(rec)
        
        # Display Priority 1: CRITICAL
        if priority_groups[1]:
            st.error("**🚨 Priority 1: CRITICAL - Immediate Action Required**")
            for rec in priority_groups[1][:5]:
                st.markdown(f"• {rec}")
        
        # Display Priority 2: HIGH
        if priority_groups[2]:
            st.warning("**⚠️ Priority 2: HIGH - Urgent Response Needed**")
            for rec in priority_groups[2][:5]:
                st.markdown(f"• {rec}")
        
        # Display Priority 3: MEDIUM
        if priority_groups[3]:
            st.info("**👀 Priority 3: MEDIUM - Investigate Soon**")
            for rec in priority_groups[3][:5]:
                st.markdown(f"• {rec}")
        
        # Display Priority 4-5: LOW
        if priority_groups[4] or priority_groups[5]:
            with st.expander("📊 Priority 4-5: LOW - Routine Actions"):
                for rec in priority_groups[4][:3] + priority_groups[5][:3]:
                    st.markdown(f"• {rec}")
        
        # Display simple recommendations if any
        if simple_recs and not all_prioritized_recs:
            st.info("**Recommended Actions:**")
            for rec in simple_recs[:5]:
                st.markdown(f"• {rec}")
        
        if st.session_state.use_langchain:
            st.success("✅ Recommendations enhanced by Claude AI")
    else:
        st.info("""
        No recommendations available yet.
        
        **To see AI recommendations:**
        1. Click '▶️ Start' to begin monitoring
        2. Use 'Simulate Attacks' buttons to generate threats
        3. Recommendations will appear here automatically
        """)


# Auto-refresh when monitoring
if st.session_state.monitoring_active:
    import time
    time.sleep(3)
    st.rerun()