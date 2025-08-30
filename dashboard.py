import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import asyncio
import json
from src.pipeline.real_time_processor import RealTimeProcessor
from src.utils.data_generator import DataGenerator
import time
from collections import deque, defaultdict


st.set_page_config(
    page_title="AI Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'processor' not in st.session_state:
    st.session_state.processor = RealTimeProcessor(buffer_size=1000, batch_size=10)
    st.session_state.generator = DataGenerator()
    st.session_state.detection_history = deque(maxlen=100)
    st.session_state.metrics_history = []
    st.session_state.threat_level = "low"
    st.session_state.max_threat_triggered = False
    st.session_state.network_events = deque(maxlen=50)
    st.session_state.behavior_events = deque(maxlen=50)
    st.session_state.event_counts = {'network': 0, 'behavior': 0}
    st.session_state.monitoring_active = False
    st.session_state.latest_recommendations = []

def create_threat_gauge(threat_level):
    """Create an animated threat level gauge"""
    levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    colors = {'low': '#28a745', 'medium': '#ffc107', 'high': '#fd7e14', 'critical': '#dc3545'}
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=levels.get(threat_level, 0),
        title={'text': "Threat Level", 'font': {'size': 20}},
        delta={'reference': 1, 'increasing': {'color': "red"}},
        domain={'x': [0, 1], 'y': [0, 1]},
        gauge={
            'axis': {'range': [0, 4], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': colors.get(threat_level, 'gray'), 'thickness': 0.8},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 1], 'color': "#e8f5e9"},
                {'range': [1, 2], 'color': "#fff9c4"},
                {'range': [2, 3], 'color': "#ffe0b2"},
                {'range': [3, 4], 'color': "#ffebee"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 3.5
            }
        }
    ))
    
    if threat_level == 'critical':
        fig.add_annotation(
            text="⚠️ CRITICAL ⚠️",
            xref="paper", yref="paper",
            x=0.5, y=0.15,
            showarrow=False,
            font=dict(size=16, color="red", family="Arial Black"),
            bgcolor="yellow",
            bordercolor="red",
            borderwidth=2
        )
    
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20))
    return fig

def create_network_traffic_chart(network_events):
    """Create a chart showing network traffic patterns"""
    if not network_events:
        return None
    
    df = pd.DataFrame(network_events)
    
    # Parse timestamps if they're strings
    if not df.empty and isinstance(df['timestamp'].iloc[0], str):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Data Transfer Volume', 'Connection Duration'),
        vertical_spacing=0.15
    )
    
    # Data transfer chart
    fig.add_trace(
        go.Scatter(
            x=df['timestamp'],
            y=df['bytes_sent'],
            mode='lines+markers',
            name='Bytes Sent',
            line=dict(color='#17a2b8', width=2),
            marker=dict(size=6)
        ),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(
            x=df['timestamp'],
            y=df['bytes_received'],
            mode='lines+markers',
            name='Bytes Received',
            line=dict(color='#28a745', width=2),
            marker=dict(size=6)
        ),
        row=1, col=1
    )
    
    # Duration chart
    fig.add_trace(
        go.Bar(
            x=df['timestamp'],
            y=df['duration'],
            name='Duration (s)',
            marker_color=df['duration'].apply(
                lambda x: '#dc3545' if x > 3600 else '#ffc107' if x > 600 else '#28a745'
            )
        ),
        row=2, col=1
    )
    
    fig.update_xaxes(title_text="Time", row=2, col=1)
    fig.update_yaxes(title_text="Bytes", row=1, col=1)
    fig.update_yaxes(title_text="Seconds", row=2, col=1)
    
    fig.update_layout(height=400, showlegend=True, title="Network Activity Monitor")
    return fig

def create_behavior_heatmap(behavior_events):
    """Create a heatmap of user behavior patterns"""
    if not behavior_events:
        return None
    
    df = pd.DataFrame(behavior_events)
    
    # Create hour vs event type matrix
    hour_type_matrix = defaultdict(lambda: defaultdict(int))
    for _, event in df.iterrows():
        # Parse timestamp if it's a string
        timestamp = event['timestamp']
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        hour = timestamp.hour
        event_type = event['event_type']
        hour_type_matrix[hour][event_type] += 1
    
    # Convert to DataFrame
    hours = list(range(24))
    event_types = list(set(df['event_type']))
    
    matrix_data = []
    for hour in hours:
        row = [hour_type_matrix[hour][et] for et in event_types]
        matrix_data.append(row)
    
    fig = go.Figure(data=go.Heatmap(
        z=matrix_data,
        x=event_types,
        y=[f"{h:02d}:00" for h in hours],
        colorscale='RdYlGn_r',
        showscale=True,
        hoverongaps=False
    ))
    
    fig.update_layout(
        title="User Behavior Heatmap (24-hour)",
        xaxis_title="Event Type",
        yaxis_title="Hour of Day",
        height=400
    )
    
    return fig

def create_ip_network_graph(network_events):
    """Create a network graph showing IP connections"""
    if not network_events or len(network_events) < 2:
        return None
    
    df = pd.DataFrame(network_events)
    
    # Count connections between IPs
    connections = df.groupby(['source_ip', 'destination_ip']).size().reset_index(name='count')
    
    # Create nodes and edges
    nodes = list(set(df['source_ip'].unique()) | set(df['destination_ip'].unique()))
    
    fig = go.Figure()
    
    # Add edges
    for _, conn in connections.iterrows():
        fig.add_trace(go.Scatter(
            x=[conn['source_ip'], conn['destination_ip']],
            y=[0, 1],
            mode='lines',
            line=dict(width=conn['count'], color='rgba(125, 125, 125, 0.5)'),
            hoverinfo='skip',
            showlegend=False
        ))
    
    # Add nodes
    for i, node in enumerate(nodes):
        is_suspicious = any(ip in node for ip in ['185.', '45.', '199.', '192.241.', '104.'])
        fig.add_trace(go.Scatter(
            x=[node],
            y=[i % 2],
            mode='markers+text',
            marker=dict(
                size=20,
                color='red' if is_suspicious else 'blue'
            ),
            text=node.split('.')[-1],
            textposition='top center',
            name=node,
            hovertemplate=f"IP: {node}<extra></extra>"
        ))
    
    fig.update_layout(
        title="Network Connection Graph",
        showlegend=False,
        height=300,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=True),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    
    return fig

async def simulate_network_attack():
    """Simulate network-based attacks only"""
    processor = st.session_state.processor
    generator = st.session_state.generator
    
    network_events = []
    
    # Generate various network threats
    for _ in range(5):
        # Suspicious network events
        event = generator.generate_suspicious_network_event()
        network_events.append(event)
        st.session_state.network_events.append(event)
        st.session_state.event_counts['network'] += 1
    
    # Add critical network threat
    critical_network = generator.generate_critical_threat_event()
    while critical_network['type'] != 'network':
        critical_network = generator.generate_critical_threat_event()
    network_events.append(critical_network)
    st.session_state.network_events.append(critical_network)
    st.session_state.event_counts['network'] += 1
    
    # Process events
    for event in network_events:
        processor.add_event(event)
    
    await processor.process_batch(network_events)
    
    st.session_state.threat_level = "high"
    
    return len(network_events)

async def simulate_ueba_attack():
    """Simulate user behavior-based attacks only"""
    processor = st.session_state.processor
    generator = st.session_state.generator
    
    behavior_events = []
    
    # Generate suspicious user behaviors
    for _ in range(5):
        event = generator.generate_suspicious_behavior_event()
        behavior_events.append(event)
        st.session_state.behavior_events.append(event)
        st.session_state.event_counts['behavior'] += 1
    
    # Add critical behavior threat
    critical_behavior = generator.generate_critical_threat_event()
    while critical_behavior['type'] != 'behavior':
        critical_behavior = generator.generate_critical_threat_event()
    behavior_events.append(critical_behavior)
    st.session_state.behavior_events.append(critical_behavior)
    st.session_state.event_counts['behavior'] += 1
    
    # Process events
    for event in behavior_events:
        processor.add_event(event)
    
    await processor.process_batch(behavior_events)
    
    st.session_state.threat_level = "high"
    
    return len(behavior_events)

async def simulate_critical_attack():
    """Simulate a critical multi-stage attack"""
    processor = st.session_state.processor
    generator = st.session_state.generator
    
    # Generate mixed critical events (both network and behavior)
    critical_events = []
    
    # Add critical network events
    for _ in range(3):
        event = generator.generate_critical_threat_event()
        critical_events.append(event)
        if event['type'] == 'network':
            st.session_state.network_events.append(event)
        else:
            st.session_state.behavior_events.append(event)
    
    # Add multi-stage attack
    attack_events = generator.generate_attack_scenario('critical_multi_stage')
    critical_events.extend(attack_events)
    
    # Process events
    for event in critical_events:
        processor.add_event(event)
        if event['type'] == 'network':
            st.session_state.network_events.append(event)
            st.session_state.event_counts['network'] += 1
        else:
            st.session_state.behavior_events.append(event)
            st.session_state.event_counts['behavior'] += 1
    
    await processor.process_batch(critical_events)
    
    st.session_state.threat_level = "critical"
    st.session_state.max_threat_triggered = True
    
    return len(critical_events)

def main():
    st.title("🛡️ Complete Security Monitoring Dashboard")
    st.markdown("**Real-time Network & User Behavior Analytics (UEBA) with AI-Powered Threat Detection**")
    
    # Critical alert banner
    if st.session_state.threat_level == "critical":
        st.error("🚨 **CRITICAL SECURITY INCIDENT IN PROGRESS** - Immediate response required!")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Threat Level", "CRITICAL", "⬆️")
        with col2:
            st.metric("Risk Score", "95%", "+45%")
        with col3:
            st.metric("Action Required", "IMMEDIATE", "")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Control Panel")
        
        monitoring_mode = st.radio(
            "📡 Monitoring Mode",
            ["Normal Operations", "Enhanced Detection", "Attack Simulation"],
            help="Select monitoring sensitivity level"
        )
        
        anomaly_rate = st.slider(
            "🎯 Detection Sensitivity",
            min_value=0.0,
            max_value=0.5,
            value=0.1,
            step=0.05,
            help="Higher values detect more anomalies"
        )
        
        st.divider()
        
        # Control buttons
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            if st.button("▶️ Start", type="primary", use_container_width=True):
                st.session_state.monitoring_active = True
        with col_btn2:
            if st.button("⏸️ Stop", use_container_width=True):
                st.session_state.monitoring_active = False
        
        st.divider()
        
        # Attack simulation section
        st.subheader("🎯 Attack Simulation")
        
        # Show success message if it exists
        if st.session_state.get('show_success', False):
            st.success(st.session_state.get('success_message', ''))
            st.session_state.show_success = False
        
        # Two columns for different threat types
        threat_col1, threat_col2 = st.columns(2)
        
        with threat_col1:
            if st.button("🌐 **Network Attack**", type="secondary", use_container_width=True, help="Simulate network-based threats"):
                # Set flag to trigger network attack
                st.session_state.trigger_network_attack = True
                st.session_state.monitoring_active = True
                st.rerun()
        
        with threat_col2:
            if st.button("👤 **UEBA Threat**", type="secondary", use_container_width=True, help="Simulate user behavior threats"):
                # Set flag to trigger UEBA attack
                st.session_state.trigger_ueba_attack = True
                st.session_state.monitoring_active = True
                st.rerun()
        
        # Combined critical threat button
        if st.button("🔴 **TRIGGER BOTH (CRITICAL)**", type="primary", use_container_width=True, help="Simulate combined critical attack"):
            # Set flag to trigger both attacks
            st.session_state.trigger_attack = True
            st.session_state.monitoring_active = True
            st.rerun()
        
        if st.button("🟢 Reset System", use_container_width=True):
            st.session_state.threat_level = "low"
            st.session_state.max_threat_triggered = False
            st.session_state.network_events.clear()
            st.session_state.behavior_events.clear()
            st.rerun()
        
        st.divider()
        
        # Live statistics
        st.subheader("📊 Live Statistics")
        stats_placeholder = st.empty()
    
    # Main dashboard tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Network Events", "👤 User Behavior", "🔍 Threat Analysis", "📈 Metrics"])
    
    with tab1:
        st.header("Network Traffic Analysis")
        
        # Network metrics
        net_col1, net_col2, net_col3, net_col4 = st.columns(4)
        with net_col1:
            st.metric(
                "Network Events",
                st.session_state.event_counts['network'],
                delta="+5" if st.session_state.monitoring_active else None
            )
        with net_col2:
            st.metric(
                "Suspicious IPs",
                len([e for e in st.session_state.network_events if any(ip in str(e.get('source_ip', '')) for ip in ['185.', '45.'])]),
                delta=None
            )
        with net_col3:
            st.metric(
                "Data Volume (MB)",
                f"{sum(e.get('bytes_sent', 0) for e in st.session_state.network_events) / 1_000_000:.1f}",
                delta=None
            )
        with net_col4:
            st.metric(
                "Long Connections",
                len([e for e in st.session_state.network_events if e.get('duration', 0) > 3600]),
                delta=None
            )
        
        # Network charts
        network_col1, network_col2 = st.columns([2, 1])
        
        with network_col1:
            st.subheader("📊 Network Traffic Patterns")
            network_chart_placeholder = st.empty()
        
        with network_col2:
            st.subheader("🔗 IP Connection Map")
            ip_graph_placeholder = st.empty()
        
        # Network events table
        st.subheader("📋 Recent Network Events")
        network_table_placeholder = st.empty()
    
    with tab2:
        st.header("User & Entity Behavior Analytics")
        
        # Behavior metrics
        beh_col1, beh_col2, beh_col3, beh_col4 = st.columns(4)
        with beh_col1:
            st.metric(
                "User Events",
                st.session_state.event_counts['behavior'],
                delta="+3" if st.session_state.monitoring_active else None
            )
        with beh_col2:
            privilege_escalations = len([e for e in st.session_state.behavior_events if e.get('event_type') == 'privilege_escalation'])
            st.metric(
                "Privilege Escalations",
                privilege_escalations,
                delta="+1" if privilege_escalations > 0 else None
            )
        with beh_col3:
            unique_users = len(set(e.get('user_id', '') for e in st.session_state.behavior_events))
            st.metric(
                "Active Users",
                unique_users,
                delta=None
            )
        with beh_col4:
            sensitive_access = len([e for e in st.session_state.behavior_events if 'sensitive' in str(e.get('resource', '')).lower()])
            st.metric(
                "Sensitive Access",
                sensitive_access,
                delta="+1" if sensitive_access > 0 else None
            )
        
        # Behavior charts
        behavior_col1, behavior_col2 = st.columns(2)
        
        with behavior_col1:
            st.subheader("🗓️ Activity Heatmap")
            heatmap_placeholder = st.empty()
        
        with behavior_col2:
            st.subheader("📊 Event Type Distribution")
            event_dist_placeholder = st.empty()
        
        # Behavior events table
        st.subheader("📋 Recent User Activities")
        behavior_table_placeholder = st.empty()
    
    with tab3:
        st.header("Threat Detection & Analysis")
        
        # Threat gauge and metrics
        threat_col1, threat_col2 = st.columns([1, 2])
        
        with threat_col1:
            st.subheader("⚠️ Current Threat Level")
            gauge_placeholder = st.empty()
        
        with threat_col2:
            st.subheader("🎯 Active Threats")
            threats_placeholder = st.empty()
        
        # Recent detections
        st.subheader("🔍 Recent Security Detections")
        detections_placeholder = st.empty()
    
    with tab4:
        st.header("System Performance Metrics")
        
        # Performance metrics placeholders
        perf_col1, perf_col2, perf_col3, perf_col4 = st.columns(4)
        
        # Initialize metrics with default values
        with perf_col1:
            total_events_metric = st.empty()
            total_events_metric.metric("Total Events", "0", delta=None)
        with perf_col2:
            anomalies_metric = st.empty()
            anomalies_metric.metric("Anomalies", "0", delta=None)
        with perf_col3:
            fp_metric = st.empty()
            fp_metric.metric("FP Reduced", "0", delta=None)
        with perf_col4:
            accuracy_metric = st.empty()
            accuracy_metric.metric("Accuracy", "0%", delta=None)
        
        # Recommendations
        st.subheader("💡 AI-Generated Recommendations")
        recommendations_placeholder = st.empty()
        
        # Initialize empty recommendations list
        if 'latest_recommendations' not in st.session_state:
            st.session_state.latest_recommendations = []
    
    # Main update function
    async def update_dashboard():
        processor = st.session_state.processor
        generator = st.session_state.generator
        
        # Generate mixed events (network and behavior)
        if monitoring_mode == "Normal Operations":
            network_events = [generator.generate_normal_network_event() for _ in range(5)]
            behavior_events = [generator.generate_normal_behavior_event() for _ in range(5)]
            suspicious_events = generator.generate_event_stream(10, anomaly_rate)
            events = network_events + behavior_events + suspicious_events
        elif monitoring_mode == "Enhanced Detection":
            events = generator.generate_event_stream(30, anomaly_rate * 1.5)
        else:  # Attack Simulation
            normal = generator.generate_event_stream(10, 0.05)
            critical = [generator.generate_critical_threat_event() for _ in range(3)]
            events = normal + critical
        
        # Track events by type
        for event in events:
            processor.add_event(event)
            if event['type'] == 'network':
                st.session_state.network_events.append(event)
                st.session_state.event_counts['network'] += 1
            else:
                st.session_state.behavior_events.append(event)
                st.session_state.event_counts['behavior'] += 1
        
        # Process batch
        await processor.process_batch(events)
        stats = processor.get_stats()
        
        # Update network visualizations
        if st.session_state.network_events:
            network_chart = create_network_traffic_chart(list(st.session_state.network_events)[-20:])
            if network_chart:
                network_chart_placeholder.plotly_chart(network_chart, use_container_width=True)
            
            ip_graph = create_ip_network_graph(list(st.session_state.network_events)[-10:])
            if ip_graph:
                ip_graph_placeholder.plotly_chart(ip_graph, use_container_width=True)
            
            # Network events table with host names
            network_df = pd.DataFrame(list(st.session_state.network_events)[-5:])
            if not network_df.empty:
                # Parse timestamps for display
                if isinstance(network_df['timestamp'].iloc[0], str):
                    network_df['timestamp'] = pd.to_datetime(network_df['timestamp']).dt.strftime('%H:%M:%S')
                
                # Select columns with fallback for older events
                display_cols = []
                for col in ['timestamp', 'source_host', 'source_ip', 'destination_host', 'destination_ip', 'service', 'bytes_sent', 'protocol']:
                    if col in network_df.columns:
                        display_cols.append(col)
                    elif col == 'source_host' and 'source_ip' in network_df.columns:
                        network_df['source_host'] = network_df['source_ip']
                        display_cols.append('source_host')
                    elif col == 'destination_host' and 'destination_ip' in network_df.columns:
                        network_df['destination_host'] = network_df['destination_ip']
                        display_cols.append('destination_host')
                    elif col == 'service' and 'protocol' in network_df.columns:
                        network_df['service'] = 'UNKNOWN'
                        display_cols.append('service')
                
                if display_cols:
                    network_df = network_df[display_cols]
                    network_table_placeholder.dataframe(network_df, use_container_width=True, hide_index=True)
        
        # Update behavior visualizations
        if st.session_state.behavior_events:
            heatmap = create_behavior_heatmap(list(st.session_state.behavior_events))
            if heatmap:
                heatmap_placeholder.plotly_chart(heatmap, use_container_width=True)
            
            # Event type distribution
            event_types = defaultdict(int)
            for e in st.session_state.behavior_events:
                event_types[e.get('event_type', 'unknown')] += 1
            
            if event_types:
                pie_fig = go.Figure(data=[go.Pie(
                    labels=list(event_types.keys()),
                    values=list(event_types.values()),
                    hole=0.3
                )])
                pie_fig.update_layout(height=300)
                event_dist_placeholder.plotly_chart(pie_fig, use_container_width=True)
            
            # Behavior events table with user details
            behavior_df = pd.DataFrame(list(st.session_state.behavior_events)[-5:])
            if not behavior_df.empty:
                # Parse timestamps for display
                if isinstance(behavior_df['timestamp'].iloc[0], str):
                    behavior_df['timestamp'] = pd.to_datetime(behavior_df['timestamp']).dt.strftime('%H:%M:%S')
                
                # Select columns with user details
                available_cols = behavior_df.columns.tolist()
                desired_cols = ['timestamp', 'user_name', 'user_id', 'user_role', 'department', 'event_type', 'action', 'resource', 'location']
                display_cols = []
                
                for col in desired_cols:
                    if col in available_cols:
                        display_cols.append(col)
                    elif col == 'user_name' and 'user_id' in available_cols:
                        # Fallback for older events without user_name
                        behavior_df['user_name'] = behavior_df['user_id']
                        display_cols.append('user_name')
                
                if display_cols:
                    behavior_df = behavior_df[display_cols]
                    behavior_table_placeholder.dataframe(behavior_df, use_container_width=True, hide_index=True)
        
        # Update threat analysis
        if stats['recent_detections']:
            # Update threat level
            threat_levels = [d.threat_level.value for d in stats['recent_detections'][-10:]]
            if 'critical' in threat_levels:
                st.session_state.threat_level = 'critical'
            elif 'high' in threat_levels:
                st.session_state.threat_level = 'high'
            elif 'medium' in threat_levels:
                st.session_state.threat_level = 'medium'
            else:
                st.session_state.threat_level = 'low'
            
            # Threat gauge
            threat_fig = create_threat_gauge(st.session_state.threat_level)
            gauge_placeholder.plotly_chart(threat_fig, use_container_width=True)
            
            # Active threats - preserve in session state
            if 'active_threats' not in st.session_state:
                st.session_state.active_threats = []
            
            # Add new critical threats
            critical_threats = [d for d in stats['recent_detections'][-10:] 
                              if d.threat_level.value in ['high', 'critical']]
            
            for threat in critical_threats:
                # Check if this threat is already tracked (by description and time)
                threat_key = f"{threat.description}_{threat.timestamp.strftime('%H:%M:%S')}"
                existing_keys = [t.get('key', '') for t in st.session_state.active_threats]
                
                if threat_key not in existing_keys:
                    st.session_state.active_threats.append({
                        'key': threat_key,
                        'Level': threat.threat_level.value.upper(),
                        'Type': threat.event_type.value,
                        'Description': threat.description[:50] + '...',
                        'Confidence': f"{threat.confidence_score:.1%}",
                        'Time': threat.timestamp.strftime('%H:%M:%S')
                    })
            
            # Keep only the most recent 10 active threats
            st.session_state.active_threats = st.session_state.active_threats[-10:]
            
            # Display active threats
            if st.session_state.active_threats:
                threats_display = [{
                    '⏰ Time': t['Time'],
                    '⚠️ Level': t['Level'],
                    '🔍 Type': t['Type'],
                    '📝 Description': t['Description'],
                    '📊 Confidence': t['Confidence']
                } for t in st.session_state.active_threats]
                threats_df = pd.DataFrame(threats_display)
                threats_placeholder.dataframe(threats_df, use_container_width=True, hide_index=True)
            
            # Recent detections table
            detections_data = []
            for d in stats['recent_detections'][-5:]:
                detections_data.append({
                    '⏰ Time': d.timestamp.strftime('%H:%M:%S'),
                    '🔍 Type': d.event_type.value,
                    '⚠️ Level': d.threat_level.value.upper(),
                    '📊 Confidence': f"{d.confidence_score:.1%}",
                    '📝 Description': d.description[:40] + '...'
                })
            if detections_data:
                det_df = pd.DataFrame(detections_data)
                detections_placeholder.dataframe(det_df, use_container_width=True, hide_index=True)
            
            # Recommendations - accumulate in session state for persistence
            latest = stats['recent_detections'][-1]
            
            # Check if we have prioritized recommendations stored on the detection object
            if hasattr(latest, 'prioritized_recommendations') and latest.prioritized_recommendations:
                # Use the prioritized format
                if 'latest_recommendations' not in st.session_state:
                    st.session_state.latest_recommendations = []
                
                for priority, action in latest.prioritized_recommendations:
                    # Check if this action already exists (compare just the text)
                    existing_actions = [a[1] if isinstance(a, tuple) else a for a in st.session_state.latest_recommendations]
                    if action not in existing_actions:
                        st.session_state.latest_recommendations.append((priority, action))
                
                # Sort by priority and keep most recent 15 recommendations
                st.session_state.latest_recommendations = sorted(
                    st.session_state.latest_recommendations[-15:],
                    key=lambda x: x[0] if isinstance(x, tuple) else 3
                )
            elif latest.recommended_actions:
                # Fallback to string format for backward compatibility
                if 'latest_recommendations' not in st.session_state:
                    st.session_state.latest_recommendations = []
                
                for action in latest.recommended_actions:
                    # Assign priority based on content
                    if '🚨' in action or 'IMMEDIATE' in action:
                        priority = 1
                    elif '⚠️' in action or 'HIGH' in action:
                        priority = 2
                    else:
                        priority = 3
                    
                    # Check if this action already exists
                    existing_actions = [a[1] if isinstance(a, tuple) else a for a in st.session_state.latest_recommendations]
                    if action not in existing_actions:
                        st.session_state.latest_recommendations.append((priority, action))
                
                # Sort by priority and keep most recent 15 recommendations
                st.session_state.latest_recommendations = sorted(
                    st.session_state.latest_recommendations[-15:],
                    key=lambda x: x[0] if isinstance(x, tuple) else 3
                )
        
        # Display recommendations (either new or from session state)
        if st.session_state.get('latest_recommendations') and len(st.session_state.latest_recommendations) > 0:
            # Filter out generic recommendations that don't have specific context
            filtered_recs = []
            for item in st.session_state.latest_recommendations:
                if isinstance(item, tuple):
                    priority, action = item
                else:
                    action = item
                    priority = 3
                
                # Only keep recommendations with specific user/network/system information
                has_context = ('(' in action and ')' in action) or \
                            any(name in action for name in ['Ram Katakam', 'Pavan Katakam', 'Kittu Katakam', 
                                                            'Jyothi Katakam', 'Mani Katakam', 'Venkat Bezawada', 
                                                            'Ramakrishna Katakam']) or \
                            any(term in action for term in ['prod-web', 'prod-db', 'dev-server', 'analytics', 
                                                            'backup-server', 'monitoring'])
                
                # Always keep critical actions even without specific context
                is_critical = '🚨' in action or 'IMMEDIATE' in action or priority == 1
                
                if has_context or is_critical:
                    filtered_recs.append((priority, action) if isinstance(item, tuple) else (priority, action))
            
            if filtered_recs:
                # Group recommendations by priority
                priority_groups = {1: [], 2: [], 3: [], 4: [], 5: []}
                
                for priority, action in filtered_recs:
                    priority_groups[priority].append(action)
                
                rec_content = ""
                
                # Priority 1: Critical/Immediate - RED background
                if priority_groups[1]:
                    rec_content += '<div style="background-color: #ffebee; padding: 10px; border-radius: 5px; margin-bottom: 10px; border-left: 4px solid #d32f2f;">\n\n'
                    rec_content += "### 🔴 **Priority 1: CRITICAL** - Immediate Action Required\n"
                    for rec in priority_groups[1]:
                        rec_content += f"- **{rec}**\n"
                    rec_content += '\n</div>\n\n'
                
                # Priority 2: High - ORANGE background
                if priority_groups[2]:
                    rec_content += '<div style="background-color: #fff3e0; padding: 10px; border-radius: 5px; margin-bottom: 10px; border-left: 4px solid #f57c00;">\n\n'
                    rec_content += "### 🟠 **Priority 2: HIGH** - Urgent Response Needed\n"
                    for rec in priority_groups[2]:
                        rec_content += f"- {rec}\n"
                    rec_content += '\n</div>\n\n'
                
                # Priority 3: Medium - YELLOW background
                if priority_groups[3]:
                    rec_content += '<div style="background-color: #fffde7; padding: 10px; border-radius: 5px; margin-bottom: 10px; border-left: 4px solid #fbc02d;">\n\n'
                    rec_content += "### 🟡 **Priority 3: MEDIUM** - Investigate Soon\n"
                    for rec in priority_groups[3]:
                        rec_content += f"- {rec}\n"
                    rec_content += '\n</div>\n\n'
                
                # Priority 4: Low - BLUE background
                if priority_groups[4]:
                    rec_content += '<div style="background-color: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 10px; border-left: 4px solid #1976d2;">\n\n'
                    rec_content += "### 🔵 **Priority 4: LOW** - Monitor\n"
                    for rec in priority_groups[4]:
                        rec_content += f"- {rec}\n"
                    rec_content += '\n</div>\n\n'
                
                # Priority 5: Informational - GRAY background
                if priority_groups[5]:
                    rec_content += '<div style="background-color: #f5f5f5; padding: 10px; border-radius: 5px; margin-bottom: 10px; border-left: 4px solid #616161;">\n\n'
                    rec_content += "### ⚪ **Priority 5: INFO** - Best Practices\n"
                    for rec in priority_groups[5]:
                        rec_content += f"- {rec}\n"
                    rec_content += '\n</div>\n\n'
                
                recommendations_placeholder.markdown(rec_content, unsafe_allow_html=True)
            else:
                # No context-specific recommendations available
                recommendations_placeholder.info(
                    "### ℹ️ No Active Recommendations\n"
                    "System is operating normally. Use the attack simulation buttons to test threat detection."
                )
            
        else:
            # Show informational message when no specific threats detected
            recommendations_placeholder.info(
                "### ℹ️ System Status: Normal\n"
                "No active threats detected. Use the attack simulation buttons in the sidebar to test the threat detection system:\n"
                "- **🌐 Network Attack** - Simulate network-based threats\n"
                "- **👤 UEBA Threat** - Simulate user behavior anomalies\n"
                "- **🔴 TRIGGER BOTH** - Simulate combined critical attack"
            )
        
        # Update performance metrics
        total_events_metric.metric("Total Events", f"{stats['events_processed']:,}", delta=f"+{len(events)}")
        anomalies_metric.metric("Anomalies", f"{stats['anomalies_detected']:,}")
        fp_metric.metric("FP Reduced", f"{stats['false_positives_reduced']:,}")
        
        if stats['events_processed'] > 0:
            accuracy = (1 - stats['false_positives_reduced'] / max(stats['events_processed'], 1)) * 100
            accuracy_metric.metric("Accuracy", f"{accuracy:.1f}%")
        
        # Update sidebar stats
        with st.sidebar:
            stats_placeholder.markdown(f"""
            **System Performance:**
            - Processing: {stats['processing_time_avg']*1000:.1f}ms
            - Buffer: {stats['buffer_size']} events
            - Detections: {len(stats['recent_detections'])}
            - Network Events: {st.session_state.event_counts['network']}
            - Behavior Events: {st.session_state.event_counts['behavior']}
            - **Threat: {st.session_state.threat_level.upper()}**
            """)
    
    # Main execution - ensure everything stays within tabs
    if st.session_state.get('monitoring_active', False):
        # Check for network attack trigger
        if st.session_state.get('trigger_network_attack', False):
            event_count = asyncio.run(simulate_network_attack())
            st.session_state.trigger_network_attack = False
            st.session_state.show_success = True
            st.session_state.success_message = f"🌐 Generated {event_count} network attack events!"
            
            # Add network-specific recommendations
            if 'latest_recommendations' not in st.session_state:
                st.session_state.latest_recommendations = []
            
            network_recommendations = [
                "🌐 NETWORK THREAT DETECTED: Block all suspicious external IPs immediately",
                "🔍 Analyze network traffic patterns for data exfiltration",
                "🛡️ Enable DDoS protection and rate limiting",
                "📊 Check firewall logs for port scanning attempts",
                "🚨 Monitor bandwidth usage for unusual spikes"
            ]
            
            for rec in network_recommendations:
                if rec not in st.session_state.latest_recommendations:
                    st.session_state.latest_recommendations.append(rec)
        
        # Check for UEBA attack trigger
        elif st.session_state.get('trigger_ueba_attack', False):
            event_count = asyncio.run(simulate_ueba_attack())
            st.session_state.trigger_ueba_attack = False
            st.session_state.show_success = True
            st.session_state.success_message = f"👤 Generated {event_count} UEBA threat events!"
            
            # Add UEBA-specific recommendations
            if 'latest_recommendations' not in st.session_state:
                st.session_state.latest_recommendations = []
            
            ueba_recommendations = [
                "👤 USER THREAT DETECTED: Review all user access permissions immediately",
                "🔐 Force password reset for all suspicious accounts",
                "📍 Verify physical locations of all login attempts",
                "🔑 Audit privilege escalation attempts in last 48 hours",
                "⏰ Check for after-hours access patterns"
            ]
            
            for rec in ueba_recommendations:
                if rec not in st.session_state.latest_recommendations:
                    st.session_state.latest_recommendations.append(rec)
        
        # Check if we need to trigger both attacks (critical)
        elif st.session_state.get('trigger_attack', False):
            event_count = asyncio.run(simulate_critical_attack())
            st.session_state.trigger_attack = False
            st.session_state.show_success = True
            st.session_state.success_message = f"✅ Generated {event_count} critical events!"
            
            # Force critical recommendations immediately
            if 'latest_recommendations' not in st.session_state:
                st.session_state.latest_recommendations = []
            
            # Extract actual user and network info from recent events
            compromised_users = set()
            suspicious_ips = set()
            affected_systems = set()
            
            # Get user info from behavior events
            for event in list(st.session_state.behavior_events)[-10:]:
                if event.get('event_type') in ['privilege_escalation', 'file_access']:
                    user_name = event.get('user_name', event.get('user_id', 'Unknown'))
                    user_role = event.get('user_role', '')
                    if user_role:
                        compromised_users.add(f"{user_name} ({user_role})")
                    else:
                        compromised_users.add(user_name)
                    
                    entity = event.get('entity_id', '')
                    if entity:
                        affected_systems.add(entity)
            
            # Get network info from network events  
            for event in list(st.session_state.network_events)[-10:]:
                source_host = event.get('source_host', event.get('source_ip', ''))
                dest_host = event.get('destination_host', event.get('destination_ip', ''))
                
                # Check for suspicious IPs
                if any(ip in str(source_host) for ip in ['TOR', 'C2', 'SUSPICIOUS', 'SCANNER', 'MINER']):
                    suspicious_ips.add(f"{source_host} ({event.get('source_ip', '')})")
                if any(ip in str(dest_host) for ip in ['TOR', 'C2', 'SUSPICIOUS', 'SCANNER', 'MINER']):
                    suspicious_ips.add(f"{dest_host} ({event.get('destination_ip', '')})")
                    
                # Check for affected systems
                if event.get('bytes_sent', 0) > 50000000:  # Large data transfer
                    affected_systems.add(source_host if source_host else event.get('source_ip', ''))
            
            # Build context-aware recommendations with proper priorities
            critical_recommendations = [
                (1, f"🚨 IMMEDIATE ACTION: Isolate affected systems ({', '.join(list(affected_systems)[:3]) if affected_systems else 'Check logs'})"),
                (1, "📞 Contact security team and management immediately")
            ]
            
            if compromised_users:
                users_list = ', '.join(list(compromised_users)[:3])
                critical_recommendations.append((1, f"🔒 Disable compromised accounts: {users_list}"))
            
            if suspicious_ips:
                ips_list = ', '.join(list(suspicious_ips)[:3])
                critical_recommendations.append((2, f"🌐 Block suspicious IPs: {ips_list}"))
            
            critical_recommendations.extend([
                (3, "📊 Analyze network traffic for ongoing data exfiltration"),
                (2, "🔑 Review all privilege escalations in last 24 hours"),
                (3, "📝 Document all findings for incident report")
            ])
            
            for priority, rec in critical_recommendations:
                # Check if this action already exists (compare just the text)
                existing_actions = [a[1] if isinstance(a, tuple) else a for a in st.session_state.latest_recommendations]
                if rec not in existing_actions:
                    st.session_state.latest_recommendations.append((priority, rec))
        
        # Run the regular update
        asyncio.run(update_dashboard())
        
        # Auto-refresh after delay
        time.sleep(1.5)
        st.rerun()
    else:
        # Show initial state info only in first tab
        with tab1:
            st.info("⏸️ Monitoring paused. Click 'Start' to begin real-time monitoring.")
        
        # Show threat gauge even when paused
        with tab3:
            threat_fig = create_threat_gauge(st.session_state.threat_level)
            gauge_placeholder.plotly_chart(threat_fig, use_container_width=True)

if __name__ == "__main__":
    main()