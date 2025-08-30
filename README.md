# Agentic AI Security Monitoring System

A real-time anomaly detection system for network and User Entity Behavior Analytics (UEBA) data with confidence scoring and false positive reduction.

## Features

- **Real-time Processing**: Processes network and user behavior events in real-time
- **Multi-layered Anomaly Detection**: Uses statistical analysis and machine learning
- **Confidence Scoring**: Provides confidence levels for each detection
- **False Positive Reduction**: Intelligent correlation and filtering to reduce noise
- **Threat Classification**: Categorizes threats as LOW, MEDIUM, HIGH, or CRITICAL
- **Attack Pattern Recognition**: Detects common attack patterns like data exfiltration and brute force

## Architecture

```
├── src/
│   ├── models/           # Data models for events and detections
│   ├── agents/           # Anomaly detection agent
│   ├── pipeline/         # Real-time processing pipeline
│   └── utils/            # Data generation utilities
├── main.py              # CLI interface
├── dashboard.py         # Streamlit dashboard
└── requirements.txt     # Python dependencies
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

```bash
python main.py
```

Select from:
1. Demo Mode - Run predefined scenarios
2. Continuous Monitoring - Ongoing real-time monitoring
3. Exit

### Web Dashboard

```bash
streamlit run dashboard.py
```

Opens a web interface at http://localhost:8501 with:
- Real-time metrics
- Threat level gauge
- Detection timeline
- Recent anomalies table
- Recommended actions

## How It Works

### Anomaly Detection

The system uses multiple techniques:

1. **Statistical Analysis**: Maintains baselines and calculates z-scores
2. **Pattern Matching**: Identifies known attack patterns
3. **Behavioral Analysis**: Tracks user behavior deviations
4. **Network Analysis**: Monitors unusual network patterns

### Confidence Scoring

Each detection includes:
- **Anomaly Score**: 0-1 scale of how anomalous the event is
- **Confidence Score**: System's confidence in the detection
- **False Positive Probability**: Estimated chance of false positive

### False Positive Reduction

- **Event Correlation**: Groups related events within time windows
- **Threshold Adjustment**: Dynamic thresholds based on context
- **Historical Analysis**: Learns from past detections

## Example Scenarios

### Data Exfiltration
- Detects privilege escalation followed by large data transfers
- Identifies connections to suspicious IPs
- Monitors sensitive file access patterns

### Brute Force Attacks
- Identifies multiple failed login attempts
- Tracks rapid authentication attempts
- Monitors unusual login times and locations

## Key Components

### NetworkEvent
- Source/destination IPs and ports
- Protocol, bytes transferred, duration
- Packet counts and flags

### UserBehaviorEvent
- User and entity IDs
- Event types (login, file access, etc.)
- Actions, resources, locations
- Session tracking

### AnomalyDetection
- Threat level classification
- Confidence and anomaly scores
- Affected entities and indicators
- Recommended response actions