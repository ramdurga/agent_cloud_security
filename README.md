# AI Security Monitoring System - Three Versions

This project provides three different implementations of an AI-powered security monitoring system for network and UEBA (User Entity Behavior Analytics) data.

## Three Versions Available

### 1. No Agent Version (`dashboard_no_agent.py`)
- **Purpose**: Basic ML-based anomaly detection without any LLM/agent capabilities
- **Technologies**: Isolation Forest, Statistical Analysis, Z-scores
- **Models**: Pydantic data models
- **When to use**: When you don't have an API key or don't need LLM capabilities
- **Run**: `streamlit run dashboard_no_agent.py`

### 2. Simple Version (`dashboard_simple.py`)
- **Purpose**: Includes LangChain agent with simplified dataclass models
- **Technologies**: ML + LangChain + Claude LLM
- **Models**: Python dataclasses (no Pydantic dependencies)
- **When to use**: When you want LLM capabilities but prefer simpler, dependency-free models
- **Run**: `streamlit run dashboard_simple.py`

### 3. Pydantic Version (`dashboard_pydantic.py`)
- **Purpose**: Full-featured with Pydantic models and LangChain agent
- **Technologies**: ML + LangChain + Claude LLM + Pydantic validation
- **Models**: Pydantic v2 models with full validation
- **When to use**: When you want full type validation and all features
- **Run**: `streamlit run dashboard_pydantic.py`

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Key (Optional, for versions 2 & 3)
Create a `.env` file:
```bash
ANTHROPIC_API_KEY=your-api-key-here
```

### 3. Run Your Preferred Version

**No Agent (ML only):**
```bash
streamlit run dashboard_no_agent.py
```

**Simple (with LLM, dataclasses):**
```bash
streamlit run dashboard_simple.py
```

**Pydantic (with LLM, full validation):**
```bash
streamlit run dashboard_pydantic.py
```

## Features Comparison

| Feature | No Agent | Simple | Pydantic |
|---------|----------|--------|----------|
| ML Anomaly Detection | ✅ | ✅ | ✅ |
| Statistical Analysis | ✅ | ✅ | ✅ |
| Isolation Forest | ✅ | ✅ | ✅ |
| LLM Integration | ❌ | ✅ | ✅ |
| Threat Intelligence | ❌ | ✅ | ✅ |
| Enhanced Descriptions | ❌ | ✅ | ✅ |
| Data Validation | Basic | Basic | Full |
| Dependencies | Minimal | Medium | Full |
| Performance | Fastest | Fast | Good |

## Project Structure

```
Agentic_cloud_security/
├── dashboard_no_agent.py     # Basic ML version
├── dashboard_simple.py        # Dataclass + LLM version  
├── dashboard_pydantic.py      # Pydantic + LLM version
├── src/
│   ├── agents/
│   │   ├── anomaly_detector_pydantic.py    # ML detector with Pydantic
│   │   ├── anomaly_detector_simple.py      # ML detector with dataclasses
│   │   ├── langchain_agent_simple.py       # Simple LLM agent
│   │   └── langchain_agent_pydantic.py     # Pydantic LLM agent
│   ├── models/
│   │   ├── data_models.py                  # Pydantic models
│   │   └── data_models_simple.py           # Dataclass models
│   ├── pipeline/
│   │   ├── processor_no_agent.py           # Basic processor
│   │   ├── processor_simple.py             # Simple processor
│   │   └── processor_pydantic.py           # Pydantic processor
│   └── utils/
│       └── data_generator.py               # Event simulation
├── .env                      # API key configuration
└── requirements.txt          # Dependencies
```

## How to Use Each Dashboard

### Common Steps:
1. Click **"▶️ Start"** to begin monitoring
2. Use sidebar buttons to simulate attacks:
   - **"🌐 Network"** - DDoS attack simulation
   - **"👤 UEBA"** - Privilege escalation
   - **"💣 Critical"** - Data exfiltration

### Dashboard Tabs:
- **📊 Real-Time Monitoring** - Live threat feed
- **🔍 Threat Analysis** - Statistics and timeline
- **📈 Analytics** - System metrics
- **🤖 AI Recommendations** - Prioritized actions (Simple & Pydantic versions only)

## How It Works

### Anomaly Detection Techniques
- **Statistical Analysis**: Maintains baselines using Welford's algorithm and calculates z-scores
- **Machine Learning**: Uses Isolation Forest for outlier detection
- **Pattern Matching**: Identifies known attack patterns (DDoS, privilege escalation, data exfiltration)
- **Behavioral Analysis**: Tracks deviations in user behavior patterns
- **Network Analysis**: Monitors unusual network traffic patterns

### Confidence Scoring
- **Anomaly Score**: 0-1 scale indicating how anomalous the event is
- **Confidence Score**: System's confidence in the detection
- **False Positive Probability**: Estimated chance of false positive

### False Positive Reduction
- **Event Correlation**: Groups related events within 5-minute windows
- **Dynamic Thresholds**: Adjusts thresholds based on context and time
- **Historical Learning**: Uses exponential moving average (EMA) for continuous baseline updates

## Choosing the Right Version

### Use No Agent if you:
- Don't have an API key
- Want fastest performance
- Only need statistical anomaly detection
- Prefer minimal dependencies

### Use Simple if you:
- Have an API key
- Want LLM capabilities
- Prefer minimal dependencies
- Need simpler code maintenance
- Want to avoid Pydantic complexity

### Use Pydantic if you:
- Have an API key
- Want full data validation
- Need enterprise-grade type safety
- Want all advanced features
- Prefer strict data contracts

## Key Differences

### No Agent Version
```python
# Uses only ML-based detection
detection = anomaly_detector.process_event(event)
```

### Simple Version
```python
# Uses dataclasses and LLM enhancement
@dataclass
class NetworkEvent:
    timestamp: datetime
    source_ip: str
    # ... simple fields

# Enhanced with LLM
detection = langchain_agent.analyze_event(event)
```

### Pydantic Version
```python
# Uses Pydantic models with validation
class NetworkEvent(BaseModel):
    timestamp: datetime
    source_ip: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    # ... validated fields

# Full LLM integration with tools
detection = langchain_agent.analyze_with_tools(event)
```

## Example Detections

### Data Exfiltration
- Detects privilege escalation followed by large data transfers
- Identifies connections to C2 servers
- Monitors sensitive file access patterns

### DDoS Attacks
- Identifies high-volume traffic from TOR exit nodes
- Detects unusual packet patterns
- Monitors connection duration anomalies

### Privilege Escalation
- Tracks unusual privilege changes
- Monitors admin access patterns
- Identifies lateral movement attempts

## Notes

- All versions detect the same core threats
- LLM versions provide enhanced descriptions and recommendations
- Performance varies based on API latency for LLM versions
- The Simple version is recommended for most use cases
- All versions use custom names: Ram Katakam, Pavan Katakam, Kittu Katakam, etc.