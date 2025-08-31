# 🌳 Branch Structure

## Current Branches

### `main` branch
- **Purpose**: Future implementation with established agent frameworks (LangChain, AutoGen, CrewAI, etc.)
- **Status**: Ready for agent framework integration
- **Next Steps**: Implement using popular agentic frameworks

### `no_agent` branch
- **Purpose**: Custom agent implementation from scratch (current working system)
- **Status**: ✅ Complete and functional
- **Features**:
  - Custom-built agent architecture without external frameworks
  - Pure Python implementation with scikit-learn for ML
  - Isolation Forest anomaly detection
  - Welford's algorithm for continuous learning
  - Real-time event processing with asyncio
  - Streamlit dashboard with priority-based recommendations

## How to Switch Branches

```bash
# To use the custom implementation (no frameworks)
git checkout no_agent

# To work on framework-based implementation
git checkout main
```

## Comparison

| Feature | `no_agent` branch | `main` branch (future) |
|---------|-------------------|------------------------|
| Implementation | Custom from scratch | Using frameworks |
| Dependencies | Minimal (sklearn, streamlit) | Will include LangChain/AutoGen/etc |
| LLM Integration | None | Planned |
| Learning Method | Statistical + ML | Statistical + ML + LLM |
| Agent Coordination | Basic | Advanced multi-agent |
| Maintenance | Manual | Framework-supported |

## Recommended Usage

- **Use `no_agent` branch if you want**:
  - Lightweight deployment
  - Full control over agent behavior
  - Minimal dependencies
  - Educational understanding of agent concepts

- **Use `main` branch (when ready) if you want**:
  - LLM-powered intelligence
  - Pre-built agent tools and plugins
  - Advanced multi-agent coordination
  - Framework ecosystem benefits

## Current Implementation Status

### `no_agent` branch ✅
- Fully functional security monitoring system
- Real-time anomaly detection
- Continuous learning capabilities
- Production-ready dashboard

### `main` branch 🚧
- Awaiting framework integration
- Will maintain same functionality with enhanced capabilities
- Planned frameworks: LangChain, AutoGen, CrewAI