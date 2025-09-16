# Technology Mapping - Frida Script Runner

## High-Level Architecture Overview

```mermaid
graph TB
    subgraph "User Interface Layer"
        UI[Web Interface - Flask]
        BT[Claude Bridge Tester]
    end
    
    subgraph "AI Integration Layer"
        CB[Claude Bridge HTTP Server]
        CC[Claude CLI]
        MCP[MCP Client Protocol]
    end
    
    subgraph "Binary Analysis Layer"
        GH[Ghidra MCP Server]
        JX[JADX MCP Server]
    end
    
    subgraph "Frida Runtime Layer"
        FR[Frida Core]
        FS[Frida Scripts]
        FJS[Generated JS Scripts]
    end
    
    subgraph "Target Devices"
        AD[Android Device - Rooted]
        IOS[iOS Device - Jailbroken]
    end
    
    UI --> CB
    BT --> CB
    CB --> CC
    CC --> MCP
    MCP --> GH
    MCP --> JX
    UI --> FR
    FR --> FS
    CB --> FJS
    FR --> AD
    FR --> IOS
```

## Detailed Component Technology Stack

### Frontend Technologies
```
┌─────────────────────────────────────┐
│           Frontend Stack           │
├─────────────────────────────────────┤
│ • HTML5 + CSS3 + JavaScript        │
│ • Bootstrap 4.x (UI Framework)     │
│ • Socket.IO (Real-time Updates)    │
│ • Fetch API (HTTP Requests)        │
│ • WebSocket (Live Output Stream)   │
└─────────────────────────────────────┘
```

### Backend Technologies
```
┌─────────────────────────────────────┐
│           Backend Stack            │
├─────────────────────────────────────┤
│ • Python 3.11.x                   │
│ • Flask (Web Framework)           │
│ • Flask-SocketIO (WebSocket)      │
│ • Subprocess (CLI Integration)    │
│ • Threading (Async Operations)    │
│ • Requests (HTTP Client)          │
│ • Tempfile (Temporary Storage)    │
└─────────────────────────────────────┘
```

### AI & Analysis Technologies
```
┌─────────────────────────────────────┐
│        AI Integration Stack        │
├─────────────────────────────────────┤
│ • Claude CLI (Anthropic)          │
│ • MCP Protocol (Model Context)    │
│ • Ghidra (Binary Analysis)        │
│ • JADX (Android Decompiler)       │
│ • HTTP Bridge Server              │
│ • JSON-RPC Communication          │
└─────────────────────────────────────┘
```

### Mobile & Instrumentation
```
┌─────────────────────────────────────┐
│    Mobile Instrumentation Stack   │
├─────────────────────────────────────┤
│ • Frida 16.x+ (Instrumentation)   │
│ • ADB (Android Debug Bridge)      │
│ • ideviceinfo (iOS Tools)         │
│ • USB/TCP Communication           │
│ • ARM64/x86 Architecture Support  │
└─────────────────────────────────────┘
```

## Data Flow Architecture

```mermaid
sequenceDiagram
    participant U as User
    participant UI as Web Interface
    participant CB as Claude Bridge
    participant CC as Claude CLI
    participant MCP as MCP Servers
    participant F as Frida Runtime
    participant D as Device

    U->>UI: Submit Script Request
    UI->>CB: POST /generate-script
    CB->>CC: --file prompt.md --prompt "Generate..."
    CC->>MCP: Request binary analysis
    MCP-->>CC: Return function data
    CC-->>CB: Generated JavaScript
    CB-->>UI: Frida script response
    UI->>F: Execute script on device
    F->>D: Inject & run script
    D-->>F: Runtime output
    F-->>UI: Real-time results
    UI-->>U: Display output
```

## Technology Integration Map

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTEGRATION ECOSYSTEM                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Docker    │    │   Native    │    │   Hybrid    │         │
│  │             │    │             │    │             │         │
│  │ Container   │◄──►│ Host Setup  │◄──►│ Bridge Mode │         │
│  │ • Flask App │    │ • Claude CLI│    │ • Best of   │         │
│  │ • Frida     │    │ • MCP Srv   │    │   Both      │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                      COMMUNICATION LAYERS                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HTTP/REST ◄──► WebSocket ◄──► JSON-RPC ◄──► Binary Protocol    │
│     │              │             │              │               │
│     v              v             v              v               │
│  Web API      Live Updates   MCP Comms    Frida Runtime        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## File System Technology Layout

```
Frida-Script-Runner/
├── 🐍 Python Backend Core
│   ├── frida_script.py          # Main Flask application
│   ├── claude-bridge.py         # AI integration bridge
│   └── requirements.txt         # Python dependencies
│
├── 🌐 Web Frontend
│   ├── templates/               # HTML templates
│   ├── static/                  # CSS, JS, images
│   └── js/                      # Frontend JavaScript
│
├── 🤖 AI Integration
│   ├── claude-bridge.py         # HTTP bridge server
│   ├── MCP configurations       # Binary analysis setup
│   └── prompt templates         # AI prompt engineering
│
├── 📱 Mobile Scripts
│   ├── scripts/android/         # Android Frida scripts
│   ├── scripts/ios/             # iOS Frida scripts
│   └── script.json              # Script metadata
│
├── 🐳 Containerization
│   ├── Dockerfile               # Container definition
│   ├── docker-compose.yml       # Multi-service setup
│   └── .dockerignore           # Container exclusions
│
└── 📚 Documentation
    ├── README.md               # Main documentation
    ├── TECH_MAPPING.md         # This file
    └── DOCKER.md              # Container setup guide
```

## Port & Service Mapping

```
┌─────────────────────────────────────────────────────────────────┐
│                        SERVICE PORTS                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │    5000     │  │    8090     │  │    8080     │  │  8650   │ │
│  │             │  │             │  │             │  │         │ │
│  │ Flask App   │  │ Claude      │  │ Ghidra      │  │ JADX    │ │
│  │ Main UI     │  │ Bridge      │  │ MCP Server  │  │ MCP     │ │
│  │             │  │ Tester      │  │             │  │ Server  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                     DEVICE CONNECTIONS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  USB/ADB Connection     │  TCP/IP Connection    │ Frida Protocol │
│  • Android Devices     │  • Network Devices    │ • Port 27042   │
│  • Root Required       │  • Remote Testing     │ • TCP/USB      │
│  • Developer Mode      │  • WiFi Debugging     │ • JSON-RPC     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Security & Permission Model

```mermaid
graph LR
    subgraph "Host Security"
        HS[Host System]
        CC[Claude CLI Auth]
        MCP[MCP Server Access]
    end
    
    subgraph "Container Security"
        CS[Container Isolation]
        VB[Volume Binding]
        NB[Network Bridge]
    end
    
    subgraph "Device Security"
        ROOT[Root/Jailbreak]
        FS[Frida Server]
        APP[Target Apps]
    end
    
    HS --> CS
    CC --> VB
    MCP --> NB
    CS --> ROOT
    VB --> FS
    NB --> APP
```

## Technology Dependencies Matrix

| Component | Primary Tech | Dependencies | Optional Enhancements |
|-----------|-------------|--------------|----------------------|
| **Web Interface** | Flask + Python 3.11 | Socket.IO, Bootstrap | Real-time updates |
| **AI Integration** | Claude CLI | MCP Protocol | Ghidra, JADX servers |
| **Mobile Runtime** | Frida 16.x+ | ADB, ideviceinfo | Root/Jailbreak access |
| **Containerization** | Docker Compose | Host bridge | Volume mounting |
| **Binary Analysis** | Ghidra/JADX | MCP servers | Function analysis |

## Performance & Scalability

```
┌─────────────────────────────────────────────────────────────────┐
│                    PERFORMANCE METRICS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Component          │ Latency    │ Throughput  │ Concurrency    │
│  ──────────────────────────────────────────────────────────────  │
│  Flask Web UI       │ <100ms     │ 50 req/s    │ Multi-user     │
│  Claude Bridge      │ 1-300s     │ 1 req/min   │ Sequential     │
│  Frida Runtime      │ <50ms      │ Real-time   │ Multi-device   │
│  MCP Analysis       │ 5-30s      │ On-demand   │ Cached results │
│  Device Connection  │ 100-500ms  │ Persistent  │ USB/Network    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Future Technology Roadmap

```mermaid
gantt
    title Technology Evolution Roadmap
    dateFormat  YYYY-MM-DD
    section Current
    Core Functionality     :done, core, 2024-01-01, 2024-03-01
    AI Integration        :done, ai, 2024-03-01, 2024-06-01
    Docker Support        :done, docker, 2024-06-01, 2024-09-01
    
    section Near Future
    Enhanced MCP          :active, mcp, 2024-09-01, 2024-12-01
    Mobile CI/CD          :mobile, 2024-12-01, 2025-03-01
    
    section Long Term
    Cloud Integration     :cloud, 2025-03-01, 2025-06-01
    ML Model Training     :ml, 2025-06-01, 2025-09-01
```

## Integration Patterns

### 1. **Synchronous Pattern** (Traditional)
```
User Request → Flask → Frida → Device → Response
```

### 2. **Asynchronous Pattern** (AI-Enhanced)
```
User Request → Claude Bridge → MCP Analysis → Script Generation → Execution
```

### 3. **Hybrid Pattern** (Current Implementation)
```
User Input → AI Processing → Script Enhancement → Real-time Execution → Live Output
```

---

**This technology mapping provides a comprehensive view of the Frida Script Runner's technical architecture, integrations, and future evolution path.**