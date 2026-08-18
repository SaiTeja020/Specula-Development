# Specula Architecture & Real-Time Flow Visualizer

A dedicated, lightweight frontend layer for monitoring and visualizing the **Specula Multi-Agent DFIR System** in real time.

---

## 🎯 What It Is

This visualizer provides a real-time, interactive graph representation of the **23-node LangGraph orchestration pipeline** used by Specula. It acts as an isolated visual monitoring dashboard that:
- Connects to the standalone FastAPI Visualizer backend (`src.agents.visualizer_api`) via WebSockets.
- Dynamically receives active node execution updates and live data passage logs.
- Displays agent nodes in a structured, top-to-bottom pipeline layout.

---

## 🛠️ Key Features & Components

### 1. Hierarchical 7-Stage Pipeline Layout
Nodes are organized into clear horizontal tiers based on their role in the digital forensics workflow:
- **Stage 0 (Blue)**: Entry & Supervisor (`Start`, `Supervisor`)
- **Stage 1 (Green)**: Primary Tier Fan-Out (`Evidence Collection`, `Log Analysis`, `Network Forensics`, `Primary Tier Join`)
- **Stage 2 (Purple)**: Specialist Tier (`Memory Forensics`, `Identity & Cloud`, `Malware Stylometry`, `Insider Threat`, `Specialist Join`)
- **Stage 3 (Amber)**: Synthesis (`Timeline Reconstruction`, `Threat Attribution`)
- **Stage 4 (Magenta)**: Debate Loop (`Proponent`, `Critic`, `Judge`)
- **Stage 5 (Pink/Red)**: Guardrail Chains (Tiers 1–3) & HITL Analyst Review (`Hitl`)
- **Stage 6 (Emerald)**: Output & Case Finalization (`Report Generation`, `Timeline Artifacts`, `Final Output Join`, `Case Closed Rejected`, `End`)

### 2. Real-Time WebSocket Streaming & Animations
- **Active Node Highlighting**: Glowing blue aura (`scale(1.08)`) when an agent node is actively processing.
- **Completion States**: Pulse green indicator upon task completion.
- **Animated Flow Edges**: Connectors animate dynamically to visualize real-time data passage.
- **Execution Log Sidebar**: Displays a live timestamped log feed of agent status updates and case progression.

### 3. Isolated Architecture
Located in `/visualization`, this layer is completely decoupled from core agent logic and can be modified, styled, or extended without impacting graph execution.

---

## 🚀 How to Run

### Prerequisites
- Node.js (v18+)
- Python 3.10+ with project virtual environment (`venv`)

---

### Step 1: Start the Visualizer Backend API
From the project root directory, run the standalone FastAPI microservice (runs on port **8300**):

```bash
# Windows PowerShell
.\venv\Scripts\python -m src.agents.visualizer_api
```

*(Or `python -m src.agents.visualizer_api` if using an activated virtual environment)*

---

### Step 2: Install Frontend Dependencies & Start UI
Navigate to the `visualization` directory and start the Vite development server:

```bash
cd visualization
npm install
npm run dev
```

---

### Step 3: Open Dashboard & Test Flow
1. Open `http://localhost:5173` in your browser.
2. Click **"Trigger Execution Trace"** in the top right header.
3. Watch the graph traverse through the 23 nodes in real-time with live updates in the execution sidebar!
