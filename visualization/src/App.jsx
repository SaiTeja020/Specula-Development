import { useState, useEffect, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  MarkerType,
  Handle,
  Position,
} from 'reactflow';
import 'reactflow/dist/style.css';

// Logical stage mapping for top-to-bottom pipeline architecture
const NODE_CONFIGS = {
  // Stage 0: Entry
  '__start__': { rank: 0, pos: 0, category: 'entry', label: 'Start' },
  'supervisor': { rank: 1, pos: 0, category: 'entry', label: 'Supervisor' },

  // Stage 1: Primary Tier
  'evidence_collection': { rank: 2, pos: -1.3, category: 'primary', label: 'Evidence Collection' },
  'log_analysis': { rank: 2, pos: 0, category: 'primary', label: 'Log Analysis' },
  'network_forensics': { rank: 2, pos: 1.3, category: 'primary', label: 'Network Forensics' },
  'primary_tier_join': { rank: 3, pos: 0, category: 'control', label: 'Primary Tier Join' },

  // Stage 2: Specialist Tier
  'memory_forensics': { rank: 4, pos: -1.8, category: 'specialist', label: 'Memory Forensics' },
  'identity_cloud': { rank: 4, pos: -0.6, category: 'specialist', label: 'Identity & Cloud' },
  'malware_stylometry': { rank: 4, pos: 0.6, category: 'specialist', label: 'Malware Stylometry' },
  'insider_threat': { rank: 4, pos: 1.8, category: 'specialist', label: 'Insider Threat' },
  'specialist_join': { rank: 5, pos: 0, category: 'control', label: 'Specialist Join' },

  // Stage 3: Synthesis
  'timeline_reconstruction': { rank: 6, pos: -0.8, category: 'synthesis', label: 'Timeline Reconstruction' },
  'threat_attribution': { rank: 6, pos: 0.8, category: 'synthesis', label: 'Threat Attribution' },

  // Stage 4: Debate Subgraph Loop
  'proponent': { rank: 7, pos: -1, category: 'debate', label: 'Proponent' },
  'critic': { rank: 7, pos: 0, category: 'debate', label: 'Critic' },
  'judge': { rank: 7, pos: 1, category: 'debate', label: 'Judge' },

  // Stage 5: Guardrails & HITL
  'guardrail_tier1': { rank: 8, pos: -1.5, category: 'guardrail', label: 'Guardrail Tier 1 (Regex)' },
  'guardrail_tier2': { rank: 8, pos: -0.5, category: 'guardrail', label: 'Guardrail Tier 2 (Vector)' },
  'guardrail_tier3': { rank: 8, pos: 0.5, category: 'guardrail', label: 'Guardrail Tier 3 (LLM)' },
  'hitl': { rank: 8, pos: 1.8, category: 'hitl', label: 'HITL Analyst Review' },

  // Stage 6: Output & Terminal
  'report_generation': { rank: 9, pos: -1, category: 'output', label: 'Report Generation' },
  'timeline_artifact_generation': { rank: 9, pos: 0, category: 'output', label: 'Timeline Artifacts' },
  'case_closed_rejected': { rank: 9, pos: 1.5, category: 'terminal', label: 'Case Rejected' },

  // Stage 7: End Join
  'final_output_join': { rank: 10, pos: -0.5, category: 'control', label: 'Final Output Join' },
  '__end__': { rank: 11, pos: 0, category: 'terminal', label: 'End' }
};

const CATEGORY_STYLES = {
  entry: { bg: '#1e293b', border: '#3b82f6', text: '#93c5fd' },
  primary: { bg: '#064e3b', border: '#10b981', text: '#a7f3d0' },
  specialist: { bg: '#4c1d95', border: '#8b5cf6', text: '#ddd6fe' },
  synthesis: { bg: '#78350f', border: '#f59e0b', text: '#fde68a' },
  debate: { bg: '#701a75', border: '#d946ef', text: '#f5d0fe' },
  guardrail: { bg: '#831843', border: '#ec4899', text: '#fbcfe8' },
  hitl: { bg: '#7f1d1d', border: '#ef4444', text: '#fca5a5' },
  output: { bg: '#14532d', border: '#22c55e', text: '#bbf7d0' },
  control: { bg: '#334155', border: '#64748b', text: '#cbd5e1' },
  terminal: { bg: '#0f172a', border: '#475569', text: '#94a3b8' }
};

// Custom React Flow Node Component
function SpeculaNode({ data }) {
  const { label, category, status } = data;
  const baseStyle = CATEGORY_STYLES[category] || CATEGORY_STYLES.control;

  let bg = baseStyle.bg;
  let border = baseStyle.border;
  let text = baseStyle.text;
  let boxShadow = '0 4px 12px rgba(0,0,0,0.4)';
  let transform = 'scale(1)';

  if (status === 'active') {
    bg = '#2563eb';
    border = '#60a5fa';
    text = '#ffffff';
    boxShadow = '0 0 24px #3b82f6';
    transform = 'scale(1.08)';
  } else if (status === 'completed') {
    bg = '#059669';
    border = '#34d399';
    text = '#ffffff';
    boxShadow = '0 0 12px rgba(16, 185, 129, 0.4)';
  }

  return (
    <div style={{
      background: bg,
      color: text,
      border: `2px solid ${border}`,
      borderRadius: '8px',
      padding: '10px 16px',
      fontWeight: 600,
      fontSize: '13px',
      minWidth: '160px',
      textAlign: 'center',
      boxShadow,
      transform,
      transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)'
    }}>
      <Handle type="target" position={Position.Top} style={{ background: border }} />
      <div>{label}</div>
      <Handle type="source" position={Position.Bottom} style={{ background: border }} />
    </div>
  );
}

const nodeTypes = { specula: SpeculaNode };

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [caseStatus, setCaseStatus] = useState('Idle');
  const [logs, setLogs] = useState([]);

  // Fetch initial topology and calculate positions once
  useEffect(() => {
    fetch('http://localhost:8300/api/graph/topology')
      .then(res => res.json())
      .then(data => {
        const layoutedNodes = data.nodes.map(node => {
          const config = NODE_CONFIGS[node.id] || { rank: 5, pos: 0, category: 'control', label: node.id };
          
          return {
            id: node.id,
            type: 'specula',
            position: {
              x: 550 + config.pos * 220,
              y: 80 + config.rank * 115
            },
            data: {
              label: config.label,
              category: config.category,
              status: 'idle'
            }
          };
        });

        const styledEdges = data.edges.map(edge => ({
          ...edge,
          type: 'smoothstep',
          animated: false,
          style: { stroke: '#475569', strokeWidth: 1.5 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#475569',
          },
        }));

        setNodes(layoutedNodes);
        setEdges(styledEdges);
      })
      .catch(err => console.error("Failed to fetch topology:", err));
  }, [setNodes, setEdges]);

  // Connect to WebSocket for live streaming
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8300/api/graph/stream');

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const { type, payload } = data;

      if (type === 'node_active') {
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Active Node: ${payload.node} (${payload.data?.status || ''})`]);

        // Update node status inside data without touching position at all
        setNodes(nds => nds.map(n => {
          if (n.id === payload.node) {
            return {
              ...n,
              data: { ...n.data, status: 'active' }
            };
          }
          return n;
        }));

        // Animate incoming edge
        setEdges(eds => eds.map(e => {
          if (e.target === payload.node) {
            return { ...e, animated: true, style: { stroke: '#60a5fa', strokeWidth: 2.5 } };
          }
          return e;
        }));

      } else if (type === 'node_complete') {
        // Mark node status as completed
        setNodes(nds => nds.map(n => {
          if (n.id === payload.node) {
            return {
              ...n,
              data: { ...n.data, status: 'completed' }
            };
          }
          return n;
        }));

      } else if (type === 'run_complete') {
        setCaseStatus(`Completed (Case ${payload.case_id})`);
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Run Completed: Case ${payload.case_id}`]);
      }
    };

    return () => ws.close();
  }, [setNodes, setEdges]);

  const runMock = () => {
    setCaseStatus('Monitoring Live Execution...');
    setLogs([]);

    // Reset all node statuses to idle without touching positions
    setNodes(nds => nds.map(n => ({
      ...n,
      data: { ...n.data, status: 'idle' }
    })));

    setEdges(eds => eds.map(e => ({ ...e, animated: false, style: { stroke: '#475569', strokeWidth: 1.5 } })));

    fetch('http://localhost:8300/api/graph/run_mock', { method: 'POST' });
  };

  return (
    <div className="app-container">
      <header className="header glass-panel">
        <div className="header-title">
          <h1>Specula Architecture Monitor</h1>
          <span className={`status-badge ${caseStatus.includes('Monitoring') ? 'pulse' : ''}`}>{caseStatus}</span>
        </div>
        <button className="primary-btn" onClick={runMock}>Trigger Execution Trace</button>
      </header>

      <main className="main-content">
        <div className="graph-container glass-panel">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
            attributionPosition="bottom-right"
          >
            <Background color="#1e293b" gap={24} size={1} />
            <Controls />
          </ReactFlow>
        </div>

        <aside className="sidebar glass-panel">
          <h2>Execution Log</h2>
          <div className="logs-container">
            {logs.map((log, i) => (
              <div key={i} className="log-entry">{log}</div>
            ))}
            {logs.length === 0 && <div className="log-empty">Click "Trigger Execution Trace" to monitor real-time graph flow.</div>}
          </div>
        </aside>
      </main>
    </div>
  );
}
