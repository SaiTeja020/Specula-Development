import { useState, useEffect, useRef } from 'react';
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
  '__start__': { rank: 0, pos: 0, category: 'entry', label: 'Start' },
  'supervisor': { rank: 1, pos: 0, category: 'entry', label: 'Supervisor' },
  'evidence_collection': { rank: 2, pos: -1.3, category: 'primary', label: 'Evidence Collection' },
  'log_analysis': { rank: 2, pos: 0, category: 'primary', label: 'Log Analysis' },
  'network_forensics': { rank: 2, pos: 1.3, category: 'primary', label: 'Network Forensics' },
  'primary_tier_join': { rank: 3, pos: 0, category: 'control', label: 'Primary Tier Join' },
  'memory_forensics': { rank: 4, pos: -1.8, category: 'specialist', label: 'Memory Forensics' },
  'identity_cloud': { rank: 4, pos: -0.6, category: 'specialist', label: 'Identity & Cloud' },
  'malware_stylometry': { rank: 4, pos: 0.6, category: 'specialist', label: 'Malware Stylometry' },
  'insider_threat': { rank: 4, pos: 1.8, category: 'specialist', label: 'Insider Threat' },
  'specialist_join': { rank: 5, pos: 0, category: 'control', label: 'Specialist Join' },
  'timeline_reconstruction': { rank: 6, pos: -0.8, category: 'synthesis', label: 'Timeline Reconstruction' },
  'threat_attribution': { rank: 6, pos: 0.8, category: 'synthesis', label: 'Threat Attribution' },
  'proponent': { rank: 7, pos: -1, category: 'debate', label: 'Proponent' },
  'critic': { rank: 7, pos: 0, category: 'debate', label: 'Critic' },
  'judge': { rank: 7, pos: 1, category: 'debate', label: 'Judge' },
  'guardrail_tier1': { rank: 8, pos: -1.5, category: 'guardrail', label: 'Guardrail Tier 1 (Regex)' },
  'guardrail_tier2': { rank: 8, pos: -0.5, category: 'guardrail', label: 'Guardrail Tier 2 (Vector)' },
  'guardrail_tier3': { rank: 8, pos: 0.5, category: 'guardrail', label: 'Guardrail Tier 3 (LLM)' },
  'hitl': { rank: 8, pos: 1.8, category: 'hitl', label: 'HITL Analyst Review' },
  'report_generation': { rank: 9, pos: -1, category: 'output', label: 'Report Generation' },
  'timeline_artifact_generation': { rank: 9, pos: 0, category: 'output', label: 'Timeline Artifacts' },
  'case_closed_rejected': { rank: 9, pos: 1.5, category: 'terminal', label: 'Case Rejected' },
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
    bg = '#0ea5e9';
    border = '#38bdf8';
    text = '#ffffff';
    boxShadow = '0 0 24px rgba(14,165,233,0.6)';
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

// --- PAGE 1: CONFIGURATION ---
function ConfigPage({ onStart }) {
  const [startDate, setStartDate] = useState('2026-08-25T00:00:00');
  const [endDate, setEndDate] = useState('2026-09-01T23:59:59');
  
  const handleSubmit = (e) => {
    e.preventDefault();
    onStart({ startDate, endDate });
  };

  return (
    <div className="config-container">
      <div className="config-card glass-panel">
        <div className="config-header">
          <h2>SPECULA // New Forensic Investigation Setup</h2>
          <p>Configure execution bounds and trigger data ingestion.</p>
        </div>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Case Identifier</label>
            <div className="form-row">
              <input className="input-field" type="text" defaultValue="CASE-2026-0901-A" readOnly />
              <input className="input-field" type="text" defaultValue="auto-generated-uuid" readOnly />
            </div>
          </div>

          <div className="form-group">
            <label>Time Range Filter (Date Band)</label>
            <div className="form-row">
              <input 
                className="input-field" 
                type="datetime-local" 
                value={startDate} 
                onChange={e => setStartDate(e.target.value)} 
                required 
              />
              <input 
                className="input-field" 
                type="datetime-local" 
                value={endDate} 
                onChange={e => setEndDate(e.target.value)} 
                required 
              />
            </div>
          </div>

          <div className="form-group">
            <label>Data Channels & Log Sources</label>
            <div className="checkbox-grid">
              <label className="checkbox-label"><input type="checkbox" defaultChecked /> Windows EVTX / Sysmon</label>
              <label className="checkbox-label"><input type="checkbox" defaultChecked /> Network PCAP / Zeek</label>
              <label className="checkbox-label"><input type="checkbox" defaultChecked /> NTFS Artifacts</label>
              <label className="checkbox-label"><input type="checkbox" defaultChecked /> Active Directory Logs</label>
              <label className="checkbox-label"><input type="checkbox" /> CloudTrail Telemetry</label>
              <label className="checkbox-label"><input type="checkbox" /> Memory Dump (.dmp)</label>
            </div>
          </div>

          <div className="form-group">
            <label>Execution Mode</label>
            <div className="radio-group">
              <label className="radio-label"><input type="radio" name="mode" defaultChecked /> Scrape Local System & Ingest</label>
              <label className="radio-label"><input type="radio" name="mode" /> Stream via Kafka Broker (:9092)</label>
            </div>
          </div>

          <div className="form-actions">
            <button type="submit" className="primary-btn">START FORENSIC PIPELINE</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// --- PAGE 2: LIVE CONSOLE ---
function LiveConsole({ caseId }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [caseStatus, setCaseStatus] = useState('RUNNING');
  const [logs, setLogs] = useState([]);
  const [activeStage, setActiveStage] = useState(0);
  const [hitlData, setHitlData] = useState(null);
  
  const logsEndRef = useRef(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Fetch initial topology
  useEffect(() => {
    fetch('http://localhost:8300/api/graph/topology')
      .then(res => res.json())
      .then(data => {
        const layoutedNodes = data.nodes.map(node => {
          const config = NODE_CONFIGS[node.id] || { rank: 5, pos: 0, category: 'control', label: node.id };
          return {
            id: node.id,
            type: 'specula',
            position: { x: 550 + config.pos * 220, y: 80 + config.rank * 115 },
            data: { label: config.label, category: config.category, status: 'idle' }
          };
        });

        const styledEdges = data.edges.map(edge => ({
          ...edge,
          type: 'smoothstep',
          animated: false,
          style: { stroke: 'rgba(56, 189, 248, 0.3)', strokeWidth: 1.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color: 'rgba(56, 189, 248, 0.3)' },
        }));

        setNodes(layoutedNodes);
        setEdges(styledEdges);
      })
      .catch(err => console.error("Failed to fetch topology:", err));
  }, [setNodes, setEdges]);

  // Connect to WebSocket
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8300/api/graph/stream');

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const { type, payload } = data;

      if (type === 'pipeline_started') {
         setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), msg: `[INGEST] Pipeline initialized for ${payload.case_id}` }]);
      } else if (type === 'node_active') {
        setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), msg: `[NODE] ${payload.node} active: ${payload.data?.status || 'Processing'}` }]);
        
        // Update stage tracker (mock logic for demo)
        if (payload.node.includes('supervisor')) setActiveStage(2);
        if (payload.node.includes('proponent')) setActiveStage(4);
        if (payload.node.includes('report')) setActiveStage(5);

        if (payload.node === 'hitl') {
          setHitlData({
            confidence: 0.65,
            blastRadius: '14 Hosts',
            tamperCheck: 'VCT VALID'
          });
        }

        setNodes(nds => nds.map(n => n.id === payload.node ? { ...n, data: { ...n.data, status: 'active' } } : n));
        setEdges(eds => eds.map(e => e.target === payload.node ? { ...e, animated: true, style: { stroke: '#0ea5e9', strokeWidth: 2.5 } } : e));

      } else if (type === 'node_complete') {
        setNodes(nds => nds.map(n => n.id === payload.node ? { ...n, data: { ...n.data, status: 'completed' } } : n));
        if (payload.node === 'hitl') setHitlData(null);

      } else if (type === 'run_complete') {
        setCaseStatus(`COMPLETED`);
        setActiveStage(6);
        setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), msg: `[SYSTEM] Run Completed: Case ${payload.case_id}` }]);
      }
    };

    return () => ws.close();
  }, [setNodes, setEdges]);

  const handleHitlAction = (action) => {
    setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), msg: `[HITL] Analyst Action: ${action.toUpperCase()}` }]);
    setHitlData(null);
    // In real app, would send action to backend
  };

  const stages = [
    { id: 0, label: 'Ingest & Hash' },
    { id: 1, label: 'Entropy Distill' },
    { id: 2, label: 'DFKG Write' },
    { id: 3, label: 'Supervisor' },
    { id: 4, label: 'ACH Debate' },
    { id: 5, label: 'Verification' }
  ];

  return (
    <div className="app-container">
      <header className="header glass-panel">
        <div className="header-title">
          <h1>CASE: {caseId}</h1>
          <span className={`status-badge`}>Status: {caseStatus}</span>
        </div>
        <button className="primary-btn" onClick={() => window.location.reload()}>New Investigation</button>
      </header>

      <div className="tracker-panel glass-panel">
        <div className="tracker-title">Pipeline Status Tracker</div>
        <div className="stepper">
          {stages.map((stage) => (
            <div key={stage.id} className={`step ${activeStage > stage.id ? 'completed' : activeStage === stage.id ? 'active' : ''}`}>
              <div className="step-icon">
                {activeStage > stage.id ? '✓' : activeStage === stage.id ? '↻' : (stage.id + 1)}
              </div>
              <div className="step-label">{stage.label}</div>
            </div>
          ))}
        </div>
      </div>

      <main className="main-content">
        <div className="left-panel">
          <div className="terminal-panel glass-panel">
            <div className="terminal-header">
              <span>Live Execution Telemetry</span>
              <span>Total Events: {logs.length}</span>
            </div>
            <div className="terminal-window">
              {logs.map((log, i) => (
                <div key={i} className="log-line">
                  <span className="log-time">[{log.time}]</span>
                  <span className="log-msg">{log.msg}</span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>
        
        <div className="right-panel">
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
              <Background color="#0f172a" gap={24} size={1} />
              <Controls />
            </ReactFlow>
            
            {hitlData && (
              <div className="hitl-modal glass-panel">
                <div className="hitl-header">
                  <span>⚠️ HITL Escalation Gate</span>
                </div>
                <div className="hitl-body">
                  <p><strong>Confidence:</strong> {hitlData.confidence}</p>
                  <p><strong>Blast Radius:</strong> {hitlData.blastRadius}</p>
                  <p><strong>Tamper Check:</strong> {hitlData.tamperCheck}</p>
                </div>
                <div className="hitl-actions">
                  <button className="hitl-btn btn-approve" onClick={() => handleHitlAction('approve')}>APPROVE REPORT</button>
                  <button className="hitl-btn btn-reject" onClick={() => handleHitlAction('reject')}>REJECT / HALT</button>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

// --- MAIN APP COMPONENT ---
export default function App() {
  const [page, setPage] = useState('config'); // 'config' or 'live'
  const [caseId] = useState('CASE-2026-0901-A');

  const startPipeline = async (config) => {
    // Switch page immediately
    setPage('live');
    
    // Trigger backend
    try {
      await fetch('http://localhost:8300/api/trigger_pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId, ...config })
      });
    } catch (e) {
      console.error("Failed to trigger pipeline", e);
    }
  };

  if (page === 'config') {
    return <ConfigPage onStart={startPipeline} />;
  }

  return <LiveConsole caseId={caseId} />;
}
