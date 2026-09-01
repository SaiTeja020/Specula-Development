import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
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
import LandingPage from './LandingPage';

// ═══════════════════════════════════════════════════════════
// GRAPH TOPOLOGY CONFIG
// ═══════════════════════════════════════════════════════════

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

const API_BASE = 'http://localhost:8300';

// ═══════════════════════════════════════════════════════════
// REACT FLOW NODE
// ═══════════════════════════════════════════════════════════

function SpeculaNode({ data }) {
  const { label, category, status } = data;
  const base = CATEGORY_STYLES[category] || CATEGORY_STYLES.control;
  let bg = base.bg, border = base.border, text = base.text;
  let boxShadow = '0 4px 12px rgba(0,0,0,0.4)', transform = 'scale(1)';

  if (status === 'active') {
    bg = '#2563eb'; border = '#60a5fa'; text = '#ffffff';
    boxShadow = '0 0 24px #3b82f6'; transform = 'scale(1.08)';
  } else if (status === 'completed') {
    bg = '#059669'; border = '#34d399'; text = '#ffffff';
    boxShadow = '0 0 12px rgba(16,185,129,0.4)';
  }

  return (
    <div style={{ background: bg, color: text, border: `2px solid ${border}`, borderRadius: '8px', padding: '10px 16px', fontWeight: 600, fontSize: '13px', minWidth: '160px', textAlign: 'center', boxShadow, transform, transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)' }}>
      <Handle type="target" position={Position.Top} style={{ background: border }} />
      <div>{label}</div>
      <Handle type="source" position={Position.Bottom} style={{ background: border }} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// TAB DEFINITIONS
// ═══════════════════════════════════════════════════════════

const TABS = [
  { id: 'graph', label: 'Agent Graph', icon: '🔗' },
  { id: 'logs',  label: 'Forensic Logs', icon: '📋' },
  { id: 'neo4j', label: 'Knowledge Graph', icon: '🕸️' },
];

// ═══════════════════════════════════════════════════════════
// QUICKWIT LOG PANEL
// ═══════════════════════════════════════════════════════════

function QuickwitPanel() {
  const [query, setQuery] = useState('*');
  const [hits, setHits] = useState([]);
  const [numHits, setNumHits] = useState(0);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const timerRef = useRef(null);

  const doSearch = useCallback(async (q) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/logs/search?q=${encodeURIComponent(q)}&max_hits=50`);
      const data = await res.json();
      if (data.error) {
        setError(data.error);
        setHits([]);
        setNumHits(0);
      } else {
        setHits(data.hits || []);
        setNumHits(data.num_hits || 0);
      }
    } catch (e) {
      setError('Visualizer API not reachable (is it running on port 8300?)');
      setHits([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => { doSearch(query); }, []);

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      timerRef.current = setInterval(() => doSearch(query), 5000);
    }
    return () => clearInterval(timerRef.current);
  }, [autoRefresh, query, doSearch]);

  const handleSubmit = (e) => {
    e.preventDefault();
    doSearch(query);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px' }}>
      {/* Search bar */}
      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Lucene query (e.g. source_type:evtx, uid:*, *)"
            style={{
              width: '100%', padding: '11px 16px', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.1)',
              background: 'rgba(255,255,255,0.04)', color: '#e2e8f0', fontSize: '13px',
              fontFamily: "'JetBrains Mono', monospace", outline: 'none',
              transition: 'border-color 0.2s',
            }}
            onFocus={e => e.target.style.borderColor = 'rgba(99,102,241,0.5)'}
            onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}
          />
        </div>
        <button type="submit" className="primary-btn" style={{ padding: '11px 20px', fontSize: '13px', whiteSpace: 'nowrap' }}>
          {loading ? '⏳ Searching...' : '🔍 Search'}
        </button>
        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#64748b', cursor: 'pointer', whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)}
            style={{ accentColor: '#6366f1' }}
          />
          Auto (5s)
        </label>
      </form>

      {/* Status bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px' }}>
        <span style={{ color: '#64748b' }}>
          {error ? (
            <span style={{ color: '#f87171' }}>⚠️ {error}</span>
          ) : (
            <span style={{ color: '#94a3b8' }}>
              <strong style={{ color: '#e2e8f0' }}>{numHits}</strong> hits found
              {autoRefresh && <span style={{ color: '#6366f1', marginLeft: '8px' }}>● Live</span>}
            </span>
          )}
        </span>
        <span style={{ marginLeft: 'auto', color: '#334155', fontSize: '11px' }}>
          Index: <code style={{ color: '#818cf8' }}>specula_raw_evidence</code>
        </span>
      </div>

      {/* Results table */}
      <div style={{ flex: 1, overflow: 'auto', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(15,23,42,0.5)' }}>
        {hits.length === 0 && !loading && !error && (
          <div style={{ padding: '48px', textAlign: 'center', color: '#475569' }}>
            <div style={{ fontSize: '36px', marginBottom: '12px' }}>📋</div>
            <p style={{ fontSize: '14px', marginBottom: '8px' }}>No logs found</p>
            <p style={{ fontSize: '12px', color: '#334155' }}>
              Start the ingestion pipeline to see forensic logs here, or search with <code>*</code>.
            </p>
          </div>
        )}
        {hits.length === 0 && !loading && error && (
          <div style={{ padding: '48px', textAlign: 'center', color: '#475569' }}>
            <div style={{ fontSize: '36px', marginBottom: '12px' }}>🔌</div>
            <p style={{ fontSize: '14px', marginBottom: '8px' }}>Cannot reach Quickwit</p>
            <p style={{ fontSize: '12px', color: '#334155' }}>
              Make sure <code>docker-compose up -d quickwit</code> is running and the Visualizer API is started.
            </p>
          </div>
        )}
        {hits.length > 0 && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', position: 'sticky', top: 0, background: '#0f172a', zIndex: 1 }}>
                {['uid', 'trace_id', 'sha256', 'source_type', 'committed_at_ms'].map(col => (
                  <th key={col} style={{ padding: '10px 14px', textAlign: 'left', color: '#818cf8', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '1px', fontSize: '10px' }}>
                    {col.replace('_', ' ')}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {hits.map((hit, i) => (
                <>
                  <tr
                    key={i}
                    onClick={() => setExpanded(expanded === i ? null : i)}
                    style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      cursor: 'pointer',
                      background: expanded === i ? 'rgba(99,102,241,0.06)' : 'transparent',
                      transition: 'background 0.15s',
                    }}
                    onMouseEnter={e => { if (expanded !== i) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                    onMouseLeave={e => { if (expanded !== i) e.currentTarget.style.background = 'transparent'; }}
                  >
                    <td style={{ padding: '9px 14px', color: '#94a3b8', fontFamily: "'JetBrains Mono', monospace", maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {hit.uid || '—'}
                    </td>
                    <td style={{ padding: '9px 14px', color: '#64748b', fontFamily: "'JetBrains Mono', monospace", maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {hit.trace_id || '—'}
                    </td>
                    <td style={{ padding: '9px 14px', color: '#64748b', fontFamily: "'JetBrains Mono', monospace", maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {hit.sha256 ? hit.sha256.slice(0, 16) + '…' : '—'}
                    </td>
                    <td style={{ padding: '9px 14px' }}>
                      {hit.source_type ? (
                        <span style={{ background: 'rgba(99,102,241,0.1)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.25)', borderRadius: '100px', padding: '2px 10px', fontSize: '11px', fontWeight: 600 }}>
                          {hit.source_type}
                        </span>
                      ) : '—'}
                    </td>
                    <td style={{ padding: '9px 14px', color: '#475569', fontSize: '11px' }}>
                      {hit.committed_at_ms ? new Date(hit.committed_at_ms).toLocaleString() : '—'}
                    </td>
                  </tr>
                  {expanded === i && (
                    <tr key={`exp-${i}`}>
                      <td colSpan={5} style={{ padding: '12px 14px', background: 'rgba(15,23,42,0.8)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                        <pre style={{ margin: 0, color: '#94a3b8', fontSize: '11px', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: '200px', overflow: 'auto' }}>
                          {JSON.stringify(hit, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// NEO4J PANEL
// ═══════════════════════════════════════════════════════════

function Neo4jPanel() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [iframeLoaded, setIframeLoaded] = useState(false);

  useEffect(() => {
    const fetchSummary = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/neo4j/summary`);
        const data = await res.json();
        setSummary(data);
      } catch {
        setSummary({ connected: false, error: 'Visualizer API not reachable' });
      } finally {
        setLoading(false);
      }
    };
    fetchSummary();
    const interval = setInterval(fetchSummary, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '12px' }}>
      {/* Stats overlay bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', padding: '12px 16px', borderRadius: '12px', background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(255,255,255,0.07)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: summary?.connected ? '#10b981' : '#f87171',
            boxShadow: summary?.connected ? '0 0 8px #10b981' : '0 0 8px #f87171',
          }} />
          <span style={{ fontSize: '12px', color: summary?.connected ? '#a7f3d0' : '#fca5a5', fontWeight: 600 }}>
            {loading ? 'Connecting...' : summary?.connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>

        {summary?.connected && (
          <>
            <div style={{ width: '1px', height: '16px', background: 'rgba(255,255,255,0.1)' }} />
            <StatBadge label="Nodes" value={summary.total_nodes} color="#6366f1" />
            <StatBadge label="Relationships" value={summary.total_relationships} color="#06b6d4" />
            {summary.node_labels && Object.keys(summary.node_labels).length > 0 && (
              <>
                <div style={{ width: '1px', height: '16px', background: 'rgba(255,255,255,0.1)' }} />
                <span style={{ fontSize: '11px', color: '#475569' }}>Labels:</span>
                {Object.entries(summary.node_labels).slice(0, 5).map(([label, count]) => (
                  <span key={label} style={{ fontSize: '11px', color: '#818cf8', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: '100px', padding: '2px 8px' }}>
                    {label} ({count})
                  </span>
                ))}
              </>
            )}
          </>
        )}

        <span style={{ marginLeft: 'auto', fontSize: '11px', color: '#334155' }}>
          bolt://localhost:7687
        </span>
      </div>

      {/* Neo4j Browser iframe */}
      <div style={{ flex: 1, borderRadius: '12px', border: '1px solid rgba(255,255,255,0.07)', overflow: 'hidden', position: 'relative', background: '#0f172a' }}>
        {!iframeLoaded && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '12px', zIndex: 2 }}>
            <div style={{ fontSize: '36px' }}>🕸️</div>
            <p style={{ color: '#94a3b8', fontSize: '13px' }}>Loading Neo4j Browser...</p>
            <p style={{ color: '#475569', fontSize: '11px' }}>Make sure <code>docker-compose up -d neo4j</code> is running</p>
          </div>
        )}
        <iframe
          src="http://localhost:7474/browser/"
          title="Neo4j Browser"
          onLoad={() => setIframeLoaded(true)}
          onError={() => setIframeLoaded(false)}
          style={{
            width: '100%', height: '100%', border: 'none',
            opacity: iframeLoaded ? 1 : 0,
            transition: 'opacity 0.4s ease',
          }}
        />
      </div>
    </div>
  );
}

function StatBadge({ label, value, color }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
      <span style={{ fontSize: '16px', fontWeight: 800, color, fontFamily: "'Sora', sans-serif" }}>{value ?? '—'}</span>
      <span style={{ fontSize: '11px', color: '#475569', fontWeight: 500 }}>{label}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// DASHBOARD — tabbed layout
// ═══════════════════════════════════════════════════════════

function Dashboard({ onBackToLanding }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [caseStatus, setCaseStatus] = useState('Idle');
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('graph');

  const nodeTypes = useMemo(() => ({ specula: SpeculaNode }), []);

  // Fetch initial topology
  useEffect(() => {
    fetch(`${API_BASE}/api/graph/topology`)
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
          ...edge, type: 'smoothstep', animated: false,
          style: { stroke: '#475569', strokeWidth: 1.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' },
        }));
        setNodes(layoutedNodes);
        setEdges(styledEdges);
      })
      .catch(err => console.error("Failed to fetch topology:", err));
  }, [setNodes, setEdges]);

  // WebSocket streaming
  useEffect(() => {
    const ws = new WebSocket(`ws://localhost:8300/api/graph/stream`);
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const { type, payload } = data;

      if (type === 'node_active') {
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Active: ${payload.node} (${payload.data?.status || ''})`]);
        setNodes(nds => nds.map(n => n.id === payload.node ? { ...n, data: { ...n.data, status: 'active' } } : n));
        setEdges(eds => eds.map(e => e.target === payload.node ? { ...e, animated: true, style: { stroke: '#60a5fa', strokeWidth: 2.5 } } : e));
      } else if (type === 'node_complete') {
        setNodes(nds => nds.map(n => n.id === payload.node ? { ...n, data: { ...n.data, status: 'completed' } } : n));
      } else if (type === 'run_complete') {
        setCaseStatus(`Completed (Case ${payload.case_id})`);
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ✅ Run Completed: Case ${payload.case_id}`]);
      }
    };
    return () => ws.close();
  }, [setNodes, setEdges]);

  const runMock = () => {
    setCaseStatus('Monitoring Live Execution...');
    setLogs([]);
    setNodes(nds => nds.map(n => ({ ...n, data: { ...n.data, status: 'idle' } })));
    setEdges(eds => eds.map(e => ({ ...e, animated: false, style: { stroke: '#475569', strokeWidth: 1.5 } })));
    fetch(`${API_BASE}/api/graph/run_mock`, { method: 'POST' });
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header style={{
        padding: '12px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: 'rgba(15,23,42,0.85)', backdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button
            onClick={onBackToLanding}
            style={{
              background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
              color: '#94a3b8', padding: '8px 14px', borderRadius: '8px', cursor: 'pointer',
              fontSize: '13px', fontWeight: 500, fontFamily: 'Inter, sans-serif',
              display: 'flex', alignItems: 'center', gap: '6px', transition: 'all 0.2s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.09)'; e.currentTarget.style.color = '#e2e8f0'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; e.currentTarget.style.color = '#94a3b8'; }}
          >
            ← Back
          </button>
          <h1 style={{ fontSize: '16px', fontWeight: 700, fontFamily: "'Sora', sans-serif", color: '#f1f5f9', margin: 0 }}>
            Specula Live Monitor
          </h1>
          <span className={`status-badge ${caseStatus.includes('Monitoring') ? 'pulse' : ''}`}>{caseStatus}</span>
        </div>
        <button className="primary-btn" onClick={runMock}>Trigger Execution Trace</button>
      </header>

      {/* Tab bar */}
      <div style={{
        display: 'flex', gap: '4px', padding: '10px 24px',
        background: 'rgba(10,15,30,0.6)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '8px 18px', borderRadius: '8px', border: 'none', cursor: 'pointer',
              fontSize: '13px', fontWeight: 600, fontFamily: "'Inter', sans-serif",
              display: 'flex', alignItems: 'center', gap: '7px',
              background: activeTab === tab.id ? 'rgba(99,102,241,0.15)' : 'transparent',
              color: activeTab === tab.id ? '#a5b4fc' : '#475569',
              borderBottom: activeTab === tab.id ? '2px solid #6366f1' : '2px solid transparent',
              transition: 'all 0.2s',
            }}
            onMouseEnter={e => { if (activeTab !== tab.id) e.currentTarget.style.color = '#94a3b8'; }}
            onMouseLeave={e => { if (activeTab !== tab.id) e.currentTarget.style.color = '#475569'; }}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <main style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {activeTab === 'graph' && (
          <>
            <div className="graph-container glass-panel">
              <ReactFlow
                nodes={nodes} edges={edges} nodeTypes={nodeTypes}
                onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                fitView attributionPosition="bottom-right"
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
          </>
        )}

        {activeTab === 'logs' && (
          <div style={{ flex: 1, padding: '20px 24px', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <QuickwitPanel />
          </div>
        )}

        {activeTab === 'neo4j' && (
          <div style={{ flex: 1, padding: '20px 24px', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <Neo4jPanel />
          </div>
        )}
      </main>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// ROOT — Landing ↔ Dashboard router
// ═══════════════════════════════════════════════════════════

export default function App() {
  const [showDashboard, setShowDashboard] = useState(false);

  if (showDashboard) {
    return <Dashboard onBackToLanding={() => setShowDashboard(false)} />;
  }

  return <LandingPage onEnterDashboard={() => setShowDashboard(true)} />;
}
