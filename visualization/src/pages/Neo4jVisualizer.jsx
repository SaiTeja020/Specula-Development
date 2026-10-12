import { useState, useEffect, useMemo } from 'react';
import { apiFetch } from '../lib/api';
import { localFetch } from '../lib/localApi';
import { usePipeline } from '../contexts/PipelineContext';
import ReactFlow, { Background, Controls, Handle } from 'reactflow';
import 'reactflow/dist/style.css';
import * as d3 from 'd3-force';

const NODE_COLORS = {
  Case: '#5E6AD2',
  Event: '#8AA8CB',
  DetectionFinding: '#F87171',
  Entity: '#FBBF24',
  AgentRun: '#4ADE80',
  Report: '#A78BFA',
  Process: '#47BFFF',
  User: '#4ADE80',
  File: '#FBBF24',
  NetworkConnection: '#F87171',
  Host: '#A78BFA',
  Default: '#94A3B8'
};

const Neo4jNode = ({ data }) => {
  const [isHovered, setIsHovered] = useState(false);
  const color = NODE_COLORS[data.neo4jLabel] || NODE_COLORS.Default;
  
  return (
    <div 
      style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 80, position: 'relative' }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <Handle type="target" position="top" style={{ opacity: 0 }} />
      <div style={{
        width: 48, height: 48, borderRadius: '50%', backgroundColor: color,
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        border: '2px solid rgba(255,255,255,0.2)',
        boxShadow: isHovered ? `0 0 20px ${color}` : '0 4px 12px rgba(0,0,0,0.5)',
        color: '#fff', fontSize: '12px', fontWeight: 'bold',
        transition: 'all 0.2s ease-in-out',
        transform: isHovered ? 'scale(1.1)' : 'scale(1)'
      }}>
        {data.neo4jLabel.substring(0, 3).toUpperCase()}
      </div>
      <div style={{ marginTop: 6, fontSize: 10, color: '#e2e8f0', textAlign: 'center', wordBreak: 'break-word', lineHeight: 1.2 }}>
        {data.displayProp}
      </div>
      <Handle type="source" position="bottom" style={{ opacity: 0 }} />
    </div>
  );
};

const Legend = ({ nodes }) => (
  <div style={{
    position: 'absolute', bottom: 20, right: 20, zIndex: 10,
    background: 'rgba(15, 23, 42, 0.8)', padding: '1rem',
    borderRadius: '8px', border: '1px solid var(--sp-border-thin)',
    backdropFilter: 'blur(8px)',
    display: 'flex', flexDirection: 'column', gap: '0.5rem'
  }}>
    <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '0.9rem', color: 'white' }}>Node Types</h3>
    {[...new Set(nodes.map(node => node.data.neo4jLabel))].sort().map(label => (
      <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <div style={{ width: 12, height: 12, borderRadius: '50%', backgroundColor: NODE_COLORS[label] || NODE_COLORS.Default }} />
        <span style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>{label}</span>
      </div>
    ))}
    {nodes.length > 0 && <span style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>Dashed link = case tag only</span>}
  </div>
);

const GraphStats = ({ nodes, edges, totals, isPanelOpen }) => {
  const shownCounts = nodes.reduce((acc, n) => {
    acc[n.data.neo4jLabel] = (acc[n.data.neo4jLabel] || 0) + 1;
    return acc;
  }, {});

  const edgeCounts = edges.reduce((acc, e) => {
    acc[e.data?.relationshipType] = (acc[e.data?.relationshipType] || 0) + 1;
    return acc;
  }, {});

  return (
    <div style={{
      position: 'absolute', top: 20, right: isPanelOpen ? 420 : 20, zIndex: 10,
      background: 'rgba(15, 23, 42, 0.8)', padding: '1rem',
      borderRadius: '8px', border: '1px solid var(--sp-border-thin)',
      backdropFilter: 'blur(8px)',
      display: 'flex', flexDirection: 'column', gap: '1rem',
      color: '#e2e8f0', minWidth: '180px',
      transition: 'right 0.3s ease'
    }}>
      <div>
        <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '0.85rem', color: 'white', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Case Node Counts</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          {Object.entries(totals).filter(([, count]) => count > 0).map(([type, count]) => (
            <div key={type} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
              <span style={{ color: NODE_COLORS[type] || NODE_COLORS.Default }}>{type}</span>
              <span style={{ fontWeight: 'bold' }}>{shownCounts[type] || 0} / {count}</span>
            </div>
          ))}
          {nodes.length === 0 && <div style={{ fontSize: '0.8rem', opacity: 0.5 }}>No nodes</div>}
        </div>
      </div>
      <div>
        <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '0.85rem', color: 'white', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Relationships</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          {Object.entries(edgeCounts).filter(([type]) => type !== 'CASE_TAG').map(([type, count]) => (
            <div key={type} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
              <span style={{ opacity: 0.8 }}>{type}</span>
              <span style={{ fontWeight: 'bold' }}>{count}</span>
            </div>
          ))}
          {edges.length === 0 && <div style={{ fontSize: '0.8rem', opacity: 0.5 }}>No relationships</div>}
        </div>
      </div>
    </div>
  );
};

const runForceLayout = (nodes, edges) => {
  const nodeById = new Map(nodes.map(node => [node.id, node]));
  const simNodes = nodes.map(n => ({ ...n, x: Math.random() * 800, y: Math.random() * 600 }));
  const simEdges = edges.map(e => ({ ...e, source: e.source, target: e.target }));

  const simulation = d3.forceSimulation(simNodes)
    .force('charge', d3.forceManyBody().strength(-1000))
    .force('center', d3.forceCenter(400, 300))
    .force('collide', d3.forceCollide().radius(60))
    .force('link', d3.forceLink(simEdges).id(d => d.id).distance(120))
    .stop();

  // Run synchronously to calculate positions
  const iterations = nodes.length > 600 ? 40 : nodes.length > 200 ? 80 : 200;
  for (let i = 0; i < iterations; ++i) simulation.tick();

  return simNodes.map(n => {
    const orig = nodeById.get(n.id);
    return {
      ...orig,
      position: { x: n.x - 40, y: n.y - 40 } // Offset for the node dimensions
    };
  });
};

export default function Neo4jVisualizer() {
  const { caseId: activeCaseId } = usePipeline();
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [totals, setTotals] = useState({});
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [tooltip, setTooltip] = useState({ show: false, x: 0, y: 0, data: null });
  const [selectedNode, setSelectedNode] = useState(null);

  const nodeTypes = useMemo(() => ({ neo4j: Neo4jNode }), []);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        let response;
        try {
          response = await localFetch(`/api/local/data/neo4j${selectedCase ? `?case_id=${encodeURIComponent(selectedCase)}` : ''}`);
        } catch {
          response = await apiFetch(`http://localhost:8300/api/data/neo4j${selectedCase ? `?case_id=${encodeURIComponent(selectedCase)}` : ''}`);
        }
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `Graph returned HTTP ${response.status}`);
        if (data.status !== 'success') throw new Error(data.message || 'Graph store unavailable');
        if (cancelled) return;
        if (data.status === 'success') {
          setCases(data.cases || []);
          setTotals(data.totals || {});
          if (!selectedCase && data.case_id) setSelectedCase(data.cases?.includes(activeCaseId) ? activeCaseId : data.case_id);
          const rfNodes = data.nodes.map((n) => {
            const displayProp = n.label === 'AgentRun' ? `${n.properties.sequence + 1}. ${n.properties.agent_role}`
              : n.label === 'Report' ? `Report: ${n.properties.status}`
                : n.properties.process_name || n.properties.finding_info || n.properties.host_name || n.properties.uid || n.properties.name || n.label;
            return {
              id: n.id,
              type: 'neo4j',
              position: { x: 0, y: 0 },
              data: { neo4jLabel: n.label, displayProp, properties: n.properties }
            };
          });

          const rfEdges = data.edges.map(e => ({
            id: e.id,
            source: e.source,
            target: e.target,
            data: { relationshipType: e.type },
            label: e.type === 'HAS_EVENT' || e.type === 'HAS_AGENT_RUN' || e.derived ? undefined : e.type,
            style: { stroke: e.derived ? '#94A3B8' : 'var(--sp-color-accent-indigo)',
              strokeWidth: 1.5, opacity: e.derived ? 0.35 : 0.65,
              strokeDasharray: e.derived ? '4 5' : undefined },
            animated: false
          }));

          const layoutedNodes = runForceLayout(rfNodes, rfEdges);

          setNodes(layoutedNodes);
          setEdges(rfEdges);
        }
      } catch (error) {
        if (!cancelled) setLoadError(error.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [selectedCase, activeCaseId]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1rem' }}>
      <div className="header glass-panel" style={{ padding: '1rem 1.5rem', margin: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <img src="/Specula_logo.png" alt="Specula Logo" style={{ height: '24px' }} />
          <h1 style={{ fontSize: '1.25rem', margin: 0 }}>Knowledge Graph (Neo4j)</h1>
          <label style={{ marginLeft: 'auto', fontSize: '0.85rem' }}>Case{' '}
            <select value={selectedCase} onChange={e => { setLoading(true); setSelectedCase(e.target.value); }}>
              {!selectedCase && <option value="">Latest available case</option>}
              {cases.map(id => <option key={id} value={id}>{id}</option>)}
            </select>
          </label>
        </div>
        <p style={{ marginBottom: 0, fontSize: '0.8rem' }}>Showing up to 300 nodes per type. Counts show displayed / total case nodes; dashed links are derived from case tags.</p>
      </div>
      <div className="graph-container glass-panel" style={{ flex: 1, padding: 0, position: 'relative' }}>
        {loadError && <p role="alert" style={{ padding: '1rem', color: 'var(--sp-color-status-breach)' }}>{loadError}</p>}
        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--sp-color-text-secondary)' }}>Loading graph data...</div>
        ) : (
          <>
            <ReactFlow 
              nodes={nodes} 
              edges={edges} 
              nodeTypes={nodeTypes} 
              fitView 
              minZoom={0.1}
              onNodeMouseEnter={(e, node) => setTooltip({ show: true, x: e.clientX, y: e.clientY, data: node.data })}
              onNodeMouseMove={(e) => setTooltip(t => ({ ...t, x: e.clientX, y: e.clientY }))}
              onNodeMouseLeave={() => setTooltip({ show: false, x: 0, y: 0, data: null })}
              onNodeDoubleClick={(e, node) => setSelectedNode(node)}
              onPaneClick={() => setSelectedNode(null)}
            >
              <Background color="var(--sp-color-border-grid)" />
              <Controls />
            </ReactFlow>
            <Legend nodes={nodes} />
            <GraphStats nodes={nodes} edges={edges} totals={totals} isPanelOpen={!!selectedNode} />
            {tooltip.show && tooltip.data && tooltip.data.properties && (
              <div style={{
                position: 'fixed',
                top: tooltip.y - 10,
                left: tooltip.x + 15,
                background: 'rgba(15, 23, 42, 0.95)',
                border: '1px solid var(--sp-color-accent-indigo)',
                padding: '12px',
                borderRadius: '8px',
                color: '#e2e8f0',
                fontSize: '11px',
                width: 'max-content',
                maxWidth: '400px',
                zIndex: 999999,
                boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)',
                pointerEvents: 'none',
                backdropFilter: 'blur(4px)',
                textAlign: 'left'
              }}>
                <div style={{ fontWeight: 'bold', marginBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '6px', color: NODE_COLORS[tooltip.data.neo4jLabel] || NODE_COLORS.Default, fontSize: '13px' }}>
                  {tooltip.data.neo4jLabel}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {Object.entries(tooltip.data.properties).map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', gap: '12px' }}>
                      <span style={{ opacity: 0.6, minWidth: '60px' }}>{k}:</span>
                      <span style={{ wordBreak: 'break-word', flex: 1, fontFamily: 'var(--sp-font-mono)' }}>
                        {typeof v === 'object' ? JSON.stringify(v) : (String(v).length > 200 ? String(v).substring(0, 200) + '...' : String(v))}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Side Panel for Selected Node */}
            {selectedNode && selectedNode.data && (
              <div style={{
                position: 'absolute',
                top: 0,
                right: 0,
                bottom: 0,
                width: '400px',
                background: 'rgba(15, 23, 42, 0.98)',
                borderLeft: '1px solid var(--sp-color-accent-indigo)',
                boxShadow: '-10px 0 25px rgba(0,0,0,0.5)',
                zIndex: 9999,
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
                backdropFilter: 'blur(10px)'
              }}>
                <div style={{
                  padding: '1.5rem',
                  borderBottom: '1px solid rgba(255,255,255,0.1)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{ 
                      width: 16, height: 16, borderRadius: '50%', 
                      backgroundColor: NODE_COLORS[selectedNode.data.neo4jLabel] || NODE_COLORS.Default 
                    }} />
                    <h2 style={{ margin: 0, fontSize: '1.25rem', color: 'white' }}>{selectedNode.data.neo4jLabel} Details</h2>
                  </div>
                  <button 
                    onClick={() => setSelectedNode(null)}
                    style={{ 
                      background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer', fontSize: '1.2rem', padding: '0.25rem' 
                    }}
                  >
                    ✕
                  </button>
                </div>
                <div style={{ padding: '1.5rem', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {Object.entries(selectedNode.data.properties || {}).map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: '#94A3B8', letterSpacing: '0.05em' }}>{k}</span>
                      <span style={{ color: '#e2e8f0', fontFamily: 'var(--sp-font-mono)', fontSize: '0.9rem', wordBreak: 'break-word', background: 'rgba(255,255,255,0.03)', padding: '0.75rem', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.05)' }}>
                        {typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
