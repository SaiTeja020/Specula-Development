import { useState, useEffect, useMemo } from 'react';
import { apiFetch } from '../lib/api';
import ReactFlow, { Background, Controls, Handle } from 'reactflow';
import 'reactflow/dist/style.css';
import * as d3 from 'd3-force';

const NODE_COLORS = {
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

const Legend = () => (
  <div style={{
    position: 'absolute', bottom: 20, right: 20, zIndex: 10,
    background: 'rgba(15, 23, 42, 0.8)', padding: '1rem',
    borderRadius: '8px', border: '1px solid var(--sp-border-thin)',
    backdropFilter: 'blur(8px)',
    display: 'flex', flexDirection: 'column', gap: '0.5rem'
  }}>
    <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '0.9rem', color: 'white' }}>Node Types</h3>
    {Object.entries(NODE_COLORS).filter(([k]) => k !== 'Default').map(([label, color]) => (
      <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <div style={{ width: 12, height: 12, borderRadius: '50%', backgroundColor: color }} />
        <span style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>{label}</span>
      </div>
    ))}
  </div>
);

const GraphStats = ({ nodes, edges, isPanelOpen }) => {
  const nodeCounts = nodes.reduce((acc, n) => {
    acc[n.data.neo4jLabel] = (acc[n.data.neo4jLabel] || 0) + 1;
    return acc;
  }, {});

  const edgeCounts = edges.reduce((acc, e) => {
    acc[e.label] = (acc[e.label] || 0) + 1;
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
        <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '0.85rem', color: 'white', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Node Counts</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          {Object.entries(nodeCounts).map(([type, count]) => (
            <div key={type} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
              <span style={{ color: NODE_COLORS[type] || NODE_COLORS.Default }}>{type}</span>
              <span style={{ fontWeight: 'bold' }}>{count}</span>
            </div>
          ))}
          {nodes.length === 0 && <div style={{ fontSize: '0.8rem', opacity: 0.5 }}>No nodes</div>}
        </div>
      </div>
      <div>
        <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '0.85rem', color: 'white', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Relationships</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          {Object.entries(edgeCounts).map(([type, count]) => (
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
  const simNodes = nodes.map(n => ({ ...n, x: Math.random() * 800, y: Math.random() * 600 }));
  const simEdges = edges.map(e => ({ ...e, source: e.source, target: e.target }));

  const simulation = d3.forceSimulation(simNodes)
    .force('charge', d3.forceManyBody().strength(-1000))
    .force('center', d3.forceCenter(400, 300))
    .force('collide', d3.forceCollide().radius(60))
    .force('link', d3.forceLink(simEdges).id(d => d.id).distance(120))
    .stop();

  // Run synchronously to calculate positions
  for (let i = 0; i < 200; ++i) simulation.tick();

  return simNodes.map(n => {
    const orig = nodes.find(on => on.id === n.id);
    return {
      ...orig,
      position: { x: n.x - 40, y: n.y - 40 } // Offset for the node dimensions
    };
  });
};

export default function Neo4jVisualizer() {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tooltip, setTooltip] = useState({ show: false, x: 0, y: 0, data: null });
  const [selectedNode, setSelectedNode] = useState(null);

  const nodeTypes = useMemo(() => ({ neo4j: Neo4jNode }), []);

  useEffect(() => {
    apiFetch('http://localhost:8300/api/data/neo4j')
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          const rfNodes = data.nodes.map((n) => {
            const displayProp = n.properties.name || n.properties.ip || n.properties.cmd || 'Node';
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
            label: e.type,
            style: { stroke: 'var(--sp-color-accent-indigo)', strokeWidth: 1.5, opacity: 0.6 },
            animated: true
          }));

          const layoutedNodes = runForceLayout(rfNodes, rfEdges);

          setNodes(layoutedNodes);
          setEdges(rfEdges);
        }
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1rem' }}>
      <div className="header glass-panel" style={{ padding: '1rem 1.5rem', margin: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <img src="/Specula_logo.png" alt="Specula Logo" style={{ height: '24px' }} />
          <h1 style={{ fontSize: '1.25rem', margin: 0 }}>Knowledge Graph (Neo4j)</h1>
        </div>
      </div>
      <div className="graph-container glass-panel" style={{ flex: 1, padding: 0, position: 'relative' }}>
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
            <Legend />
            <GraphStats nodes={nodes} edges={edges} isPanelOpen={!!selectedNode} />
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
