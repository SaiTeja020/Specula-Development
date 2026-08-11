import { useState, useEffect, useCallback } from 'react';
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [caseStatus, setCaseStatus] = useState('Idle');
  const [activeNodes, setActiveNodes] = useState(new Set());
  const [logs, setLogs] = useState([]);

  // Fetch initial topology
  useEffect(() => {
    fetch('http://localhost:8300/api/graph/topology')
      .then(res => res.json())
      .then(data => {
        // We do a very primitive layout based on some known nodes for demonstration
        const layoutedNodes = data.nodes.map((node, i) => {
          let x = 200 + (i % 4) * 250;
          let y = 100 + Math.floor(i / 4) * 150;
          
          if (node.id === '__start__') { x = 400; y = 50; }
          else if (node.id === 'supervisor') { x = 400; y = 150; }
          
          return {
            ...node,
            position: { x, y },
            className: 'custom-node',
            style: {
              background: '#1f2937',
              color: '#f3f4f6',
              border: '1px solid #4b5563',
              borderRadius: '8px',
              padding: '12px',
              boxShadow: '0 4px 6px rgba(0,0,0,0.3)'
            }
          };
        });
        
        const styledEdges = data.edges.map(edge => ({
          ...edge,
          style: { stroke: '#4b5563', strokeWidth: 2 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#4b5563',
          },
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
      
      if (type === 'node_active') {
        setActiveNodes(prev => new Set(prev).add(payload.node));
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Active: ${payload.node} - ${payload.data?.status || ''}`]);
        
        // Highlight node
        setNodes(nds => nds.map(n => {
          if (n.id === payload.node) {
            n.style = { ...n.style, background: '#3b82f6', border: '1px solid #60a5fa', boxShadow: '0 0 15px rgba(59, 130, 246, 0.7)' };
          }
          return n;
        }));
        
      } else if (type === 'node_complete') {
        setActiveNodes(prev => {
          const next = new Set(prev);
          next.delete(payload.node);
          return next;
        });
        
        // Reset node style, maybe make it green for completed
        setNodes(nds => nds.map(n => {
          if (n.id === payload.node) {
            n.style = { ...n.style, background: '#10b981', border: '1px solid #34d399', boxShadow: 'none' };
          }
          return n;
        }));
        
      } else if (type === 'run_complete') {
        setCaseStatus(`Completed ${payload.case_id}`);
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Run Completed: ${payload.case_id}`]);
        setTimeout(() => {
          setNodes(nds => nds.map(n => ({...n, style: {...n.style, background: '#1f2937', border: '1px solid #4b5563'}})));
        }, 3000);
      }
    };
    
    return () => ws.close();
  }, [setNodes]);

  const runMock = () => {
    setCaseStatus('Running mock...');
    setLogs([]);
    fetch('http://localhost:8300/api/graph/run_mock', { method: 'POST' });
  };

  return (
    <div className="app-container">
      <header className="header glass-panel">
        <div className="header-title">
          <h1>Specula Visualizer</h1>
          <span className={`status-badge ${caseStatus.includes('Run') ? 'pulse' : ''}`}>{caseStatus}</span>
        </div>
        <button className="primary-btn" onClick={runMock}>Start Mock Run</button>
      </header>
      
      <main className="main-content">
        <div className="graph-container glass-panel">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
            attributionPosition="bottom-right"
          >
            <Background color="#374151" gap={20} />
            <Controls />
          </ReactFlow>
        </div>
        
        <aside className="sidebar glass-panel">
          <h2>Execution Logs</h2>
          <div className="logs-container">
            {logs.map((log, i) => (
              <div key={i} className="log-entry">{log}</div>
            ))}
            {logs.length === 0 && <div className="log-empty">No activity yet.</div>}
          </div>
        </aside>
      </main>
    </div>
  );
}
