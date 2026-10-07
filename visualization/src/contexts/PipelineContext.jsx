import React, { createContext, useState, useEffect, useContext, useRef } from 'react';

const PipelineContext = createContext();

export function usePipeline() {
  return useContext(PipelineContext);
}



const mapNodeToStage = (nodeId) => {
  if (['__start__'].includes(nodeId)) return 0;
  if (['evidence_collection'].includes(nodeId)) return 1;
  if (['supervisor', 'log_analysis', 'network_forensics', 'primary_tier_join', 'memory_forensics', 'identity_cloud', 'malware_stylometry', 'insider_threat', 'specialist_join'].includes(nodeId)) return 2;
  if (['timeline_reconstruction', 'threat_attribution'].includes(nodeId)) return 3;
  if (['proponent', 'critic', 'judge'].includes(nodeId)) return 4;
  if (['guardrail_tier1', 'guardrail_tier2', 'guardrail_tier3', 'hitl', 'report_generation', 'timeline_artifact_generation', 'case_closed_rejected', 'final_output_join', '__end__'].includes(nodeId)) return 5;
  return -1;
};

export function PipelineProvider({ children }) {
  const [caseId, setCaseId] = useState(new URLSearchParams(window.location.search).get('case') || 'CASE-2026-0915-ALPHA');
  const socketRef = useRef(null);
  const [isStarted, setIsStarted] = useState(false);
  const [caseStatus, setCaseStatus] = useState('IDLE');
  
  const [activeStage, setActiveStage] = useState(-1);
  const [stageLogs, setStageLogs] = useState({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
  const [hitlData, setHitlData] = useState(null);
  const [caseResult, setCaseResult] = useState(null);

  const applySnapshot = (snapshot) => {
    setCaseResult(snapshot);
    setIsStarted(true);
    if (snapshot.paused_at?.includes('hitl')) {
      setCaseStatus('AWAITING REVIEW');
      setActiveStage(5);
      setHitlData({ confidence: snapshot.attribution?.overall_confidence ?? 0,
        blastRadius: `${snapshot.attribution?.dfkg_refs?.length ?? 0} cited events`,
        tamperCheck: 'Integrity review required; Fabric deferred' });
    } else if (snapshot.case_status === 'closed') {
      setCaseStatus('COMPLETED'); setActiveStage(6); setHitlData(null);
    } else {
      setCaseStatus('RUNNING');
    }
  };

  const appendLog = (stageIdx, msg) => {
    setStageLogs(prev => ({
      ...prev,
      [stageIdx]: [...(prev[stageIdx] || []), { time: new Date().toLocaleTimeString(), msg }]
    }));
  };

  useEffect(() => {
    let cancelled = false;
    setCaseResult(null); setHitlData(null); setIsStarted(false);
    setCaseStatus('IDLE'); setActiveStage(-1);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    const ws = new WebSocket('ws://localhost:8300/api/graph/stream');
    socketRef.current = ws;
    ws.onopen = async () => {
      try {
        const res = await fetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}`);
        if (res.ok) {
          const snapshot = await res.json();
          if (cancelled || snapshot.case_id !== caseId) return;
          applySnapshot(snapshot);
          snapshot.agent_traces?.forEach(trace => {
            const stage = mapNodeToStage(trace.agent_role);
            if (stage >= 0) appendLog(stage, `[SAVED] ${trace.observation || trace.action || trace.agent_role}`);
          });
        }
      } catch (e) { if (!cancelled) appendLog(5, `[SNAPSHOT ERROR] ${e.message}`); }
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const { type, payload } = data;
      if (payload.case_id && payload.case_id !== caseId) return;

      if (type === 'pipeline_started') {
        setActiveStage(0);
        appendLog(0, `[INGEST] Pipeline initialized for ${payload.case_id}`);
      } else if (type === 'node_active') {
        const stageIndex = mapNodeToStage(payload.node);
        if (stageIndex >= 0) {
          setActiveStage(stageIndex);
          appendLog(stageIndex, `[NODE ACTIVE] ${payload.node.toUpperCase()} :: ${payload.data?.status || 'Processing'}`);
        }

      } else if (type === 'node_complete') {
        const stageIndex = mapNodeToStage(payload.node);
        if (stageIndex >= 0) {
          appendLog(stageIndex, `[OK] ${payload.node.toUpperCase()} completed successfully.`);
        }
        if (payload.node === 'hitl') setHitlData(null);

      } else if (type === 'hitl_required') {
        setCaseResult(payload);
        setCaseStatus('AWAITING REVIEW');
        setHitlData({
          confidence: payload.attribution?.overall_confidence ?? 0,
          blastRadius: `${payload.attribution?.dfkg_refs?.length ?? 0} cited events`,
          tamperCheck: 'Integrity review required; Fabric deferred'
        });
      } else if (type === 'run_complete') {
        setCaseResult(payload);
        setHitlData(null);
        setCaseStatus('COMPLETED');
        setActiveStage(6); // Moves beyond the last stage
        appendLog(5, `[SYSTEM] Run Completed: Case ${payload.case_id}`);
      }
    };

    return () => { cancelled = true; ws.close(); socketRef.current = null; };
  }, [caseId]);

  const handleStart = async (config) => {
    setIsStarted(true);
    setCaseStatus('RUNNING');
    setActiveStage(0);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    try {
      const ws = socketRef.current;
      if (!ws || ws.readyState > WebSocket.OPEN) throw new Error('Live update connection unavailable');
      if (ws.readyState !== WebSocket.OPEN) await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Live update connection timed out')), 5000);
        ws.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
        ws.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Live update connection failed')); }, { once: true });
      });
      const res = await fetch('http://localhost:8300/api/trigger_pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          case_id: caseId,
          ...config
        })
      });
      
      const data = await res.json();
      if (res.ok) applySnapshot(data);
      if (!res.ok || data.status === 'error') {
        setIsStarted(false);
        setCaseStatus('IDLE');
        setActiveStage(-1);
        
        if (data.message === 'docker_offline') {
          alert('Docker Engine is offline. Please start Docker Desktop and try again.');
        } else if (data.message === 'docker_cli_not_found') {
          alert('Docker CLI not found. Please ensure Docker is installed and in your PATH.');
        } else {
          alert(`Failed to start pipeline: ${data.detail || data.message}`);
        }
      }
    } catch (e) {
      console.error("Failed to trigger pipeline", e);
      setIsStarted(false);
      setCaseStatus('IDLE');
      setActiveStage(-1);
      alert(`Investigation failed: ${e.message}`);
    }
  };

  const handleHitlAction = async (action) => {
    try {
      const res = await fetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}/review`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: action === 'clarification' ? 'clarify' : action })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Analyst decision failed');
      applySnapshot(data);
      appendLog(5, `[HITL] Analyst decision accepted: ${action.toUpperCase()}`);
      if (!data.paused_at?.length) setHitlData(null);
    } catch (e) {
      appendLog(5, `[HITL ERROR] ${e.message}`);
    }
  };

  return (
    <PipelineContext.Provider value={{
      caseId, setCaseId, caseResult, isStarted, caseStatus, activeStage, stageLogs, hitlData,
      handleStart, handleHitlAction
    }}>
      {children}
    </PipelineContext.Provider>
  );
}
