import React, { createContext, useState, useEffect, useContext } from 'react';

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
  const [caseId] = useState('CASE-2026-0915-ALPHA');
  const [isStarted, setIsStarted] = useState(false);
  const [caseStatus, setCaseStatus] = useState('IDLE');
  
  const [activeStage, setActiveStage] = useState(-1);
  const [stageLogs, setStageLogs] = useState({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
  const [hitlData, setHitlData] = useState(null);

  const appendLog = (stageIdx, msg) => {
    setStageLogs(prev => ({
      ...prev,
      [stageIdx]: [...(prev[stageIdx] || []), { time: new Date().toLocaleTimeString(), msg }]
    }));
  };

  useEffect(() => {
    if (!isStarted) return;
    
    const ws = new WebSocket('ws://localhost:8300/api/graph/stream');

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const { type, payload } = data;

      if (type === 'pipeline_started') {
        setActiveStage(0);
        appendLog(0, `[INGEST] Pipeline initialized for ${payload.case_id}`);
      } else if (type === 'node_active') {
        const stageIndex = mapNodeToStage(payload.node);
        if (stageIndex >= 0) {
          setActiveStage(stageIndex);
          appendLog(stageIndex, `[NODE ACTIVE] ${payload.node.toUpperCase()} :: ${payload.data?.status || 'Processing'}`);
        }

        if (payload.node === 'hitl') {
          setHitlData({
            confidence: 0.65,
            blastRadius: '14 Hosts',
            tamperCheck: 'VCT VALID'
          });
        }
      } else if (type === 'node_complete') {
        const stageIndex = mapNodeToStage(payload.node);
        if (stageIndex >= 0) {
          appendLog(stageIndex, `[OK] ${payload.node.toUpperCase()} completed successfully.`);
        }
        if (payload.node === 'hitl') setHitlData(null);

      } else if (type === 'run_complete') {
        setCaseStatus('COMPLETED');
        setActiveStage(6); // Moves beyond the last stage
        appendLog(5, `[SYSTEM] Run Completed: Case ${payload.case_id}`);
      }
    };

    return () => ws.close();
  }, [isStarted]);

  const handleStart = async (config) => {
    setIsStarted(true);
    setCaseStatus('RUNNING');
    setActiveStage(0);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    try {
      const res = await fetch('http://localhost:8300/api/trigger_pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          case_id: caseId,
          ...config
        })
      });
      
      const data = await res.json();
      if (data.status === 'error') {
        setIsStarted(false);
        setCaseStatus('IDLE');
        setActiveStage(-1);
        
        if (data.message === 'docker_offline') {
          alert('Docker Engine is offline. Please start Docker Desktop and try again.');
        } else if (data.message === 'docker_cli_not_found') {
          alert('Docker CLI not found. Please ensure Docker is installed and in your PATH.');
        } else {
          alert(`Failed to start pipeline: ${data.message}`);
        }
      }
    } catch (e) {
      console.error("Failed to trigger pipeline", e);
      setIsStarted(false);
      setCaseStatus('IDLE');
      setActiveStage(-1);
      alert('Network error communicating with the backend API.');
    }
  };

  const handleHitlAction = (action) => {
    appendLog(5, `[HITL] Analyst Action: ${action.toUpperCase()}`);
    setHitlData(null);
  };

  return (
    <PipelineContext.Provider value={{
      caseId, isStarted, caseStatus, activeStage, stageLogs, hitlData,
      handleStart, handleHitlAction
    }}>
      {children}
    </PipelineContext.Provider>
  );
}
