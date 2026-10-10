import React, { createContext, useState, useEffect, useContext, useRef } from 'react';
import { useAuth } from './AuthContext';
import { apiFetch } from '../lib/api';

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
  const { session } = useAuth();
  const accessToken = session?.access_token;
  const [caseId, setCaseId] = useState(new URLSearchParams(window.location.search).get('case') || 'CASE-2026-0915-ALPHA');
  const socketRef = useRef(null);
  const connectionRef = useRef(null);
  const generationRef = useRef(0);
  const [isStarted, setIsStarted] = useState(false);
  const [caseStatus, setCaseStatus] = useState('IDLE');
  
  const [activeStage, setActiveStage] = useState(-1);
  const [stageLogs, setStageLogs] = useState({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
  const [hitlData, setHitlData] = useState(null);
  const [caseResult, setCaseResult] = useState(null);

  const applySnapshot = (snapshot) => {
    setCaseResult(snapshot);
    setIsStarted(true);
    if (snapshot.failed_nodes?.length) {
      setCaseStatus('PAUSED AFTER ERROR');
      setIsStarted(false);
      setHitlData(null);
    } else if (snapshot.paused_at?.includes('hitl')) {
      setCaseStatus('AWAITING REVIEW');
      setActiveStage(5);
      setHitlData({ confidence: snapshot.attribution?.overall_confidence ?? 0,
        blastRadius: `${snapshot.attribution?.dfkg_refs?.length ?? 0} cited events`,
        tamperCheck: 'Integrity review required; Fabric deferred' });
    } else if (snapshot.case_status === 'closed') {
      setCaseStatus(snapshot.acceptance_status === 'incomplete' ? 'CLOSED WITH LIMITATIONS' : 'COMPLETED');
      setActiveStage(6); setHitlData(null);
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
    let reconnectTimer;
    let handshakeTimer;
    let currentSocket;
    const generation = ++generationRef.current;
    const current = () => !cancelled && generationRef.current === generation;
    setCaseResult(null); setHitlData(null); setIsStarted(false);
    setCaseStatus('IDLE'); setActiveStage(-1);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    if (!accessToken) {
      connectionRef.current = null;
      socketRef.current = null;
      return () => { cancelled = true; };
    }

    const connect = () => {
      if (!current()) return;
      const ws = new WebSocket('ws://localhost:8300/api/graph/stream');
      currentSocket = ws;
      socketRef.current = ws;
      let resolveReady, rejectReady;
      let authenticated = false;
      const ready = new Promise((resolve, reject) => {
        resolveReady = resolve; rejectReady = reject;
      });
      // A connection may be idle without a run waiting for its handshake.
      ready.catch(() => {});
      connectionRef.current = { ws, ready, generation };
      handshakeTimer = setTimeout(() => {
        rejectReady(new Error('Live update authentication timed out'));
        ws.close();
      }, 10000);
      ws.onopen = () => {
        if (!current()) { ws.close(); return; }
        ws.send(JSON.stringify({ type: 'authenticate', token: accessToken, case_id: caseId }));
      };
      ws.onmessage = async (event) => {
        if (!current()) return;
        let data;
        try { data = JSON.parse(event.data); } catch { return; }
        const { type } = data;
        const payload = data.payload || {};
        if (type === 'authenticated') {
          authenticated = true;
          clearTimeout(handshakeTimer);
          resolveReady();
          try {
            const res = await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}`);
            if (!res.ok) return;
            const snapshot = await res.json();
            if (!current() || snapshot.case_id !== caseId) return;
            applySnapshot(snapshot);
            snapshot.agent_traces?.forEach(trace => {
              const stage = mapNodeToStage(trace.agent_role);
              if (stage >= 0) appendLog(stage, `[SAVED] ${trace.observation || trace.action || trace.agent_role}`);
            });
          } catch { if (current()) appendLog(5, '[SNAPSHOT ERROR] Unable to retrieve investigation'); }
          return;
        }
        if (!authenticated || (payload.case_id && payload.case_id !== caseId)) return;
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
          if (stageIndex >= 0) appendLog(stageIndex, `[NODE FINISHED] ${payload.node.toUpperCase()}`);
          if (payload.node === 'hitl') setHitlData(null);
        } else if (type === 'hitl_required') {
          setCaseResult(payload);
          setCaseStatus('AWAITING REVIEW');
          setHitlData({ confidence: payload.attribution?.overall_confidence ?? 0,
            blastRadius: `${payload.attribution?.dfkg_refs?.length ?? 0} cited events`,
            tamperCheck: 'Integrity review required; Fabric deferred' });
        } else if (type === 'run_complete') {
          setCaseResult(payload); setHitlData(null);
          setCaseStatus(payload.acceptance_status === 'incomplete' ? 'CLOSED WITH LIMITATIONS' : 'COMPLETED');
          setActiveStage(6);
          appendLog(5, `[SYSTEM] Run ended: Case ${payload.case_id}`);
        }
      };
      ws.onerror = () => rejectReady(new Error('Live update connection failed'));
      ws.onclose = (event) => {
        clearTimeout(handshakeTimer);
        rejectReady(new Error('Live update connection closed'));
        if (!current()) return;
        if ([1008, 4401, 4403].includes(event.code)) {
          appendLog(5, '[AUTH] Live update access denied; sign in again or select an owned case');
          return;
        }
        reconnectTimer = setTimeout(connect, 2000);
      };
    };
    connect();
    return () => {
      cancelled = true;
      clearTimeout(reconnectTimer); clearTimeout(handshakeTimer);
      currentSocket?.close();
      socketRef.current = null; connectionRef.current = null;
    };
  }, [caseId, accessToken]);

  const handleStart = async (config) => {
    const generation = generationRef.current;
    if (!accessToken) { alert('Sign in to run an investigation'); return; }
    setIsStarted(true);
    setCaseStatus('RUNNING');
    setActiveStage(0);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    try {
      const connection = connectionRef.current;
      if (!connection || connection.ws.readyState > WebSocket.OPEN) throw new Error('Live update connection unavailable');
      await connection.ready;
      if (generationRef.current !== generation) return;
      const retry = caseResult?.case_id === caseId && caseResult.failed_nodes?.length;
      const endpoint = retry
        ? `http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}/retry`
        : 'http://localhost:8300/api/trigger_pipeline';
      const res = await apiFetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          ...config,
          case_id: caseId
        })
      });
      
      const data = await res.json();
      if (generationRef.current !== generation || (data.case_id && data.case_id !== caseId)) return;
      if (res.ok) applySnapshot(data);
      if (!res.ok || data.status === 'error') {
        const saved = await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}`);
        if (saved.ok && generationRef.current === generation) {
          const checkpoint = await saved.json();
          if (checkpoint.case_id === caseId && checkpoint.failed_nodes?.length) {
            applySnapshot(checkpoint);
            appendLog(5, '[SYSTEM] Checkpoint retained. Restore dependencies, then start to retry.');
            return;
          }
        }
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
      if (generationRef.current !== generation) return;
      setIsStarted(false);
      setCaseStatus('IDLE');
      setActiveStage(-1);
      alert(`Investigation failed: ${e.message}`);
    }
  };

  const handleHitlAction = async (action) => {
    const generation = generationRef.current;
    try {
      const res = await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}/review`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: action === 'clarification' ? 'clarify' : action })
      });
      const data = await res.json();
      if (generationRef.current !== generation || (data.case_id && data.case_id !== caseId)) return;
      if (!res.ok) throw new Error(data.detail || 'Analyst decision failed');
      applySnapshot(data);
      appendLog(5, `[HITL] Analyst decision accepted: ${action.toUpperCase()}`);
      if (!data.paused_at?.length) setHitlData(null);
    } catch (e) {
      if (generationRef.current !== generation) return;
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
