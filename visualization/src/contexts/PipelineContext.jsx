import React, { createContext, useState, useEffect, useContext, useRef } from 'react';
import { useAuth } from './AuthContext';
import { apiFetch } from '../lib/api';
import { localFetch } from '../lib/localApi';

const PipelineContext = createContext();
const LOCAL_JOB_KEY = 'specula.localInvestigationJob';

export function usePipeline() {
  return useContext(PipelineContext);
}



const mapNodeToStage = (nodeId) => {
  if (['__start__'].includes(nodeId)) return 0;
  if (['evidence_collection'].includes(nodeId)) return 1;
  if (['supervisor', 'log_analysis', 'network_forensics', 'network_specialist', 'primary_tier_join', 'memory_forensics', 'identity', 'cloud_container', 'malware_stylometry', 'insider_threat', 'specialist_join'].includes(nodeId)) return 2;
  if (['timeline_reconstruction', 'threat_attribution'].includes(nodeId)) return 3;
  if (['proponent', 'critic', 'judge'].includes(nodeId)) return 4;
  if (['guardrail_tier1', 'guardrail_tier2', 'guardrail_tier3', 'hitl', 'report_generation', 'timeline_artifact_generation', 'case_closed_rejected', 'final_output_join', '__end__'].includes(nodeId)) return 5;
  return -1;
};

export function PipelineProvider({ children }) {
  const { session } = useAuth();
  const accessToken = session?.access_token;
  const [caseId, setCaseId] = useState(new URLSearchParams(window.location.search).get('case') || '');
  const localCaseRef = useRef('');
  const skipLocalSnapshotRef = useRef('');
  const pendingLocalCaseRef = useRef('');
  const socketRef = useRef(null);
  const connectionRef = useRef(null);
  const generationRef = useRef(0);
  const [isStarted, setIsStarted] = useState(false);
  const [caseStatus, setCaseStatus] = useState('IDLE');
  
  const [activeStage, setActiveStage] = useState(-1);
  const [stageLogs, setStageLogs] = useState({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
  const [hitlData, setHitlData] = useState(null);
  const [caseResult, setCaseResult] = useState(null);
  const [launchError, setLaunchError] = useState('');
  const [ingestionPhase, setIngestionPhase] = useState('');
  const [ingestionDiagnostics, setIngestionDiagnostics] = useState(null);
  const [isReviewing, setIsReviewing] = useState(false);
  const reviewingRef = useRef(false);
  const observedTracesRef = useRef(0);

  const applySnapshot = (snapshot) => {
    setCaseResult(snapshot);
    setIngestionDiagnostics(snapshot.ingestion_provenance?.processing || null);
    observedTracesRef.current = snapshot.agent_traces?.length || 0;
    setIsStarted(true);
    if (snapshot.failed_nodes?.length) {
      setCaseStatus('PAUSED AFTER ERROR');
      setIsStarted(false);
      setHitlData(null);
    } else if (snapshot.paused_at?.includes('hitl')) {
      setCaseStatus('AWAITING REVIEW');
      setActiveStage(5);
      setHitlData({ confidence: snapshot.attribution?.overall_confidence ?? 0,
        reviewReason: snapshot.judge_review?.rationale || 'Review is incomplete or requires an analyst decision. Inspect agent assessments and counter-evidence.',
        blastRadius: `${snapshot.attribution?.dfkg_refs?.length ?? 0} cited events`,
        tamperCheck: 'Integrity review required; Fabric deferred' });
    } else if (snapshot.case_status === 'closed') {
      setCaseStatus(snapshot.acceptance_status === 'incomplete' ? 'CLOSED WITH LIMITATIONS' : 'COMPLETED');
      setActiveStage(6); setHitlData(null);
    } else {
      setCaseStatus('RUNNING');
      setHitlData(null);
      const stage = mapNodeToStage(snapshot.paused_at?.[0]);
      if (stage >= 0) setActiveStage(stage);
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
    if (caseId.startsWith('LOCAL-')) {
      localCaseRef.current = caseId;
      if (skipLocalSnapshotRef.current === caseId) {
        skipLocalSnapshotRef.current = '';
        return () => { cancelled = true; };
      }
      if (pendingLocalCaseRef.current === caseId) return () => { cancelled = true; };
      setCaseResult(null); setLaunchError('');
      localFetch(`/api/local/cases/${encodeURIComponent(caseId)}`)
        .then(async response => {
          const snapshot = await response.json();
          if (!response.ok) throw new Error(snapshot.detail || `Saved case returned HTTP ${response.status}`);
          return snapshot;
        })
        .then(snapshot => { if (current() && snapshot?.case_id === caseId) applySnapshot(snapshot); })
        .catch(error => { if (current()) setLaunchError(`Saved local case is unavailable: ${error.message}`); });
      return () => { cancelled = true; };
    }
    setCaseResult(null); setHitlData(null); setIsStarted(false);
    setCaseStatus('IDLE'); setActiveStage(-1);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    if (!accessToken || !caseId) {
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

  useEffect(() => {
    if (!caseId.startsWith('LOCAL-') || !isStarted ||
        ['COMPLETED', 'CLOSED WITH LIMITATIONS'].includes(caseStatus)) return;
    let cancelled = false;
    const refresh = async () => {
      try {
        const response = await localFetch(`/api/local/cases/${encodeURIComponent(caseId)}`);
        if (!response.ok) return;
        const snapshot = await response.json();
        if (!cancelled && snapshot.case_id === caseId) applySnapshot(snapshot);
      } catch { /* Keep the last checkpoint visible until the next poll. */ }
    };
    const timer = setInterval(refresh, 5000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [caseId, isStarted, caseStatus]);

  const handleStart = async (config) => {
    const generation = generationRef.current;
    if (!accessToken) { alert('Sign in to run an investigation'); return; }
    setIsStarted(true);
    setCaseStatus('RUNNING');
    setActiveStage(0);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    setLaunchError('');
    try {
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
      setLaunchError(e.message);
    }
  };

  const handleIngestAndStart = async (config) => {
    setLaunchError(''); setCaseResult(null); setIsStarted(true); setIngestionDiagnostics(null);
    setCaseStatus('INGESTING'); setActiveStage(0);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    try {
      const query = new URLSearchParams({ start_date: config.start_date || '', end_date: config.end_date || '',
        max_events: String(config.max_events), exclude_ports: config.exclude_ports.join(',') });
      const start = config.archiveFile
        ? await localFetch(`/api/local/investigations/upload?${query}`, {
          method: 'POST', headers: { 'Content-Type': 'application/zip' }, body: config.archiveFile
        })
        : await localFetch('/api/local/investigations', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config)
        });
      const created = await start.json();
      if (start.status === 404) {
        throw new Error('Local controller is outdated. Restart the controller on port 8400, then retry.');
      }
      if (!start.ok) throw new Error(created.detail || `Ingestion returned HTTP ${start.status}`);
      sessionStorage.setItem(LOCAL_JOB_KEY, created.id);
      pendingLocalCaseRef.current = created.case_id;
      observedTracesRef.current = 0;
      setCaseId(created.case_id);
      await followLocalJob(created.id);
    } catch (error) {
      setIsStarted(false); setCaseStatus('IDLE'); setActiveStage(-1);
      setLaunchError(error.message === 'Failed to fetch'
        ? 'Local controller unavailable. Restart it on port 8400 and retry.' : error.message);
    }
  };

  const followLocalJob = async (jobId, cancelled = () => false) => {
    let priorPhase = '';
    while (!cancelled()) {
      const response = await localFetch(`/api/local/investigations/${encodeURIComponent(jobId)}`);
      const job = await response.json();
      if (!response.ok) throw new Error(job.detail || `Investigation status returned HTTP ${response.status}`);
      if (cancelled()) return;
      if (job.ingestion) setIngestionDiagnostics({
        ...job.ingestion,
        selected_records_without_normalized_events: job.ingestion.excluded_records,
      });
      if (job.phase !== priorPhase) {
        priorPhase = job.phase;
        setIngestionPhase(job.phase);
        if (job.phase === 'investigating') {
          setCaseStatus('RUNNING'); setActiveStage(2);
          appendLog(0, `[INGEST] ${job.ingestion?.accepted ?? 0} normalized events linked to ${job.case_id}`);
        }
      }
      if (job.phase === 'error') {
        sessionStorage.removeItem(LOCAL_JOB_KEY);
        setIsStarted(false); setCaseStatus('IDLE'); setActiveStage(-1);
        setLaunchError(job.message || 'Local investigation failed');
        return;
      }
      if (job.phase === 'investigating' && job.case_id) {
        try {
          const saved = await localFetch(`/api/local/cases/${encodeURIComponent(job.case_id)}`);
          if (saved.ok && !cancelled()) {
            const snapshot = await saved.json();
            const traces = snapshot.agent_traces || [];
            traces.slice(observedTracesRef.current).forEach(trace => {
              const stage = mapNodeToStage(trace.agent_role);
              if (stage >= 0) appendLog(stage, `[${trace.agent_role}] ${trace.observation || trace.action || 'completed'}`);
            });
            applySnapshot(snapshot);
          }
        } catch { /* The first checkpoint may not exist yet; keep polling. */ }
      }
      if (job.phase === 'complete') {
        pendingLocalCaseRef.current = '';
        localCaseRef.current = job.case_id;
        skipLocalSnapshotRef.current = job.case_id;
        setCaseId(job.case_id);
        applySnapshot(job.result);
        appendLog(5, `[SYSTEM] Case ${job.case_id} reached ${job.result?.case_status || 'a checkpoint'}`);
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  };

  useEffect(() => {
    let cancelled = false;
    const restore = async () => {
      try {
        if (new URLSearchParams(window.location.search).get('case')) return;
        const savedId = sessionStorage.getItem(LOCAL_JOB_KEY);
        const currentResponse = await localFetch('/api/local/investigations/current');
        let job = currentResponse.ok ? await currentResponse.json() : null;
        if (!job?.id && savedId) {
          const savedResponse = await localFetch(`/api/local/investigations/${encodeURIComponent(savedId)}`);
          if (savedResponse.ok) job = await savedResponse.json();
        }
        if (cancelled || !job?.id) return;
        if (job.phase === 'error' && job.case_id) {
          const snapshotResponse = await localFetch(`/api/local/cases/${encodeURIComponent(job.case_id)}`);
          if (snapshotResponse.ok && !cancelled) {
            const snapshot = await snapshotResponse.json();
            localCaseRef.current = job.case_id;
            skipLocalSnapshotRef.current = job.case_id;
            setCaseId(job.case_id);
            applySnapshot(snapshot);
            return;
          }
        }
        const running = ['queued', 'ingesting', 'investigating'].includes(job.phase);
        if (!running && job.id !== savedId) return;
        sessionStorage.setItem(LOCAL_JOB_KEY, job.id);
        pendingLocalCaseRef.current = running ? job.case_id : '';
        setCaseId(job.case_id);
        setIsStarted(true);
        setCaseStatus(job.phase === 'investigating' ? 'RUNNING' : 'INGESTING');
        setActiveStage(job.phase === 'investigating' ? 2 : 0);
        await followLocalJob(job.id, () => cancelled);
      } catch (error) {
        if (!cancelled) setLaunchError(`Could not reconnect to the local investigation: ${error.message}`);
      }
    };
    restore();
    return () => { cancelled = true; };
  }, []);

  const handleHitlAction = async (action) => {
    if (reviewingRef.current) return;
    reviewingRef.current = true;
    setIsReviewing(true);
    const generation = generationRef.current;
    try {
      const options = {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: action === 'clarification' ? 'clarify' : action })
      };
      const res = localCaseRef.current === caseId
        ? await localFetch(`/api/local/cases/${encodeURIComponent(caseId)}/review`, options)
        : await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}/review`, options);
      const data = await res.json();
      if (generationRef.current !== generation || (data.case_id && data.case_id !== caseId)) return;
      if (res.status === 409) {
        appendLog(5, '[HITL] A review request is already processing. Waiting for the saved checkpoint.');
        return;
      }
      if (!res.ok) throw new Error(data.detail || 'Analyst decision failed');
      applySnapshot(data);
      appendLog(5, `[HITL] Analyst decision accepted: ${action.toUpperCase()}`);
      if (data.paused_at?.includes('hitl')) {
        appendLog(5, '[HITL] Guardrails requested another analyst review.');
      }
      if (!data.paused_at?.length) setHitlData(null);
    } catch (e) {
      if (generationRef.current !== generation) return;
      appendLog(5, `[HITL ERROR] ${e.message}`);
    } finally {
      reviewingRef.current = false;
      setIsReviewing(false);
    }
  };

  const resetPipeline = () => {
    sessionStorage.removeItem(LOCAL_JOB_KEY);
    localCaseRef.current = '';
    pendingLocalCaseRef.current = '';
    setCaseId(''); setCaseResult(null); setIsStarted(false);
    setCaseStatus('IDLE'); setActiveStage(-1); setHitlData(null);
    setLaunchError(''); setIngestionPhase(''); setIngestionDiagnostics(null);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
  };

  return (
    <PipelineContext.Provider value={{
      caseId, setCaseId, caseResult, isStarted, caseStatus, activeStage, stageLogs, hitlData,
      launchError, ingestionPhase, ingestionDiagnostics, isReviewing, handleStart, handleIngestAndStart, handleHitlAction, resetPipeline
    }}>
      {children}
    </PipelineContext.Provider>
  );
}
