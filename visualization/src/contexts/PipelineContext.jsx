import React, { createContext, useState, useEffect, useContext } from 'react';

const PipelineContext = createContext();

export function usePipeline() {
  return useContext(PipelineContext);
}

const mapNodeToStage = (nodeId) => {
  if (['__start__'].includes(nodeId)) return 0;
  if (['evidence_collection'].includes(nodeId)) return 1;
  if (['supervisor', 'log_analysis', 'network_forensics', 'primary_tier_join', 'memory_forensics', 'identity', 'cloud_container', 'malware_stylometry', 'insider_threat', 'specialist_join'].includes(nodeId)) return 2;
  if (['timeline_reconstruction', 'threat_attribution', 'dag'].includes(nodeId)) return 3;
  if (['proponent', 'critic', 'judge'].includes(nodeId)) return 4;
  if (['guardrail_tier1', 'guardrail_tier2', 'guardrail_tier3', 'hitl', 'report_generation', 'timeline_artifact_generation', 'case_closed_rejected', 'final_output_join', '__end__'].includes(nodeId)) return 5;
  return -1;
};

const HITL_API_BASE = 'http://localhost:8300/api';

export function PipelineProvider({ children }) {
  const [caseId] = useState('CASE-2026-0915-ALPHA');
  const [isStarted, setIsStarted] = useState(false);
  const [caseStatus, setCaseStatus] = useState('IDLE');
  const [activeStage, setActiveStage] = useState(-1);
  const [stageLogs, setStageLogs] = useState({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
  const [hitlData, setHitlData] = useState(null);
  // Real thread_id tracked for HITL resume
  const [activeThreadId, setActiveThreadId] = useState(null);
  // Final result from run_complete event
  const [investigationResult, setInvestigationResult] = useState(null);

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
      let data;
      try { data = JSON.parse(event.data); } catch { return; }
      const { type, payload } = data;

      if (type === 'pipeline_started') {
        setActiveStage(0);
        setInvestigationResult(null);
        if (payload.thread_id) setActiveThreadId(payload.thread_id);
        appendLog(0, `[SYSTEM] Pipeline started — case: ${payload.case_id}, thread: ${payload.thread_id || 'pending'}`);

      } else if (type === 'node_active') {
        const stageIndex = mapNodeToStage(payload.node);
        if (stageIndex >= 0) {
          setActiveStage(stageIndex);
          appendLog(stageIndex, `[NODE ACTIVE] ${payload.node.toUpperCase()} :: ${payload.data?.status || 'Processing'}`);
        }

      } else if (type === 'node_complete') {
        const stageIndex = mapNodeToStage(payload.node);
        if (stageIndex >= 0) {
          appendLog(stageIndex, `[OK] ${payload.node.toUpperCase()} completed.`);
        }

      } else if (type === 'hitl_required') {
        // Real HITL event from the graph — populate with actual snapshot data
        const snap = payload.snapshot || {};
        setHitlData({
          threadId: payload.thread_id,
          caseId: payload.case_id,
          hitlUrl: payload.hitl_url,
          entryReason: snap.entry_reason || 'review_required',
          guardrailTier: snap.guardrail_fail_tier ?? null,
          findingsCount: snap.findings_count ?? 0,
          debateOutcome: snap.debate_outcome ?? null,
        });
        setCaseStatus('WAITING_FOR_HUMAN');
        if (payload.thread_id) setActiveThreadId(payload.thread_id);
        appendLog(5, `[HITL] Human review required — thread: ${payload.thread_id}`);
        appendLog(5, `[HITL] Reason: ${snap.entry_reason || 'unknown'}`);

      } else if (type === 'hitl_resumed') {
        setCaseStatus('RUNNING');
        setHitlData(null);
        appendLog(5, `[HITL] Graph resumed by human decision: ${payload.decision}`);

      } else if (type === 'run_complete') {
        setCaseStatus('COMPLETED');
        setActiveStage(6);
        setActiveThreadId(null);
        _activeInvestigations.delete(payload.case_id);
        if (payload.answer) {
          setInvestigationResult(payload);
          appendLog(5, `[DONE] Investigation complete — ${payload.agents_used?.join(', ') || 'agents ran'}`);
          appendLog(5, `[RESULT] ${payload.answer.slice(0, 200)}...`);
        } else {
          appendLog(5, `[SYSTEM] Run completed: case ${payload.case_id}`);
        }

      } else if (type === 'run_error') {
        setCaseStatus('ERROR');
        setIsStarted(false);
        appendLog(5, `[ERROR] ${payload.error || 'Investigation failed'}`);
      }
    };

    ws.onerror = () => appendLog(0, '[WARN] WebSocket connection error — check that Visualizer API is running on :8300');
    ws.onclose = () => appendLog(0, '[SYSTEM] WebSocket closed.');

    return () => ws.close();
  }, [isStarted]);

  // Track launched case_ids in module scope to match backend duplicate guard
  const _activeInvestigations = new Set();

  const handleStart = async (config) => {
    const { query, ...rest } = config;
    setIsStarted(true);
    setCaseStatus('RUNNING');
    setActiveStage(0);
    setStageLogs({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
    setHitlData(null);
    setInvestigationResult(null);

    try {
      const res = await fetch('http://localhost:8300/api/trigger_pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          query: query || 'Investigate the available activity in this case and identify anything that may require attention.',
          ...rest,
        }),
      });

      const data = await res.json();

      if (data.status === 'already_running') {
        appendLog(0, `[WARN] Investigation already in progress: thread=${data.thread_id}`);
        if (data.thread_id) setActiveThreadId(data.thread_id);
        return;
      }

      if (data.status === 'error') {
        setIsStarted(false);
        setCaseStatus('IDLE');
        setActiveStage(-1);
        if (data.message === 'docker_offline') {
          alert('Docker Engine is offline. Please start Docker Desktop and try again.');
        } else {
          alert(`Failed to start pipeline: ${data.message}`);
        }
        return;
      }

      // Success — capture the thread_id returned synchronously by the API
      if (data.thread_id) setActiveThreadId(data.thread_id);
      appendLog(0, `[SYSTEM] Investigation triggered — thread: ${data.thread_id}, query: "${(query || '').slice(0, 80)}"`);

    } catch (e) {
      console.error('Failed to trigger pipeline', e);
      setIsStarted(false);
      setCaseStatus('IDLE');
      setActiveStage(-1);
      alert('Network error communicating with the backend API on :8300.');
    }
  };

  const handleHitlAction = async (action, query = '') => {
    const threadId = hitlData?.threadId || activeThreadId;
    if (!threadId) {
      appendLog(5, `[ERROR] No thread_id available — cannot submit HITL decision`);
      return;
    }

    appendLog(5, `[HITL] Submitting decision: ${action.toUpperCase()} → thread: ${threadId}`);

    try {
      const url = hitlData?.hitlUrl || `${HITL_API_BASE}/hitl/${threadId}`;
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: action, query }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        appendLog(5, `[ERROR] HITL API returned ${res.status}: ${err.detail || err.message || 'unknown error'}`);
        return;
      }
      const result = await res.json();
      appendLog(5, `[HITL] Decision accepted — status: resuming...`);
      setHitlData(null);
      setCaseStatus('RUNNING');
      if (action === 'reject') {
        // Just let it resume and run to termination
      }
    } catch (e) {
      appendLog(5, `[ERROR] HITL API request failed: ${e.message}`);
    }
  };

  return (
    <PipelineContext.Provider value={{
      caseId, isStarted, caseStatus, activeStage, stageLogs, hitlData,
      activeThreadId, investigationResult,
      handleStart, handleHitlAction,
    }}>
      {children}
    </PipelineContext.Provider>
  );
}

