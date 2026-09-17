import { useState, useEffect, useRef } from 'react';

const STAGES = [
  { 
    id: 0, 
    title: 'Ingestion & Integrity Preservation', 
    desc: 'Stream capture across heterogeneous sources, SHA-256 SIMD hashing, Quickwit WORM commit, and OCSF schema normalization.' 
  },
  { 
    id: 1, 
    title: 'Entropy Distillation & DFKG Write', 
    desc: 'Drain3 template clustering, SimHash anti-poisoning, and Neo4j Digital Forensic Knowledge Graph node/edge creation.' 
  },
  { 
    id: 2, 
    title: 'Multi-Agent Forensic Triage', 
    desc: 'Supervisor dispatches Primary Tier in parallel with conditional Specialist routing on dead-ends.' 
  },
  { 
    id: 3, 
    title: 'Synthesis & Attack Reconstruction', 
    desc: 'Sequential execution of Timeline Reconstruction and Threat Attribution (MITRE ATT&CK correlation via FAISS).' 
  },
  { 
    id: 4, 
    title: 'Adversarial ACH Debate', 
    desc: 'Proponent vs. Critic agents debate competing hypotheses, evaluated by the Judge agent to eliminate hallucinations.' 
  },
  { 
    id: 5, 
    title: 'Guardrails, HITL & Final Assembly', 
    desc: '3-tier zero-trust safety checks, Human-in-the-Loop escalation gate, and 17-section Daubert-admissible PDF generation.' 
  }
];

const mapNodeToStage = (nodeId) => {
  if (['__start__'].includes(nodeId)) return 0;
  if (['evidence_collection'].includes(nodeId)) return 1; // Mapped here for demonstration to bridge the gap
  if (['supervisor', 'log_analysis', 'network_forensics', 'primary_tier_join', 'memory_forensics', 'identity_cloud', 'malware_stylometry', 'insider_threat', 'specialist_join'].includes(nodeId)) return 2;
  if (['timeline_reconstruction', 'threat_attribution'].includes(nodeId)) return 3;
  if (['proponent', 'critic', 'judge'].includes(nodeId)) return 4;
  if (['guardrail_tier1', 'guardrail_tier2', 'guardrail_tier3', 'hitl', 'report_generation', 'timeline_artifact_generation', 'case_closed_rejected', 'final_output_join', '__end__'].includes(nodeId)) return 5;
  return -1;
};

export default function InvestigationConsole() {
  const [caseId, setCaseId] = useState('CASE-2026-0915-ALPHA');
  const [isStarted, setIsStarted] = useState(false);
  const [caseStatus, setCaseStatus] = useState('IDLE');
  
  const [activeStage, setActiveStage] = useState(-1);
  const [stageLogs, setStageLogs] = useState({ 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] });
  const [hitlData, setHitlData] = useState(null);

  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [maxEvents, setMaxEvents] = useState(2000);
  const [excludePorts, setExcludePorts] = useState('80,443,53');

  // Connect to WebSocket only when started
  useEffect(() => {
    if (!isStarted) return;
    
    const ws = new WebSocket('ws://localhost:8300/api/graph/stream');

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const { type, payload } = data;
      const timestamp = new Date().toLocaleTimeString();

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

  const appendLog = (stageIdx, msg) => {
    setStageLogs(prev => ({
      ...prev,
      [stageIdx]: [...(prev[stageIdx] || []), { time: new Date().toLocaleTimeString(), msg }]
    }));
  };

  const handleStart = async () => {
    setIsStarted(true);
    setCaseStatus('RUNNING');
    setActiveStage(0);
    try {
      const res = await fetch('http://localhost:8300/api/trigger_pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          case_id: caseId,
          start_date: startDate,
          end_date: endDate,
          max_events: maxEvents,
          exclude_ports: excludePorts
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1rem', overflowY: 'auto', paddingBottom: '2rem' }}>
      <div className="header" style={{ padding: '1.5rem', margin: 0, borderBottom: 'var(--sp-border-thin)', background: 'var(--sp-color-bg-surface)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <img src="/Specula_logo.png" alt="Specula Logo" style={{ height: '24px' }} />
          <h1 style={{ fontSize: '1.25rem', margin: 0 }}>Live Investigation</h1>
          <span style={{ 
            padding: '4px 8px',
            fontSize: '0.8rem',
            fontWeight: 600,
            borderRadius: 'var(--sp-radius-sharp)',
            border: 'var(--sp-border-thin)',
            background: caseStatus === 'RUNNING' ? 'rgba(71, 191, 255, 0.15)' : 'rgba(181, 186, 197, 0.1)',
            color: caseStatus === 'RUNNING' ? 'var(--sp-color-accent-indigo)' : 'var(--sp-color-text-secondary)'
          }}>{caseStatus}</span>
        </div>
        {!isStarted && (
          <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.85rem' }}>
                Start Date:
                <input type="datetime-local" value={startDate} onChange={e => setStartDate(e.target.value)} style={{ background: 'var(--sp-color-bg-base)', border: 'var(--sp-border-thin)', color: 'white', padding: '0.5rem', borderRadius: '4px' }} />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.85rem' }}>
                End Date:
                <input type="datetime-local" value={endDate} onChange={e => setEndDate(e.target.value)} style={{ background: 'var(--sp-color-bg-base)', border: 'var(--sp-border-thin)', color: 'white', padding: '0.5rem', borderRadius: '4px' }} />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.85rem' }}>
                Max Events:
                <input type="number" value={maxEvents} onChange={e => setMaxEvents(e.target.value)} style={{ background: 'var(--sp-color-bg-base)', border: 'var(--sp-border-thin)', color: 'white', padding: '0.5rem', borderRadius: '4px', width: '100px' }} />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.85rem' }}>
                Exclude Ports:
                <input type="text" value={excludePorts} onChange={e => setExcludePorts(e.target.value)} style={{ background: 'var(--sp-color-bg-base)', border: 'var(--sp-border-thin)', color: 'white', padding: '0.5rem', borderRadius: '4px', width: '150px' }} />
              </label>
            </div>
            <button className="primary-btn" onClick={handleStart} style={{ alignSelf: 'flex-start' }}>Launch Multi-Agent Pipeline</button>
          </div>
        )}
      </div>

      <div style={{ maxWidth: '1000px', width: '100%', margin: '0 auto', padding: '0 1.5rem' }}>
        {STAGES.map((stage, idx) => {
          const isCompleted = activeStage > idx || caseStatus === 'COMPLETED';
          const isActive = activeStage === idx && caseStatus !== 'COMPLETED';
          const isIdle = activeStage < idx;

          let borderColor = 'var(--sp-color-border-grid)';
          let bgColor = 'var(--sp-color-bg-surface)';
          let titleColor = 'var(--sp-color-text-secondary)';
          let icon = String(idx + 1);

          if (isCompleted) {
            borderColor = 'var(--sp-color-status-admissible)';
            titleColor = 'var(--sp-color-text-primary)';
            icon = '✓';
          } else if (isActive) {
            borderColor = 'var(--sp-color-accent-indigo)';
            titleColor = 'var(--sp-color-text-primary)';
            icon = '↻';
          }

          const logs = stageLogs[idx] || [];

          return (
            <div key={idx} style={{ 
              border: `1px solid ${borderColor}`,
              borderRadius: 'var(--sp-radius-sharp)',
              background: bgColor,
              marginBottom: '1rem',
              overflow: 'hidden',
              transition: 'all 0.15s linear'
            }}>
              {/* Header */}
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                padding: '1rem 1.5rem',
                borderBottom: isActive ? `1px solid ${borderColor}` : 'none',
                background: isActive ? 'rgba(94, 106, 210, 0.05)' : 'transparent'
              }}>
                <div style={{
                  width: '28px', height: '28px', 
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: isCompleted ? 'rgba(16, 185, 129, 0.15)' : (isActive ? 'rgba(94, 106, 210, 0.2)' : 'rgba(255,255,255,0.05)'),
                  color: isCompleted ? 'var(--sp-color-status-admissible)' : (isActive ? 'var(--sp-color-accent-indigo)' : 'var(--sp-color-text-secondary)'),
                  borderRadius: 'var(--sp-radius-sharp)',
                  marginRight: '1rem',
                  fontSize: '0.85rem',
                  fontWeight: 'bold',
                  border: isCompleted ? '1px solid var(--sp-color-status-admissible)' : (isActive ? '1px solid var(--sp-color-accent-indigo)' : '1px solid var(--sp-color-border-grid)')
                }}>
                  {icon}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '1rem', fontWeight: 600, color: titleColor }}>{stage.title}</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--sp-color-text-secondary)', marginTop: '4px' }}>{stage.desc}</div>
                </div>
                
                {isCompleted && (
                  <div style={{ fontSize: '0.8rem', fontFamily: 'var(--sp-font-mono)', color: 'var(--sp-color-status-admissible)' }}>
                    [EXECUTED]
                  </div>
                )}
                {isIdle && (
                  <div style={{ fontSize: '0.8rem', fontFamily: 'var(--sp-font-mono)', color: 'var(--sp-color-text-secondary)' }}>
                    [PENDING]
                  </div>
                )}
              </div>

              {/* Accordion Body for Telemetry */}
              {(isActive || (isCompleted && logs.length > 0)) && (
                <div style={{ 
                  padding: '1rem 1.5rem',
                  background: 'var(--sp-color-bg-void)',
                  borderTop: isCompleted ? `1px solid var(--sp-color-border-grid)` : 'none'
                }}>
                  <div style={{ 
                    fontFamily: 'var(--sp-font-mono)', 
                    fontSize: '12px',
                    color: 'var(--sp-color-text-secondary)',
                    maxHeight: isActive ? '300px' : '150px',
                    overflowY: 'auto'
                  }}>
                    {logs.map((log, i) => (
                      <div key={i} style={{ marginBottom: '4px' }}>
                        <span style={{ color: 'var(--sp-color-border-grid)', marginRight: '8px' }}>[{log.time}]</span>
                        <span style={{ color: log.msg.includes('[OK]') ? 'var(--sp-color-status-admissible)' : 'inherit' }}>{log.msg}</span>
                      </div>
                    ))}
                    {isActive && logs.length === 0 && <span style={{ opacity: 0.5 }}>Waiting for node telemetry...</span>}
                  </div>

                  {/* HITL Modal embedded inside Step 6 */}
                  {isActive && idx === 5 && hitlData && (
                    <div style={{ 
                      marginTop: '1.5rem', 
                      border: '1px solid var(--sp-color-status-hitl)', 
                      borderRadius: 'var(--sp-radius-sharp)',
                      background: 'rgba(245, 158, 11, 0.05)',
                      padding: '1rem'
                    }}>
                      <div style={{ color: 'var(--sp-color-status-hitl)', fontWeight: 600, marginBottom: '0.5rem' }}>
                        ⚠️ HITL Escalation Gate
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem', fontSize: '0.9rem' }}>
                        <div><strong>Confidence:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.confidence}</span></div>
                        <div><strong>Blast Radius:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.blastRadius}</span></div>
                        <div><strong>Tamper Check:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.tamperCheck}</span></div>
                      </div>
                      <div style={{ display: 'flex', gap: '1rem' }}>
                        <button 
                          onClick={() => handleHitlAction('approve')}
                          style={{ background: 'var(--sp-color-status-admissible)', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: 'var(--sp-radius-sharp)', cursor: 'pointer', fontWeight: 600 }}>
                          APPROVE
                        </button>
                        <button 
                          onClick={() => handleHitlAction('reject')}
                          style={{ background: 'var(--sp-color-status-breach)', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: 'var(--sp-radius-sharp)', cursor: 'pointer', fontWeight: 600 }}>
                          REJECT / HALT
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
