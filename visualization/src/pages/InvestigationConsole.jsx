import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import ZipFormatGuide from './ZipFormatGuide';
import { usePipeline } from '../contexts/PipelineContext';
import { AgentsView, AttackGraphView, ReportView, TimelineView } from './InvestigationViews';

const VIEWS = [
  { id: 'pipeline', label: 'Pipeline' },
  { id: 'agents', label: 'Agents' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'attack-graph', label: 'Attack Graph' },
  { id: 'report', label: 'Report' },
];

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
    desc: '3-tier zero-trust safety checks, Human-in-the-Loop escalation gate, and case report generation. Fabric anchoring and legal admissibility remain unverified.'
  }
];

export default function InvestigationConsole() {
  const initialView = new URLSearchParams(window.location.search).get('view');
  const [view, setView] = useState(VIEWS.some(item => item.id === initialView) ? initialView : 'pipeline');
  const tabRefs = useRef({});
  const zipGuideRef = useRef(null);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [maxEvents, setMaxEvents] = useState(2000);
  const [excludedPorts, setExcludedPorts] = useState('80,443,53');
  const [formError, setFormError] = useState('');
  const [source, setSource] = useState('local');
  const [archiveFile, setArchiveFile] = useState(null);
  const location = useLocation();
  const navigate = useNavigate();
  const { 
    caseId, setCaseId, caseResult, isStarted, caseStatus, activeStage, stageLogs, hitlData,
    launchError, ingestionPhase, ingestionDiagnostics, isReviewing, handleIngestAndStart, handleHitlAction, resetPipeline
  } = usePipeline();

  useEffect(() => {
    const requested = new URLSearchParams(location.search).get('case');
    if (requested && requested !== caseId) setCaseId(requested);
  }, [location.search, caseId, setCaseId]);

  const onLaunch = () => {
    setFormError('');
    if (source === 'upload' && (!archiveFile || archiveFile.size > 50 * 1024 * 1024)) {
      setFormError('Select a ZIP archive no larger than 50 MiB.'); return;
    }
    const ports = excludedPorts.split(',').map(value => value.trim()).filter(Boolean);
    if (ports.some(value => !/^\d+$/.test(value) || Number(value) > 65535)) {
      setFormError('Enter excluded ports as comma-separated numbers from 0 to 65535.'); return;
    }
    if (Boolean(startDate) !== Boolean(endDate) || (startDate && startDate >= endDate)) {
      setFormError('Choose a start date before the end date, or leave both dates blank.'); return;
    }
    handleIngestAndStart({ start_date: startDate, end_date: endDate,
      max_events: Number(maxEvents), exclude_ports: ports.map(Number), archiveFile: source === 'upload' ? archiveFile : null });
  };

  const selectView = (id) => {
    setView(id);
    const query = new URLSearchParams(location.search);
    query.set('view', id);
    navigate({ pathname: location.pathname, search: query.toString() }, { replace: true });
  };

  const onNewInvestigation = () => {
    const query = new URLSearchParams(location.search);
    query.delete('case'); query.set('view', 'pipeline');
    navigate({ pathname: location.pathname, search: query.toString() }, { replace: true });
    setView('pipeline'); resetPipeline();
  };

  const onTabKeyDown = (event, index) => {
    const target = event.key === 'Home' ? 0 : event.key === 'End' ? VIEWS.length - 1
      : event.key === 'ArrowRight' ? (index + 1) % VIEWS.length
        : event.key === 'ArrowLeft' ? (index - 1 + VIEWS.length) % VIEWS.length : -1;
    if (target >= 0) {
      event.preventDefault();
      selectView(VIEWS[target].id);
      tabRefs.current[VIEWS[target].id]?.focus();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1rem', overflowY: 'auto', paddingBottom: '2rem' }}>
      <ZipFormatGuide dialogRef={zipGuideRef} />
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
        <p>Case: {caseId || 'A new local case will be created from the selected logs.'}</p>
        {caseId && !caseResult && !launchError && <p role="status">Loading case data or waiting for the first saved checkpoint…</p>}
        {(formError || launchError) && <p role="alert" style={{ color: 'var(--sp-color-status-breach)' }}>
          {formError || launchError}
        </p>}
        {isStarted && ingestionPhase && <p aria-live="polite">Pipeline stage: {ingestionPhase}</p>}
        {!!ingestionDiagnostics?.selected_records_without_normalized_events && <details>
          <summary>{ingestionDiagnostics.selected_records_without_normalized_events} records excluded from normalized evidence — view ingestion diagnostics</summary>
          <ul>{ingestionDiagnostics.record_errors_sample?.map((item, index) => <li key={index}>
            {item.file || 'Source'} · record {item.record}: {item.reason}
          </li>)}</ul>
          <p>Original uploaded records remain in the preserved ZIP. This list shows up to 20 exclusions.</p>
        </details>}
        {['COMPLETED', 'CLOSED WITH LIMITATIONS', 'AWAITING REVIEW', 'PAUSED AFTER ERROR'].includes(caseStatus) && (
          <button className="secondary-btn" onClick={onNewInvestigation}>New Investigation</button>
        )}
        {caseResult && <section aria-live="polite" style={{ marginTop: '1rem' }}>
          <p>{caseResult.findings?.length ?? 0} findings · {caseResult.agent_traces?.length ?? 0} execution traces</p>
          <p>{caseResult.attribution?.summary || 'No supported attribution is available.'}</p>
          <p>Report reference: {caseResult.final_output_ref || 'Not generated'}</p>
        </section>}
        {view === 'pipeline' && !isStarted && (
          <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label>Evidence source{' '}
              <select value={source} onChange={e => setSource(e.target.value)}>
                <option value="local">Collect local Windows logs</option>
                <option value="upload">Upload exported logs (ZIP)</option>
              </select>
            </label>
            {source === 'upload' && <div>
              <label>Log archive <input type="file" accept=".zip,application/zip"
                onChange={e => setArchiveFile(e.target.files?.[0] || null)} /></label>
              <button type="button" className="secondary-btn" style={{ marginTop: '0.75rem' }}
                aria-haspopup="dialog" onClick={() => zipGuideRef.current?.showModal()}>
                ZIP format guide
              </button>
            </div>}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem' }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                Start Date
                <input type="datetime-local" value={startDate} onChange={e => setStartDate(e.target.value)} />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                End Date
                <input type="datetime-local" value={endDate} onChange={e => setEndDate(e.target.value)} />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {source === 'upload' ? 'Max Events per Uploaded File' : 'Max Events per Channel'}
                <input type="number" min="1" max="5000" value={maxEvents}
                  onChange={e => setMaxEvents(e.target.value)} />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                Excluded Ports
                <input type="text" value={excludedPorts} onChange={e => setExcludedPorts(e.target.value)}
                  placeholder="80,443,53" />
              </label>
            </div>
            <p>{source === 'upload'
              ? 'Preserve the uploaded archive, normalize supported logs and investigate a new case. Leave dates blank to use all selected records.'
              : 'Collect local Windows logs in the selected interval, preserve and normalize them, then investigate a new case. Leave both dates blank for the most recent logs.'}</p>
            <button className="primary-btn" onClick={onLaunch} style={{ alignSelf: 'flex-start' }}>Launch Multi-Agent Pipeline</button>
          </div>
        )}
      </div>

      <div role="tablist" aria-label="Investigation views" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', padding: '0 1.5rem' }}>
        {VIEWS.map((item, index) => <button key={item.id} type="button" role="tab"
          id={`view-tab-${item.id}`} aria-controls="investigation-view-panel"
          aria-selected={view === item.id} tabIndex={view === item.id ? 0 : -1}
          ref={element => { tabRefs.current[item.id] = element; }}
          onClick={() => selectView(item.id)} onKeyDown={event => onTabKeyDown(event, index)}
          className={view === item.id ? 'primary-btn' : 'secondary-btn'}>
          {item.label}
        </button>)}
      </div>

      <div id="investigation-view-panel" role="tabpanel" aria-labelledby={`view-tab-${view}`}
        style={{ maxWidth: '1100px', width: '100%', margin: '0 auto', padding: '0 1.5rem' }}>
        {view === 'pipeline' && STAGES.map((stage, idx) => {
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
              borderRadius: 'var(--sp-radius-md)',
              background: bgColor,
              marginBottom: '1rem',
              overflow: 'hidden',
              transition: 'all 0.15s ease'
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
                      <p role="status">{hitlData.reviewReason}</p>
                      <button type="button" className="secondary-btn" onClick={() => setView('agents')}>Inspect agent assessments</button>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem', fontSize: '0.9rem' }}>
                        <div><strong>Heuristic evidence weight:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.confidence}</span><small> Actor probability is not calibrated.</small></div>
                        <div><strong>Attribution citations:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.blastRadius}</span></div>
                        <div><strong>Integrity:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.tamperCheck}</span></div>
                      </div>
                      <div style={{ display: 'flex', gap: '1rem' }}>
                        <button 
                          onClick={() => handleHitlAction('approve')}
                          disabled={isReviewing}
                          style={{ background: 'var(--sp-color-status-admissible)', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: 'var(--sp-radius-sharp)', cursor: 'pointer', fontWeight: 600 }}>
                          APPROVE DRAFT GENERATION
                        </button>
                        <button 
                          onClick={() => handleHitlAction('reject')}
                          disabled={isReviewing}
                          style={{ background: 'var(--sp-color-status-breach)', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: 'var(--sp-radius-sharp)', cursor: 'pointer', fontWeight: 600 }}>
                          REJECT / HALT
                        </button>
                        {isReviewing && <span role="status">Processing review and guardrails...</span>}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {view === 'agents' && <AgentsView snapshot={caseResult} />}
        {view === 'timeline' && <TimelineView snapshot={caseResult} />}
        {view === 'attack-graph' && <AttackGraphView snapshot={caseResult} />}
        {view === 'report' && <ReportView snapshot={caseResult} />}
      </div>
    </div>
  );
}
