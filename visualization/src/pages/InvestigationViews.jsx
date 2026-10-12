import { useEffect, useState } from 'react';
import { apiFetch } from '../lib/api';
import { localFetch } from '../lib/localApi';

const ROLE_PURPOSE = {
  supervisor: 'Routes the case to the relevant workers and decides whether specialist review is needed.',
  evidence_collection: 'Reads case-linked evidence and records deterministic triage decisions.',
  log_analysis: 'Checks process and file logs for supported detections.',
  network_forensics: 'Checks case-linked network events for supported anomalies.',
  memory_forensics: 'Examines available memory findings for injection or persistence indicators.',
  identity: 'Examines identity and credential activity.',
  cloud_container: 'Examines cloud and container activity.',
  malware_stylometry: 'Examines malware and code-style indicators.',
  insider_threat: 'Examines activity that may indicate insider misuse.',
  timeline_reconstruction: 'Orders cited findings by their recorded event times.',
  threat_attribution: 'Scores observed techniques against the available threat-intelligence corpus.',
  dag: 'Reviews possible attack paths and residual risk; a verified path requires structured evidence.',
  proponent: 'Argues a candidate explanation from the available findings.',
  critic: 'Challenges the candidate explanation and identifies evidence gaps.',
  judge: 'Evaluates the debate and decides whether the explanation is supported.',
  guardrail_tier3: 'Checks the final analysis for unsupported claims.',
  report_generation: 'Renders the cited case report from verified structured evidence.',
  timeline_artifact_generation: 'Renders the evidence timeline artifact.',
};

const panelStyle = {
  border: 'var(--sp-border-thin)',
  borderRadius: 'var(--sp-radius-md)',
  background: 'var(--sp-color-bg-surface)',
  padding: '1rem 1.25rem',
};

const proseStyle = {
  whiteSpace: 'pre-wrap',
  overflowWrap: 'anywhere',
  fontFamily: 'var(--sp-font-mono)',
  fontSize: '0.85rem',
  lineHeight: 1.6,
};

function EmptyView({ title, detail }) {
  return <div style={panelStyle} role="status">
    <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>{title}</h2>
    <p style={{ marginBottom: 0, color: 'var(--sp-color-text-secondary)' }}>{detail}</p>
  </div>;
}

function statusLabel(item) {
  if (item.paused_at?.includes('hitl')) return 'Awaiting review';
  if (item.case_status === 'closed' && item.acceptance_status === 'incomplete') return 'Closed with limitations';
  if (item.case_status === 'closed') return 'Completed';
  return item.case_status?.replaceAll('_', ' ') || 'In progress';
}

export function HistoryView() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        let response;
        try {
          response = await localFetch('/api/local/investigations/history');
        } catch {
          response = await apiFetch('http://localhost:8300/api/investigations/history');
        }
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `History returned HTTP ${response.status}`);
        if (!cancelled) setItems(data.investigations || []);
      } catch (cause) {
        if (!cancelled) setError(cause.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, []);

  if (loading) return <EmptyView title="Loading investigation history" detail="Reading saved case checkpoints…" />;
  if (error) return <div role="alert" style={panelStyle}>Could not load history: {error}</div>;
  if (!items.length) return <EmptyView title="No saved investigations" detail="Launch an investigation to create a case history entry." />;

  return <section aria-label="Previous investigations" style={{ display: 'grid', gap: '0.75rem' }}>
    <p style={{ color: 'var(--sp-color-text-secondary)', margin: 0 }}>
      Open a saved case to review its executed agents, timeline, attack graph analysis and report.
    </p>
    {items.map(item => <article key={item.case_id} style={panelStyle}>
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: '0.75rem' }}>
        <div>
          <a href={`/investigate?case=${encodeURIComponent(item.case_id)}&view=agents`}
            style={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{item.case_id}</a>
          <div style={{ color: 'var(--sp-color-text-secondary)', fontSize: '0.85rem' }}>
            Started {item.started_at ? new Date(item.started_at).toLocaleString() : 'time unavailable'}
          </div>
        </div>
        <strong>{statusLabel(item)}</strong>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem 1rem', marginTop: '0.75rem', fontSize: '0.85rem' }}>
        <span>{item.event_count} evidence events</span>
        <span>{item.agent_count} agent steps</span>
        <span>{item.finding_count} findings</span>
        <span>{item.has_timeline ? 'Timeline saved' : 'No timeline yet'}</span>
        <span>{item.has_attack_analysis ? 'Attack analysis saved' : 'No attack analysis yet'}</span>
        <span>{item.has_report ? 'Report saved' : 'No report yet'}</span>
      </div>
    </article>)}
  </section>;
}

export function AgentsView({ snapshot }) {
  if (!snapshot) return <EmptyView title="No case selected" detail="Open a saved investigation from History or launch a new one." />;
  const findingsByRole = new Map();
  for (const finding of snapshot.findings || []) {
    const role = finding.agent_role;
    findingsByRole.set(role, [...(findingsByRole.get(role) || []), finding]);
  }
  const occurrences = new Map();
  const executions = (snapshot.agent_traces || []).map((trace, index) => {
    const role = trace.agent_role || 'unknown';
    const occurrence = occurrences.get(role) || 0;
    occurrences.set(role, occurrence + 1);
    return { trace, index, finding: findingsByRole.get(role)?.[occurrence] };
  });
  if (!executions.length) return <EmptyView title="No agent steps saved yet" detail="Execution details will appear as checkpoints are written." />;
  return <section aria-label="Executed agents" style={{ display: 'grid', gap: '0.75rem' }}>
    <p style={{ color: 'var(--sp-color-text-secondary)', margin: 0 }}>
      Each card describes an executed step. Output and citations come from the saved checkpoint; model labels reflect actual invocation.
    </p>
    {executions.map(({ trace, index, finding }) => {
      const refs = trace.dfkg_refs || finding?.dfkg_refs || [];
      return <article key={`${trace.agent_role}-${index}`} style={panelStyle}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: '0.5rem' }}>
          <h2 style={{ margin: 0, fontSize: '1rem' }}>{index + 1}. {trace.agent_role?.replaceAll('_', ' ') || 'Agent'}</h2>
          <span style={{ fontFamily: 'var(--sp-font-mono)', fontSize: '0.8rem' }}>{trace.model_used || 'No model invoked'}</span>
        </div>
        <p style={{ marginBottom: '0.5rem' }}><strong>Purpose:</strong> {ROLE_PURPOSE[trace.agent_role] || 'Process the available case state.'}</p>
        <div style={{ color: 'var(--sp-color-text-secondary)', fontSize: '0.8rem' }}>
          Action: {trace.action || 'not recorded'}
          {trace.latency_ms != null && ` · ${trace.latency_ms} ms`}
          {trace.timestamp && ` · ${new Date(trace.timestamp).toLocaleString()}`}
        </div>
        <pre style={proseStyle}>{finding?.summary || trace.observation || 'No output text recorded.'}</pre>
        {refs.length > 0 && <div style={{ fontSize: '0.8rem', overflowWrap: 'anywhere' }}>
          Evidence ({refs.length}): {refs.slice(0, 8).join(', ')}{refs.length > 8 && ` and ${refs.length - 8} more`}
        </div>}
      </article>;
    })}
  </section>;
}

export function TimelineView({ snapshot }) {
  const [page, setPage] = useState(0);
  if (!snapshot) return <EmptyView title="No case selected" detail="Open a saved investigation to view its timeline." />;
  const reconstructed = snapshot.timeline?.events || [];
  const evidence = snapshot.evidence_collection?.records || [];
  const source = reconstructed.length ? reconstructed : evidence;
  const events = source.map((item, index) => ({
    id: item.uid || item.dfkg_refs?.[0] || `event-${index}`,
    time: item.time || item.timestamp || '',
    summary: item.summary || item.process_name || item.command_line ||
      [item.host_name, item.class_uid != null && `OCSF class ${item.class_uid}`].filter(Boolean).join(' · ') || 'Evidence event',
    severity: item.severity_id,
    refs: item.dfkg_refs || (item.uid ? [item.uid] : []),
  })).sort((a, b) => String(a.time).localeCompare(String(b.time)));
  const pageSize = 50;
  const pageCount = Math.max(1, Math.ceil(events.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  return <section aria-label="Reconstructed timeline" style={{ display: 'grid', gap: '0.75rem' }}>
    <div style={panelStyle}>
      <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Reconstructed timeline</h2>
      <p>{reconstructed.length
        ? `${reconstructed.length} cited timeline events saved by reconstruction.`
        : `${events.length} preserved evidence events ordered by their recorded timestamps. No structured reconstruction events were saved for this case.`}</p>
      {snapshot.timeline?.summary && <details><summary>Agent synthesis</summary><pre style={proseStyle}>{snapshot.timeline.summary}</pre></details>}
    </div>
    {events.length > 0 ? <>
      <ol start={currentPage * pageSize + 1} style={{ display: 'grid', gap: '0.5rem', paddingLeft: '1.5rem', margin: 0 }}>
        {events.slice(currentPage * pageSize, (currentPage + 1) * pageSize).map((event, index) => <li
          key={`${event.id}-${currentPage}-${index}`} style={panelStyle}>
          <time style={{ fontFamily: 'var(--sp-font-mono)', fontSize: '0.8rem' }}>{event.time || 'Time unavailable'}</time>
          <p style={{ margin: '0.4rem 0', overflowWrap: 'anywhere' }}>{event.summary}</p>
          <small>UID: {event.id}{event.severity != null ? ` · Severity ${event.severity}` : ''}</small>
          {event.refs.length > 1 && <small> · {event.refs.length} cited events</small>}
        </li>)}
      </ol>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <button type="button" className="secondary-btn" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
        <span>Page {currentPage + 1} of {pageCount}</span>
        <button type="button" className="secondary-btn" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>Next</button>
      </div>
    </> : <EmptyView title="No timeline events saved" detail="The investigation has not recorded a supported event chronology yet." />}
    {snapshot.timeline_artifact && <details style={panelStyle}>
      <summary>Saved evidence timeline artifact</summary>
      <pre style={proseStyle}>{snapshot.timeline_artifact}</pre>
    </details>}
  </section>;
}

export function AttackGraphView({ snapshot }) {
  if (!snapshot) return <EmptyView title="No case selected" detail="Open a saved investigation to view its attack graph analysis." />;
  const finding = (snapshot.findings || []).find(item => item.agent_role === 'dag');
  const trace = (snapshot.agent_traces || []).find(item => item.agent_role === 'dag');
  return <section aria-label="Dynamic attack graph" style={{ display: 'grid', gap: '0.75rem' }}>
    <div style={panelStyle}>
      <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Dynamic attack graph</h2>
      <p style={{ marginBottom: 0 }}>No verified exploit-path nodes or edges were saved for this case. The agent output below is analysis text, not a computed graph path.</p>
    </div>
    {finding ? <article style={panelStyle}>
      <h3 style={{ marginTop: 0 }}>Agent analysis</h3>
      <p style={{ color: 'var(--sp-color-text-secondary)', fontSize: '0.85rem' }}>
        Model: {trace?.model_used || 'not recorded'} · Evidence references: {finding.dfkg_refs?.length || 0}
      </p>
      <pre style={proseStyle}>{finding.summary}</pre>
    </article> : <EmptyView title="Attack graph step pending" detail="The Dynamic Attack Graph agent has not saved analysis for this case." />}
    <a href={`/neo4j?case=${encodeURIComponent(snapshot.case_id)}`}>View this case’s stored Neo4j relationships</a>
  </section>;
}

export function ReportView({ snapshot }) {
  const [kind, setKind] = useState('court');
  const [document, setDocument] = useState('');
  const [digest, setDigest] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [downloadUrl, setDownloadUrl] = useState('');
  const caseId = snapshot?.case_id;
  const hasReport = Boolean(snapshot?.report_output);
  useEffect(() => {
    let cancelled = false;
    setDocument(''); setError(''); setDigest('');
    if (!caseId || !hasReport) return () => { cancelled = true; };
    setLoading(true);
    const load = async () => {
      try {
        const response = caseId.startsWith('LOCAL-')
          ? await localFetch(`/api/local/cases/${encodeURIComponent(caseId)}/reports/${kind}`)
          : await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}/reports/${kind}`);
        if (!response.ok) throw new Error(`Report returned HTTP ${response.status}`);
        const text = await response.text();
        if (!cancelled) { setDocument(text); setDigest(response.headers.get('X-Report-SHA256') || ''); }
      } catch (cause) { if (!cancelled) setError(cause.message); }
      finally { if (!cancelled) setLoading(false); }
    };
    load();
    return () => { cancelled = true; };
  }, [caseId, hasReport, kind]);
  useEffect(() => {
    if (!document) { setDownloadUrl(''); return; }
    const url = URL.createObjectURL(new Blob([document], { type: 'text/html;charset=utf-8' }));
    setDownloadUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [document]);
  if (!snapshot) return <EmptyView title="No case selected" detail="Open a saved investigation to view its final report." />;
  if (!snapshot.report_output) return <EmptyView title="Report not generated yet"
    detail={snapshot.paused_at?.includes('hitl')
      ? 'This case is awaiting analyst review before final report generation.'
      : 'The investigation has not reached final report generation.'} />;
  const metadata = snapshot.report_metadata || {};
  return <section aria-label="Final generated reports" style={panelStyle}>
    <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Examination reports</h2>
    <label>Report format{' '}<select value={kind} onChange={event => setKind(event.target.value)}>
      <option value="court">Court submission report</option>
      <option value="technical">Technical cyber-team report</option>
    </select></label>
    {kind === 'court' && <p>Formal submission draft. Examiner review, qualifications, custody verification and admissibility review are required before filing.</p>}
    <p>Status: <strong>{metadata.status || snapshot.acceptance_status || 'unknown'}</strong>
      {metadata.generated_at && ` · Generated ${new Date(metadata.generated_at).toLocaleString()}`}</p>
    {metadata.degraded_flags?.length > 0 && <p>Limitations: {metadata.degraded_flags.join(', ')}</p>}
    <p>Reference: {snapshot.final_output_ref || 'No final output reference saved'}</p>
    {loading && <p role="status">Preparing report…</p>}
    {error && <p role="alert">{error}</p>}
    {downloadUrl && <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
      <a href={downloadUrl} download={`specula-${caseId}-${kind}.html`}>Download report (HTML)</a>
      <a href={downloadUrl} target="_blank" rel="noopener noreferrer">Open printable report / save as PDF</a>
    </div>}
    {digest && <p style={{ fontSize: '0.8rem', overflowWrap: 'anywhere' }}>Document SHA-256: {digest}</p>}
    {document && <iframe title={kind === 'court' ? 'Court submission report preview' : 'Technical report preview'}
      srcDoc={document} sandbox="" style={{ width: '100%', height: '80vh', border: 'var(--sp-border-thin)', background: '#fff' }} />}
    <details><summary>Original saved evidence report</summary><pre style={proseStyle}>{snapshot.report_output}</pre></details>
  </section>;
}
