import ReactFlow, { Background, Controls } from 'reactflow';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiFetch } from '../lib/api';
import { localFetch } from '../lib/localApi';
import CodeBlock from '../components/CodeBlock';

const ROLE_PURPOSE = {
  supervisor: 'Routes the case to the relevant workers and decides whether specialist review is needed.',
  evidence_collection: 'Reads case-linked evidence and records deterministic triage decisions.',
  log_analysis: 'Checks process and file logs for supported detections.',
  network_forensics: 'Checks case-linked network events for supported anomalies.',
  network_specialist: 'Correlates failed/successful flows and independently reviews primary network observations.',
  memory_forensics: 'Examines available memory findings for injection or persistence indicators.',
  identity: 'Examines identity and credential activity.',
  cloud_container: 'Examines cloud and container activity.',
  malware_stylometry: 'Examines malware and code-style indicators.',
  insider_threat: 'Examines activity that may indicate insider misuse.',
  timeline_reconstruction: 'Reconstructs source-linked episodes, preserves original times and records clock uncertainty.',
  threat_attribution: 'Scores observed techniques against the available threat-intelligence corpus.',
  dag: 'Builds source-cited activity relationships and candidate chains; verified exploitation requires separate reviewed evidence.',
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

function activityPositions(graph) {
  const levels = new Map(graph.nodes.map(node => [node.id, 0]));
  const incoming = new Map(graph.nodes.map(node => [node.id, 0]));
  const outgoing = new Map(graph.nodes.map(node => [node.id, []]));
  for (const edge of graph.edges) {
    if (!incoming.has(edge.target) || !outgoing.has(edge.source)) continue;
    incoming.set(edge.target, incoming.get(edge.target) + 1);
    outgoing.get(edge.source).push(edge.target);
  }
  const ready = [...incoming.keys()].filter(id => incoming.get(id) === 0);
  for (let index = 0; index < ready.length; index++) {
    const id = ready[index];
    for (const target of outgoing.get(id)) {
      levels.set(target, Math.max(levels.get(target), levels.get(id) + 1));
      incoming.set(target, incoming.get(target) - 1);
      if (incoming.get(target) === 0) ready.push(target);
    }
  }
  const groups = new Map();
  for (const node of graph.nodes) {
    const level = levels.get(node.id);
    groups.set(level, [...(groups.get(level) || []), node.id]);
  }
  const positions = new Map();
  let y = 0;
  for (const level of [...groups.keys()].sort((a, b) => a - b)) {
    const ids = groups.get(level);
    ids.forEach((id, index) => positions.set(id, { x: (index % 5) * 300, y: y + Math.floor(index / 5) * 180 }));
    y += Math.ceil(ids.length / 5) * 180 + 80;
  }
  return positions;
}

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
          <Link to={`/history/${encodeURIComponent(item.case_id)}?view=agents`}
            className="secondary-btn"
            style={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{item.case_id}</Link>
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

function SandboxReceipts({ caseId, receipts }) {
  const [downloading, setDownloading] = useState('');
  const [error, setError] = useState('');
  const download = async receipt => {
    setDownloading(receipt.uid); setError('');
    try {
      const suffix = `/sandbox/${encodeURIComponent(receipt.uid)}/report`;
      const response = caseId.startsWith('LOCAL-')
        ? await localFetch(`/api/local/cases/${encodeURIComponent(caseId)}${suffix}`)
        : await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}${suffix}`);
      if (!response.ok) throw new Error(`Sandbox report returned HTTP ${response.status}`);
      const bytes = await response.arrayBuffer();
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
        .map(byte => byte.toString(16).padStart(2, '0')).join('');
      if (digest !== receipt.report_sha256) throw new Error('Sandbox report digest does not match the saved receipt');
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url; link.download = `cape-${caseId}-${receipt.cape_task_id}.json`;
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (cause) { setError(cause.message); }
    finally { setDownloading(''); }
  };
  return <section aria-label="CAPE sandbox examinations" style={{ marginBlock: '1rem' }}>
    <h3 style={{ fontSize: '1rem' }}>CAPE dynamic analysis</h3>
    <p>Results describe an isolated laboratory guest. They do not establish execution on the investigated host.</p>
    {receipts.map((receipt, index) => <div key={receipt.uid || index} style={{ ...panelStyle, marginBottom: '0.5rem' }}>
      <p><strong>Status: {receipt.status}</strong>{receipt.cape_task_id && ` · CAPE task ${receipt.cape_task_id}`}</p>
      <p>{receipt.limitation}</p>
      {receipt.sample_sha256 && <p style={{ overflowWrap: 'anywhere' }}>Sample SHA-256: {receipt.sample_sha256}</p>}
      {receipt.report_sha256 && <button type="button" className="secondary-btn" disabled={Boolean(downloading)} onClick={() => download(receipt)}>
        {downloading === receipt.uid ? 'Downloading CAPE report…' : 'Download CAPE report (JSON)'}
      </button>}
      <details><summary>Recorded observations and coverage</summary>
        <CodeBlock language="json" caption="Sandbox examination receipt" value={receipt} />
      </details>
    </div>)}
    {downloading && <p role="status">Verifying sandbox report download…</p>}
    {error && <p role="alert">{error}</p>}
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
  return <section className="review-content" aria-label="Executed agents" style={{ display: 'grid', gap: '1.25rem' }}>
    <p style={{ color: 'var(--sp-color-text-secondary)', margin: 0 }}>
      Each card describes an executed step. Output and citations come from the saved checkpoint; model labels reflect actual invocation.
    </p>
    {executions.map(({ trace, index, finding }) => {
      const refs = trace.dfkg_refs || finding?.dfkg_refs || [];
      return <article className="review-card" key={`${trace.agent_role}-${index}`} style={panelStyle}>
        <div className="agent-heading">
          <h2 style={{ margin: 0, fontSize: '1rem' }}>{index + 1}. {trace.agent_role?.replaceAll('_', ' ') || 'Agent'}</h2>
          <span className="model-badge">{trace.model_used || 'No model invoked'}</span>
        </div>
        <p><strong>Purpose:</strong> {ROLE_PURPOSE[trace.agent_role] || 'Process the available case state.'}</p>
        <dl className="agent-metadata">
          <div><dt>Action</dt><dd>{trace.action?.replaceAll('_', ' ') || 'Not recorded'}</dd></div>
          {trace.latency_ms != null && <div><dt>Duration</dt><dd>{(trace.latency_ms / 1000).toFixed(2)} seconds</dd></div>}
          {trace.timestamp && <div><dt>Executed</dt><dd>{new Date(trace.timestamp).toLocaleString()}</dd></div>}
        </dl>
        <p className="agent-observation">{finding?.summary || trace.observation || 'No output text recorded.'}</p>
        {trace.sandbox_examinations?.length > 0 && <SandboxReceipts caseId={snapshot.case_id} receipts={trace.sandbox_examinations} />}
        {trace.review_coverage && <dl className="review-coverage">
          {trace.review_unit && <div><dt>Review unit</dt><dd>{trace.review_unit.replaceAll('_', ' ')}</dd></div>}
          {trace.preserved_event_count != null && <div><dt>Preserved source events</dt><dd>{trace.preserved_event_count}</dd></div>}
          <div><dt>Review coverage</dt><dd>{trace.review_coverage.submitted} / {trace.review_coverage.total} submitted; {trace.review_coverage.validated} valid responses</dd></div>
          <div><dt>Review status</dt><dd>{trace.review_coverage.complete ? 'Complete' : 'Incomplete — human review required'}</dd></div>
        </dl>}
        {trace.model_output && <details><summary>Recorded model assessment · {trace.model_output_validated ? 'validated response' : 'rejected output'}</summary>
          <CodeBlock language="json" caption="Recorded model assessment" value={trace.model_output} />
          <p className="review-note">Validation checks response structure and case references. Model assessments remain analysis, not source evidence.</p>
          {(trace.review_batches || trace.review_attempts) && <details><summary>Review batches and retry results</summary>
            <CodeBlock language="json" caption="Review batches and retry results" value={trace.review_batches || trace.review_attempts} />
          </details>}
        </details>}
        {refs.length > 0 && <details><summary>Evidence references ({refs.length})</summary>
          <CodeBlock caption="Evidence identifiers" value={refs.join('\n')} />
        </details>}
      </article>;
    })}
  </section>;
}

export { default as TimelineView } from './EvidenceTimeline';

export function AttackGraphView({ snapshot }) {
  if (!snapshot) return <EmptyView title="No case selected" detail="Open a saved investigation to view its attack graph analysis." />;
  const graph = snapshot.attack_graph;
  const positions = graph ? activityPositions(graph) : new Map();
  const finding = (snapshot.findings || []).find(item => item.agent_role === 'dag');
  const trace = (snapshot.agent_traces || []).find(item => item.agent_role === 'dag');
  return <section aria-label="Dynamic attack graph" style={{ display: 'grid', gap: '0.75rem' }}>
    <div style={panelStyle}>
      <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Dynamic attack graph</h2>
      <p style={{ marginBottom: 0 }}>{graph ? 'Cited observations and source records linked by temporal or explicit identifier relationships. Candidate chains do not establish causation, one actor or verified exploitation.' : 'No verified exploit-path nodes or edges were saved for this case. Historical model prose is unverified.'}</p>
    </div>
    {snapshot.exploit_topology && <article style={panelStyle}>
      <h3>Analyst-reviewed exploit topology</h3>
      <p>Reviewed by {snapshot.exploit_topology.reviewed_by}. Path: {snapshot.exploit_topology.path.join(' → ') || 'No path'}.</p>
      <p>{snapshot.exploit_topology.path_conditional_probability === null
        ? 'Probability unavailable: calibrated inputs were not supplied.'
        : `Conditional model probability: ${snapshot.exploit_topology.path_conditional_probability}. This is not observed case certainty.`}</p>
      <details><summary>Topology, calibration citations and assumptions</summary><CodeBlock language="json" caption="Exploit topology" value={snapshot.exploit_topology} /></details>
    </article>}
    {graph && <>
      <div style={{ height: '60vh', minHeight: 400, border: 'var(--sp-border-thin)' }}>
        <ReactFlow fitView nodes={graph.nodes.map(node => ({ id: node.id,
          position: positions.get(node.id),
          style: { borderStyle: node.node_kind === 'evidence' ? 'dashed' : 'solid', width: 240 },
          data: { label: `${node.node_kind === 'evidence' ? 'Source record' : 'Observation'}: ${node.label.replaceAll('_', ' ')}\n${node.effect_scope === 'sandbox_execution' ? 'CAPE laboratory guest' : node.canonical_host_id || 'Host unknown'}\n${node.classification || 'Unresolved'} / ${node.operation_outcome || 'Outcome unknown'}\n${node.dfkg_refs.length} cited events` } }))}
          edges={graph.edges.map(edge => ({ ...edge, id: edge.id || `${edge.type}-${edge.source}-${edge.target}`, label: edge.type }))}>
          <Background /><Controls />
        </ReactFlow>
      </div>
      <p>{graph.observation_count ?? graph.nodes.length} observations; {graph.related_evidence_count || 0} source records; {graph.edges.length} links. Solid boxes: observations. Dashed boxes: source records. PRECEDES: temporal association. Other links: source correlations.</p>
      {graph.activity_paths?.length > 0 && <details style={panelStyle}><summary>Candidate activity chains ({graph.activity_paths.length})</summary>
        <p>Longest source-relation chains. No exploit probability is calculated.</p>
        {graph.activity_paths.map((path, index) => <p key={index}>{path.nodes.map(id => graph.nodes.find(node => node.id === id)?.summary || id).join(' ? ')}</p>)}
      </details>}
      <details style={panelStyle}><summary>Relationship evidence and basis</summary><CodeBlock language="json" caption="Relationship evidence" value={graph.source_relations || graph.edges} /></details>
      <details><summary>Graph records ({graph.nodes.length})</summary>
      {graph.nodes.map(node => <article key={node.id} style={panelStyle}>
        <strong>{node.label.replaceAll('_', ' ')}</strong><p>{node.summary}</p>
        <small>{node.time} ? Evidence: {node.dfkg_refs.join(', ')}</small>
      </article>)}</details>
    </>}
    {!graph && finding ? <article style={panelStyle}>
      <h3 style={{ marginTop: 0 }}>Agent analysis</h3>
      <p style={{ color: 'var(--sp-color-text-secondary)', fontSize: '0.85rem' }}>
        Model: {trace?.model_used || 'not recorded'} · Evidence references: {finding.dfkg_refs?.length || 0}
      </p>
      <CodeBlock caption="Saved attack analysis" value={finding.summary} />
    </article> : <EmptyView title={graph ? "Exploit-path calculation unavailable" : "Attack graph step pending"} detail={graph ? graph.limitations.join(" ") : "The Dynamic Attack Graph agent has not saved analysis for this case."} />}
    <Link className="secondary-btn" to={`/history/${encodeURIComponent(snapshot.case_id)}?view=neo4j`}>View this case’s stored Neo4j relationships</Link>
  </section>;
}

export function ReportView({ snapshot }) {
  const [kind, setKind] = useState('court');
  const [documentMetadata, setDocumentMetadata] = useState({});
  const [document, setDocument] = useState('');
  const [digest, setDigest] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [downloadUrl, setDownloadUrl] = useState('');
  const [retry, setRetry] = useState(0);
  const caseId = snapshot?.case_id;
  const hasReport = Boolean(snapshot?.report_output);
  useEffect(() => {
    let cancelled = false;
    setDocument(''); setError(''); setDigest('');
    setDocumentMetadata({});
    if (!caseId || !hasReport) return () => { cancelled = true; };
    setLoading(true);
    const load = async () => {
      try {
        const response = caseId.startsWith('LOCAL-')
          ? await localFetch(`/api/local/cases/${encodeURIComponent(caseId)}/reports/${kind}`)
          : await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}/reports/${kind}`);
        if (!response.ok) {
          const problem = await response.json().catch(() => ({}));
          throw new Error(problem.detail || `Report returned HTTP ${response.status}`);
        }
        const pdf = await response.blob();
        if (!cancelled) {
          setDocument(pdf);
          setDigest(response.headers.get('X-Report-SHA256') || '');
          setDocumentMetadata({
            status: response.headers.get('X-Report-Status'),
            generated_at: response.headers.get('X-Report-Generated-At'),
          });
        }
      } catch (cause) { if (!cancelled) setError(cause.message); }
      finally { if (!cancelled) setLoading(false); }
    };
    load();
    return () => { cancelled = true; };
  }, [caseId, hasReport, kind, retry]);
  useEffect(() => {
    if (!document) { setDownloadUrl(''); return; }
    const url = URL.createObjectURL(document);
    setDownloadUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [document]);
  if (!snapshot) return <EmptyView title="No case selected" detail="Open a saved investigation to view its final report." />;
  if (!snapshot.report_output) return <EmptyView title="Report not generated yet"
    detail={snapshot.paused_at?.includes('hitl')
      ? 'This case is awaiting analyst review before final report generation.'
      : 'The investigation has not reached final report generation.'} />;
  const metadata = { ...snapshot.report_metadata, ...documentMetadata };
  return <section className="report-view review-content" aria-label="Final generated reports" style={panelStyle}>
    <h2 style={{ margin: 0, fontSize: '1.35rem' }}>Examination reports</h2>
    <label className="report-selector">Report type{' '}<select value={kind} onChange={event => setKind(event.target.value)}>
      <option value="court">Court submission report</option>
      <option value="technical">Technical cyber-team report</option>
    </select></label>
    {kind === 'court' && <p>Formal submission draft. Examiner review, qualifications, custody verification and admissibility review are required before filing.</p>}
    {kind === 'technical' && <p>Telemetry coverage, detection analysis, event details and analyst follow-up.</p>}
    <dl className="report-metadata">
      <div><dt>Status</dt><dd><span className="report-status">{metadata.status || snapshot.acceptance_status || 'Unknown'}</span></dd></div>
      <div><dt>Generated</dt><dd>{metadata.generated_at ? new Date(metadata.generated_at).toLocaleString() : 'Not recorded'}</dd></div>
    </dl>
    {metadata.degraded_flags?.length > 0 && <section className="report-limitations"><h3>Limitations requiring review</h3>
      <ul>{metadata.degraded_flags.map(flag => <li key={flag}>{flag.replaceAll('_', ' ').replace(/^./, char => char.toUpperCase())}</li>)}</ul>
    </section>}
    {snapshot.final_output_ref && <CodeBlock caption="Saved report reference" value={snapshot.final_output_ref} />}
    {loading && <p role="status">Preparing report…</p>}
    {error && <div role="alert"><p>{error}</p><button type="button" className="secondary-btn" onClick={() => setRetry(value => value + 1)}>Retry PDF download</button></div>}
    {downloadUrl && <div className="report-actions">
      <a className="secondary-btn" href={downloadUrl} download={`specula-${caseId}-${kind}.pdf`}>Download report (PDF)</a>
      <a className="secondary-btn" href={downloadUrl} target="_blank" rel="noopener noreferrer">Open PDF</a>
    </div>}
    {digest && <CodeBlock caption="Document SHA-256" value={digest} />}
    {downloadUrl && <iframe title={kind === 'court' ? 'Court submission report preview' : 'Technical report preview'}
      src={downloadUrl} style={{ width: '100%', height: '80vh', border: 'var(--sp-border-thin)', background: '#fff' }} />}
    <details><summary>Original saved evidence report</summary><CodeBlock language="markdown" caption="Original evidence report" value={snapshot.report_output} /></details>
  </section>;
}
