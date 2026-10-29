import { useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { localFetch } from '../lib/localApi';
import { apiFetch } from '../lib/api';
import { AgentsView, AttackGraphView, HistoryView, ReportView, TimelineView } from './InvestigationViews';
import DatabaseVisualizers from './DatabaseVisualizers';
import Neo4jVisualizer from './Neo4jVisualizer';

const VIEWS = [
  ['agents', 'Agents'], ['timeline', 'Timeline'], ['attack-graph', 'Attack Graph'],
  ['report', 'Report'], ['stores', 'Data Stores'], ['neo4j', 'Neo4j Graph'],
];

export default function InvestigationHistory() {
  const { caseId } = useParams();
  const [params, setParams] = useSearchParams();
  const requested = params.get('view');
  const view = VIEWS.some(([id]) => id === requested) ? requested : 'agents';
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let cancelled = false;
    if (!caseId) return;
    const load = async () => {
      try {
        let response;
        try {
          if (!caseId.startsWith('LOCAL-')) throw new Error('Use authenticated case API');
          response = await localFetch(`/api/local/cases/${encodeURIComponent(caseId)}`);
        } catch {
          response = await apiFetch(`http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}`);
        }
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
        if (!cancelled) { setResult(payload); setError(''); }
      } catch (cause) {
        if (!cancelled) { setError(cause.message); setResult(null); }
      }
    };
    load();
    return () => { cancelled = true; };
  }, [caseId, revision]);

  const snapshot = result?.case_id === caseId ? result : null;
  return <div style={{ padding: '1.5rem', overflowY: 'auto', height: '100%', boxSizing: 'border-box' }}>
    <h1>Investigation History</h1>
    {!caseId ? <HistoryView /> : <>
      <Link to="/history" className="secondary-btn">Back to all cases</Link>
      <h2 style={{ overflowWrap: 'anywhere' }}>Case: {caseId}</h2>
      <p>Saved case review{snapshot?.case_status ? ` · ${snapshot.case_status.replaceAll('_', ' ')}` : ''}</p>
      <button type="button" className="secondary-btn" onClick={() => { setError(''); setResult(null); setRevision(value => value + 1); }}>Refresh saved case</button>
      <nav aria-label="Saved case views" style={{ display: 'flex', flexWrap: 'wrap', gap: '.75rem', margin: '1rem 0' }}>
        {VIEWS.map(([id, label]) => <button key={id} type="button" aria-pressed={view === id}
          className={view === id ? 'primary-btn' : 'secondary-btn'}
          onClick={() => setParams({ view: id })}>{label}</button>)}
      </nav>
      {error ? <p role="alert">Could not load case: {error}</p> : !snapshot ? <p role="status">Loading saved case…</p> :
        <section key={`${caseId}:${revision}`} aria-label={`${caseId} ${view}`}>
          {view === 'agents' && <AgentsView snapshot={snapshot} />}
          {view === 'timeline' && <TimelineView snapshot={snapshot} />}
          {view === 'attack-graph' && <AttackGraphView snapshot={snapshot} />}
          {view === 'report' && <ReportView snapshot={snapshot} />}
          {view === 'stores' && <DatabaseVisualizers caseId={caseId} />}
          {view === 'neo4j' && <div style={{ height: '75vh', minHeight: 500 }}><Neo4jVisualizer caseId={caseId} /></div>}
        </section>}
    </>}
  </div>;
}
