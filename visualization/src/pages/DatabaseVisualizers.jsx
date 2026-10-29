import { useEffect, useRef, useState } from 'react';
import { Database, Search, Activity, Box } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { localFetch } from '../lib/localApi';
import { startPolling } from '../lib/polling';
import CodeBlock from '../components/CodeBlock';

const STORES = [
  { id: 'quickwit', name: 'Quickwit (Logs)', icon: Search },
  { id: 'duckdb', name: 'DuckDB (Analytics)', icon: Activity },
  { id: 'chroma', name: 'ChromaDB (Embeddings)', icon: Database },
  { id: 'faiss', name: 'FAISS (Threat Intel)', icon: Box },
];

function storeSummary(id, payload) {
  if (payload.error) return payload.error;
  if (payload.status !== 'success' && payload.status !== 'ready') return payload.detail || 'Store unavailable';
  if (id === 'quickwit') return `${payload.total_records ?? payload.logs?.length ?? 0} matching preserved records (${payload.logs?.length ?? 0} displayed)`;
  if (id === 'chroma') return payload.total_vectors !== undefined
    ? payload.total_events !== undefined
      ? `${payload.total_vectors} semantic chunks covering ${payload.total_events} events`
      : `${payload.total_vectors} vectors across ${payload.collections?.length ?? 0} collections`
    : `${payload.collections?.length ?? 0} collections`;
  if (id === 'faiss') return `${payload.total_vectors ?? 0} indexed vectors`;
  return payload.metrics?.indexed_cases !== undefined ? `${payload.metrics.indexed_cases} indexed case snapshots` : `${payload.tables?.length ?? 0} tables`;
}

export default function DatabaseVisualizers({ caseId = '' }) {
  const [data, setData] = useState({});
  const [activeStore, setActiveStore] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [checkedAt, setCheckedAt] = useState(null);
  const refreshRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    setData({}); setCheckedAt(null); setActiveStore(null);
    const load = async () => {
      setRefreshing(true);
      const entries = await Promise.all(STORES.map(async ({ id }) => {
      try {
        let response;
        try {
          if (caseId && !caseId.startsWith('LOCAL-')) throw new Error('Use authenticated case API');
          response = await localFetch(`/api/local/data/${id}${caseId ? `?case_id=${encodeURIComponent(caseId)}` : ''}`, { cache: 'no-store' });
        } catch {
          response = await apiFetch(caseId
            ? `http://localhost:8300/api/investigations/${encodeURIComponent(caseId)}/stores/${id}`
            : `http://localhost:8300/api/data/${id}`, { cache: 'no-store' });
        }
        const payload = await response.json();
        return [id, response.ok ? payload : { error: payload.detail || `HTTP ${response.status}` }];
      } catch {
        return [id, { error: 'Store status could not be loaded' }];
      }
      }));
      if (!cancelled) {
        setData(Object.fromEntries(entries)); setCheckedAt(new Date()); setRefreshing(false);
      }
    };
    const poller = startPolling(load);
    refreshRef.current = poller.refresh;
    return () => { cancelled = true; poller.stop(); refreshRef.current = null; };
  }, [caseId]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', padding: '1.5rem', overflowY: 'auto' }}>
      <h1 style={{ margin: 0 }}>Data Store Monitors</h1>
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <button type="button" className="secondary-btn" disabled={refreshing} onClick={() => refreshRef.current?.()}>Refresh now</button>
        <span role="status">{refreshing ? 'Checking stores…' : checkedAt ? `Last checked ${checkedAt.toLocaleTimeString()}` : 'Waiting to refresh'}</span>
        <span>Auto-refresh every 10 seconds while this tab is visible.</span>
      </div>
      <p>Quickwit and ChromaDB query the current stores. DuckDB contains saved case analytics; FAISS is a shared reference corpus and changes when the index is rebuilt.</p>
      {caseId && <p>Evidence stores for {caseId}. FAISS is shared threat intelligence, not case evidence.</p>}
      <div className="db-grid">
        {STORES.map(({ id, name, icon: Icon }) => (
          <button key={id} type="button" className="db-card glass-panel"
            onClick={() => setActiveStore(id)}
            style={{ textAlign: 'left', cursor: 'pointer', color: 'inherit' }}>
            <div className="db-card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Icon size={20} /><strong>{name}</strong>
            </div>
            <p>{data[id] ? storeSummary(id, data[id]) : 'Loading...'}</p>
            {data[id]?.warning && <p>{data[id].warning}</p>}
          </button>
        ))}
      </div>
      {activeStore && <div role="dialog" aria-modal="true" aria-label={`${activeStore} details`}
        onClick={() => setActiveStore(null)}
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.7)', zIndex: 1000,
          display: 'grid', placeItems: 'center', padding: '1rem' }}>
        <div className="glass-panel" onClick={event => event.stopPropagation()}
          style={{ maxWidth: '800px', width: '100%', maxHeight: '80vh', overflow: 'auto', padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2>{STORES.find(store => store.id === activeStore)?.name}</h2>
            <button type="button" className="secondary-btn" onClick={() => setActiveStore(null)}>Close</button>
          </div>
          <CodeBlock language="json" caption={`${activeStore} store response`} value={data[activeStore] ?? { status: 'loading' }} />
        </div>
      </div>}
    </div>
  );
}
