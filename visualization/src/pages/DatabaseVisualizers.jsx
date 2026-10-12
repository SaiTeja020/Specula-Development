import { useEffect, useState } from 'react';
import { Database, Search, Activity, Box } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { localFetch } from '../lib/localApi';

const STORES = [
  { id: 'quickwit', name: 'Quickwit (Logs)', icon: Search },
  { id: 'duckdb', name: 'DuckDB (Analytics)', icon: Activity },
  { id: 'chroma', name: 'ChromaDB (Embeddings)', icon: Database },
  { id: 'faiss', name: 'FAISS (Threat Intel)', icon: Box },
];

function storeSummary(id, payload) {
  if (payload.error) return payload.error;
  if (payload.status !== 'success' && payload.status !== 'ready') return 'Store unavailable';
  if (id === 'quickwit') return `${payload.logs?.length ?? 0} recent preserved records`;
  if (id === 'chroma') return `${payload.collections?.length ?? 0} collections`;
  if (id === 'faiss') return `${payload.total_vectors ?? 0} indexed vectors`;
  return `${payload.tables?.length ?? 0} tables`;
}

export default function DatabaseVisualizers() {
  const [data, setData] = useState({});
  const [activeStore, setActiveStore] = useState(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all(STORES.map(async ({ id }) => {
      try {
        let response;
        try {
          response = await localFetch(`/api/local/data/${id}`);
        } catch {
          response = await apiFetch(`http://localhost:8300/api/data/${id}`);
        }
        const payload = await response.json();
        return [id, response.ok ? payload : { error: response.status === 403
          ? 'Administrator access required' : (payload.detail || `HTTP ${response.status}`) }];
      } catch {
        return [id, { error: 'Store status could not be loaded' }];
      }
    })).then(entries => { if (!cancelled) setData(Object.fromEntries(entries)); });
    return () => { cancelled = true; };
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', padding: '1.5rem', overflowY: 'auto' }}>
      <h1 style={{ margin: 0 }}>Data Store Monitors</h1>
      <div className="db-grid">
        {STORES.map(({ id, name, icon: Icon }) => (
          <button key={id} type="button" className="db-card glass-panel"
            onClick={() => setActiveStore(id)}
            style={{ textAlign: 'left', cursor: 'pointer', color: 'inherit' }}>
            <div className="db-card-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Icon size={20} /><strong>{name}</strong>
            </div>
            <p>{data[id] ? storeSummary(id, data[id]) : 'Loading...'}</p>
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
            <button type="button" onClick={() => setActiveStore(null)}>Close</button>
          </div>
          <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
            {JSON.stringify(data[activeStore] ?? { status: 'loading' }, null, 2)}
          </pre>
        </div>
      </div>}
    </div>
  );
}
