import { useState, useEffect } from 'react';
import { Database, Search, Activity, Box } from 'lucide-react';

export default function DatabaseVisualizers() {
  const [data, setData] = useState({
    quickwit: null,
    chroma: null,
    duckdb: null,
    faiss: null
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [qw, ch, dd, fa] = await Promise.all([
          fetch('http://localhost:8300/api/data/quickwit').then(r => r.json()),
          fetch('http://localhost:8300/api/data/chroma').then(r => r.json()),
          fetch('http://localhost:8300/api/data/duckdb').then(r => r.json()),
          fetch('http://localhost:8300/api/data/faiss').then(r => r.json())
        ]);
        
        setData({
          quickwit: qw,
          chroma: ch,
          duckdb: dd,
          faiss: fa
        });
      } catch (err) {
        console.error("Error fetching DB data:", err);
      }
    };
    fetchData();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1.5rem', overflowY: 'auto', paddingRight: '1rem' }}>
      <div className="header" style={{ marginBottom: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <img src="/specula-logo.svg" alt="Specula Logo" style={{ height: '24px' }} />
          <h1 style={{ fontSize: '1.5rem', margin: 0 }}>Data Store Monitors</h1>
        </div>
      </div>

      <div className="db-grid">
        {/* Quickwit Panel */}
        <div className="db-card glass-panel">
          <div className="db-card-header">
            <Search size={20} color="var(--accent-secondary)" />
            <span>Quickwit (Logs)</span>
          </div>
          <div style={{ background: 'rgba(11, 15, 25, 0.5)', padding: '1rem', borderRadius: '8px', fontSize: '0.85rem' }}>
            {data.quickwit ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {data.quickwit.logs.map(log => (
                  <div key={log.event_id} style={{ borderLeft: `2px solid ${log.level === 'WARN' ? 'var(--warning)' : 'var(--accent-secondary)'}`, paddingLeft: '0.5rem' }}>
                    <div style={{ color: 'var(--text-secondary)' }}>{log.timestamp}</div>
                    <div>{log.message}</div>
                  </div>
                ))}
              </div>
            ) : "Loading..."}
          </div>
        </div>

        {/* DuckDB Panel */}
        <div className="db-card glass-panel">
          <div className="db-card-header">
            <Activity size={20} color="var(--success)" />
            <span>DuckDB (Analytics)</span>
          </div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            {data.duckdb ? (
              <>
                <div style={{ background: 'rgba(11, 15, 25, 0.5)', padding: '1rem', borderRadius: '8px', flex: 1 }}>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Bytes Transferred</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>{data.duckdb.metrics.total_bytes_transferred}</div>
                </div>
                <div style={{ background: 'rgba(11, 15, 25, 0.5)', padding: '1rem', borderRadius: '8px', flex: 1 }}>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Unique Procs</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>{data.duckdb.metrics.unique_processes}</div>
                </div>
              </>
            ) : "Loading..."}
          </div>
        </div>

        {/* ChromaDB Panel */}
        <div className="db-card glass-panel">
          <div className="db-card-header">
            <Database size={20} color="var(--accent)" />
            <span>ChromaDB (Embeddings)</span>
          </div>
          <div style={{ background: 'rgba(11, 15, 25, 0.5)', padding: '1rem', borderRadius: '8px', fontSize: '0.85rem' }}>
            {data.chroma ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div style={{ color: 'var(--text-secondary)' }}>Collections: {data.chroma.collections.join(', ')}</div>
                <div style={{ marginTop: '0.5rem' }}>Recent Query:</div>
                <div style={{ padding: '0.5rem', background: 'rgba(255,255,255,0.05)', borderRadius: '4px' }}>
                  "{data.chroma.recent_queries[0].query}" ({data.chroma.recent_queries[0].matches} matches)
                </div>
              </div>
            ) : "Loading..."}
          </div>
        </div>

        {/* FAISS Panel */}
        <div className="db-card glass-panel">
          <div className="db-card-header">
            <Box size={20} color="var(--warning)" />
            <span>FAISS (Threat Intel)</span>
          </div>
          <div style={{ background: 'rgba(11, 15, 25, 0.5)', padding: '1rem', borderRadius: '8px', fontSize: '0.85rem' }}>
            {data.faiss ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div style={{ color: 'var(--text-secondary)' }}>Index Type: {data.faiss.index_type}</div>
                <div style={{ color: 'var(--text-secondary)' }}>Total Vectors: {data.faiss.total_vectors.toLocaleString()}</div>
                <div style={{ marginTop: '0.5rem' }}>Top Hit:</div>
                <div style={{ padding: '0.5rem', background: 'rgba(245, 158, 11, 0.1)', color: 'var(--warning)', borderRadius: '4px', fontWeight: 600 }}>
                  {data.faiss.recent_hits[0].cve} - Score: {data.faiss.recent_hits[0].score}
                </div>
              </div>
            ) : "Loading..."}
          </div>
        </div>
      </div>
    </div>
  );
}
