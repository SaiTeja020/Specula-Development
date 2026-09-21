import { Link } from 'react-router-dom';
import { Zap, Network, Database, BrainCircuit } from 'lucide-react';

export default function LandingPage() {
  return (
    <div className="landing-hero">
      <div style={{ marginBottom: '2rem' }}>
        <img src="/Specula_logo.png" alt="Specula Logo" style={{ height: '100px' }} />
      </div>
      <h1 className="landing-title">
        Specula Multi-Agent DFIR
      </h1>
      <p className="landing-subtitle">
        Asynchronous, event-driven, multi-agent digital forensics platform. 
        Ingest, process, and analyze telemetry at scale with immutable provenance and cryptographic integrity.
      </p>
      
      <div className="button-group">
        <Link to="/startup" className="primary-btn" style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <Zap size={18} /> Initialize System
        </Link>
        <Link to="/investigate" className="secondary-btn" style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <BrainCircuit size={18} /> Resume Investigation
        </Link>
      </div>

      <div style={{ marginTop: '5rem', display: 'flex', gap: '4rem', color: 'var(--text-secondary)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
          <Network size={32} />
          <span style={{ fontWeight: 600 }}>LangGraph Orchestration</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
          <Database size={32} />
          <span style={{ fontWeight: 600 }}>Neo4j / Quickwit Core</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
          <BrainCircuit size={32} />
          <span style={{ fontWeight: 600 }}>ACH Debate Loop</span>
        </div>
      </div>
    </div>
  );
}
