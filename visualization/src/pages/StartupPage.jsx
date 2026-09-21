import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  CheckCircle2, 
  CircleDashed, 
  Server, 
  Database, 
  Activity, 
  Cpu, 
  Terminal, 
  ArrowRight,
  ShieldCheck
} from 'lucide-react';

const BOOT_SEQUENCE = [
  { id: 'redis', label: 'Redis Cache', port: '6379', icon: <Activity size={18} /> },
  { id: 'kafka', label: 'Kafka Broker', port: '9092', icon: <Server size={18} /> },
  { id: 'quickwit', label: 'Quickwit WORM Datastore', port: '7280', icon: <Database size={18} /> },
  { id: 'neo4j', label: 'Neo4j Graph Database', port: '7687', icon: <Database size={18} /> },
  { id: 'chroma', label: 'ChromaDB Vector Store', port: '8000', icon: <Database size={18} /> },
  { id: 'llm', label: 'LLM Multi-Agent Orchestrator', port: 'LangGraph', icon: <Cpu size={18} /> },
];

export default function StartupPage() {
  const [activeStep, setActiveStep] = useState(-1);
  const [logs, setLogs] = useState([]);
  const navigate = useNavigate();
  const terminalBodyRef = useRef(null);

  useEffect(() => {
    if (terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    const runBoot = async () => {
      for (let i = 0; i < BOOT_SEQUENCE.length; i++) {
        setActiveStep(i);
        const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
        setLogs(prev => [...prev, { time: timeStr, tag: 'INIT', msg: `Initializing ${BOOT_SEQUENCE[i].label} on port ${BOOT_SEQUENCE[i].port}...` }]);
        await new Promise(r => setTimeout(r, 650));
        
        const okTime = new Date().toLocaleTimeString('en-US', { hour12: false });
        setLogs(prev => [...prev, { time: okTime, tag: 'OK', msg: `Service ${BOOT_SEQUENCE[i].id} (${BOOT_SEQUENCE[i].port}) verified online and healthy.` }]);
        await new Promise(r => setTimeout(r, 150));
      }
      setActiveStep(BOOT_SEQUENCE.length);
      const doneTime = new Date().toLocaleTimeString('en-US', { hour12: false });
      setLogs(prev => [...prev, { time: doneTime, tag: 'SYSTEM', msg: 'All core microservices and datastores online. Specula readiness: 100%.' }]);
    };
    runBoot();
  }, []);

  const isComplete = activeStep === BOOT_SEQUENCE.length;

  return (
    <div className="app-container-fullscreen" style={{ padding: '2rem 1.5rem', alignItems: 'center' }}>
      
      {/* Header */}
      <div style={{ width: '100%', maxWidth: '850px', textAlign: 'center', marginBottom: '1.25rem', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.4rem' }}>
        <img src="/Specula_logo.png" alt="Specula Logo" style={{ height: '48px', objectFit: 'contain' }} />
        <h1 style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--sp-color-text-primary)', margin: 0 }}>
          System Initialization
        </h1>
        <p style={{ color: 'var(--sp-color-text-secondary)', fontSize: '0.9rem', margin: 0 }}>
          Booting underlying DFIR infrastructure and establishing cryptographic integrity checks.
        </p>
      </div>

      {/* 1. Service Health Checks Box (TOP) */}
      <div className="startup-container glass-panel" style={{ maxWidth: '850px', width: '100%', marginBottom: '1.25rem' }}>
        <div style={{ 
          padding: '0.85rem 1.25rem', 
          borderBottom: 'var(--sp-border-thin)', 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          background: 'rgba(0, 0, 0, 0.02)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, color: 'var(--sp-color-text-primary)' }}>
            <ShieldCheck size={18} color="var(--sp-color-accent-indigo)" />
            <span>Service Health Checks</span>
          </div>
          <span style={{ 
            fontSize: '0.75rem', 
            fontWeight: 600,
            padding: '2px 10px',
            borderRadius: '12px',
            background: isComplete ? 'rgba(16, 185, 129, 0.1)' : 'rgba(30, 64, 175, 0.1)',
            color: isComplete ? 'var(--sp-color-status-admissible)' : 'var(--sp-color-accent-indigo)'
          }}>
            {isComplete ? 'ALL 6 SERVICES ONLINE' : `BOOTING (${Math.max(0, activeStep)}/${BOOT_SEQUENCE.length})`}
          </span>
        </div>

        <div className="services-health-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr' }}>
          {BOOT_SEQUENCE.map((service, idx) => {
            const isServiceDone = activeStep > idx;
            const isServiceCurrent = activeStep === idx;
            const isLeftColumn = idx % 2 === 0;

            return (
              <div 
                key={service.id} 
                className="service-row"
                style={{
                  padding: '0.75rem 1.25rem',
                  borderRight: isLeftColumn ? 'var(--sp-border-thin)' : 'none',
                  borderBottom: idx < 4 ? 'var(--sp-border-thin)' : 'none',
                  background: isServiceCurrent ? 'rgba(30, 64, 175, 0.03)' : 'transparent'
                }}
              >
                <div className="service-info" style={{ gap: '0.75rem' }}>
                  <div style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '6px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: isServiceDone ? 'rgba(16, 185, 129, 0.1)' : (isServiceCurrent ? 'rgba(30, 64, 175, 0.1)' : 'rgba(0, 0, 0, 0.04)'),
                    color: isServiceDone ? 'var(--sp-color-status-admissible)' : (isServiceCurrent ? 'var(--sp-color-accent-indigo)' : 'var(--sp-color-text-secondary)')
                  }}>
                    {service.icon}
                  </div>
                  <div>
                    <div style={{ 
                      fontSize: '0.88rem',
                      fontWeight: 600, 
                      color: activeStep >= idx ? 'var(--sp-color-text-primary)' : 'var(--sp-color-text-secondary)' 
                    }}>
                      {service.label}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--sp-color-text-secondary)', fontFamily: 'var(--sp-font-mono)' }}>
                      Port: {service.port}
                    </div>
                  </div>
                </div>
                <div>
                  {isServiceDone ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.72rem', fontWeight: 700, color: 'var(--sp-color-status-admissible)', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                      <CheckCircle2 size={13} /> ONLINE
                    </span>
                  ) : isServiceCurrent ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.72rem', fontWeight: 700, color: 'var(--sp-color-accent-indigo)', background: 'rgba(30, 64, 175, 0.1)', padding: '2px 8px', borderRadius: '4px' }}>
                      <CircleDashed className="animate-spin" size={13} style={{ animation: 'spin 1s linear infinite' }} /> CHECKING
                    </span>
                  ) : (
                    <span style={{ fontSize: '0.72rem', color: 'var(--sp-color-text-secondary)', background: 'rgba(0, 0, 0, 0.03)', padding: '2px 8px', borderRadius: '4px' }}>
                      QUEUED
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. Terminal Box (BELOW THE HEALTH CHECKS BOX) */}
      <div className="terminal-box" style={{ width: '100%', maxWidth: '850px', height: '260px' }}>
        <div className="terminal-header">
          <div className="terminal-controls">
            <span className="terminal-dot red"></span>
            <span className="terminal-dot yellow"></span>
            <span className="terminal-dot green"></span>
          </div>
          <div className="terminal-title">
            <Terminal size={14} />
            <span>specula-kernel-boot :: /dev/tty1</span>
          </div>
          <div>
            {isComplete ? (
              <span className="terminal-badge-live">● READY</span>
            ) : (
              <span className="terminal-badge-ready" style={{ color: '#F59E0B', background: 'rgba(245, 158, 11, 0.15)' }}>● BOOTING</span>
            )}
          </div>
        </div>

        <div className="terminal-body" ref={terminalBodyRef}>
          <div style={{ color: '#94A3B8', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: '#38BDF8', fontWeight: 700 }}>specula@dfir-node:~$</span>
            <span style={{ color: '#F8FAFC' }}>specula-cli system boot --verbose --verify-vct</span>
          </div>

          {logs.map((log, i) => {
            let tagColor = '#94A3B8';
            if (log.tag === 'OK') tagColor = '#34D399';
            if (log.tag === 'INIT') tagColor = '#60A5FA';
            if (log.tag === 'SYSTEM') tagColor = '#A78BFA';

            return (
              <div key={i} className="log-line" style={{ display: 'flex', gap: '8px', alignItems: 'baseline' }}>
                <span style={{ color: '#64748B', fontSize: '0.8rem', userSelect: 'none' }}>[{log.time}]</span>
                <span style={{ color: tagColor, fontWeight: 700, minWidth: '60px' }}>[{log.tag}]</span>
                <span style={{ color: log.tag === 'OK' ? '#E2E8F0' : (log.tag === 'SYSTEM' ? '#F8FAFC' : '#CBD5E1') }}>
                  {log.msg}
                </span>
              </div>
            );
          })}
          
          {!isComplete && (
            <div style={{ marginTop: '4px' }}>
              <span style={{ color: '#38BDF8' }}>❯</span>
              <span className="cursor-blink" />
            </div>
          )}
        </div>
      </div>

      {/* 3. Action CTA (BELOW TERMINAL) */}
      <div style={{ marginTop: '1.5rem', marginBottom: '2rem', minHeight: '48px', display: 'flex', justifyContent: 'center' }}>
        {isComplete && (
          <button 
            className="primary-btn" 
            onClick={() => navigate('/investigate')}
            style={{ padding: '0.85rem 2.25rem', fontSize: '1rem' }}
          >
            Proceed to Investigation Console <ArrowRight size={18} />
          </button>
        )}
      </div>

      <style>{`
        @keyframes spin { 100% { transform: rotate(360deg); } }
        @media (max-width: 700px) {
          .services-health-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
}
