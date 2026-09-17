import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle2, CircleDashed, Server, Database, Activity, ShieldAlert, Cpu } from 'lucide-react';

const BOOT_SEQUENCE = [
  { id: 'redis', label: 'Redis Cache (Port 6379)', icon: <Activity size={18} /> },
  { id: 'kafka', label: 'Kafka Broker (Port 9092)', icon: <Server size={18} /> },
  { id: 'quickwit', label: 'Quickwit WORM Datastore (Port 7280)', icon: <Database size={18} /> },
  { id: 'neo4j', label: 'Neo4j Graph Database (Port 7687)', icon: <Database size={18} /> },
  { id: 'chroma', label: 'ChromaDB Vector Store (Port 8000)', icon: <Database size={18} /> },
  { id: 'llm', label: 'LLM Multi-Agent Orchestrator', icon: <Cpu size={18} /> },
];

export default function StartupPage() {
  const [activeStep, setActiveStep] = useState(-1);
  const [logs, setLogs] = useState([]);
  const navigate = useNavigate();
  const logsEndRef = useRef(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    const runBoot = async () => {
      for (let i = 0; i < BOOT_SEQUENCE.length; i++) {
        setActiveStep(i);
        setLogs(prev => [...prev, `[INIT] Starting service: ${BOOT_SEQUENCE[i].label}...`]);
        await new Promise(r => setTimeout(r, 800));
        setLogs(prev => [...prev, `[OK] Service ${BOOT_SEQUENCE[i].id} online and healthy.`]);
        await new Promise(r => setTimeout(r, 200));
      }
      setActiveStep(BOOT_SEQUENCE.length);
      setLogs(prev => [...prev, '[SYSTEM] All services online. System ready for ingestion.']);
    };
    runBoot();
  }, []);

  return (
    <div className="app-container-fullscreen" style={{ padding: '2rem', alignItems: 'center' }}>
      <div className="header" style={{ width: '100%', maxWidth: '800px', justifyContent: 'center', marginBottom: '3rem', flexDirection: 'column', gap: '1rem' }}>
        <img src="/Specula_logo.png" alt="Specula Logo" style={{ height: '64px' }} />
        <h1 style={{ fontSize: '2rem' }}>System Initialization</h1>
        <p style={{ color: 'var(--text-secondary)' }}>Booting underlying infrastructure and connecting to datastores.</p>
      </div>

      <div className="startup-container glass-panel">
        <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--panel-border)', fontWeight: 600 }}>
          Service Health Checks
        </div>
        <div>
          {BOOT_SEQUENCE.map((service, idx) => (
            <div key={service.id} className="service-row">
              <div className="service-info">
                <span style={{ color: 'var(--accent-secondary)' }}>{service.icon}</span>
                <span style={{ color: activeStep >= idx ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                  {service.label}
                </span>
              </div>
              <div>
                {activeStep > idx ? (
                  <CheckCircle2 color="var(--success)" size={20} />
                ) : activeStep === idx ? (
                  <CircleDashed className="animate-spin" color="var(--accent)" size={20} style={{ animation: 'spin 1s linear infinite' }} />
                ) : (
                  <CircleDashed color="var(--text-secondary)" size={20} />
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="terminal-box" style={{ width: '100%', maxWidth: '800px' }}>
        <div style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>$ specula-cli system boot --verbose</div>
        {logs.map((log, i) => (
          <div key={i} className="log-line">
            <span style={{ color: log.includes('[OK]') ? 'var(--success)' : 'inherit' }}>{log}</span>
          </div>
        ))}
        <div ref={logsEndRef} />
      </div>

      {activeStep === BOOT_SEQUENCE.length && (
        <div style={{ marginTop: '2rem' }}>
          <button className="primary-btn" onClick={() => navigate('/investigate')}>
            Proceed to Investigation Console
          </button>
        </div>
      )}
      <style>{`
        @keyframes spin { 100% { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
