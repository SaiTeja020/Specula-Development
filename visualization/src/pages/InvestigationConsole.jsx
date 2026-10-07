import { useState } from 'react';
import { usePipeline } from '../contexts/PipelineContext';

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
  const { 
    caseId, setCaseId, caseResult, isStarted, caseStatus, activeStage, stageLogs, hitlData,
    handleStart, handleHitlAction 
  } = usePipeline();

  const onLaunch = () => handleStart({});

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1rem', overflowY: 'auto', paddingBottom: '2rem' }}>
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
        <p>Case: {caseId}</p>
        {caseResult && <section aria-live="polite" style={{ marginTop: '1rem' }}>
          <p>{caseResult.findings?.length ?? 0} findings · {caseResult.agent_traces?.length ?? 0} execution traces</p>
          <p>{caseResult.attribution?.summary || 'No supported attribution is available.'}</p>
          <p>Report reference: {caseResult.final_output_ref || 'Not generated'}</p>
        </section>}
        {!isStarted && (
          <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              Ingested case ID
              <input value={caseId} onChange={e => setCaseId(e.target.value)} />
            </label>
            <p>Run analysis on evidence already ingested for this case.</p>
            <button className="primary-btn" onClick={onLaunch} style={{ alignSelf: 'flex-start' }}>Launch Multi-Agent Pipeline</button>
          </div>
        )}
      </div>

      <div style={{ maxWidth: '1000px', width: '100%', margin: '0 auto', padding: '0 1.5rem' }}>
        {STAGES.map((stage, idx) => {
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
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem', fontSize: '0.9rem' }}>
                        <div><strong>Confidence:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.confidence}</span></div>
                        <div><strong>Evidence:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.blastRadius}</span></div>
                        <div><strong>Integrity:</strong> <span style={{ fontFamily: 'var(--sp-font-mono)' }}>{hitlData.tamperCheck}</span></div>
                      </div>
                      <div style={{ display: 'flex', gap: '1rem' }}>
                        <button 
                          onClick={() => handleHitlAction('approve')}
                          style={{ background: 'var(--sp-color-status-admissible)', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: 'var(--sp-radius-sharp)', cursor: 'pointer', fontWeight: 600 }}>
                          APPROVE
                        </button>
                        <button 
                          onClick={() => handleHitlAction('reject')}
                          style={{ background: 'var(--sp-color-status-breach)', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: 'var(--sp-radius-sharp)', cursor: 'pointer', fontWeight: 600 }}>
                          REJECT / HALT
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
