import { useEffect, useRef, useState } from 'react';

// ═══════════════════════════════════════════════════════════
// DATA
// ═══════════════════════════════════════════════════════════

const AGENTS = [
  { name: 'Supervisor', tier: 'Orchestrator', icon: '🧠', color: '#6366f1', desc: 'Routes cases across tiers and manages HITL interrupts' },
  { name: 'Evidence Collection', tier: 'Primary', icon: '🔬', color: '#10b981', desc: 'Multi-criterion relevance filtering with Kafka verdict publishing' },
  { name: 'Log Analysis', tier: 'Primary', icon: '📋', color: '#10b981', desc: 'Signature detection, anomaly scoring and LLM-enriched findings' },
  { name: 'Network Forensics', tier: 'Primary', icon: '🌐', color: '#10b981', desc: 'PCAP / dpkt dissection with OCSF NetworkActivity normalization' },
  { name: 'Memory Forensics', tier: 'Specialist', icon: '💾', color: '#8b5cf6', desc: 'Volatile memory extraction and process injection detection' },
  { name: 'Identity & Cloud', tier: 'Specialist', icon: '☁️', color: '#8b5cf6', desc: 'IAM abuse, cloud API tracing and lateral movement graphs' },
  { name: 'Malware Stylometry', tier: 'Specialist', icon: '🦠', color: '#8b5cf6', desc: 'Code authorship fingerprinting and malware family classification' },
  { name: 'Insider Threat', tier: 'Specialist', icon: '🕵️', color: '#8b5cf6', desc: 'UEBA behavioral baselining and data exfiltration detection' },
  { name: 'Timeline Reconstruction', tier: 'Synthesis', icon: '⏱️', color: '#f59e0b', desc: 'Cross-source event correlation and causal chain assembly' },
  { name: 'Threat Attribution', tier: 'Synthesis', icon: '🎯', color: '#f59e0b', desc: 'ATT&CK TTP mapping and adversary group fingerprinting' },
  { name: 'Proponent', tier: 'Debate', icon: '💬', color: '#ec4899', desc: 'Champions the strongest forensic hypothesis in ACH rounds' },
  { name: 'Critic', tier: 'Debate', icon: '🧐', color: '#ec4899', desc: 'Challenges hypothesis consistency and surfaces evidence gaps' },
  { name: 'Judge', tier: 'Debate', icon: '⚖️', color: '#ec4899', desc: 'Scores debate rounds and selects the consensus hypothesis' },
  { name: 'Report Generation', tier: 'Output', icon: '📄', color: '#22c55e', desc: 'Compiles cryptographically signed forensic reports and timelines' },
];

const PHASES = [
  { num: '01', title: 'Forensic Ingestion & Preservation', desc: 'Raw logs SHA-256 hashed, Merkle Tree VCT sealed, stored in a Quickwit WORM store — every artifact is cryptographically immutable before analysis begins.', color: '#06b6d4', icon: '🛡️', tags: ['SHA-256', 'Merkle VCT', 'Quickwit WORM', 'OCSF / OSSEM'] },
  { num: '02', title: 'Knowledge Graph & Vector Intelligence', desc: 'Normalized OCSF events stream via Kafka into Neo4j. FAISS IndexIVFPQ indexes 10k+ ATT&CK STIX techniques and NVD CVEs for semantic threat retrieval.', color: '#8b5cf6', icon: '🕸️', tags: ['Neo4j', 'FAISS IVF-PQ', 'ATT&CK STIX', 'NVD CVEs'] },
  { num: '03', title: 'Multi-Agent Orchestration', desc: '23-node LangGraph StateGraph deploys 14 specialist agents in parallel fan-out. The Blackboard Coordination Pattern keeps state coherent — no giant prompt blobs.', color: '#6366f1', icon: '🤖', tags: ['LangGraph', 'Blackboard', 'Fan-Out', 'ACH Debate'] },
  { num: '04', title: '3-Tier Guardrails & HITL Review', desc: 'Regex → Semantic BoW → LLM judge guards every inference call. A FastAPI HITL interrupt halts the graph until a human analyst approves or rejects critical findings.', color: '#ec4899', icon: '🔒', tags: ['Regex T1', 'Semantic T2', 'LLM T3', 'HITL Gate'] },
  { num: '05', title: 'Real-Time Visualization', desc: 'WebSocket streaming from the FastAPI visualizer drives a React Flow dashboard. Watch the 23-node graph animate live — each agent node lights up as it executes.', color: '#f59e0b', icon: '📊', tags: ['WebSocket', 'React Flow', 'Live Monitor'] },
];

const STEPS = [
  { n: 1, title: 'Ingest', desc: 'Drop raw EVTX, PCAP, or cloud logs', color: '#06b6d4', icon: '📥' },
  { n: 2, title: 'Preserve', desc: 'SHA-256 + Merkle VCT seals every artifact', color: '#8b5cf6', icon: '🛡️' },
  { n: 3, title: 'Investigate', desc: '14 agents deploy across 4 specialized tiers', color: '#6366f1', icon: '🤖' },
  { n: 4, title: 'Debate', desc: 'ACH Proponent / Critic / Judge reach consensus', color: '#ec4899', icon: '⚖️' },
  { n: 5, title: 'Approve', desc: 'HITL interrupt gates analyst oversight', color: '#f59e0b', icon: '👁️' },
  { n: 6, title: 'Report', desc: 'Signed forensic reports + timeline artifacts', color: '#22c55e', icon: '📄' },
];

const TECH = [
  { name: 'LangGraph', desc: 'Multi-agent StateGraph', color: '#6366f1', letter: 'L' },
  { name: 'Neo4j', desc: 'Knowledge graph DB', color: '#06b6d4', letter: 'N' },
  { name: 'Apache Kafka', desc: 'Event streaming bus', color: '#f59e0b', letter: 'K' },
  { name: 'FastAPI', desc: 'REST & WebSocket API', color: '#22c55e', letter: 'F' },
  { name: 'Quickwit', desc: 'WORM forensic store', color: '#ec4899', letter: 'Q' },
  { name: 'ChromaDB', desc: 'Vector embeddings', color: '#8b5cf6', letter: 'C' },
  { name: 'FAISS', desc: 'Threat intel indexing', color: '#f97316', letter: 'F' },
  { name: 'Redis', desc: 'Graph checkpointing', color: '#ef4444', letter: 'R' },
  { name: 'Multi-LLM', desc: 'Config-driven model routing', color: '#3b82f6', letter: 'M' },
  { name: 'React Flow', desc: 'Graph visualization', color: '#06b6d4', letter: 'R' },
  { name: 'Docker', desc: 'Container runtime', color: '#0ea5e9', letter: 'D' },
  { name: 'Vite + React', desc: 'Frontend build', color: '#a855f7', letter: 'V' },
];

const STATS = [
  { value: '14',   label: 'AI Agents',       color: '#6366f1' },
  { value: '5',    label: 'Pipeline Phases',  color: '#06b6d4' },
  { value: '250+', label: 'Tests Passing',    color: '#10b981' },
  { value: '3',    label: 'Guardrail Tiers',  color: '#ec4899' },
];

// ═══════════════════════════════════════════════════════════
// MATH
// ═══════════════════════════════════════════════════════════

const clamp   = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const lerp    = (a, b, t) => a + (b - a) * t;
const sp      = (v, s, e) => clamp((v - s) / (e - s), 0, 1);
const easeOut = t => 1 - Math.pow(1 - t, 3);

function hexRgb(h) { return `${parseInt(h.slice(1,3),16)},${parseInt(h.slice(3,5),16)},${parseInt(h.slice(5,7),16)}`; }

// ═══════════════════════════════════════════════════════════
// HOOKS
// ═══════════════════════════════════════════════════════════

/**
 * Returns [ref, progress] where progress ∈ [0, 1].
 *   0 = element top is at viewport bottom (entering)
 *   1 = element bottom is at viewport top (exiting)
 * Based on getBoundingClientRect — always correct regardless of
 * sticky, overflow, or any CSS complexity.
 */
function useViewProgress() {
  const ref = useRef(null);
  const [p, setP] = useState(0);
  useEffect(() => {
    let raf;
    const update = () => {
      const el = ref.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      setP(clamp((window.innerHeight - r.top) / (window.innerHeight + r.height), 0, 1));
    };
    const h = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(update); };
    window.addEventListener('scroll', h, { passive: true });
    window.addEventListener('resize', h, { passive: true });
    update();
    return () => { window.removeEventListener('scroll', h); window.removeEventListener('resize', h); cancelAnimationFrame(raf); };
  }, []);
  return [ref, p];
}

function useScrollY() {
  const [y, setY] = useState(0);
  useEffect(() => {
    let raf;
    const h = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => setY(window.scrollY)); };
    window.addEventListener('scroll', h, { passive: true });
    return () => { window.removeEventListener('scroll', h); cancelAnimationFrame(raf); };
  }, []);
  return y;
}

// ═══════════════════════════════════════════════════════════
// PARTICLE CANVAS
// ═══════════════════════════════════════════════════════════

function ParticleCanvas() {
  const ref = useRef(null);
  useEffect(() => {
    const c = ref.current; if (!c) return;
    const ctx = c.getContext('2d'); let id;
    const resize = () => { c.width = window.innerWidth; c.height = window.innerHeight; };
    resize(); window.addEventListener('resize', resize);
    const pts = Array.from({ length: 65 }, () => ({
      x: Math.random()*c.width, y: Math.random()*c.height,
      vx: (Math.random()-0.5)*0.25, vy: (Math.random()-0.5)*0.25,
      r: Math.random()*1.4+0.4, o: Math.random()*0.28+0.06,
    }));
    const tick = () => {
      ctx.clearRect(0,0,c.width,c.height);
      for (let i=0;i<pts.length;i++) for (let j=i+1;j<pts.length;j++){
        const d=Math.hypot(pts[i].x-pts[j].x,pts[i].y-pts[j].y);
        if(d<125){ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.strokeStyle=`rgba(99,102,241,${0.1*(1-d/125)})`;ctx.lineWidth=0.6;ctx.stroke();}
      }
      pts.forEach(p=>{p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>c.width)p.vx*=-1;if(p.y<0||p.y>c.height)p.vy*=-1;ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fillStyle=`rgba(99,102,241,${p.o})`;ctx.fill();});
      id=requestAnimationFrame(tick);
    };
    tick();
    return()=>{cancelAnimationFrame(id);window.removeEventListener('resize',resize);};
  },[]);
  return <canvas ref={ref} style={{position:'absolute',inset:0,width:'100%',height:'100%',pointerEvents:'none'}} />;
}

// ═══════════════════════════════════════════════════════════
// NAVBAR
// ═══════════════════════════════════════════════════════════

function Navbar({ scrollY, onEnterDashboard }) {
  const s = scrollY > 60;
  return (
    <nav style={{
      position:'fixed',top:0,left:0,right:0,zIndex:999,padding:'14px 48px',
      display:'flex',alignItems:'center',justifyContent:'space-between',
      background:s?'rgba(3,7,18,0.92)':'transparent',
      backdropFilter:s?'blur(24px)':'none',WebkitBackdropFilter:s?'blur(24px)':'none',
      borderBottom:s?'1px solid rgba(99,102,241,0.1)':'none',
      transition:'all 0.4s ease',
    }}>
      <div style={{display:'flex',alignItems:'center',gap:'10px'}}>
        <div style={{width:'32px',height:'32px',borderRadius:'9px',background:'linear-gradient(135deg,#6366f1,#06b6d4)',display:'flex',alignItems:'center',justifyContent:'center',fontFamily:"'Sora',sans-serif",fontWeight:800,fontSize:'16px',color:'white',boxShadow:'0 0 14px rgba(99,102,241,0.4)'}}>S</div>
        <span style={{fontFamily:"'Sora',sans-serif",fontWeight:700,fontSize:'18px',letterSpacing:'-0.5px',color:'#f1f5f9'}}>Specula</span>
      </div>
      <div style={{display:'flex',gap:'4px',alignItems:'center'}}>
        {[['#about','About'],['#pipeline','Pipeline'],['#agents','Agents'],['#tech','Tech']].map(([href,label])=>(
          <a key={href} href={href} style={{color:'#475569',textDecoration:'none',padding:'7px 13px',fontSize:'13px',fontWeight:500,transition:'color 0.2s'}}
            onMouseEnter={e=>e.target.style.color='#e2e8f0'} onMouseLeave={e=>e.target.style.color='#475569'}
          >{label}</a>
        ))}
        <button onClick={onEnterDashboard} className="btn btn-primary" style={{marginLeft:'10px',fontSize:'13px',padding:'9px 16px',boxShadow:'0 0 18px rgba(99,102,241,0.3)'}}>
          Live Monitor →
        </button>
      </div>
    </nav>
  );
}

// ═══════════════════════════════════════════════════════════
// HERO — content visible on load, morphs away on scroll
// ═══════════════════════════════════════════════════════════

function HeroSection({ onEnterDashboard }) {
  const [ref, p] = useViewProgress();
  // p rises from 0→1 as hero scrolls out of viewport.
  // We want content to morph out when p > 0.5 (the hero is scrolling past centre).
  const exitP = sp(p, 0.5, 0.85);

  return (
    <section ref={ref} style={{ minHeight: '100vh', position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      <ParticleCanvas />
      <div style={{ position:'absolute', inset:0, background: `radial-gradient(ellipse 80% 60% at 50% 42%, rgba(99,102,241,${lerp(0.12, 0.22, exitP)}) 0%, transparent 70%)`, pointerEvents:'none' }} />

      <div style={{
        position:'relative', textAlign:'center', maxWidth:'860px', padding:'0 24px',
        transform: `translateY(${-exitP * 90}px) scale(${1 - exitP*0.05}) rotateX(${exitP * 8}deg)`,
        opacity: clamp(1 - exitP * 2, 0, 1),
        perspective: '1200px',
      }}>
        <div style={{ display:'inline-flex',alignItems:'center',gap:'10px', background:'rgba(99,102,241,0.09)',border:'1px solid rgba(99,102,241,0.25)', borderRadius:'100px',padding:'8px 20px',marginBottom:'34px', fontSize:'13px',color:'#a5b4fc',fontWeight:500, animation:'fadeUp 0.7s 0.1s ease both' }}>
          <span style={{width:'6px',height:'6px',borderRadius:'50%',background:'#818cf8',boxShadow:'0 0 8px #818cf8'}} />
          Multi-Agent DFIR System
        </div>
        <h1 style={{ fontFamily:"'Sora',sans-serif",fontSize:'clamp(2.8rem,7.5vw,5rem)',fontWeight:800,lineHeight:1.08,marginBottom:'28px', background:'linear-gradient(145deg,#f1f5f9 20%,#a5b4fc 55%,#67e8f9 90%)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent',backgroundClip:'text', animation:'fadeUp 0.75s 0.2s ease both' }}>
          Illuminate the Dark.<br/>Reconstruct the Truth.
        </h1>
        <p style={{ fontSize:'clamp(0.95rem,1.8vw,1.15rem)',color:'#94a3b8',lineHeight:1.78,maxWidth:'600px',margin:'0 auto 44px', animation:'fadeUp 0.75s 0.32s ease both' }}>
          An event-driven forensics platform that orchestrates a colony of specialist AI agents — from evidence collection to adversarial debate — delivering cryptographically provable incident reports.
        </p>
        <div style={{display:'flex',gap:'14px',justifyContent:'center',flexWrap:'wrap',animation:'fadeUp 0.75s 0.44s ease both'}}>
          <button onClick={onEnterDashboard} className="btn btn-primary" style={{fontSize:'15px',padding:'14px 30px',boxShadow:'0 0 36px rgba(99,102,241,0.45)'}}>Open Live Monitor →</button>
          <a href="#about" className="btn btn-ghost" style={{fontSize:'15px',padding:'14px 30px'}}>Explore ↓</a>
        </div>
      </div>

      <div style={{ position:'absolute',bottom:'32px',left:'50%',transform:'translateX(-50%)', display:'flex',flexDirection:'column',alignItems:'center',gap:'8px', color:'#334155',fontSize:'11px',letterSpacing:'2px',textTransform:'uppercase', opacity:clamp(1-exitP*6,0,1), animation:'scrollBounce 2.5s ease-in-out infinite' }}>
        <span>Scroll to explore</span>
        <div style={{width:'1px',height:'36px',background:'linear-gradient(to bottom,#6366f1,transparent)'}} />
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════
// ABOUT — 3D unfold from left/right
// ═══════════════════════════════════════════════════════════

function AboutSection() {
  const [ref, p] = useViewProgress();
  const entry = easeOut(sp(p, 0.02, 0.38));
  const leftRY  = lerp(10, 0, entry);
  const rightRY = lerp(-10, 0, entry);

  const svgNodes = [
    {x:200,y:55,c:'#6366f1',e:'🧠'},{x:80,y:155,c:'#10b981',e:'🔬'},
    {x:200,y:155,c:'#10b981',e:'📋'},{x:320,y:155,c:'#10b981',e:'🌐'},
    {x:80,y:255,c:'#8b5cf6',e:'💾'},{x:200,y:255,c:'#f59e0b',e:'⏱️'},
    {x:320,y:255,c:'#ec4899',e:'⚖️'},{x:200,y:330,c:'#22c55e',e:'📄'},
  ];
  const edges = [[0,1],[0,2],[0,3],[1,4],[2,5],[3,6],[4,7],[5,7],[6,7]];

  return (
    <section id="about" ref={ref} style={{padding:'140px 60px',background:'rgba(15,23,42,0.35)',perspective:'1200px'}}>
      {/* Header */}
      <div style={{ textAlign:'center',marginBottom:'64px', opacity:entry, transform:`translateY(${lerp(30,0,entry)}px)` }}>
        <div style={{display:'inline-block',color:'#818cf8',fontWeight:600,fontSize:'11px',letterSpacing:'3px',textTransform:'uppercase',marginBottom:'14px',padding:'5px 14px',background:'rgba(99,102,241,0.08)',border:'1px solid rgba(99,102,241,0.2)',borderRadius:'100px'}}>What is Specula?</div>
        <h2 style={{fontFamily:"'Sora',sans-serif",fontSize:'clamp(1.7rem,3vw,2.5rem)',fontWeight:800,color:'#f1f5f9',lineHeight:1.15}}>Autonomous AI for Digital Investigations</h2>
      </div>

      <div style={{display:'flex',gap:'72px',alignItems:'center',marginBottom:'80px'}}>
        {/* Left text — unfolds from left */}
        <div style={{
          flex:1.2,
          opacity: entry,
          transform: `translateX(${lerp(-40,0,entry)}px) rotateY(${leftRY}deg)`,
          transformOrigin: 'right center',
        }}>
          <p style={{color:'#94a3b8',lineHeight:1.82,marginBottom:'16px',fontSize:'15px'}}>
            Traditional DFIR is slow, manual, and susceptible to analyst fatigue. Specula replaces that workflow with a fully event-driven multi-agent architecture — ingesting raw forensic artifacts, building a live knowledge graph, and deploying AI specialists in coordinated parallel tiers.
          </p>
          <p style={{color:'#94a3b8',lineHeight:1.82,marginBottom:'28px',fontSize:'15px'}}>
            Grounded in <strong style={{color:'#c7d2fe'}}>OCSF</strong> and <strong style={{color:'#c7d2fe'}}>OSSEM</strong> standards, every log is SHA-256 hashed and Merkle-sealed before any agent touches it — making findings both AI-augmented and legally defensible.
          </p>
          <div style={{display:'flex',gap:'8px',flexWrap:'wrap'}}>
            {['OCSF / OSSEM','Cryptographic Provenance','HITL Oversight','ADR-Governed'].map(b=>(
              <span key={b} style={{background:'rgba(99,102,241,0.08)',border:'1px solid rgba(99,102,241,0.22)',borderRadius:'100px',padding:'6px 13px',fontSize:'11px',color:'#a5b4fc',fontWeight:500}}>{b}</span>
            ))}
          </div>
        </div>

        {/* Right SVG — unfolds from right */}
        <div style={{
          flexShrink:0, width:'340px',
          opacity: entry,
          transform: `translateX(${lerp(40,0,entry)}px) rotateY(${rightRY}deg)`,
          transformOrigin: 'left center',
        }}>
          <div style={{borderRadius:'20px',background:'radial-gradient(ellipse at center,rgba(99,102,241,0.07) 0%,transparent 70%)',border:'1px solid rgba(99,102,241,0.12)',padding:'16px'}}>
            <svg viewBox="0 0 400 370" style={{width:'100%'}}>
              {edges.map(([a,b],i)=><line key={i} x1={svgNodes[a].x} y1={svgNodes[a].y} x2={svgNodes[b].x} y2={svgNodes[b].y} stroke="rgba(99,102,241,0.22)" strokeWidth="1.2" strokeDasharray="5 3" />)}
              {svgNodes.map((n,i)=>(
                <g key={i}>
                  <circle cx={n.x} cy={n.y} r="22" fill={`rgba(${hexRgb(n.c)},0.12)`} stroke={n.c} strokeWidth="1.4" strokeOpacity="0.65" />
                  <circle cx={n.x} cy={n.y} r="30" fill="none" stroke={n.c} strokeWidth="0.5" strokeOpacity="0.15" strokeDasharray="4 4">
                    <animateTransform attributeName="transform" attributeType="XML" type="rotate" from={`0 ${n.x} ${n.y}`} to={`${i%2===0?360:-360} ${n.x} ${n.y}`} dur={`${10+i*2}s`} repeatCount="indefinite" />
                  </circle>
                  <text x={n.x} y={n.y} textAnchor="middle" dominantBaseline="middle" fontSize="13">{n.e}</text>
                </g>
              ))}
            </svg>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:'20px',textAlign:'center',borderTop:'1px solid rgba(255,255,255,0.05)',paddingTop:'48px'}}>
        {STATS.map((s,i)=>{
          const sP = easeOut(sp(p, 0.2 + i*0.04, 0.45 + i*0.04));
          return (
            <div key={s.label} style={{opacity:sP,transform:`translateY(${lerp(20,0,sP)}px) scale(${lerp(0.9,1,sP)})`}}>
              <div style={{fontFamily:"'Sora',sans-serif",fontSize:'2.4rem',fontWeight:800,background:`linear-gradient(135deg,${s.color},${s.color}70)`,WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent',backgroundClip:'text'}}>{s.value}</div>
              <div style={{color:'#475569',fontSize:'12px',marginTop:'6px',fontWeight:500}}>{s.label}</div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════
// PIPELINE — 3D morph cards (the centrepiece)
// Each card has its own viewport progress → 3D unfold/fold
// ═══════════════════════════════════════════════════════════

function PhaseCard({ phase, index }) {
  const [ref, p] = useViewProgress();

  // Entry: card unfolds from below toward viewer
  const entry = easeOut(sp(p, 0.02, 0.38));
  // Exit: card folds away slightly as it scrolls past
  const exit  = sp(p, 0.68, 0.98);

  const rotateX = lerp(20, 0, entry) + lerp(0, -10, exit);
  const rotateY = (index % 2 === 0 ? 1 : -1) * lerp(5, 0, entry);
  const sc      = lerp(0.86, 1, entry) * lerp(1, 0.95, exit);
  const ty      = lerp(60, 0, entry)   + lerp(0, -30, exit);
  const opacity = Math.min(sp(p, 0.0, 0.15), lerp(1, 0.25, exit));

  return (
    <div ref={ref} style={{ perspective: '1200px', marginBottom: index < 4 ? '100px' : 0 }}>
      <div style={{
        transform: `rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale(${sc}) translateY(${ty}px)`,
        transformOrigin: 'center bottom',
        opacity,
        display: 'flex', gap: '40px', alignItems: 'center',
        background: `linear-gradient(135deg, rgba(${hexRgb(phase.color)},0.08), rgba(${hexRgb(phase.color)},0.02))`,
        border: `1px solid ${phase.color}30`,
        borderRadius: '28px', padding: '48px 56px',
        position: 'relative', overflow: 'hidden',
      }}>
        {/* Background glow orb — parallaxes at different rate */}
        <div style={{
          position:'absolute', top:'-40%', right:'-15%',
          width:'350px', height:'350px', borderRadius:'50%',
          background: phase.color, filter:'blur(120px)', opacity: 0.1,
          pointerEvents:'none',
          transform: `translateY(${lerp(40, -20, sp(p, 0, 0.6))}px)`,
        }} />

        {/* Left: big ghost number */}
        <div style={{
          fontFamily:"'Sora',sans-serif", fontSize:'7rem', fontWeight:800, lineHeight:1,
          background:`linear-gradient(135deg,${phase.color},${phase.color}25)`,
          WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent', backgroundClip:'text',
          opacity: 0.2, flexShrink:0, minWidth:'120px', textAlign:'center',
          transform: `translateY(${lerp(15, -5, sp(p, 0.05, 0.45))}px)`,
        }}>
          {phase.num}
        </div>

        {/* Right: content */}
        <div style={{flex:1,position:'relative'}}>
          <div style={{fontSize:'32px',marginBottom:'12px'}}>{phase.icon}</div>
          <div style={{fontFamily:"'Sora',sans-serif",fontSize:'10px',fontWeight:700,color:phase.color,letterSpacing:'3px',textTransform:'uppercase',marginBottom:'8px'}}>
            Phase {phase.num} of 5
          </div>
          <h3 style={{fontFamily:"'Sora',sans-serif",fontSize:'clamp(1.3rem,2.5vw,1.8rem)',fontWeight:800,color:'#f1f5f9',marginBottom:'14px',lineHeight:1.3}}>
            {phase.title}
          </h3>
          <p style={{color:'#94a3b8',lineHeight:1.82,fontSize:'14px',marginBottom:'22px',maxWidth:'500px'}}>
            {phase.desc}
          </p>
          <div style={{display:'flex',flexWrap:'wrap',gap:'8px'}}>
            {phase.tags.map((t, ti) => {
              const tagP = easeOut(sp(p, 0.12 + ti*0.035, 0.3 + ti*0.035));
              return (
                <span key={t} style={{
                  background:`rgba(${hexRgb(phase.color)},0.1)`, border:`1px solid ${phase.color}35`,
                  borderRadius:'100px', padding:'5px 13px', fontSize:'12px', color:phase.color, fontWeight:600,
                  opacity: tagP, transform: `translateY(${lerp(8,0,tagP)}px)`,
                }}>{t}</span>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

function PipelineSection() {
  const [ref, p] = useViewProgress();
  const headerP = easeOut(sp(p, 0.0, 0.25));

  return (
    <section id="pipeline" style={{padding:'120px 60px 60px'}}>
      <div ref={ref} style={{textAlign:'center',marginBottom:'72px',opacity:headerP,transform:`translateY(${lerp(30,0,headerP)}px)`}}>
        <div style={{display:'inline-block',color:'#818cf8',fontWeight:600,fontSize:'11px',letterSpacing:'3px',textTransform:'uppercase',marginBottom:'14px',padding:'5px 14px',background:'rgba(99,102,241,0.08)',border:'1px solid rgba(99,102,241,0.2)',borderRadius:'100px'}}>System Architecture</div>
        <h2 style={{fontFamily:"'Sora',sans-serif",fontSize:'clamp(1.6rem,3vw,2.5rem)',fontWeight:800,color:'#f1f5f9'}}>5-Phase Forensic Pipeline</h2>
      </div>
      {PHASES.map((phase, i) => <PhaseCard key={i} phase={phase} index={i} />)}
    </section>
  );
}

// ═══════════════════════════════════════════════════════════
// WORKFLOW — steps with 3D reveal + connector drawing
// ═══════════════════════════════════════════════════════════

function WorkflowSection() {
  const [ref, p] = useViewProgress();
  const headerP = easeOut(sp(p, 0.0, 0.2));
  const lineP   = sp(p, 0.1, 0.55);

  return (
    <section style={{padding:'120px 64px',background:'rgba(10,15,30,0.5)'}}>
      <div ref={ref}>
        <div style={{textAlign:'center',marginBottom:'56px',opacity:headerP,transform:`translateY(${lerp(24,0,headerP)}px)`}}>
          <div style={{display:'inline-block',color:'#818cf8',fontWeight:600,fontSize:'11px',letterSpacing:'3px',textTransform:'uppercase',marginBottom:'14px',padding:'5px 14px',background:'rgba(99,102,241,0.08)',border:'1px solid rgba(99,102,241,0.2)',borderRadius:'100px'}}>Workflow</div>
          <h2 style={{fontFamily:"'Sora',sans-serif",fontSize:'clamp(1.5rem,2.8vw,2.2rem)',fontWeight:800,color:'#f1f5f9'}}>From Log to Report in 6 Steps</h2>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'repeat(6,1fr)',gap:'14px',position:'relative',perspective:'800px'}}>
          {/* Connector draws across */}
          <div style={{
            position:'absolute',top:'38px',left:'9%',right:'9%',height:'1px',
            background:'linear-gradient(90deg,#06b6d4,#8b5cf6,#6366f1,#ec4899,#f59e0b,#22c55e)',
            opacity:0.25,
            clipPath:`inset(0 ${100 - lineP*100}% 0 0)`,
          }} />
          {STEPS.map((s,i)=>{
            const stepP = easeOut(sp(p, 0.06 + i*0.06, 0.25 + i*0.06));
            return (
              <div key={s.n} style={{
                display:'flex',flexDirection:'column',alignItems:'center',textAlign:'center',
                opacity:stepP,
                transform:`translateY(${lerp(40,0,stepP)}px) rotateX(${lerp(25,0,stepP)}deg) scale(${lerp(0.85,1,stepP)})`,
                transformOrigin:'center bottom',
              }}>
                <div style={{position:'relative',width:'76px',height:'76px',borderRadius:'50%',background:`rgba(${hexRgb(s.color)},0.1)`,border:`2px solid ${s.color}50`,display:'flex',alignItems:'center',justifyContent:'center',fontSize:'26px',marginBottom:'18px',boxShadow:stepP>0.9?`0 0 20px rgba(${hexRgb(s.color)},0.25)`:'none',transition:'box-shadow 0.3s'}}>
                  {s.icon}
                  <span style={{position:'absolute',top:'-5px',right:'-5px',width:'22px',height:'22px',borderRadius:'50%',background:s.color,color:'white',fontSize:'10px',fontWeight:800,display:'flex',alignItems:'center',justifyContent:'center',fontFamily:"'Sora',sans-serif"}}>{s.n}</span>
                </div>
                <div style={{fontWeight:700,fontSize:'14px',color:'#e2e8f0',marginBottom:'8px'}}>{s.title}</div>
                <div style={{color:'#475569',fontSize:'12px',lineHeight:1.6}}>{s.desc}</div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════
// AGENTS — grid with alternating 3D rotation entrance
// ═══════════════════════════════════════════════════════════

function AgentCardInner({ agent, hov }) {
  return (
    <>
      <div style={{fontSize:'22px',marginBottom:'9px'}}>{agent.icon}</div>
      <div style={{fontWeight:700,fontSize:'12px',color:'#e2e8f0',marginBottom:'5px',lineHeight:1.3}}>{agent.name}</div>
      <p style={{color:'#475569',fontSize:'10px',lineHeight:1.55,marginBottom:'10px'}}>{agent.desc}</p>
      <span style={{background:`rgba(${hexRgb(agent.color)},0.1)`,color:agent.color,border:`1px solid ${agent.color}35`,borderRadius:'100px',padding:'3px 9px',fontSize:'10px',fontWeight:700}}>{agent.tier}</span>
    </>
  );
}

function AgentsSection() {
  const [ref, p] = useViewProgress();
  const headerP = easeOut(sp(p, 0.0, 0.2));

  return (
    <section id="agents" style={{padding:'120px 44px',background:'rgba(15,23,42,0.35)'}}>
      <div ref={ref}>
        <div style={{textAlign:'center',marginBottom:'48px',opacity:headerP,transform:`translateY(${lerp(24,0,headerP)}px)`}}>
          <div style={{display:'inline-block',color:'#818cf8',fontWeight:600,fontSize:'11px',letterSpacing:'3px',textTransform:'uppercase',marginBottom:'14px',padding:'5px 14px',background:'rgba(99,102,241,0.08)',border:'1px solid rgba(99,102,241,0.2)',borderRadius:'100px'}}>Agent Roster</div>
          <h2 style={{fontFamily:"'Sora',sans-serif",fontSize:'clamp(1.5rem,2.8vw,2.2rem)',fontWeight:800,color:'#f1f5f9'}}>14 Specialist Investigative Agents</h2>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'repeat(7,1fr)',gap:'11px',perspective:'1000px'}}>
          {AGENTS.map((agent,i)=>{
            const col = i%7, row = Math.floor(i/7);
            const delay = col*0.03 + row*0.08;
            const cardP = easeOut(sp(p, 0.08+delay, 0.32+delay));
            const ry = (col%2===0?1:-1) * lerp(18,0,cardP);
            return <AgentCard key={agent.name} agent={agent} cardP={cardP} rotateY={ry} />;
          })}
        </div>
      </div>
    </section>
  );
}

function AgentCard({ agent, cardP, rotateY }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onMouseEnter={()=>setHov(true)} onMouseLeave={()=>setHov(false)}
      style={{
        background:hov?`rgba(${hexRgb(agent.color)},0.08)`:'rgba(255,255,255,0.02)',
        border:`1px solid ${hov?agent.color+'50':'rgba(255,255,255,0.06)'}`,
        borderRadius:'16px',padding:'18px 12px',cursor:'default',
        opacity:cardP,
        transform:`rotateY(${rotateY}deg) scale(${lerp(0.85,hov?1.04:1,cardP)}) translateZ(${lerp(-30,0,cardP)}px)`,
        transformOrigin:'center center',
        transition:'background 0.3s,border-color 0.3s',
      }}
    >
      <AgentCardInner agent={agent} hov={hov} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// TECH STACK — scale burst from center
// ═══════════════════════════════════════════════════════════

function TechSection() {
  const [ref, p] = useViewProgress();
  const headerP = easeOut(sp(p, 0.0, 0.2));

  return (
    <section id="tech" style={{padding:'120px 44px'}}>
      <div ref={ref}>
        <div style={{textAlign:'center',marginBottom:'48px',opacity:headerP,transform:`translateY(${lerp(24,0,headerP)}px)`}}>
          <div style={{display:'inline-block',color:'#818cf8',fontWeight:600,fontSize:'11px',letterSpacing:'3px',textTransform:'uppercase',marginBottom:'14px',padding:'5px 14px',background:'rgba(99,102,241,0.08)',border:'1px solid rgba(99,102,241,0.2)',borderRadius:'100px'}}>Technology</div>
          <h2 style={{fontFamily:"'Sora',sans-serif",fontSize:'clamp(1.5rem,2.8vw,2.2rem)',fontWeight:800,color:'#f1f5f9'}}>Built on Proven Infrastructure</h2>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'repeat(6,1fr)',gap:'14px',perspective:'800px'}}>
          {TECH.map((t,i)=>{
            const col=i%6, row=Math.floor(i/6);
            // Center-outward order
            const dist = Math.abs(col - 2.5) + row*0.5;
            const cardP = easeOut(sp(p, 0.06 + dist*0.04, 0.28 + dist*0.04));
            const rz = lerp(i%2===0?3:-3, 0, cardP);
            return <TechCard key={t.name} tech={t} cardP={cardP} rotateZ={rz} />;
          })}
        </div>
      </div>
    </section>
  );
}

function TechCard({ tech, cardP, rotateZ }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onMouseEnter={()=>setHov(true)} onMouseLeave={()=>setHov(false)}
      style={{
        background:hov?`rgba(${hexRgb(tech.color)},0.07)`:'rgba(255,255,255,0.02)',
        border:`1px solid ${hov?tech.color+'45':'rgba(255,255,255,0.06)'}`,
        borderRadius:'14px',padding:'20px 16px',
        opacity:cardP,
        transform:`scale(${lerp(0.75,hov?1.03:1,cardP)}) rotateZ(${rotateZ}deg) translateY(${lerp(20,0,cardP)}px)`,
        transition:'background 0.3s,border-color 0.3s',
      }}
    >
      <div style={{width:'36px',height:'36px',borderRadius:'10px',background:`rgba(${hexRgb(tech.color)},0.14)`,border:`1px solid ${tech.color}35`,display:'flex',alignItems:'center',justifyContent:'center',marginBottom:'12px',fontFamily:"'Sora',sans-serif",fontWeight:800,fontSize:'15px',color:tech.color}}>
        {tech.letter}
      </div>
      <div style={{fontWeight:700,fontSize:'13px',color:'#e2e8f0',marginBottom:'4px'}}>{tech.name}</div>
      <div style={{fontSize:'11px',color:'#475569',lineHeight:1.4}}>{tech.desc}</div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// CTA — scale + blur-in reveal
// ═══════════════════════════════════════════════════════════

function CTASection({ onEnterDashboard }) {
  const [ref, p] = useViewProgress();
  const entry = easeOut(sp(p, 0.05, 0.4));

  return (
    <section style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center',position:'relative',overflow:'hidden',background:'rgba(10,15,30,0.6)'}}>
      <div style={{position:'absolute',inset:0,background:'radial-gradient(ellipse 60% 60% at 50% 50%,rgba(99,102,241,0.1) 0%,transparent 70%)',pointerEvents:'none'}} />
      <div className="grid-bg" style={{position:'absolute',inset:0,opacity:0.4,pointerEvents:'none'}} />

      {/* Parallax orbs */}
      <div style={{position:'absolute',width:'300px',height:'300px',borderRadius:'50%',background:'#6366f1',filter:'blur(120px)',opacity:0.08,top:'20%',left:'20%',transform:`translateY(${lerp(30,-30,sp(p,0,0.8))}px)`,pointerEvents:'none'}} />
      <div style={{position:'absolute',width:'250px',height:'250px',borderRadius:'50%',background:'#06b6d4',filter:'blur(100px)',opacity:0.06,bottom:'20%',right:'20%',transform:`translateY(${lerp(-30,30,sp(p,0,0.8))}px)`,pointerEvents:'none'}} />

      <div ref={ref} style={{
        position:'relative',textAlign:'center',maxWidth:'680px',padding:'0 32px',
        opacity:entry,
        transform:`scale(${lerp(0.88,1,entry)}) translateY(${lerp(40,0,entry)}px)`,
        filter:`blur(${lerp(4,0,entry)}px)`,
      }}>
        <div style={{fontSize:'60px',marginBottom:'28px',lineHeight:1}}>🔭</div>
        <h2 style={{fontFamily:"'Sora',sans-serif",fontSize:'clamp(2rem,4.5vw,3.2rem)',fontWeight:800,marginBottom:'20px',background:'linear-gradient(135deg,#f1f5f9 40%,#a5b4fc)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent',backgroundClip:'text',lineHeight:1.15}}>
          Watch 14 AI Agents<br/>Investigate Live
        </h2>
        <p style={{color:'#64748b',fontSize:'1.1rem',lineHeight:1.78,marginBottom:'44px'}}>
          Open the Live Monitor and watch the 23-node orchestration graph animate in real-time — nodes lighting up as agents execute, findings streaming in.
        </p>
        <div style={{display:'flex',gap:'16px',justifyContent:'center',flexWrap:'wrap'}}>
          <button onClick={onEnterDashboard} className="btn btn-primary" style={{fontSize:'16px',padding:'16px 36px',boxShadow:'0 0 48px rgba(99,102,241,0.4)'}}>Open Live Monitor →</button>
          <a href="https://github.com/SaiTeja020/Specula-Development" target="_blank" rel="noreferrer" className="btn btn-ghost" style={{fontSize:'16px',padding:'16px 36px',textDecoration:'none'}}>View on GitHub ↗</a>
        </div>
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════
// ROOT
// ═══════════════════════════════════════════════════════════

export default function LandingPage({ onEnterDashboard }) {
  const scrollY = useScrollY();
  const [totalP, setTotalP] = useState(0);

  useEffect(() => {
    window.scrollTo(0, 0);
    const style = document.createElement('style');
    style.id = 'landing-styles';
    style.textContent = `
      html { scroll-behavior: smooth; scrollbar-width: none; }
      html::-webkit-scrollbar { display: none; }
    `;
    document.head.appendChild(style);

    let raf;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const h = document.documentElement.scrollHeight - window.innerHeight;
        setTotalP(h > 0 ? window.scrollY / h : 0);
      });
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => { document.getElementById('landing-styles')?.remove(); window.removeEventListener('scroll', onScroll); cancelAnimationFrame(raf); };
  }, []);

  return (
    <div style={{background:'#030712',color:'#e2e8f0',fontFamily:"'Inter',sans-serif",overflowX:'hidden'}}>
      {/* Global scroll progress */}
      <div style={{position:'fixed',top:0,left:0,height:'2px',zIndex:1001,width:`${totalP*100}%`,background:'linear-gradient(90deg,#6366f1,#8b5cf6,#06b6d4)',pointerEvents:'none'}} />

      <Navbar scrollY={scrollY} onEnterDashboard={onEnterDashboard} />
      <HeroSection onEnterDashboard={onEnterDashboard} />
      <AboutSection />
      <PipelineSection />
      <WorkflowSection />
      <AgentsSection />
      <TechSection />
      <CTASection onEnterDashboard={onEnterDashboard} />

      <footer style={{textAlign:'center',padding:'48px',color:'#334155',borderTop:'1px solid rgba(255,255,255,0.04)',background:'rgba(15,23,42,0.6)',fontSize:'13px'}}>
        <div style={{fontFamily:"'Sora',sans-serif",fontWeight:800,fontSize:'20px',marginBottom:'10px',background:'linear-gradient(135deg,#6366f1,#06b6d4)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent',backgroundClip:'text'}}>Specula</div>
        <p>Multi-Agent DFIR System · LangGraph · Neo4j · Kafka · FastAPI</p>
      </footer>
    </div>
  );
}
