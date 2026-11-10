import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, ArrowDown, ArrowRight, Fingerprint, FileJson2, Network, ScanLine, FileText, Check, ShieldCheck, Pause } from 'lucide-react';
import './landing-page.css';

const stages = [
  { label: 'Automatic parsing', title: ['First,', 'find the signal.'], text: 'Different formats. Different sources. One language. Original evidence is preserved as supported telemetry becomes structured, connected records.', detail: 'RAW TELEMETRY → STRUCTURED EVIDENCE', icon: FileJson2 },
  { label: 'Multi-agent analysis', title: ['One case.', 'Many perspectives.'], text: 'Specialists follow different threads through the same evidence. Their observations connect in a shared graph, then face independent scrutiny.', detail: 'SPECIALIST ANALYSIS → INDEPENDENT REVIEW', icon: Network },
  { label: 'Threat detection', title: ['Connect events.', 'Reveal the pattern.'], text: 'A process. A connection. An unexpected sequence. Trace suspicious activity across hosts and time, with source evidence behind every observation.', detail: 'ISOLATED EVENTS → CITED OBSERVATIONS', icon: ScanLine },
  { label: 'Report generation', title: ['The evidence.', 'In black and white.'], text: 'The case becomes a technical examination and a court-submission draft. Sources, methods and limitations stay visible. Final judgment stays with the examiner.', detail: 'REVIEWED FINDINGS → EXAMINATION REPORTS', icon: FileText },
];
const agentNodes = [
  { x: 170, y: 148, label: 'LOG ANALYSIS', sub: 'Events & processes' },
  { x: 570, y: 124, label: 'NETWORK FORENSICS', sub: 'Connections & traffic' },
  { x: 645, y: 352, label: 'SYNTHESIS', sub: 'Cross-source context' },
  { x: 375, y: 465, label: 'INDEPENDENT REVIEW', sub: 'Proponent · critic · judge' },
  { x: 120, y: 353, label: 'TIMELINE', sub: 'Recorded chronology' },
];

function BrandEye() {
  const pupil = useRef(null);
  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce), (pointer: coarse)');
    let frame;
    const reset = () => { if (pupil.current) pupil.current.style.transform = 'translate(0px, 0px)'; };
    const move = (event) => {
      if (media.matches || event.pointerType === 'touch' || pupil.current?.closest?.('[data-motion="paused"]')) return;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        if (!pupil.current) return;
        const bounds = pupil.current.ownerSVGElement.getBoundingClientRect();
        const dx = event.clientX - (bounds.left + bounds.width * .56);
        const dy = event.clientY - (bounds.top + bounds.height * .45);
        const length = Math.hypot(dx, dy) || 1;
        const distance = Math.min(length / 10, 22);
        pupil.current.style.transform = `translate(${dx / length * distance}px, ${dy / length * distance * .65}px)`;
      });
    };
    const leave = () => { cancelAnimationFrame(frame); reset(); };
    window.addEventListener('pointermove', move, { passive: true });
    document.documentElement.addEventListener('pointerleave', leave);
    window.addEventListener('blur', leave);
    media.addEventListener('change', leave);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('pointermove', move);
      document.documentElement.removeEventListener('pointerleave', leave);
      window.removeEventListener('blur', leave);
      media.removeEventListener('change', leave);
    };
  }, []);
  return <div className="sp-eye-scene" aria-hidden="true">
    <div className="sp-eye-aura" />
    <div className="sp-eye-orbit"><i /><i /><i /></div>
    <div className="sp-eye-axis sp-eye-axis-x" /><div className="sp-eye-axis sp-eye-axis-y" />
    <span className="sp-eye-index">FIG. 01 — THE OBSERVER</span>
    <svg className="sp-brand-eye" viewBox="0 0 600 700" fill="none">
      <defs>
        <linearGradient id="sp-sculpture" x1="115" y1="50" x2="495" y2="650" gradientUnits="userSpaceOnUse"><stop stopColor="#b9a0db" /><stop offset=".28" stopColor="#7348ad" /><stop offset=".65" stopColor="#42246d" /><stop offset="1" stopColor="#241339" /></linearGradient>
        <linearGradient id="sp-edge" x1="180" y1="170" x2="420" y2="500"><stop stopColor="#e4d2ff" /><stop offset="1" stopColor="#7e52ae" stopOpacity="0" /></linearGradient>
        <radialGradient id="sp-iris"><stop stopColor="#241339" /><stop offset=".68" stopColor="#4d2b76" /><stop offset="1" stopColor="#9775ba" /></radialGradient>
        <clipPath id="sp-eye-clip"><path d="M98 332Q298 110 502 326Q320 526 98 332Z" /></clipPath>
      </defs>
      <ellipse cx="305" cy="657" rx="135" ry="12" fill="#4b2867" opacity=".09" />
      <g className="sp-logo-sculpture">
        <path d="M148 247Q134 259 143 240L306 39Q325 14 346 36L374 68Q391 91 368 111Z" fill="url(#sp-sculpture)" stroke="url(#sp-edge)" strokeWidth="1.5" />
        <path d="M98 332Q298 110 502 326Q320 526 98 332Z" fill="url(#sp-sculpture)" stroke="url(#sp-edge)" strokeWidth="2" />
        <path d="M252 405L215 638Q300 657 386 638L348 407Z" fill="url(#sp-sculpture)" />
        <path d="M253 430L223 633" stroke="#c4a4e4" strokeOpacity=".4" />
        <g clipPath="url(#sp-eye-clip)"><g ref={pupil} className="sp-pupil" data-testid="brand-pupil">
          <circle cx="329" cy="321" r="66" fill="#eee9f2" /><circle cx="329" cy="321" r="53" fill="url(#sp-iris)" />
          {Array.from({ length: 40 }, (_, i) => <path key={i} d="M329 273V284" stroke="#c8b1e1" strokeOpacity=".45" transform={`rotate(${i * 9} 329 321)`} />)}
          <circle cx="329" cy="321" r="28" fill="#190f26" /><circle cx="329" cy="321" r="20" stroke="#a180c1" strokeOpacity=".35" />
          <ellipse cx="346" cy="302" rx="11" ry="6" fill="white" opacity=".85" transform="rotate(-35 346 302)" /><circle cx="314" cy="339" r="4" fill="#e0caff" opacity=".5" />
        </g></g>
        <path d="M108 330Q294 127 493 326" stroke="#dcc6f3" strokeOpacity=".5" strokeWidth="1.5" />
      </g>
    </svg>
    <div className="sp-eye-reticle"><span /><span /><span /><span /></div>
    <div className="sp-eye-label"><span className="sp-status-light" /><span>ATTENTION, BY DESIGN.</span><span className="sp-eye-label-line" /></div>
    <span className="sp-eye-instruction">Move your cursor. It’s looking back.</span>
  </div>;
}

function EvidenceScene({ stage }) {
  return <div className={`sp-evidence-scene sp-scene-${stage}`} aria-hidden="true">
    <svg className="sp-evidence-svg" viewBox="0 0 800 570" fill="none">
      <defs>
        <linearGradient id="sp-wire"><stop stopColor="#b5a0d1" stopOpacity=".05" /><stop offset=".5" stopColor="#c3a3ef" /><stop offset="1" stopColor="#b5a0d1" stopOpacity=".08" /></linearGradient>
        <linearGradient id="sp-scan"><stop stopColor="#ad86ee" stopOpacity="0" /><stop offset="1" stopColor="#ad86ee" stopOpacity=".2" /></linearGradient>
        <radialGradient id="sp-node-glow"><stop stopColor="#baa0e9" stopOpacity=".23" /><stop offset="1" stopColor="#baa0e9" stopOpacity="0" /></radialGradient>
      </defs>
      {Array.from({ length: 7 }, (_, i) => <ellipse key={i} cx="390" cy="285" rx={100 + i * 38} ry={55 + i * 26} stroke="#b09acc" strokeOpacity={.025 + i * .008} transform="rotate(-18 390 285)" />)}
      {stage === 0 && <g className="sp-parse-art">
        {[0, 1, 2, 3, 4].map((i) => <g key={i} className="sp-packet" style={{ '--i': i }}>
          <path d={`M${65 + i * 8} ${125 + i * 72}C280 ${100 + i * 75} 270 285 425 285`} stroke="url(#sp-wire)" strokeWidth="1" />
          <path className="sp-flow-pulse" d={`M${65 + i * 8} ${125 + i * 72}C280 ${100 + i * 75} 270 285 425 285`} stroke="#cdb1fa" strokeWidth="2" strokeDasharray="7 330" />
          <rect x={42 + i * 8} y={108 + i * 72} width="158" height="36" rx="4" fill="#18161f" stroke="#44394f" />
          <circle cx={57 + i * 8} cy={126 + i * 72} r="3" fill="#aa88d3" />
          <text x={70 + i * 8} y={130 + i * 72} fill="#b9b0c5" fontSize="10">{['security.jsonl', 'network.json', 'sysmon.jsonl', 'process events', 'source metadata'][i]}</text>
        </g>)}
        <g className="sp-parser-gate"><path d="M395 128L455 102V442L395 469Z" fill="#a37dd9" fillOpacity=".08" stroke="#a37dd9" strokeOpacity=".5" /><path d="M425 115V455" stroke="#d0adff" strokeWidth="2" /><path className="sp-scan-beam" d="M394 167L455 141V237L394 263Z" fill="url(#sp-scan)" /><text x="431" y="360" transform="rotate(-90 431 360)" fill="#cbb3e9" fontSize="10" letterSpacing="6">NORMALIZE</text></g>
        <path d="M455 285H555" stroke="#a788c7" /><path className="sp-flow-pulse" d="M455 285H555" stroke="#e1cbff" strokeWidth="2" strokeDasharray="5 100" />
        <g className="sp-event-record"><rect x="550" y="186" width="203" height="202" rx="6" fill="#211b2b" stroke="#80629c" /><path d="M550 226H753" stroke="#594268" /><text x="571" y="212" fill="#e6d6fa" fontSize="11">STRUCTURED EVENT</text><text x="571" y="257" fill="#8f7da1" fontSize="10">class</text><text x="571" y="278" fill="#ded1ed" fontSize="13">NetworkActivity</text><text x="571" y="308" fill="#8f7da1" fontSize="10">uid</text><text x="571" y="329" fill="#ded1ed" fontSize="13">a7e2...9f01</text><circle cx="576" cy="361" r="3" fill="#a6d9bb" /><text x="588" y="365" fill="#a6d9bb" fontSize="9">Source reference retained</text></g>
        <text x="55" y="530" fill="#82718f" fontSize="9" letterSpacing="2">01 / PRESERVE</text><text x="365" y="530" fill="#82718f" fontSize="9" letterSpacing="2">02 / PARSE</text><text x="606" y="530" fill="#82718f" fontSize="9" letterSpacing="2">03 / CONNECT</text>
      </g>}
      {stage === 1 && <g className="sp-agents-art">
        <circle cx="385" cy="280" r="180" fill="url(#sp-node-glow)" />
        {agentNodes.map((node, i) => <g key={node.label} className="sp-agent-satellite" style={{ '--i': i }}>
          <path d={`M385 280Q${node.x} 280 ${node.x} ${node.y}`} stroke="#79628f" strokeWidth="1" />
          <path className="sp-flow-pulse" d={`M385 280Q${node.x} 280 ${node.x} ${node.y}`} stroke="#d8b9ff" strokeWidth="2" strokeDasharray="8 360" />
          <circle cx={node.x} cy={node.y} r="27" fill="#24202d" stroke="#82659f" /><circle className="sp-node-halo" cx={node.x} cy={node.y} r="35" stroke="#a889ca" strokeOpacity=".25" />
          <path d={`M${node.x - 7} ${node.y}h14M${node.x} ${node.y - 7}v14`} stroke="#d2b6f3" />
          <text x={node.x} y={node.y + 53} textAnchor="middle" fill="#ddcbed" fontSize="10" letterSpacing="1">{node.label}</text>
          <text x={node.x} y={node.y + 70} textAnchor="middle" fill="#92839e" fontSize="9">{node.sub}</text>
        </g>)}
        <g className="sp-graph-core"><circle cx="385" cy="280" r="77" fill="#b692e0" fillOpacity=".05" stroke="#9672ba" strokeOpacity=".3" /><circle className="sp-core-ring" cx="385" cy="280" r="63" stroke="#c6a4ef" strokeDasharray="2 8" /><circle cx="385" cy="280" r="51" fill="#c5a5e6" /><path d="M365 278L385 258L405 278L385 298Z" stroke="#4b2e68" strokeWidth="1.5" /><circle cx="385" cy="278" r="7" fill="#4b2e68" /><text x="385" y="374" textAnchor="middle" fill="#d8c6e8" fontSize="10" letterSpacing="3">SHARED EVIDENCE</text></g>
      </g>}
      {stage === 2 && <g className="sp-detection-art">
        <path d="M55 180H755M55 240H755M55 300H755" stroke="#44364f" strokeDasharray="2 7" />
        {Array.from({ length: 64 }, (_, i) => <path key={i} className="sp-signal-bar" style={{ '--i': i }} d={`M${62 + i * 10.5} 308v-${18 + ((i * 19) % 65) + (i > 35 && i < 45 ? 85 : 0)}`} stroke={i > 35 && i < 45 ? '#e4bc8b' : '#7c638f'} strokeWidth="4" />)}
        <g className="sp-threat-window"><rect x="431" y="119" width="110" height="208" rx="4" stroke="#e4bc8b" strokeDasharray="4 5" fill="#e4bc8b" fillOpacity=".035" /><text x="439" y="104" fill="#e4bc8b" fontSize="10" letterSpacing="2">INVESTIGATE</text></g>
        <path d="M100 418H700" stroke="#8f7157" /><path className="sp-timeline-trace" d="M100 418H700" stroke="#e4bc8b" strokeWidth="2" pathLength="1" />
        {[{ x: 100, title: 'AUTHENTICATION', time: '14:32:08' }, { x: 390, title: 'PROCESS CREATED', time: '14:32:11' }, { x: 700, title: 'OUTBOUND ACTIVITY', time: '14:32:19' }].map((event, i) => <g className="sp-threat-event" key={event.title} style={{ '--i': i }}><circle cx={event.x} cy="418" r="7" fill="#1d1922" stroke="#e4bc8b" /><circle className="sp-node-halo" cx={event.x} cy="418" r="17" stroke="#e4bc8b" strokeOpacity=".3" /><text x={event.x} y="453" textAnchor="middle" fill="#dccab8" fontSize="9">{event.title}</text><text x={event.x} y="475" textAnchor="middle" fill="#938374" fontSize="10">{event.time}</text></g>)}
        <text x="400" y="542" textAnchor="middle" fill="#c7a88b" fontSize="9" letterSpacing="2">3 SOURCE-LINKED OBSERVATIONS / REVIEW REQUIRED</text>
      </g>}
      {stage === 3 && <g className="sp-report-art">
        <g className="sp-paper sp-paper-back" transform="translate(160 105) rotate(-12 130 180)"><rect width="265" height="354" rx="3" fill="#bca9d0" /><text x="28" y="42" fill="#53415f" fontSize="8" letterSpacing="1">SPECULA / COURT-SUBMISSION DRAFT</text><path d="M28 62H237" stroke="#907b9f" /><text x="28" y="118" fill="#32233e" fontSize="27">Evidence.</text><text x="28" y="151" fill="#32233e" fontSize="27">In context.</text>{[0, 1, 2, 3, 4, 5].map(i => <path key={i} d={`M28 ${190 + i * 17}h${i % 3 === 0 ? 150 : 200}`} stroke="#8e779f" strokeWidth="3" />)}<text x="28" y="325" fill="#53415f" fontSize="8">EXAMINER REVIEW REQUIRED</text></g>
        <g className="sp-paper sp-paper-front" transform="translate(360 66) rotate(8 140 200)"><rect width="284" height="392" rx="3" fill="#f0ece4" /><text x="28" y="38" fill="#736a79" fontSize="8" letterSpacing="1">SPECULA / TECHNICAL EXAMINATION</text><path d="M28 56H256" stroke="#c7bdce" /><path d="M28 92L45 75L62 92L45 109Z" stroke="#6c477e" /><text x="28" y="154" fill="#302438" fontSize="29">The complete</text><text x="28" y="190" fill="#302438" fontSize="29">case record.</text><text x="28" y="224" fill="#82728c" fontSize="8" letterSpacing="1">EVIDENCE / METHODS / LIMITATIONS</text>{[0, 1, 2, 3].map(i => <path className="sp-report-line" style={{ '--i': i }} key={i} d={`M28 ${253 + i * 17}h${i === 3 ? 145 : 220}`} stroke="#b8acbf" strokeWidth="3" pathLength="1" />)}<path d="M28 338H256" stroke="#c7bdce" /><circle cx="35" cy="359" r="5" stroke="#6b886e" /><path d="M32 359L34 361L38 357" stroke="#6b886e" /><text x="49" y="362" fill="#617364" fontSize="8">Evidence references included</text></g>
        <g className="sp-report-seal"><circle cx="635" cy="428" r="40" fill="#2d2436" stroke="#b593ce" /><path d="M622 427L631 436L649 417" stroke="#dac4eb" strokeWidth="2" /><circle cx="635" cy="428" r="33" stroke="#b593ce" strokeDasharray="1 5" /></g>
      </g>}
    </svg>
    <div className="sp-scene-coordinates"><span>ILLUSTRATIVE WORKFLOW</span><span>NOT LIVE CASE DATA</span></div>
  </div>;
}

export default function LandingPage() {
  const [stage, setStage] = useState(0);
  const page = useRef(null);
  useEffect(() => {
    if (!('IntersectionObserver' in window)) return;
    const root = page.current;
    const story = root.querySelector('.sp-story');
    const hero = root.querySelector('.sp-hero');
    const intro = root.querySelector('.sp-intro');
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const smallScreen = window.matchMedia('(max-width: 760px)');
    let scrollFrame = 0;
    let pointerFrame = 0;
    let currentStage = -1;
    let pointerX = window.innerWidth / 2;
    let pointerY = window.innerHeight / 2;
    let smoothX = pointerX;
    let smoothY = pointerY;
    let active = true;
    const observer = new IntersectionObserver(entries => entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('sp-in-view'); observer.unobserve(entry.target); }
    }), { threshold: .15 });
    root.querySelectorAll('[data-reveal]').forEach(node => observer.observe(node));
    const updateScroll = () => {
      scrollFrame = 0;
      if (!active) return;
      const height = window.innerHeight;
      const heroRect = hero.getBoundingClientRect();
      const storyRect = story.getBoundingClientRect();
      const introRect = intro.getBoundingClientRect();
      const reduced = motion.matches || root.dataset.motion === 'paused';
      const progress = Math.max(0, Math.min(1, -storyRect.top / Math.max(1, story.offsetHeight - height)));
      const scaled = Math.min(3.999, progress * 4);
      root.style.setProperty('--hero-exit', reduced ? 0 : Math.max(0, Math.min(1, -heroRect.top / height)));
      root.style.setProperty('--intro-progress', reduced ? .5 : Math.max(0, Math.min(1, (height - introRect.top) / (height + introRect.height))));
      root.style.setProperty('--journey-progress', progress);
      root.style.setProperty('--stage-progress', scaled % 1);
      root.dataset.storyVisible = storyRect.top < height && storyRect.bottom > 0 ? 'true' : 'false';
      if (!smallScreen.matches && !motion.matches && storyRect.top <= 1 && storyRect.bottom >= height - 1) {
        const next = Math.floor(scaled);
        if (next !== currentStage) { currentStage = next; setStage(next); }
      }
    };
    const onScroll = () => { if (!scrollFrame) scrollFrame = requestAnimationFrame(updateScroll); };
    const updatePointer = () => {
      if (!active) return;
      const reduced = motion.matches || root.dataset.motion === 'paused';
      smoothX += (pointerX - smoothX) * .13;
      smoothY += (pointerY - smoothY) * .13;
      root.style.setProperty('--cursor-x', `${smoothX}px`);
      root.style.setProperty('--cursor-y', `${smoothY}px`);
      root.style.setProperty('--look-x', reduced ? 0 : (smoothX / window.innerWidth - .5) * 2);
      root.style.setProperty('--look-y', reduced ? 0 : (smoothY / window.innerHeight - .5) * 2);
      pointerFrame = !reduced && (Math.abs(pointerX - smoothX) > .15 || Math.abs(pointerY - smoothY) > .15) ? requestAnimationFrame(updatePointer) : 0;
    };
    const onPointer = event => {
      if (event.pointerType === 'touch' || motion.matches) return;
      pointerX = event.clientX; pointerY = event.clientY;
      root.dataset.cursor = event.target.closest('a, button') ? 'link' : 'observe';
      root.dataset.pointer = 'true';
      if (!pointerFrame) pointerFrame = requestAnimationFrame(updatePointer);
    };
    const leave = () => { root.dataset.pointer = 'false'; };
    const visibility = () => { if (document.hidden) { cancelAnimationFrame(pointerFrame); pointerFrame = 0; leave(); } else onScroll(); };
    window.addEventListener('scroll', onScroll, { passive: true, capture: true });
    window.addEventListener('resize', onScroll, { passive: true });
    window.addEventListener('pointermove', onPointer, { passive: true });
    window.addEventListener('blur', leave);
    document.documentElement.addEventListener('pointerleave', leave);
    document.addEventListener('visibilitychange', visibility);
    motion.addEventListener('change', onScroll);
    updateScroll();
    return () => {
      active = false;
      observer.disconnect(); cancelAnimationFrame(scrollFrame); cancelAnimationFrame(pointerFrame);
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onScroll);
      window.removeEventListener('pointermove', onPointer);
      window.removeEventListener('blur', leave);
      document.documentElement.removeEventListener('pointerleave', leave);
      document.removeEventListener('visibilitychange', visibility);
      motion.removeEventListener('change', onScroll);
    };
  }, []);
  const chooseStage = index => {
    setStage(index);
    const story = page.current?.querySelector('.sp-story');
    if (!story || window.matchMedia('(max-width: 760px), (prefers-reduced-motion: reduce)').matches) return;
    const target = story.getBoundingClientRect().top + window.scrollY + (story.offsetHeight - window.innerHeight) * ((index + .12) / 4);
    window.scrollTo({ top: target, behavior: 'smooth' });
  };
  const selectWithKeys = (event, index) => {
    const next = event.key === 'ArrowDown' || event.key === 'ArrowRight' ? (index + 1) % 4 : event.key === 'ArrowUp' || event.key === 'ArrowLeft' ? (index + 3) % 4 : event.key === 'Home' ? 0 : event.key === 'End' ? 3 : null;
    if (next === null) return;
    event.preventDefault(); chooseStage(next); document.getElementById(`sp-stage-${next}`).focus();
  };
  const toggleMotion = event => {
    const button = event.currentTarget;
    const paused = button.getAttribute('aria-pressed') !== 'true';
    button.setAttribute('aria-pressed', String(paused));
    button.setAttribute('aria-label', paused ? 'Resume ambient motion' : 'Pause ambient motion');
    page.current.dataset.motion = paused ? 'paused' : 'playing';
  };
  return <div className="sp-landing" ref={page} data-motion="playing">
    <a className="sp-skip" href="#sp-main">Skip to content</a>
    <div className="sp-cursor" aria-hidden="true"><span /></div>
    <header className="sp-nav">
      <Link to="/" className="sp-wordmark" aria-label="Specula home"><img src="/Specula_logo.png" alt="" /><span>specula.</span></Link>
      <nav aria-label="Landing page"><a href="#how-it-works">How it works <span>↘</span></a><Link to="/history">Case history</Link></nav>
      <div className="sp-nav-end"><button type="button" className="sp-motion-toggle" aria-label="Pause ambient motion" aria-pressed="false" onClick={toggleMotion}><Pause size={13} /></button><Link to="/investigate">Workspace <ArrowUpRight size={15} /></Link></div>
    </header>
    <main id="sp-main">
      <section className="sp-hero" aria-labelledby="sp-hero-title">
        <div className="sp-hero-copy">
          <div className="sp-eyebrow sp-hero-enter"><span className="sp-status-light" /> MULTI-AGENT DIGITAL FORENSICS</div>
          <h1 id="sp-hero-title"><span className="sp-title-line"><span>Look closer.</span></span><span className="sp-title-line"><span>Nothing exists</span></span><span className="sp-title-line sp-title-italic"><span>in isolation.</span></span></h1>
          <p className="sp-hero-enter">The evidence is scattered.<br />The story doesn’t have to be.</p>
          <div className="sp-hero-actions sp-hero-enter"><Link to="/startup" className="sp-button sp-button-primary"><span>Initialize system</span><ArrowUpRight size={18} /></Link><Link to="/investigate" className="sp-resume">Resume investigation <ArrowRight size={15} /></Link></div>
        </div>
        <BrandEye />
        <div className="sp-hero-bottom"><a href="#how-it-works" className="sp-scroll-cue"><span className="sp-scroll-icon"><ArrowDown size={15} /></span><span>SCROLL TO INVESTIGATE</span></a><span className="sp-hero-signoff">Built to see the connections.</span><span className="sp-hero-edition">EVIDENCE → INTELLIGENCE</span></div>
      </section>
      <section className="sp-intro" id="how-it-works" aria-labelledby="sp-intro-title">
        <div className="sp-intro-meta"><span>THE SPACE BETWEEN THE SIGNALS</span><span>01 — 04</span></div>
        <h2 id="sp-intro-title" data-reveal>One event is a clue.<br /><span>A connection</span><br /><em>changes everything.</em></h2>
        <div className="sp-intro-bottom"><p>Follow the journey from raw telemetry to a case you can explain. Four stages. A continuous thread of evidence.</p><div><span>THE INVESTIGATION, UNFOLDED</span><ArrowDown size={18} /></div></div>
        <div className="sp-intro-thread" aria-hidden="true"><svg viewBox="0 0 1200 220" preserveAspectRatio="none"><path d="M-100 180C300 180 220 -80 600 100S850 150 1300 0" /></svg><i /></div>
      </section>
      <section className="sp-story" aria-label="The four stages of an investigation">
        <div className="sp-story-pin">
          <div className="sp-story-grid" aria-hidden="true" />
          <div className="sp-story-top"><span><span className="sp-status-light" /> THE EVIDENCE ENGINE</span><span>SCROLL TO EXPLORE <ArrowDown size={12} /></span><span>0{stage + 1} / 04</span></div>
          <div className="sp-story-main" id="sp-stage-panel" role="tabpanel" aria-labelledby={`sp-stage-${stage}`} tabIndex={0}>
            <div className="sp-story-copy" key={`copy-${stage}`}><span className="sp-chapter-kicker">CHAPTER 0{stage + 1} / {stages[stage].label.toUpperCase()}</span><h2>{stages[stage].title[0]}<br /><em>{stages[stage].title[1]}</em></h2><p>{stages[stage].text}</p><span className="sp-stage-detail"><span />{stages[stage].detail}</span></div>
            <EvidenceScene stage={stage} key={stage} />
          </div>
          <div className="sp-story-controls"><div className="sp-stage-list" role="tablist" aria-label="Investigation stages">{stages.map((item, index) => <button type="button" key={item.label} id={`sp-stage-${index}`} className={`sp-stage ${index === stage ? 'is-selected' : ''} ${index < stage ? 'is-complete' : ''}`} role="tab" aria-selected={stage === index} aria-controls="sp-stage-panel" tabIndex={stage === index ? 0 : -1} onClick={() => chooseStage(index)} onKeyDown={event => selectWithKeys(event, index)}><span className="sp-stage-track"><i /></span><span className="sp-stage-index">0{index + 1}</span><span>{item.label}</span><item.icon size={16} /></button>)}</div></div>
        </div>
      </section>
      <section className="sp-human" aria-labelledby="sp-human-title">
        <div className="sp-human-heading" data-reveal><div className="sp-eyebrow">AUTONOMOUS ANALYSIS. ACCOUNTABLE DECISIONS.</div><h2 id="sp-human-title">The final word<br />is <em>always yours.</em></h2><p>Agents connect the dots. You challenge the conclusions.<br />Every finding is a starting point for human judgment.</p></div>
        <div className="sp-human-visual" aria-hidden="true"><div className="sp-human-orbit sp-human-orbit-a" /><div className="sp-human-orbit sp-human-orbit-b" /><div className="sp-human-orbit sp-human-orbit-c" /><div className="sp-human-core"><Fingerprint size={68} strokeWidth={.7} /></div><span className="sp-human-node sp-human-node-a"><Network size={17} />Agents</span><span className="sp-human-node sp-human-node-b"><ShieldCheck size={17} />Evidence</span><span className="sp-human-node sp-human-node-c"><Check size={17} />Your judgment</span></div>
      </section>
      <section className="sp-closing"><div className="sp-closing-top"><span className="sp-eyebrow">A DIFFERENT WAY TO SEE.</span><ArrowUpRight size={28} strokeWidth={1} /></div><Link to="/startup" className="sp-closing-link"><span>Start connecting.</span><span className="sp-closing-arrow"><ArrowUpRight strokeWidth={.8} /></span></Link><div className="sp-closing-bottom"><span>Your next investigation starts with a closer look.</span><Link to="/investigate">Or pick up where you left off <ArrowRight size={14} /></Link></div></section>
    </main>
    <footer className="sp-footer"><Link to="/" className="sp-wordmark">specula.</Link><span>Independent perspectives. Connected intelligence.</span><a href="#sp-main">BACK TO TOP <ArrowUpRight size={13} /></a></footer>
  </div>;
}
