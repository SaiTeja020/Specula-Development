import { useState } from 'react';
import { buildTimeline, utcTime } from '../lib/timeline';
import './evidence-timeline.css';

export default function EvidenceTimeline({ snapshot }) {
  const [filter, setFilter] = useState('All activity');
  const [page, setPage] = useState(0);
  if (!snapshot) return <p role="status">Open a saved investigation to view its timeline.</p>;
  const events = buildTimeline(snapshot);
  const categories = [...new Set(events.map(e => e.category))].sort();
  const selected = filter === 'All activity' ? events : events.filter(e => e.category === filter);
  const pageSize = 25;
  const pages = Math.max(1, Math.ceil(selected.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = selected.slice(current * pageSize, (current + 1) * pageSize);
  const dated = events.filter(e => e.time);
  const episodes = snapshot.timeline?.episodes || [];
  return <section className="evidence-timeline" aria-label="Evidence timeline">
    <header className="timeline-intro">
      <p className="timeline-eyebrow">CASE CHRONOLOGY</p>
      <h2>What happened, and when</h2>
      <p>Follow the recorded activity in time order. All times are UTC. Related records show an association, not proof of causation.</p>
      <dl className="timeline-metrics">
        <div><dt>Recorded events</dt><dd>{events.length}</dd></div>
        <div><dt>Related-event groups</dt><dd>{episodes.length}</dd></div>
        <div><dt>Unplaced in time</dt><dd>{events.length - dated.length}</dd></div>
      </dl>
      {dated.length > 0 && <p className="timeline-range">Recorded range: {dated[0].day} to {dated.at(-1).day}</p>}
    </header>
    {episodes.length > 0 && <details className="timeline-episodes">
      <summary>Explore {episodes.length} related-event groups</summary>
      <p>These groups use source identifiers and time windows. They are not verified attack stages.</p>
      {episodes.map((episode, index) => <article key={episode.id || index}>
        <h3>Group {index + 1} · {episode.dfkg_refs?.length || 0} records</h3>
        <p>{(episode.hosts || []).join(', ') || 'Host not recorded'}</p>
        <p>{utcTime(episode.start_time) || 'Start time unavailable'} to {utcTime(episode.end_time) || 'End time unavailable'}</p>
        <p>Connections: {(episode.relation_types || []).map(r => r.replaceAll('_', ' ')).join(', ') || 'See cited records'}</p>
        {episode.clock_uncertainty_present && <p>Source clock uncertainty affects this group.</p>}
        <details><summary>Evidence references</summary><ul>{(episode.dfkg_refs || []).map(uid => <li key={uid}><code>{uid}</code></li>)}</ul></details>
      </article>)}
    </details>}
    <div className="timeline-toolbar">
      <label>Show activity <select value={filter} onChange={e => { setFilter(e.target.value); setPage(0); }}>
        <option>All activity</option>{categories.map(category => <option key={category}>{category}</option>)}
      </select></label>
      <span role="status">{selected.length} event{selected.length === 1 ? '' : 's'}</span>
    </div>
    {!selected.length && <p role="status">No recorded events are available for this selection.</p>}
    <ol className="timeline-events">
      {visible.map((event, index) => <li key={`${event.id}-${index}`}>
        {(index === 0 || visible[index - 1].day !== event.day) && <h3 className="timeline-day">{event.day === 'Time unavailable' ? 'Time unavailable' : `${event.day} · UTC`}</h3>}
        <article className="timeline-card">
          <div className="timeline-event-meta"><time dateTime={event.time || undefined}>{event.time?.slice(11, 19) || 'Unplaced'}</time><span>{event.category}</span></div>
          <h4>{event.title}</h4>
          <p className="timeline-host">{event.host}</p>
          {event.context && <p>{event.context}</p>}
          {event.note && <p>{event.note}</p>}
          {event.metadata && <p className="timeline-time-note">File metadata time · does not establish when the file was executed.</p>}
          {event.capture && <p className="timeline-time-note">Capture time · describes the memory observation, not necessarily when activity began.</p>}
          {event.uncertain && <p className="timeline-time-note">Source clock uncertainty · interpret ordering with caution.</p>}
          {event.derivedTime && <p className="timeline-time-note">Source-declared adjusted time: {event.derivedTime}. Original time is retained above.</p>}
          <details><summary>Source details and {event.refs.length} evidence reference{event.refs.length === 1 ? '' : 's'}</summary>
            <dl className="timeline-source-fields">{event.details.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{String(value)}</dd></div>)}</dl>
            <ul>{event.refs.map(ref => <li key={ref}><code>{ref}</code></li>)}</ul>
          </details>
        </article>
      </li>)}
    </ol>
    {pages > 1 && <nav className="timeline-pagination" aria-label="Timeline pages">
      <button type="button" className="secondary-btn" disabled={current === 0} onClick={() => setPage(current - 1)}>Previous</button>
      <span>Page {current + 1} of {pages}</span>
      <button type="button" className="secondary-btn" disabled={current + 1 === pages} onClick={() => setPage(current + 1)}>Next</button>
    </nav>}
  </section>;
}
