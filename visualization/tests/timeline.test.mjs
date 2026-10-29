import assert from 'node:assert/strict';
import { test } from 'node:test';
import React from 'react';
import { renderToString } from 'react-dom/server';
import { createServer } from 'vite';
import { buildTimeline, utcTime } from '../src/lib/timeline.js';

const snapshot = {
  case_id: 'history-case',
  evidence_collection: { records: [
    { uid: 'file', time: '2025-01-01T00:00:00Z', si_created: '2025-01-01T00:00:00Z', file_path: 'C:\\sample.exe' },
    { uid: 'failed', time: '2026-10-27T15:00:00+05:30', source_type: 'evtx', source_event_id: 4625, source_user_name: 'analyst', host_name: 'host-a' },
    { uid: 'process', time: '2026-10-27T10:00:00Z', source_event_id: 1, process_name: 'C:\\powershell.exe', command_line: '<script>&source-command', host_name: 'host-a' },
    { uid: 'undated', time: '2026-10-27T09:00:00', host_name: 'host-b' },
  ] },
  timeline: { events: [
    { uid: 'process', time: '2026-10-27T10:00:00Z', dfkg_refs: ['process'], summary: 'INTERNAL LOG DUMP' },
    { uid: 'file', time: '2025-01-01T00:00:00Z', dfkg_refs: ['file'], time_basis: 'file_metadata' },
    { uid: 'undated', time: '2026-10-27T09:00:00', dfkg_refs: ['undated'] },
    { uid: 'failed', time: '2026-10-27T15:00:00+05:30', dfkg_refs: ['failed'] },
  ] },
};

test('timeline joins original fields and sorts UTC times with unknown times last', () => {
  const original = structuredClone(snapshot);
  const events = buildTimeline(snapshot);
  assert.deepEqual(events.map(e => e.id), ['file', 'failed', 'process', 'undated']);
  assert.equal(events[0].title, 'File timestamp recorded');
  assert.equal(events[0].metadata, true);
  assert.equal(events[1].title, 'Sign-in failed');
  assert.equal(events[1].time, '2026-10-27T09:30:00.000Z');
  assert.equal(events[2].title, 'powershell.exe — process started');
  assert.equal(events[2].host, 'host-a');
  assert.ok(events[2].details.some(([key, value]) => key === 'Command' && value.includes('<script>')));
  assert.equal(events[3].time, null);
  assert.deepEqual(snapshot, original);
  assert.equal(utcTime(0), '1970-01-01T00:00:00.000Z');
  assert.equal(utcTime(1793095200000), '2026-10-27T10:00:00.000Z');
  assert.equal(utcTime('invalid'), null);
  assert.equal(utcTime('2026-10-27T09:00:00'), null);
  assert.equal(buildTimeline({ evidence_collection: snapshot.evidence_collection }).length, 4);
});

test('saved timeline renders readable cards, time caveats, filters and escaped source details', async () => {
  const server = await createServer({ root: new URL('../', import.meta.url).pathname.replace(/^\/(\w:)/, '$1'), server: { middlewareMode: true, hmr: false } });
  try {
    const { default: Timeline } = await server.ssrLoadModule('/src/pages/EvidenceTimeline.jsx');
    const html = renderToString(React.createElement(Timeline, { snapshot }));
    assert.match(html, /What happened, and when/);
    assert.match(html, /Sign-in failed/);
    assert.match(html, /does not establish when the file was executed/);
    assert.match(html, /Show activity/);
    assert.match(html, /Time unavailable/);
    assert.match(html, /&lt;script&gt;/);
    assert.doesNotMatch(html, /INTERNAL LOG DUMP|<script>/);
    assert.match(html, /Source details and/);
    assert.ok(html.indexOf('2025-01-01 · UTC') < html.indexOf('2026-10-27 · UTC'));
  } finally { await server.close(); }
});
