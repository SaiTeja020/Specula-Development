import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { startPolling } from '../src/lib/polling.js';

test('visible polling reloads changed data, pauses hidden, refreshes on focus and stops cleanly', async t => {
  globalThis.document = new EventTarget();
  document.hidden = false;
  globalThis.window = new EventTarget();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let calls = 0;
  let total = 1;
  const seen = [];
  const poller = startPolling(async () => { calls++; seen.push(total); });
  try {
    await setImmediate();
    assert.equal(calls, 1);
    total = 2;
    t.mock.timers.tick(10000);
    await setImmediate();
    assert.deepEqual(seen, [1, 2]);
    document.hidden = true;
    document.dispatchEvent(new Event('visibilitychange'));
    t.mock.timers.tick(30000);
    await setImmediate();
    assert.equal(calls, 2);
    document.hidden = false;
    document.dispatchEvent(new Event('visibilitychange'));
    await setImmediate();
    assert.equal(calls, 3);
    window.dispatchEvent(new Event('focus'));
    await setImmediate();
    assert.equal(calls, 4);
    await poller.refresh();
    assert.equal(calls, 5);
    poller.stop();
    t.mock.timers.tick(30000);
    window.dispatchEvent(new Event('focus'));
    await setImmediate();
    assert.equal(calls, 5);
  } finally {
    poller.stop(); t.mock.timers.reset(); delete globalThis.document; delete globalThis.window;
  }
});

test('slow requests never overlap and stopped requests never schedule another refresh', async t => {
  globalThis.document = new EventTarget(); document.hidden = false;
  globalThis.window = new EventTarget();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let finish;
  let calls = 0;
  const poller = startPolling(async () => { calls++; await new Promise(resolve => { finish = resolve; }); });
  try {
    await poller.refresh();
    t.mock.timers.tick(50000);
    window.dispatchEvent(new Event('focus'));
    assert.equal(calls, 1);
    poller.stop();
    finish();
    await setImmediate();
    t.mock.timers.tick(50000);
    assert.equal(calls, 1);
  } finally {
    poller.stop(); t.mock.timers.reset(); delete globalThis.document; delete globalThis.window;
  }
});
