import assert from 'node:assert/strict';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { MemoryRouter } from 'react-router-dom';

test('landing navigation, stage selection, keyboard controls and bounded eye motion', async () => {
  const effects = [];
  const refs = [];
  let selected = 0;
  globalThis.__landingHooks = {
    useState: () => [selected, value => { selected = value; }],
    useEffect: effect => effects.push(effect),
    useRef: () => { const ref = { current: null }; refs.push(ref); return ref; },
  };
  const server = await createServer({
    root: new URL('../', import.meta.url).pathname.replace(/^\/(\w:)/, '$1'),
    // SSR checks do not need the client optimizer or its shared dev cache.
    cacheDir: `node_modules/.vite-tests/landing-${process.pid}`, optimizeDeps: { noDiscovery: true, include: [] },
    server: { middlewareMode: true, hmr: false, ws: false },
    plugins: [{ name: 'landing-hook-probe', enforce: 'pre', transform(code, id) {
      if (id.replaceAll('\\', '/').endsWith('/src/pages/LandingPage.jsx')) {
        return code.replace("import { useEffect, useRef, useState } from 'react';", 'const { useEffect, useRef, useState } = globalThis.__landingHooks;');
      }
    } }],
  });
  const previous = Object.fromEntries(['window', 'document', 'requestAnimationFrame', 'cancelAnimationFrame'].map(key => [key, globalThis[key]]));
  try {
    const { default: LandingPage } = await server.ssrLoadModule('/src/pages/LandingPage.jsx');
    const render = () => renderToStaticMarkup(React.createElement(MemoryRouter, null, React.createElement(LandingPage)));
    let html = render();
    assert.match(html, /href="\/startup"/);
    assert.match(html, /href="\/investigate"/);
    assert.match(html, /href="\/history"/);
    assert.match(html, /href="#how-it-works"/);
    assert.equal((html.match(/role="tab"/g) || []).length, 4);
    assert.match(html, /ILLUSTRATIVE WORKFLOW/);
    const walk = (element, predicate) => {
      if (!React.isValidElement(element)) return [];
      return [...(predicate(element) ? [element] : []), ...React.Children.toArray(element.props.children).flatMap(child => walk(child, predicate))];
    };
    const tabs = () => walk(LandingPage(), element => element.props.role === 'tab');
    for (const [index, expected] of ['sp-parse-art', 'sp-agents-art', 'sp-detection-art', 'sp-report-art'].entries()) {
      tabs()[index].props.onClick();
      html = render();
      assert.ok(html.includes(expected));
      assert.ok(html.includes(`aria-labelledby="sp-stage-${index}"`));
      assert.equal((html.match(/aria-selected="true"/g) || []).length, 1);
    }
    let focused;
    globalThis.document = { getElementById: id => ({ focus: () => { focused = id; } }) };
    let prevented = false;
    tabs()[3].props.onKeyDown({ key: 'ArrowDown', preventDefault: () => { prevented = true; } });
    assert.equal(selected, 0); assert.equal(focused, 'sp-stage-0'); assert.ok(prevented);
    tabs()[0].props.onKeyDown({ key: 'End', preventDefault() {} });
    assert.equal(selected, 3);
    tabs()[3].props.onKeyDown({ key: 'ArrowUp', preventDefault() {} });
    assert.equal(selected, 2);
    tabs()[2].props.onKeyDown({ key: 'Home', preventDefault() {} });
    assert.equal(selected, 0);

    // The first render registers the page observer followed by the actual eye effect.
    const pupil = refs[1];
    pupil.current = { style: {}, ownerSVGElement: { getBoundingClientRect: () => ({ left: 500, top: 100, width: 315, height: 440 }) } };
    const listeners = new Map();
    const media = { matches: false, addEventListener: (key, fn) => listeners.set(`media:${key}`, fn), removeEventListener: key => listeners.delete(`media:${key}`) };
    globalThis.window = { matchMedia: () => media, addEventListener: (key, fn) => listeners.set(key, fn), removeEventListener: key => listeners.delete(key) };
    globalThis.document.documentElement = { addEventListener: (key, fn) => listeners.set(key, fn), removeEventListener: key => listeners.delete(key) };
    let scheduled;
    globalThis.requestAnimationFrame = fn => { scheduled = fn; return 1; };
    globalThis.cancelAnimationFrame = () => { scheduled = null; };
    const cleanup = effects[1]();
    const move = (x, y, pointerType = 'mouse') => { listeners.get('pointermove')({ clientX: x, clientY: y, pointerType }); if (scheduled) { const run = scheduled; scheduled = null; run(); } };
    move(10000, 10000);
    const [x, y] = pupil.current.style.transform.match(/-?[\d.]+/g).map(Number);
    assert.ok(x > 0 && y > 0 && Math.hypot(x, y / .65) <= 22.001);
    move(-10000, -10000); assert.match(pupil.current.style.transform, /translate\(-/);
    listeners.get('blur')(); assert.equal(pupil.current.style.transform, 'translate(0px, 0px)');
    media.matches = true; move(10000, 10000); assert.equal(pupil.current.style.transform, 'translate(0px, 0px)');
    media.matches = false; move(10000, 10000, 'touch'); assert.equal(pupil.current.style.transform, 'translate(0px, 0px)');
    cleanup(); assert.equal(listeners.size, 0);
  } finally {
    await server.close();
    delete globalThis.__landingHooks;
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete globalThis[key]; else globalThis[key] = value; }
  }
});
