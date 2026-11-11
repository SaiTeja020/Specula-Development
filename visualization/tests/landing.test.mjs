import assert from 'node:assert/strict';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { MemoryRouter } from 'react-router-dom';

test('landing routes, six pillars, accessible source/graph/debate interactions and preview-only review', async () => {
  let selected = 0;
  const server = await createServer({
    root: new URL('../', import.meta.url).pathname.replace(/^\/(\w:)/, '$1'),
    cacheDir: `node_modules/.vite-tests/landing-${process.pid}`,
    optimizeDeps: { noDiscovery: true, include: [] },
    server: { middlewareMode: true, hmr: false, ws: false },
    plugins: [{name:'landing-test-exports',enforce:'pre',transform(code,id){
      if (id.replaceAll('\\','/').endsWith('/src/pages/LandingPage.jsx')) return code + '\nexport { Lens, Graph, Debate, Governance, BrandEye };';
    }}],
  });
  const oldDocument = globalThis.document;
  try {
    const module = await server.ssrLoadModule('/src/pages/LandingPage.jsx');
    const render = component => renderToStaticMarkup(React.createElement(MemoryRouter,null,React.createElement(component)));
    const html = render(module.default);
    for (const route of ['/startup','/investigate','/history']) assert.ok(html.includes(`href="${route}"`));
    for (const anchor of ['architecture','pillars','debate','provenance']) {
      assert.ok(html.includes(`href="#${anchor}"`)); assert.ok(html.includes(`id="${anchor}"`));
    }
    assert.equal((html.match(/data-pillar=/g)||[]).length,6);
    assert.equal((html.match(/class="lp-graph-node"/g)||[]).length,6);
    assert.equal((html.match(/role="tab"/g)||[]).length,3);
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map(x=>x[1]);
    assert.equal(new Set(ids).size,ids.length,'SVG and control IDs must be unique');
    assert.match(html,/src="\/Specula_logo.png"/);
    assert.match(html,/data-testid="brand-pupil"/);
    assert.doesNotMatch(html,/Start connecting|class="lp-closing"|id="lp-lines"/);
    assert.match(html,/ILLUSTRATIVE DATA/);assert.match(html,/independent review/);
    // Probe real handlers with a minimal hook dispatcher; no DOM or backend mutations.
    const internals = React.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;
    const saved = internals.H;
    const walk = element => !React.isValidElement(element) ? [] : [element,...React.Children.toArray(element.props.children).flatMap(walk)];
    const tree = component => {internals.H={useState:()=>[selected,value=>{selected=value;}]};try{return walk(component());}finally{internals.H=saved;}};
    const buttons = component => tree(component).filter(el=>el.type==='button');
    selected=0;
    const sources=buttons(module.Lens);assert.equal(sources.length,14);
    sources[3].props.onClick();assert.equal(selected,3);
    assert.ok(tree(module.Lens).some(el=>React.Children.toArray(el.props.children).includes('Memory Forensics')));
    selected=2;
    let prevented=false;
    tree(module.Graph).filter(el=>el.props.role==='button')[4].props.onKeyDown({key:'Enter',preventDefault(){prevented=true;}});
    assert.equal(selected,4);assert.ok(prevented);
    let focused;
    globalThis.document={getElementById:id=>({focus(){focused=id;}})};
    selected=0;
    buttons(module.Debate)[0].props.onKeyDown({key:'End',preventDefault(){}});
    assert.equal(selected,2);assert.equal(focused,'lp-debate-2');
    assert.ok(tree(module.Debate).some(el=>el.props.children==='HUMAN REVIEW REQUIRED'));
    buttons(module.Debate)[2].props.onKeyDown({key:'ArrowRight',preventDefault(){}});assert.equal(selected,0);
    selected=false;buttons(module.Governance)[0].props.onClick();assert.equal(selected,true);
    const prior = Object.fromEntries(['window','document','requestAnimationFrame','cancelAnimationFrame'].map(k=>[k,globalThis[k]]));
    const listeners = new Map();
    const media = {matches:false,addEventListener:(k,fn)=>listeners.set(`media:${k}`,fn),removeEventListener:k=>listeners.delete(`media:${k}`)};
    const pupil = {current:{style:{},ownerSVGElement:{getBoundingClientRect:()=>({left:500,top:100,width:400,height:440})}}};
    let effect, scheduled, cleanup;
    try {
      globalThis.window={matchMedia:()=>media,addEventListener:(k,fn)=>listeners.set(k,fn),removeEventListener:k=>listeners.delete(k)};
      globalThis.document={documentElement:{addEventListener:(k,fn)=>listeners.set(k,fn),removeEventListener:k=>listeners.delete(k)}};
      globalThis.requestAnimationFrame=fn=>{scheduled=fn;return 1;};globalThis.cancelAnimationFrame=()=>{scheduled=null;};
      internals.H={useRef:()=>pupil,useEffect:fn=>{effect=fn;}};
      try {module.BrandEye();} finally {internals.H=saved;}
      cleanup=effect();
      const move=(x,y,pointerType='mouse')=>{listeners.get('pointermove')({clientX:x,clientY:y,pointerType});if(scheduled){const run=scheduled;scheduled=null;run();}};
      move(10000,10000);
      const [x,y]=pupil.current.style.transform.match(/-?[\d.]+/g).map(Number);
      assert.ok(x>0&&y>0&&Math.hypot(x,y/.65)<=22.001);
      move(-10000,-10000);assert.match(pupil.current.style.transform,/translate\(-/);
      listeners.get('blur')();assert.equal(pupil.current.style.transform,'translate(0px, 0px)');
      media.matches=true;move(10000,10000);assert.equal(pupil.current.style.transform,'translate(0px, 0px)');
      media.matches=false;move(10000,10000,'touch');assert.equal(pupil.current.style.transform,'translate(0px, 0px)');
      cleanup();cleanup=null;assert.equal(listeners.size,0);
    } finally {cleanup?.();internals.H=saved;for(const [k,v] of Object.entries(prior)){if(v===undefined)delete globalThis[k];else globalThis[k]=v;}}

    assert.ok(tree(module.Governance).some(el=>typeof el.props.children==='string'&&el.props.children.includes('no case approved or signature created')));
  } finally {await server.close();if(oldDocument===undefined)delete globalThis.document;else globalThis.document=oldDocument;}
});
