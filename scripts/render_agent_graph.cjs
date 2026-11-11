/* Offline SVG layout of exact exported graph nodes/edges using installed dagre. */
const dagre = require('../visualization/node_modules/dagre');
const esc = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const colors = {
  'Orchestration':'#cee8fb', 'Primary tier':'#cdefe1', 'Specialist tier':'#fde6d8',
  'Synthesis':'#e4e1f8', 'Adversarial debate':'#fbe3ec',
  'Guardrail / human review':'#fbefd9', 'Output':'#f1efe8',
  'Adaptive examination':'#ddebdd', 'Control':'#eeeeef', 'Boundary':'#e0d8f4',
};

function render(data, mode) {
  const graph = data[mode].json;
  const layout = new dagre.graphlib.Graph({multigraph:true});
  layout.setGraph({rankdir:'TB',nodesep:28,ranksep:70,marginx:35,marginy:35});
  layout.setDefaultEdgeLabel(() => ({}));
  for (const node of graph.nodes) layout.setNode(node.id,{width:216,height:60});
  graph.edges.forEach((e,i) => layout.setEdge(e.source,e.target,{minlen:1,weight:e.conditional?1:2},String(i)));
  dagre.layout(layout);
  const {width,height} = layout.graph();
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-labelledby="title-${mode}" class="architecture-svg"><title id="title-${mode}">${mode==='native'?'Native LangGraph export':'Source-complete possible routes'} — Specula</title><defs><marker id="arrow-${mode}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10Z" fill="#7a7184"/></marker></defs><g fill="none" stroke="#7a7184" stroke-width="1.4">`;
  graph.edges.forEach((edge,i) => {
    const points = layout.edge({v:edge.source,w:edge.target,name:String(i)}).points;
    svg += `<path d="${points.map((p,j)=>(j?'L':'M')+p.x+','+p.y).join(' ')}" ${edge.conditional?'stroke-dasharray="6 5"':''} marker-end="url(#arrow-${mode})"><title>${esc(edge.source)} → ${esc(edge.target)}${edge.conditional?' (conditional / Command)':''}</title></path>`;
  });
  svg += '</g>';
  for (const node of graph.nodes) {
    const box=layout.node(node.id), category=data.categories[node.id]||'Boundary';
    const label=node.id==='__start__'?'START':node.id==='__end__'?'END':node.id;
    const lines=label.length>24?label.split(/_(?=[^_]*$)/):[label];
    svg += `<g class="graph-node" data-node="${esc(node.id)}"><title>${esc(label)} · ${esc(category)}</title><rect x="${box.x-108}" y="${box.y-30}" width="216" height="60" rx="${category==='Boundary'?30:7}" fill="${colors[category]}" stroke="#b7acbf"/><text x="${box.x}" y="${box.y-(lines.length-1)*7}" text-anchor="middle" fill="#25202e" font-family="Segoe UI,Arial,sans-serif" font-size="12">${lines.map((line,i)=>`<tspan x="${box.x}" dy="${i?15:0}">${esc(line)}</tspan>`).join('')}</text><text x="${box.x}" y="${box.y+21}" text-anchor="middle" fill="#62586c" font-family="Segoe UI,Arial,sans-serif" font-size="8">${esc(category)}</text></g>`;
  }
  return svg+'</svg>';
}
let input='';
process.stdin.setEncoding('utf8');
process.stdin.on('data',chunk=>{input+=chunk;});
process.stdin.on('end',()=>{const data=JSON.parse(input);process.stdout.write(JSON.stringify({native:render(data,'native'),complete:render(data,'complete')}));});
