import assert from 'node:assert/strict';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

test('technical content renders as safe readable code, tables and spaced metadata', async () => {
  const server = await createServer({ root: new URL('../', import.meta.url).pathname.replace(/^\/(\w:)/, '$1'), server: { middlewareMode: true, hmr: false } });
  const render = (Component, props) => renderToStaticMarkup(React.createElement(Component, props));
  try {
    const { default: CodeBlock } = await server.ssrLoadModule('/src/components/CodeBlock.jsx');
    const json = render(CodeBlock, { language: 'json', value: '{"selected_ids":[0,1],"source":"<script>untrusted</script>"}' });
    assert.match(json, /<pre[^>]*tabIndex="0"[^>]*><code>/i);
    assert.ok(json.includes('\n  &quot;selected_ids&quot;: [\n    0,\n    1\n  ]'));
    assert.ok(json.includes('&lt;script&gt;untrusted&lt;/script&gt;'));
    assert.ok(!json.includes('<script>'));
    assert.match(json, /Copy Recorded output/);
    const invalid = render(CodeBlock, { language: 'json', value: 'non-JSON source output' });
    assert.ok(invalid.includes('non-JSON source output'));
    const precise = render(CodeBlock, { language: 'json', value: '{"event_id":9007199254740993}' });
    assert.ok(precise.includes('9007199254740993') && !precise.includes('9007199254740992'));
    const { default: Guide } = await server.ssrLoadModule('/src/pages/ZipFormatGuide.jsx');
    const guide = render(Guide, { dialogRef: React.createRef() });
    assert.ok(guide.includes('class="zip-guide review-content"'));
    assert.ok(guide.includes('aria-labelledby="zip-guide-title"'));
    assert.ok(guide.includes('├── manifest.json') && guide.includes('└── Sysmon.jsonl'));
    assert.equal((guide.match(/<table/g) || []).length, 4);
    assert.ok(guide.includes('Source folders and accepted files'));
    assert.ok(guide.includes('50 MiB') && guide.includes('200 MiB') && guide.includes('25 MiB'));
    assert.ok(guide.includes('Example manifest.json') && guide.includes('Minimal Windows event'));
    assert.ok(guide.includes('method="dialog"') && guide.includes('Press Escape'));
    const { AgentsView, ReportView } = await server.ssrLoadModule('/src/pages/InvestigationViews.jsx');
    const refs = Array.from({ length: 20 }, (_, index) => `source-${index}`);
    const agents = render(AgentsView, { snapshot: { agent_traces: [{ agent_role: 'supervisor', action: 'case_evidence_review',
      model_output: '{"selected_ids":[0,1]}', model_output_validated: true, dfkg_refs: refs,
      review_coverage: { submitted: 9, total: 9, validated: 9, complete: true } }] } });
    assert.ok(agents.includes('<dl class="agent-metadata">'));
    assert.ok(agents.includes('source-19') && agents.includes('Evidence references (20)'));
    assert.ok(agents.includes('Recorded model assessment') && agents.includes('analysis, not source evidence'));
    const report = render(ReportView, { snapshot: { case_id: 'C1', report_output: '# Original report', final_output_ref: 'case-C1-final',
      report_metadata: { status: 'incomplete', degraded_flags: ['agent_review_incomplete', 'additional_evidence_requested'] } } });
    assert.ok(report.includes('<dl class="report-metadata">'));
    assert.ok(report.includes('<li>Agent review incomplete</li>'));
    assert.ok(!report.includes('agent_review_incomplete'));
    assert.ok(report.includes('Saved report reference') && report.includes('Original evidence report'));
  } finally { await server.close(); }
});
