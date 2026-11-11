"""Verify that documentation exports actual topology without running cases."""
import ast
from hashlib import sha256
from html.parser import HTMLParser
import json
import re
import subprocess
import xml.etree.ElementTree as ET

import pytest

from scripts.generate_agent_architecture import (
    ROOT, collect_architecture, command_routes, generate, json_for_html, literal_targets,
)


class ArtifactParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.scripts = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "script":
            assert "src" not in attrs, "Export must work without external scripts"
            self.current = {"type": attrs.get("type"), "text": ""}

    def handle_data(self, data):
        if self.current is not None:
            self.current["text"] += data

    def handle_endtag(self, tag):
        if tag == "script" and self.current is not None:
            self.scripts.append(self.current)
            self.current = None


def test_export_matches_real_builder_and_command_source_without_execution(monkeypatch):
    from langgraph.graph.state import CompiledStateGraph
    from src.agents.graph import build_graph
    from src.agents import config

    def forbidden(*args, **kwargs):
        raise AssertionError("Documentation must never run a workflow or model")

    for method in ("invoke", "ainvoke", "stream", "astream"):
        monkeypatch.setattr(CompiledStateGraph, method, forbidden)
    monkeypatch.setattr(config, "get_llm", forbidden)
    compiled = build_graph()
    native = compiled.get_graph()
    data = collect_architecture()
    assert data["native"]["json"] == native.to_json()
    assert data["native"]["mermaid"] == native.draw_mermaid()
    assert {node["id"] for node in data["nodes"]} == set(compiled.builder.nodes)
    complete_pairs = {(edge["source"], edge["target"]) for edge in data["complete"]["json"]["edges"]}
    expected = set(compiled.builder.edges)
    for origin, branches in compiled.builder.branches.items():
        for branch in branches.values():
            expected.update((origin, target) for target in branch.ends.values())
    for node in data["nodes"]:
        source = node["source"]
        assert (ROOT / source["path"]).is_file()
        assert sha256((ROOT / source["path"]).read_bytes()).hexdigest() == source["sha256"]
        expected.update((node["id"], route["target"]) for route in command_routes(source))
    assert complete_pairs == expected
    # The untyped Command node is the regression that makes the native view incomplete.
    assert ("investigation_followup", "timeline_reconstruction") in complete_pairs
    assert ("investigation_followup", "supervisor") in complete_pairs
    assert ("investigation_followup", "investigation_followup") in complete_pairs
    assert ("judge", "proponent") in complete_pairs
    assert ("hitl", "supervisor") in complete_pairs
    assert ("investigation_followup", "__end__") not in complete_pairs
    assert ["investigation_followup", "__end__"] in data["native_only"]


def test_command_parser_keeps_fanout_alternatives_and_rejects_unknown_routes():
    expression = ast.parse("['report_generation', 'timeline_artifact_generation']", mode="eval").body
    assert literal_targets(expression) == {"report_generation", "timeline_artifact_generation"}
    assert literal_targets(ast.parse("'proponent' if retry else 'hitl'", mode="eval").body) == {"proponent", "hitl"}
    with pytest.raises(ValueError, match="Unresolved"):
        literal_targets(ast.parse("dynamic_target", mode="eval").body)
    source = {"code": "def route(s):\n    return Command(goto='hitl')", "path": "example.py", "line": 20}
    assert command_routes(source) == [{"target": "hitl", "path": "example.py", "line": 21, "expression": "'hitl'"}]
    hostile = "</script><script>alert(1)</script>\u2028"
    encoded = json_for_html({"source": hostile})
    assert "</script>" not in encoded
    assert json.loads(encoded)["source"] == hostile


def test_generated_html_is_reproducible_offline_and_has_valid_svg_js(tmp_path):
    output = tmp_path / "agents.html"
    data = generate(output)
    first = output.read_bytes()
    generate(output)
    assert output.read_bytes() == first
    html = first.decode("utf-8")
    assert not re.search(r"@@[A-Z_]+@@", html)
    parsed = ArtifactParser()
    parsed.feed(html)
    assert len(parsed.ids) == len(set(parsed.ids)), "HTML and SVG IDs must be unique"
    embedded = next(script for script in parsed.scripts if script["type"] == "application/json")
    assert json.loads(embedded["text"]) == data
    for script in parsed.scripts:
        if script["type"] != "application/json":
            subprocess.run(["node", "--check"], input=script["text"], text=True, encoding="utf-8", capture_output=True, check=True)
    svgs = re.findall(r"<svg\b.*?</svg>", html, re.S)
    assert len(svgs) == 2
    for mode, svg in zip(("complete", "native"), svgs):
        tree = ET.fromstring(svg)
        groups = tree.findall(".//{http://www.w3.org/2000/svg}g[@data-node]")
        assert {group.attrib["data-node"] for group in groups} == {node["id"] for node in data[mode]["json"]["nodes"]}
        width, height = map(float, tree.attrib["viewBox"].split()[2:])
        assert width > 0 and height > 0
        for rect in tree.findall(".//{http://www.w3.org/2000/svg}rect"):
            assert 0 <= float(rect.attrib["x"]) <= width - float(rect.attrib["width"])
            assert 0 <= float(rect.attrib["y"]) <= height - float(rect.attrib["height"])
    # Verify the committed deliverable is current, not just a temporary export.
    assert (ROOT / "docs/architecture_agents.html").read_bytes() == first

    # Exercise the page script offline: view switches, filtering, zoom and exports.
    harness = r"""
const assert=require('node:assert/strict'),vm=require('node:vm');let input='';
process.stdin.setEncoding('utf8');process.stdin.on('data',c=>input+=c);
process.stdin.on('end',()=>{
 const {script,data}=JSON.parse(input), elements=new Map();
 class Element {
  constructor(){this.textContent='';this.hidden=false;this.style={};this.attrs={};this.children=[];this.events={};this.dataset={};}
  addEventListener(name,fn){this.events[name]=fn;}setAttribute(k,v){this.attrs[k]=v;}
  appendChild(child){this.children.push(child);return child;}append(...children){this.children.push(...children);}
  click(){this.events.click?.({target:this});}remove(){}
 }
 const get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
 get('architecture-data').textContent=JSON.stringify(data);
 const rows=data.nodes.map(n=>{const e=new Element();e.textContent=n.id+' '+n.category;return e;});
 const svgs=[new Element(),new Element()];
 const downloads=['native','complete','json'].map(mode=>{const e=new Element();e.dataset.download=mode;return e;});
 const document={getElementById:get,createElement:()=>new Element(),body:new Element(),querySelectorAll:selector=>{
  if(selector==='.architecture-svg')return svgs;if(selector==='[data-download]')return downloads;
  if(selector==='#node-table tbody tr')return rows;throw Error(selector);
 }};
 const urls=[];
 const context={document,Blob,URL:{createObjectURL:blob=>{urls.push(blob);return 'blob:local';},revokeObjectURL:()=>{}},setTimeout:fn=>fn()};
 vm.runInNewContext(script,context);
 get('native-button').click();assert.equal(get('complete-diagram').hidden,true);assert.equal(get('native-diagram').hidden,false);
 assert.equal(get('native-button').attrs['aria-pressed'],'true');get('complete-button').click();assert.equal(get('native-diagram').hidden,true);
 get('zoom').value='200';get('zoom').events.input();assert.equal(svgs[0].style.width,'200%');get('reset-zoom').click();assert.equal(svgs[1].style.width,'100%');
 get('search').events.input({target:{value:'not-a-node'}});assert.ok(rows.every(r=>r.hidden));
 get('search').events.input({target:{value:'identity'}});assert.equal(rows.filter(r=>!r.hidden).length,1);
 get('search').events.input({target:{value:''}});assert.ok(rows.every(r=>!r.hidden));
 assert.equal(get('route-rows').children.length,data.routes.length);
 assert.equal(get('native-mermaid').textContent,data.native.mermaid);
 for(const button of downloads)button.click();assert.equal(urls.length,3);assert.equal(document.body.children[2].download,'specula-agent-architecture.json');
 process.stdout.write('Offline page controls passed');
});
"""
    page_script = next(script["text"] for script in parsed.scripts if script["type"] != "application/json")
    check = subprocess.run(["node", "-e", harness], input=json.dumps({"script": page_script, "data": data}),
                           text=True, encoding="utf-8", capture_output=True, check=True)
    assert "Offline page controls passed" in check.stdout
