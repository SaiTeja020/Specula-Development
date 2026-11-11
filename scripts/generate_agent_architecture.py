"""Export the implemented Specula graph without executing any workflow nodes.

Run with the project's Python environment and Node.js; uses installed dagre only.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
from html import escape
from importlib.metadata import version
import inspect
import json
from pathlib import Path
import subprocess
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def source_record(function):
    path = Path(inspect.getsourcefile(function)).resolve()
    lines, start = inspect.getsourcelines(function)
    return {
        "path": path.relative_to(ROOT).as_posix(), "line": start,
        "end_line": start + len(lines) - 1,
        "symbol": function.__qualname__,
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "code": textwrap.dedent("".join(lines)).rstrip(),
    }


def literal_targets(expression):
    """Fail rather than silently omit a newly introduced dynamic destination."""
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return {expression.value}
    if isinstance(expression, (ast.List, ast.Tuple)):
        return set().union(*(literal_targets(item) for item in expression.elts))
    if isinstance(expression, ast.IfExp):
        return literal_targets(expression.body) | literal_targets(expression.orelse)
    raise ValueError(f"Unresolved Command.goto expression: {ast.unparse(expression)}")


def command_routes(source):
    result = []
    for call in ast.walk(ast.parse(source["code"])):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "Command":
            continue
        for keyword in call.keywords:
            if keyword.arg == "goto":
                for target in sorted(literal_targets(keyword.value)):
                    result.append({
                        "target": target, "path": source["path"],
                        "line": source["line"] + call.lineno - 1,
                        "expression": ast.unparse(keyword.value),
                    })
    return result


def category(name, primary, specialists):
    if name.startswith("__"):
        return "Boundary"
    if name == "supervisor":
        return "Orchestration"
    if name in primary:
        return "Primary tier"
    if name in specialists:
        return "Specialist tier"
    if name == "investigation_followup":
        return "Adaptive examination"
    if name in {"timeline_reconstruction", "threat_attribution", "dag"}:
        return "Synthesis"
    if name in {"proponent", "critic", "judge"}:
        return "Adversarial debate"
    if name.startswith("guardrail_") or name == "hitl":
        return "Guardrail / human review"
    if name in {"report_generation", "timeline_artifact_generation"}:
        return "Output"
    return "Control"


def collect_architecture():
    from src.agents.graph import build_graph, _SPECIALIST_MAP

    compiled = build_graph()  # Assembly only: never invoke, stream or resume.
    builder = compiled.builder
    native = compiled.get_graph()
    graph_source = source_record(build_graph)
    tree = ast.parse(graph_source["code"])
    registrations = {}
    static_locations = {}

    def name_of(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name) and node.id in {"START", "END"}:
            return {"START": "__start__", "END": "__end__"}[node.id]
        raise ValueError(f"Unsupported graph endpoint: {ast.unparse(node)}")

    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        line = graph_source["line"] + call.lineno - 1
        if call.func.attr == "add_node":
            registrations[name_of(call.args[0])] = line
        elif call.func.attr == "add_edge":
            static_locations[(name_of(call.args[0]), name_of(call.args[1]))] = line

    if set(registrations) != set(builder.nodes):
        raise ValueError("Registered source nodes differ from compiled builder")
    primary = set().union(*(set(branch.ends.values()) for branch in builder.branches["supervisor"].values()))
    nodes, routes, routers = [], [], []
    for name, spec in builder.nodes.items():
        source = source_record(spec.runnable.func)
        nodes.append({"id": name, "category": category(name, primary, set(_SPECIALIST_MAP.values())),
                      "source": source, "registration_line": registrations[name]})
        targets = command_routes(source)
        declared = set(spec.ends or ())
        observed = {item["target"] for item in targets}
        if declared and declared != observed:
            raise ValueError(f"Command declaration/source mismatch for {name}: {declared} != {observed}")
        for item in targets:
            routes.append({"source": name, "kind": "Command.goto", **item})
    for source, target in sorted(builder.edges):
        routes.append({"source": source, "target": target, "kind": "Static edge",
                       "path": graph_source["path"], "line": static_locations[(source, target)],
                       "expression": "builder.add_edge"})
    for name, branches in builder.branches.items():
        for branch_name, branch in branches.items():
            if branch.ends is None:
                raise ValueError(f"Unbounded conditional branch: {name}.{branch_name}")
            source = source_record(branch.path.func)
            routers.append({"node": name, "name": branch_name, "source": source})
            for target in sorted(set(branch.ends.values())):
                routes.append({"source": name, "target": target, "kind": "Conditional / Send",
                               "path": source["path"], "line": source["line"], "expression": branch_name})
    names = set(builder.nodes) | {"__start__", "__end__"}
    for route in routes:
        if route["source"] not in names or route["target"] not in names:
            raise ValueError(f"Unregistered route: {route}")
    # Build a separate drawing graph, preserving the native graph unmodified.
    from langchain_core.runnables.graph import Graph
    complete = Graph(nodes=dict(native.nodes))
    pairs = sorted({(r["source"], r["target"], r["kind"] != "Static edge") for r in routes})
    for source, target, conditional in pairs:
        complete.add_edge(complete.nodes[source], complete.nodes[target], conditional=conditional)
    native_pairs = {(edge.source, edge.target) for edge in native.edges}
    complete_pairs = {(source, target) for source, target, _ in pairs}
    categories = {n["id"]: n["category"] for n in nodes}
    return {
        "schema_version": 1,
        "versions": {name: version(name) for name in ("langgraph", "langchain-core")},
        "graph_source": graph_source,
        "reference_sha256": sha256((ROOT / "docs/architecture_v4.html").read_bytes()).hexdigest(),
        "nodes": nodes, "routers": routers,
        "routes": sorted(routes, key=lambda r: (r["source"], r["target"], r["kind"], r["line"])),
        "native": {"json": native.to_json(), "mermaid": native.draw_mermaid()},
        "complete": {"json": complete.to_json(), "mermaid": complete.draw_mermaid()},
        "categories": categories,
        "omitted_by_native": [list(pair) for pair in sorted(complete_pairs - native_pairs)],
        "native_only": [list(pair) for pair in sorted(native_pairs - complete_pairs)],
    }


def json_for_html(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def generate(output):
    data = collect_architecture()
    rendered = subprocess.run(
        ["node", str(ROOT / "scripts/render_agent_graph.cjs")],
        input=json.dumps(data), text=True, encoding="utf-8", capture_output=True, check=True,
    )
    diagrams = json.loads(rendered.stdout)
    template = (ROOT / "scripts/agent_architecture_template.html").read_text(encoding="utf-8")
    rows = []
    for index, node in enumerate(data["nodes"]):
        source = node["source"]
        destinations = sorted({r["target"] for r in data["routes"] if r["source"] == node["id"]})
        rows.append(f'<tr><td><a href="#source-{index}"><code>{escape(node["id"])}</code></a></td>'
                    f'<td>{escape(node["category"])}</td><td>{escape(", ".join(destinations))}</td>'
                    f'<td><code>{escape(source["path"])}:{source["line"]}</code><br>'
                    f'<details id="source-{index}"><summary>Implementation source</summary>'
                    f'<p>{escape(source["symbol"])}</p><pre>{escape(source["code"])}</pre></details></td></tr>')
    values = {
        "@@DATA@@": json_for_html(data), "@@ROWS@@": "\n".join(rows),
        "@@NATIVE_SVG@@": diagrams["native"], "@@COMPLETE_SVG@@": diagrams["complete"],
        "@@NODE_COUNT@@": str(len(data["nodes"])),
        "@@EDGE_COUNT@@": str(len(data["complete"]["json"]["edges"])),
        "@@NATIVE_EDGE_COUNT@@": str(len(data["native"]["json"]["edges"])),
        "@@MISSING_COUNT@@": str(len(data["omitted_by_native"])),
        "@@VERSIONS@@": escape(" · ".join(f"{key} {value}" for key, value in data["versions"].items())),
    }
    for key, value in values.items():
        template = template.replace(key, value)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(template, encoding="utf-8", newline="\n")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/architecture_agents.html")
    args = parser.parse_args()
    data = generate(args.output)
    print(f"Wrote {args.output}: {len(data['nodes'])} registered nodes, "
          f"{len(data['complete']['json']['edges'])} source-complete routes; no workflow executed.")


if __name__ == "__main__":
    main()
