"""Specula Investigation Trace Recorder.

Records events and reasoning steps in a deterministic trace directory
without exposing hidden LLM chain-of-thought.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("InvestigationTrace")

# Global singleton
_recorder: Optional['TraceRecorder'] = None
_thread_local = threading.local()

def set_active_agent(agent_role: str) -> None:
    _thread_local.active_agent = agent_role

def get_active_agent() -> str:
    return getattr(_thread_local, "active_agent", "unknown_agent")


def start_trace(case_id: str, query: str) -> None:
    """Initialize the trace recorder for a given case."""
    global _recorder
    _recorder = TraceRecorder(case_id, query)
    logger.info(f"Started investigation trace for {case_id}")


def get_recorder() -> Optional['TraceRecorder']:
    """Get the active trace recorder, or None if tracing is disabled."""
    return _recorder


def record_event(component: str, event_type: str, data: Dict[str, Any]) -> None:
    """Record a trace event if a trace is currently active."""
    if _recorder:
        _recorder.record(component, event_type, data)


class TraceRecorder:
    def __init__(self, case_id: str, query: str):
        self.case_id = case_id
        self.query = query
        self.run_dir = Path("investigation_runs") / case_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        
        self.json_path = self.run_dir / "investigation_trace.json"
        
        if not self.json_path.exists():
            with open(self.json_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "case_id": case_id,
                    "query": query,
                    "events": []
                }, f, indent=2)

        self._write_readme_header()
        self._write_user_query()

    def record(self, component: str, event_type: str, data: Dict[str, Any]) -> None:
        """Record an event to the JSON log and the corresponding markdown file."""
        # Sanitize data to remove any obvious secrets (API keys)
        safe_data = self._sanitize(data)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": component,
            "event_type": event_type,
            "data": safe_data
        }

        # 1. Append to JSON
        with self._lock:
            try:
                with open(self.json_path, 'r', encoding='utf-8') as f:
                    trace = json.load(f)
                trace["events"].append(event)
                with open(self.json_path, 'w', encoding='utf-8') as f:
                    json.dump(trace, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to write trace JSON: {e}")

        # 2. Append to Markdown / contextual files
        with self._lock:
            self._format_markdown(event)

    def _sanitize(self, data: Any) -> Any:
        """Strip secrets/API keys from trace logs."""
        if isinstance(data, dict):
            return {
                k: self._sanitize(v) 
                for k, v in data.items() 
                if not any(secret in k.lower() for secret in ['api_key', 'token', 'password', 'secret'])
            }
        elif isinstance(data, list):
            return [self._sanitize(v) for v in data]
        return data

    def _append_md(self, filename: str, content: str) -> None:
        """Append text to a markdown file in the trace directory."""
        path = self.run_dir / filename
        with open(path, "a", encoding='utf-8') as f:
            f.write(content + "\n")

    def _write_json(self, filename: str, content: list | dict) -> None:
        """Write or append to a structured JSON file."""
        path = self.run_dir / filename
        if path.exists():
            with open(path, "r", encoding='utf-8') as f:
                existing = json.load(f)
            if isinstance(existing, list):
                existing.append(content)
                content = existing
        else:
            if not isinstance(content, list):
                content = [content]

        with open(path, "w", encoding='utf-8') as f:
            json.dump(content, f, indent=2)

    def _write_readme_header(self) -> None:
        path = self.run_dir / "README.md"
        if not path.exists():
            with open(path, "w", encoding='utf-8') as f:
                f.write(f"# Investigation Trace: {self.case_id}\n\n")
                f.write("This directory contains the observable events and artifacts generated during the investigation.\n\n")
                f.write("## Timeline of Events\n\n")
                
    def _update_readme(self, message: str) -> None:
        """Append a chronological event to the README."""
        self._append_md("README.md", f"- {message}")

    def _write_user_query(self) -> None:
        content = f"# User Query\n\n**Case:** {self.case_id}\n**Query:** {self.query}\n"
        self._append_md("00_user_query.md", content)
        self._update_readme(f"User asked: `{self.query}`")

    def _format_markdown(self, event: dict) -> None:
        """Route the event to the appropriate markdown or json trace file."""
        comp = event["component"]
        evt = event["event_type"]
        data = event["data"]
        ts = event["timestamp"]

        # For tool events, if component is generic like "rag" or "dfkg", try to route to active agent's markdown
        active_agent = get_active_agent()
        agent_file = f"02_{active_agent}.md" if active_agent != "unknown_agent" else f"02_{comp}.md"

        if evt == "supervisor_route":
            content = f"## [{ts}] Routing Decision\n\n**Next Agents:** {', '.join(data.get('next_agents', []))}\n"
            self._append_md("01_supervisor.md", content)
            self._update_readme(f"Supervisor routed to: {', '.join(data.get('next_agents', []))}")

        elif evt == "supervisor_input":
            if not (self.run_dir / "01_supervisor.md").exists():
                self._append_md("01_supervisor.md", f"# Supervisor\n\n")

        elif evt == "agent_start":
            agent_file = f"02_{comp}.md"
            if not (self.run_dir / agent_file).exists():
                self._append_md(agent_file, f"# Agent: {comp}\n\n")
            model = data.get('model', 'unknown')
            self._append_md(agent_file, f"## [{ts}] Run Started\n**Model:** {model}\n")

        elif evt == "agent_action":
            agent_file = f"02_{comp}.md"
            action = data.get('action')
            inputs = json.dumps(data.get('action_input', {}), indent=2)
            self._append_md(agent_file, f"### Action: `{action}`\n```json\n{inputs}\n```\n")

        elif evt == "agent_observation":
            agent_file = f"02_{comp}.md"
            obs = data.get('observation')
            self._append_md(agent_file, f"### Observation\n```text\n{obs}\n```\n")

        elif evt == "rag_query":
            self._write_json("rag_retrieval.json", {
                "timestamp": ts,
                "agent": comp,
                "query": data.get("query"),
                "method": data.get("method")
            })
            self._append_md(agent_file, f"### RAG Query\n**Method:** {data.get('method')}\n**Query:** `{data.get('query')}`\n")
            self._update_readme(f"GraphRAG used by {active_agent} for: `{data.get('query')}`")

        elif evt == "rag_retrieval":
            # Append records to the latest entry in json
            path = self.run_dir / "rag_retrieval.json"
            if path.exists():
                with open(path, "r", encoding='utf-8') as f:
                    docs = json.load(f)
                if docs:
                    docs[-1]["records"] = data.get("records", [])
                    docs[-1]["dfkg_expansion"] = data.get("dfkg_expansion", {})
                with open(path, "w", encoding='utf-8') as f:
                    json.dump(docs, f, indent=2)
            
            # Add to agent's markdown
            self._append_md(agent_file, f"### RAG Retrieved Data\n```json\n{json.dumps(data.get('records', []), indent=2)}\n```\n")
            exp = data.get('dfkg_expansion', {})
            self._append_md(agent_file, f"### DFKG Graph Expansion\n**Nodes retrieved:** {exp.get('nodes_retrieved', 0)}\n")

        elif evt == "dfkg_query":
            self._write_json("dfkg_context.json", {
                "timestamp": ts,
                "agent": comp,
                "cypher": data.get("cypher"),
                "parameters": data.get("parameters"),
                "returned_entities": data.get("returned_entities"),
                "returned_relationships": data.get("returned_relationships"),
                "uids": data.get("uids")
            })
            self._append_md(agent_file, f"### DFKG Query\n**Cypher:**\n```cypher\n{data.get('cypher')}\n```\n**Entities Returned:** {data.get('returned_entities')}\n**UIDs:** {data.get('uids')}\n")

        elif evt == "agent_finding":
            self._write_json("agent_findings.json", {
                "timestamp": ts,
                "agent": comp,
                "summary": data.get("summary"),
                "evidence_uids": data.get("evidence_uids"),
                "node_uid": data.get("node_uid")
            })
            self._append_md(agent_file, f"### Agent Conclusion (Finding Published)\n```text\n{data.get('summary')}\n```\n**Evidence UIDs:** {data.get('evidence_uids')}\n")
            self._update_readme(f"{comp} created a finding on the blackboard.")

        elif evt == "hitl_pause":
            if not (self.run_dir / "hitl.md").exists():
                self._append_md("hitl.md", "# Human-In-The-Loop (HITL)\n\n")
            self._append_md("hitl.md", f"## [{ts}] HITL Triggered\n**Reason:** {data.get('entry_reason')}\n")
            self._update_readme("HITL Pause Triggered.")

        elif evt == "hitl_decision":
            self._append_md("hitl.md", f"## [{ts}] Decision Received\n**Decision:** `{data.get('decision')}`\n")
            self._update_readme(f"Human decision provided: `{data.get('decision')}`")

        elif evt == "hitl_not_triggered":
            self._append_md("hitl.md", "HITL NOT TRIGGERED\n")

        elif evt == "debate_proponent":
            if not (self.run_dir / "debate.md").exists():
                self._append_md("debate.md", "# Debate Phase\n\n")
            self._append_md("debate.md", f"## [{ts}] Proponent Argument\n{data.get('argument')}\n")
            self._update_readme("Proponent submitted an argument.")

        elif evt == "debate_critic":
            self._append_md("debate.md", f"## [{ts}] Critic Challenge\n{data.get('challenge')}\n")
            self._update_readme("Critic challenged the proponent's argument.")

        elif evt == "debate_judge":
            self._append_md("debate.md", f"## [{ts}] Judge Verdict\n**Verdict:** `{data.get('verdict')}`\n\n**Reasoning:**\n{data.get('reasoning')}\n")
            self._update_readme(f"Judge returned verdict: `{data.get('verdict')}`")

        elif evt == "synthesis":
            self._write_final_synthesis(data)
            self._update_readme("Final synthesis produced.")

    def _write_final_synthesis(self, data: dict) -> None:
        result = data.get("result", {})
        content = f"# Final Investigation\n\n"
        content += f"## User Question\n{result.get('query', '')}\n\n"
        content += f"## Agents Used\n{', '.join(result.get('agents_used', []))}\n\n"
        
        content += f"## Final Conclusion\n{result.get('answer', '')}\n\n"
        
        content += f"## Limitations\n"
        for lim in result.get("limitations", []):
            content += f"- {lim}\n"
            
        content += f"\n## Evidence UIDs\n"
        for uid in result.get("evidence_uids", []):
            content += f"- `{uid}`\n"
            
        self._append_md("final_synthesis.md", content)

