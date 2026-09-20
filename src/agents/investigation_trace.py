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
        
        # Clear out previous trace files if re-running the same case
        import glob
        for old_file in glob.glob(str(self.run_dir / "*.*")):
            try:
                os.remove(old_file)
            except OSError:
                pass
                
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
            "active_agent": get_active_agent(),
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
            
            # Now compile the single, comprehensive trace document
            try:
                self._compile_full_report()
            except Exception as e:
                logger.error(f"Failed to compile full trace report: {e}")

    def _compile_full_report(self) -> None:
        """Parse the JSON trace and compile a single sequential report matching the RAG data flow specification."""
        report_path = self.run_dir / "full_trace_report.md"
        
        with open(self.json_path, 'r', encoding='utf-8') as f:
            trace = json.load(f)
            
        events = trace.get("events", [])
        
        # Collect all valid retrieved UIDs for unsupported claim checking
        retrieved_uids = set()
        for e in events:
            if e["event_type"] == "rag_retrieval":
                for rec in e["data"].get("records", []):
                    if "uid" in rec:
                        retrieved_uids.add(rec["uid"])
            elif e["event_type"] == "dfkg_query":
                for uid in e["data"].get("uids", []):
                    retrieved_uids.add(uid)

        sections = []
        sections.append(f"# SPECULA INVESTIGATION TRACE\n\nCase: {self.case_id}\n\n---\n")
        
        counter = 1
        
        current_agent = None
        agent_block = ""
        
        for e in events:
            evt = e["event_type"]
            comp = e["component"]
            active = e.get("active_agent", "unknown_agent")
            data = e["data"]
            
            if evt == "user_query":
                sections.append(f"## {counter}. USER\n\nQuery:\n\"{data.get('query')}\"\n\n---\n")
                counter += 1
                
            elif evt == "supervisor_input":
                pass # handled below
                
            elif evt == "supervisor_route":
                sections.append(f"## {counter}. SUPERVISOR\n\n### Decision\nRoute investigation to:\n" + "\n".join([f"- {a}" for a in data.get('next_agents', [])]) + "\n\n---\n")
                counter += 1
                
            elif evt == "agent_start":
                if current_agent and agent_block:
                    agent_block += "\n(Agent run ended without publishing a final finding.)\n\n---\n"
                    sections.append(agent_block)
                current_agent = comp
                name = comp.replace("_", " ").upper()
                agent_block = f"## {counter}. {name} AGENT\n\n"
                counter += 1
                
            elif evt == "agent_action":
                if current_agent:
                    action = data.get('action')
                    inputs = json.dumps(data.get('action_input', {}), indent=2)
                    agent_block += f"### Input received\n```json\n{inputs}\n```\n\n### Action\n{action}\n\n"
                    
            elif evt == "rag_query":
                if active == current_agent:
                    agent_block += f"==================================================\nRAG REQUEST\n==================================================\n\n"
                    agent_block += f"Agent:\n{active}\n\n"
                    agent_block += f"RAG query:\n{data.get('query')}\n\n"
                    agent_block += f"Retrieval method:\n{data.get('method')}\n\n"
                    
            elif evt == "rag_retrieval":
                if active == current_agent:
                    agent_block += f"==================================================\nRAG RESPONSE\n==================================================\n\n"
                    records = data.get("records", [])
                    if not records:
                        agent_block += "No records retrieved.\n\n"
                    else:
                        for i, rec in enumerate(records, 1):
                            agent_block += f"Retrieved result #{i}\n\n"
                            agent_block += f"UID:\n{rec.get('uid', 'UNKNOWN')}\n\n"
                            agent_block += f"Type:\n{rec.get('metadata', {}).get('type', 'Unknown')}\n\n"
                            agent_block += f"Score:\n{rec.get('score', 'N/A')}\n\n"
                            agent_block += f"Data:\n{json.dumps(rec.get('page_content', ''), indent=2)}\n\n"
                            agent_block += f"Source:\n{rec.get('metadata', {}).get('source', 'Unknown')}\n\n"
                    
                    exp = data.get("dfkg_expansion", {})
                    if exp:
                        agent_block += f"==================================================\nGRAPH EXPANSION\n==================================================\n\n"
                        agent_block += f"Anchor UID:\n{exp.get('anchor_uid', 'N/A')}\n\n"
                        agent_block += f"Nodes returned:\n{exp.get('nodes_retrieved', 0)}\n\n"
                        agent_block += f"Relationships returned:\n{exp.get('rels_retrieved', 0)}\n\n"
                        agent_block += f"Hops:\n{exp.get('hops', 1)}\n\n"
                        
            elif evt == "dfkg_query":
                if active == current_agent:
                    agent_block += f"==================================================\nDFKG REQUEST\n==================================================\n\n"
                    agent_block += f"Agent:\n{active}\n\n"
                    agent_block += f"Cypher query:\n```cypher\n{data.get('cypher')}\n```\n\n"
                    
                    agent_block += f"==================================================\nDFKG RESPONSE\n==================================================\n\n"
                    agent_block += f"Entities Returned:\n{data.get('returned_entities')}\n\n"
                    agent_block += f"UIDs:\n{data.get('uids')}\n\n"
                    
            elif evt == "agent_observation":
                if comp == current_agent:
                    agent_block += f"==================================================\nAGENT OBSERVATION\n==================================================\n\n"
                    agent_block += f"{data.get('observation')}\n\n"
                    
            elif evt == "agent_finding":
                if comp == current_agent:
                    agent_block += f"==================================================\nAGENT FINDING\n==================================================\n\n"
                    agent_block += f"Finding:\n{data.get('summary')}\n\n"
                    
                    # Verify UIDs
                    uids = data.get('evidence_uids', [])
                    verified_uids = []
                    for u in uids:
                        if u in retrieved_uids:
                            verified_uids.append(u)
                        else:
                            verified_uids.append(f"{u} [UNSUPPORTED: Evidence never retrieved by RAG/DFKG]")
                            
                    agent_block += f"Evidence UIDs:\n{verified_uids}\n\n"
                    
                    agent_block += f"==================================================\nBLACKBOARD HANDOFF\n==================================================\n\n"
                    agent_block += f"Published finding UID:\n{data.get('node_uid')}\n\n---\n"
                    
                    sections.append(agent_block)
                    current_agent = None
                    agent_block = ""
                    
            elif evt == "debate_proponent":
                if current_agent and agent_block:
                    agent_block += "\n(Agent run ended without publishing a final finding.)\n\n---\n"
                    sections.append(agent_block)
                    current_agent = None
                    agent_block = ""
                sections.append(f"## {counter}. PROPONENT\n\n### Argument\n{data.get('argument')}\n\n---\n")
                counter += 1
            elif evt == "debate_critic":
                if current_agent and agent_block:
                    agent_block += "\n(Agent run ended without publishing a final finding.)\n\n---\n"
                    sections.append(agent_block)
                    current_agent = None
                    agent_block = ""
                sections.append(f"## {counter}. CRITIC\n\n### Challenge\n{data.get('challenge')}\n\n---\n")
                counter += 1
            elif evt == "debate_judge":
                if current_agent and agent_block:
                    agent_block += "\n(Agent run ended without publishing a final finding.)\n\n---\n"
                    sections.append(agent_block)
                    current_agent = None
                    agent_block = ""
                sections.append(f"## {counter}. JUDGE\n\n### Verdict\n{data.get('verdict')}\n\n### Reasoning\n{data.get('reasoning')}\n\n---\n")
                counter += 1
            elif evt == "hitl_pause":
                if current_agent and agent_block:
                    agent_block += "\n(Agent run ended without publishing a final finding.)\n\n---\n"
                    sections.append(agent_block)
                    current_agent = None
                    agent_block = ""
                sections.append(f"## {counter}. HITL\n\n### Triggered\n{data.get('entry_reason')}\n\n---\n")
                counter += 1
                
            elif evt == "synthesis":
                if current_agent and agent_block:
                    agent_block += "\n(Agent run ended without publishing a final finding.)\n\n---\n"
                    sections.append(agent_block)
                    current_agent = None
                    agent_block = ""
                result = data.get("result", {})
                syn_block = f"## {counter}. FINAL SYNTHESIS\n\n"
                syn_block += f"### User question\n{result.get('query', '')}\n\n"
                syn_block += f"### Evidence\n(Trace automatically tracks evidence UIDs)\n\n"
                syn_block += f"### Final conclusion\n{result.get('answer', '')}\n\n"
                
                uids = result.get('evidence_uids', [])
                verified_uids = []
                for u in uids:
                    if u in retrieved_uids:
                        verified_uids.append(u)
                    else:
                        verified_uids.append(f"{u} [UNSUPPORTED: Evidence never retrieved by RAG/DFKG]")
                        
                syn_block += f"### Evidence UIDs\n{verified_uids}\n\n"
                syn_block += f"### Limitations\n"
                for lim in result.get("limitations", []):
                    syn_block += f"- {lim}\n"
                syn_block += "\n---\n"
                sections.append(syn_block)
                counter += 1

        # Append any leftover agent block (if finding wasn't published)
        if current_agent and agent_block:
            agent_block += "\n(Agent run ended without publishing a final finding.)\n\n---\n"
            sections.append(agent_block)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sections))

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

