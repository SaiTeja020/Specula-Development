import datetime
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
import threading
import os

class Dashboard:
    def __init__(self):
        self.console = Console()
        self.state = {
            "case_id": "WAITING",
            "thread_id": "WAITING",
            "status": "● READY",
            "start_time": None,
            "current_node": "WAITING",
            "node_state": "IDLE",
            "backend": os.environ.get("SPECULA_LLM_BACKEND", "lmstudio"),
            "model": os.environ.get("SPECULA_LLM_MODEL", "qwen/qwen3-1.7b"),
            "last_msg": "WAITING",
            "last_msg_time": datetime.datetime.now(),
        }
        self.logs = []
        self.lock = threading.Lock()
        self.layout = self.make_layout()
        self.live = Live(self.layout, console=self.console, refresh_per_second=4)
        self.live.start()
        
    def make_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=7),
            Layout(name="logs")
        )
        return layout

    def _update_ui(self):
        # Header
        elapsed = "00:00"
        if self.state["start_time"]:
            delta = datetime.datetime.now() - self.state["start_time"]
            m, s = divmod(int(delta.total_seconds()), 60)
            elapsed = f"{m:02d}:{s:02d}"
            
        last_msg_sec = int((datetime.datetime.now() - self.state["last_msg_time"]).total_seconds())
        
        header_text = Text()
        header_text.append(Text.from_markup(f"CASE       {self.state['case_id']:<30} STATUS    {self.state['status']}\n"))
        header_text.append(Text.from_markup(f"THREAD     {self.state['thread_id']:<30} ELAPSED   {elapsed}\n"))
        header_text.append(Text.from_markup(f"CURRENT    {self.state['current_node']:<30} STATE     {self.state['node_state']}\n"))
        header_text.append(Text.from_markup(f"BACKEND    {self.state['backend']:<30} MODEL     {self.state['model']}\n"))
        header_text.append(Text.from_markup(f"LAST MSG   {self.state['last_msg']:<30} {last_msg_sec}s ago\n"))
        
        self.layout["header"].update(Panel(header_text, title="SPECULA PIPELINE", border_style="blue"))
        
        # Logs
        log_text = Text()
        for log in self.logs[-30:]: # show last 30 logs for more context
            if isinstance(log, Text):
                log_text.append(log)
            else:
                log_text.append(log)
            log_text.append("\n")
        
        self.layout["logs"].update(Panel(log_text, title="EVENTS", border_style="dim"))

    def process_log(self, msg):
        with self.lock:
            # For less noise, skip debug HTTP logs if needed
            if "GET /api/" in msg or "telemetry enabled" in msg:
                return
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            log_line = f"{ts}  {msg}"
            
            style = "white"
            lower_msg = msg.lower()
            if "error" in lower_msg or "exception" in lower_msg or "traceback" in lower_msg or "failed" in lower_msg:
                style = "red"
            elif "warning" in lower_msg:
                style = "yellow"
                
            self.logs.append(Text(log_line, style=style))
            with open("debug_dashboard.log", "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
            self._update_ui()

    def add_event_log(self, icon, origin, dest, action, color="white", error=None):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        msg = f"[{color}]{ts}  {icon} {origin:<13} → {dest}\n           {action}[/{color}]"
        if error:
            msg += f"\n           [red]ERROR: {error}[/red]"
        with self.lock:
            # We safely parse the markup we constructed
            try:
                self.logs.append(Text.from_markup(msg))
            except Exception:
                self.logs.append(Text(msg.replace('[', '').replace(']', ''))) # fallback
            
            with open("debug_dashboard.log", "a", encoding="utf-8") as f:
                f.write(msg + "\n")
            self.state["last_msg"] = f"{origin} → {dest}"
            self.state["last_msg_time"] = datetime.datetime.now()
            self._update_ui()

    def process_event(self, data):
        t = data.get("type")
        with self.lock:
            if t == "api_request":
                self.state["case_id"] = data.get("case_id", "")
                self.state["start_time"] = datetime.datetime.now()
                self.state["status"] = "[cyan]▶ RUNNING[/cyan]"
                self.add_event_log("→", "FRONTEND", "VISUALIZER API", "Investigation requested", "cyan")
            elif t == "ingestion_start":
                self.state["current_node"] = "ingestion"
                self.state["node_state"] = "[cyan]RUNNING[/cyan]"
                self.add_event_log("▶", "INGESTION", "START", "Ingestion started", "cyan")
            elif t == "ingestion_complete":
                self.state["node_state"] = "IDLE"
                self.add_event_log("✓", "INGESTION", "COMPLETE", f"Ingestion completed (code {data.get('returncode')})", "green")
            elif t == "investigation_start":
                self.state["thread_id"] = data.get("thread_id", "")
                self.add_event_log("→", "RUNNER", "LANGGRAPH", "Starting canonical 23-node graph", "cyan")
            elif t == "node_active":
                node = data.get("node")
                self.state["current_node"] = node
                self.state["node_state"] = "[cyan]RUNNING[/cyan]"
                self.add_event_log("▶", "GRAPH", node, "STARTED", "cyan")
            elif t == "node_complete":
                node = data.get("node")
                self.state["node_state"] = "IDLE"
                self.add_event_log("✓", "GRAPH", node, "COMPLETED", "green")
            elif t == "llm_start":
                node = data.get("node")
                self.state["backend"] = data.get("backend")
                self.state["model"] = data.get("model")
                self.state["node_state"] = "[yellow]LLM INFERENCE[/yellow]"
                self.add_event_log("→", str(node).upper(), "LLM", f"model={data.get('model')}", "yellow")
            elif t == "llm_complete":
                node = data.get("node")
                self.state["node_state"] = "[cyan]RUNNING[/cyan]"
                self.add_event_log("←", "LLM", str(node).upper(), f"Response received in {data.get('elapsed', 0):.1f}s", "green")
            elif t == "llm_error":
                node = data.get("node")
                self.state["node_state"] = "[red]ERROR[/red]"
                self.state["status"] = "[red]✖ FAILED[/red]"
                self.add_event_log("✖", "LLM", str(node).upper(), f"Failed in {data.get('elapsed', 0):.1f}s", "red", error=data.get('error'))
            elif t == "investigation_error":
                self.state["status"] = "[red]✖ FAILED[/red]"
                self.add_event_log("✖", "RUNNER", "GRAPH", "Investigation failed", "red", error=data.get('error'))
            elif t == "investigation_complete":
                self.state["status"] = "[green]✓ COMPLETE[/green]"
                self.state["current_node"] = "NONE"
                self.state["node_state"] = "IDLE"
                self.add_event_log("✓", "RUNNER", "GRAPH", f"Investigation complete ({data.get('status')}, {data.get('findings_count')} findings)", "green")
            elif t == "kafka_produce":
                self.add_event_log("→", "PRODUCE", data.get("topic"), f"case={data.get('case_id')}", "magenta")
            elif t == "kafka_consume":
                self.add_event_log("←", "CONSUME", data.get("topic"), f"case={data.get('case_id')}", "magenta")
            elif t == "dfkg_write":
                self.add_event_log("→", "FINDINGS", "NEO4J", f"AgentFinding created ({data.get('role')})", "blue")
            
            self._update_ui()
            
    def stop(self):
        self.live.stop()
        try:
            with open("dashboard_snapshot.txt", "w", encoding="utf-8") as f:
                self.console.print(self.layout, file=f)
        except Exception:
            pass
