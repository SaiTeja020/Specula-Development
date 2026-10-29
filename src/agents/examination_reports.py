"""Formal printable examination artifacts grounded in saved case evidence."""
from hashlib import sha256
from pathlib import Path
import platform
from importlib.metadata import PackageNotFoundError, version



def runtime_manifest():
    fingerprints = {}
    for relative in ("src/agents/examination_reports.py", "src/agents/report_document.py", "src/agents/grounded_report.py",
                     "src/ingestion/run_pipeline.py", "src/agents/log_analysis_factory.py",
                     "src/agents/log_analysis/detection_rules.py", "src/agents/case_analysis.py",
                     "src/agents/evidence_review.py", "src/agents/nodes.py", "src/agents/ollama_backend.py",
                     "src/schemas/ocsf_base.py", "src/agents/forensic_tools.py", "src/agents/network_specialist.py",
                     "src/agents/cape_sandbox.py",
                     "src/agents/behavior_analysis.py", "src/agents/exploit_paths.py", "src/agents/case_analytics.py",
                     "src/ingestion/indexing/case_evidence.py", "src/graph/process_lineage.py"):
        path = Path(__file__).resolve().parents[2] / relative
        if path.is_file():
            fingerprints[relative] = sha256(path.read_bytes()).hexdigest()
    packages = {}
    for name in ("langgraph", "neo4j", "pydantic", "fastapi", "duckdb", "chromadb", "reportlab", "pefile", "capstone", "volatility3"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = "not installed"
    return {"python": platform.python_version(), "packages": packages, "source_sha256": fingerprints}



def render_examination_report(state: dict, kind: str) -> tuple[str, dict]:
    """Render the compact HTML companion retained in case checkpoints."""
    from .report_document import render_html
    return render_html(state, kind)


def render_examination_pdf(state: dict, kind: str) -> tuple[bytes, dict]:
    """Render the downloadable audience-specific ReportLab PDF."""
    from .report_document import render_pdf
    return render_pdf(state, kind)
