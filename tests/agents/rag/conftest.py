"""
Conftest for tests/agents/rag/.

Disables lazy FAISS instantiation for tests that do not explicitly inject a
ThreatIntelMCPServer.  The FAISS native DLL (faiss-cpu) can crash the Windows
CPython process during pytest's assertion-rewriting import hook, so we skip the
auto-load path unless the test explicitly provides a server instance.

Tests that WANT to exercise the FAISS path inject their own mock server via
the `threat_intel_server` constructor argument (see test_combined_rag.py).
"""
import os
import pytest


@pytest.fixture(autouse=True)
def disable_faiss_lazy_load(monkeypatch):
    """Prevent ForensicQAService from lazily importing FAISS during RAG tests."""
    monkeypatch.setenv("SPECULA_FAISS_DISABLED", "1")

