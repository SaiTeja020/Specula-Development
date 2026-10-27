"""
Centralized configuration constants for Specula components.
"""
import os

CHROMA_EVIDENCE_COLLECTION = "case_evidence_embeddings"
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
GOOGLE_APPLICATION_CREDENTIALS = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
