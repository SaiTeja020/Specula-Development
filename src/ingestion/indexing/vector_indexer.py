"""
Specula Case Evidence Vector Indexer.

Indexes raw, unstructured text evidence (e.g. email bodies, PowerShell scripts)
into Qdrant for semantic search.

Reference: specula_ingestion_final_plan.md §9.1

Mistakes to avoid (from v6):
    Do NOT write unstructured payload data (like raw email bodies) into
    the DFKG node properties. DFKG is for structured topology.
    Vector/unstructured data goes strictly to Qdrant.
"""

import json
import logging
from typing import Dict, Any, List

# Note: In a full implementation, we'd use qdrant-client and sentence-transformers.
# We stub the client for Phase 1 as the exact embedding model is a deployment detail.

logger = logging.getLogger(__name__)


class VectorIndexer:
    """Indexes unstructured text into a vector database (Qdrant)."""

    def __init__(self, collection_name: str = "specula_evidence"):
        self.collection_name = collection_name
        # self.qdrant_client = QdrantClient(url="http://localhost:6333")
        
        # We would typically initialize the embedding model here, e.g.
        # self.model = SentenceTransformer('all-MiniLM-L6-v2')

    def index_evidence(self, event: Dict[str, Any]) -> None:
        """
        Extract unstructured text fields from the event and index them.
        
        Only indexes events that actually contain unstructured payloads
        that benefit from semantic search. Standard structured events
        (e.g., a port 443 Zeek conn log) are NOT vectorized, as they
        are better searched via Cypher in the DFKG.
        """
        
        text_to_index = None
        
        # 1. Identify unstructured fields based on event class
        class_uid = event.get("class_uid")
        
        if class_uid == 1007:  # ProcessActivity
            # PowerShell/bash scripts passed via command line
            cmd = event.get("command_line", "")
            if len(cmd) > 100:  # Arbitrary threshold for "worth vectorizing"
                text_to_index = cmd
                
        # (Other classes would be handled here, e.g., email bodies, file contents)
        
        # 2. Vectorize and Index if applicable
        if text_to_index:
            uid = event.get("uid")
            case_id = event.get("case_id")
            
            logger.debug(f"Vectorizing {len(text_to_index)} chars for event {uid}")
            
            # 3. Create payload strictly binding to the DFKG entity
            payload = {
                "uid": uid,
                "case_id": case_id,
                "class_uid": class_uid,
                # Include the raw text so we can return it in search results
                "text": text_to_index 
            }
            
            # 4. Generate Embedding and Upsert (Stubbed)
            # vector = self.model.encode(text_to_index).tolist()
            # self.qdrant_client.upsert(
            #     collection_name=self.collection_name,
            #     points=[
            #         PointStruct(
            #             id=uid, # UUIDs map directly
            #             vector=vector,
            #             payload=payload
            #         )
            #     ]
            # )
            
            # Log for the stub implementation
            logger.info(f"Indexed unstructured evidence for {uid} into Qdrant collection {self.collection_name}")
