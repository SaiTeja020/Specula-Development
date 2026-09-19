import logging
import json
import numpy as np
from typing import List, Dict, Any

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from datasketch import MinHash
from sklearn.cluster import MiniBatchKMeans
from collections import defaultdict
import math

logger = logging.getLogger(__name__)

class DistillationLayer:
    """
    Entropy-Based Semantic Distillation Layer
    
    1. Template Extraction (Drain3)
    2. Adversarial Defense (SimHash/MinHash LSH)
    3. Semantic Clustering (MiniBatchKMeans)
    """
    
    def __init__(self, entropy_threshold: float = 0.3):
        self.entropy_threshold = entropy_threshold
        
        # 1. Drain3 Configuration
        config = TemplateMinerConfig()
        config.load("")  # Default config
        config.profiling_enabled = False
        self.template_miner = TemplateMiner(config=config)
        
        # 2. MinHash state for adversarial poisoning detection
        self.seen_signatures = []
        
        # 3. MiniBatchKMeans for clustering templates
        self.kmeans = MiniBatchKMeans(n_clusters=5, random_state=42, n_init="auto", batch_size=100)
        self.is_kmeans_fitted = False
        
    def _extract_text(self, event: Dict[str, Any]) -> str:
        """Extract a suitable text representation from the event for templating."""
        if "Message" in event and isinstance(event["Message"], str):
            return event["Message"]
        if "message" in event and isinstance(event["message"], str):
            return event["message"]
        
        # Fallback: Stringify the values of the event
        # Exclude common noisy fields like timestamps
        clean_dict = {k: v for k, v in event.items() if k not in ["time", "eventTime", "timestamp"]}
        return json.dumps(clean_dict, sort_keys=True)

    def _compute_minhash(self, text: str) -> MinHash:
        """Compute MinHash signature for adversarial defense."""
        m = MinHash(num_perm=128)
        for d in text.split():
            m.update(d.encode('utf8'))
        return m
        
    def process_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a batch of events through the distillation layer.
        Returns a compressed list of events, collapsing low-entropy repetitive events.
        """
        if not events:
            return []
            
        distilled_events = []
        cluster_groups = defaultdict(list)
        
        # Phase 1 & 2: Template Extraction & MinHash Defense
        for idx, event in enumerate(events):
            text = self._extract_text(event)
            
            # Defense: LSH check (simplified for now to just record signatures)
            # In a real adversarial scenario, we would check Jaccard similarity against known poison templates.
            mh = self._compute_minhash(text)
            self.seen_signatures.append(mh)
            
            # Extract Template
            result = self.template_miner.add_log_message(text)
            template = result["template_mined"]
            cluster_id = result["cluster_id"]
            
            event["_drain_template"] = template
            event["_drain_cluster_id"] = cluster_id
            
            cluster_groups[cluster_id].append(event)
            
        # Phase 3: Entropy Calculation & MiniBatchKMeans Clustering
        # First, prepare features for KMeans (we use a simple count or length heuristic as a stand-in for deep embedding)
        # To avoid heavy NLP models, we cluster based on structural properties of the templates.
        
        X = []
        cluster_ids_ordered = []
        
        for cluster_id, grp_events in cluster_groups.items():
            template = grp_events[0]["_drain_template"]
            # Simple feature: length of template, number of wildcards <*>
            wildcard_count = template.count("<*>")
            length = len(template)
            X.append([length, wildcard_count])
            cluster_ids_ordered.append(cluster_id)
            
        if X:
            X_arr = np.array(X)
            if not self.is_kmeans_fitted and len(X_arr) >= self.kmeans.n_clusters:
                self.kmeans.fit(X_arr)
                self.is_kmeans_fitted = True
            elif self.is_kmeans_fitted:
                self.kmeans.partial_fit(X_arr)
                
        # Calculate Entropy and Compress
        total_events = len(events)
        
        for cluster_id, grp_events in cluster_groups.items():
            # Basic Shannon entropy approximation based on frequency
            prob = len(grp_events) / total_events
            entropy = -prob * math.log2(prob) if prob > 0 else 0
            
            if entropy < self.entropy_threshold and len(grp_events) > 1:
                # Collapse low-entropy events into a single summary node
                summary_event = grp_events[0].copy()
                summary_event["_distillation_summary"] = True
                summary_event["_collapsed_count"] = len(grp_events)
                
                # Clean up internal markers
                summary_event.pop("_drain_template", None)
                summary_event.pop("_drain_cluster_id", None)
                
                distilled_events.append(summary_event)
                logger.debug(f"Distillation: Collapsed {len(grp_events)} low-entropy events into 1 summary node.")
            else:
                # High-entropy anomalies pass completely intact
                for evt in grp_events:
                    evt_copy = evt.copy()
                    evt_copy["_distillation_summary"] = False
                    
                    # Clean up internal markers
                    evt_copy.pop("_drain_template", None)
                    evt_copy.pop("_drain_cluster_id", None)
                    
                    distilled_events.append(evt_copy)
                    
        return distilled_events
