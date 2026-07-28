"""
Specula Entropy Clusterer.

Calculates Shannon entropy for specific structured fields (e.g. command_line)
to flag potentially anomalous payloads like Base64 obfuscation or DGAs.

Reference: specula_ingestion_final_plan.md §7.3
"""

import math
from typing import Dict, Any

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    Higher values (e.g. > 5.0) often indicate obfuscation/encryption.
    """
    if not data:
        return 0.0
        
    entropy = 0.0
    length = len(data)
    
    # Calculate character frequencies
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
        
    # Calculate entropy
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def enrich_with_entropy(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add entropy scores to relevant fields in an OCSF event.
    For Phase 1, we focus on ProcessActivity command_line.
    """
    class_uid = event.get("class_uid")
    
    # ProcessActivity (1007)
    if class_uid == 1007:
        cmdline = event.get("command_line")
        if cmdline:
            entropy_score = calculate_shannon_entropy(cmdline)
            # In a strict OCSF schema, this might go into an enrichments object.
            # For simplicity in this structure, we add it to a custom observables map.
            observables = event.get("observables", [])
            observables.append({
                "name": "command_line_entropy",
                "type": "Float",
                "value": round(entropy_score, 3)
            })
            event["observables"] = observables
            
    # NetworkActivity (4001) - DNS queries
    elif class_uid == 4001:
        dns_query = event.get("dns_query")
        if dns_query:
            entropy_score = calculate_shannon_entropy(dns_query)
            observables = event.get("observables", [])
            observables.append({
                "name": "dns_query_entropy",
                "type": "Float",
                "value": round(entropy_score, 3)
            })
            event["observables"] = observables

    return event
