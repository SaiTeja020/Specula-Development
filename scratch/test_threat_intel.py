import sys
import os

# Append project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ingestion.indexing.threat_intel_index import ThreatIntelIndex

def main():
    print("Loading ThreatIntelIndex...")
    index = ThreatIntelIndex()
    
    print(f"\nIndex size: {index.corpus_size}")
    
    # 1. Exact lookup for T1059.001
    print("\n--- Exact Lookup: T1059.001 ---")
    meta = index._metadata.get("T1059.001")
    if meta:
        print(f"Name: {meta.get('title')}")
        print(f"Tactics: {meta.get('tags')}")
        print(f"Used by Groups: {meta.get('used_by_groups', 'Check embed text!')}")
        print(f"Platforms: {meta.get('platforms')}")
        print(f"Parent: {meta.get('parent_technique_id')}")
        print(f"STIX: {meta.get('stix_id')}")
    else:
        print("T1059.001 NOT FOUND in exact metadata.")

    # 2. Semantic lookup
    print("\n--- Semantic Retrieval: 'PowerShell execution' ---")
    results = index.query("PowerShell execution", top_k=3)
    for i, r in enumerate(results):
        print(f"{i+1}. [{r['record_id']}] {r['title']} (Score: {r['score']:.4f})")
    
    print("\n--- Semantic Retrieval: 'credential dumping' ---")
    results = index.query("credential dumping", top_k=3)
    for i, r in enumerate(results):
        print(f"{i+1}. [{r['record_id']}] {r['title']} (Score: {r['score']:.4f})")
        
    print("\n--- Threat Attribution MCP Integration Test ---")
    from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
    import json
    
    server = ThreatIntelMCPServer()
    # The MCP tool signature looks for tool 'search_threat_intel'
    # Wait, the tool is called forensic_threat_context_search in the agent wrapper
    from src.agents.react_tools import ForensicThreatContextSearchTool
    tool = ForensicThreatContextSearchTool(server)
    
    # Try the tool
    resp = tool.run(json.dumps({"query": "PowerShell execution", "record_type": "attack_technique"}))
    print(f"Tool Result received? {resp.ok}")
    print(f"Tool Data Snippet: {str(resp.data)[:200]}...")
    if "PowerShell" in str(resp.data):
        print("Integration Success: Threat Attribution retrieved expected MITRE context via Tool.")
    else:
        print("Integration Failed: Could not find expected context.")

if __name__ == "__main__":
    main()
