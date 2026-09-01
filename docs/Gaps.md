# Specula Framework: Architectural Gaps, Failures, and Solutions

## 1. Multi-Agent Roster and Domain Scope Gaps

### Orphaned Vulnerability Scans
* **Issue:** Vulnerability Scans (Tier 3, Rank 10) currently has no owning agent assigned to process the data. The Dynamic Attack Graph is listed as a skill but not one of the 15 core agents, meaning if Log Analysis hits a dead end needing residual-risk mapping, there is no specialist available.
* **Solution:** Instantiate a new dedicated Dynamic Attack Graph Agent to explicitly own the Dijkstra exploit-chain reasoning over OpenVAS/Nessus/Qualys vulnerability scans.

### Identity & Cloud Domain Conflation
* **Issue:** The "Identity & Cloud" agent is forced to perform two structurally different jobs under a single model: AD/LDAP/Kerberos forensics and Kubernetes/container-runtime forensics. These domains have entirely different failure signatures and require different reasoning logic.
* **Solution:** Split the role into two distinct agents: an Identity Agent (focused on AD/Kerberos/cloud-IAM) and a Cloud & Container Agent (dedicated to Kubernetes/container-runtime anomalies).

### Deep Network Forensics Escalation Asymmetry
* **Issue:** When primary-tier Network Forensics hits a dead end (e.g., needing multi-stage exfiltration reconstruction or encrypted C2 protocol analysis), there is no deep specialist to escalate to, unlike Log Analysis which escalates to Memory or Insider Threat agents.
* **Solution:** Give the existing Network Forensics agent a second-pass "deep-analysis mode" with an extended tool budget and PCAP-level reconstruction tools triggered upon its own dead end, rather than spinning up a new agent identity.

### Closed, Hardcoded Dead-End Dispatch
* **Issue:** The `dead_end_categories` logic uses a fixed enum (memory/identity/malware/insider). Any dead-end that doesn't cleanly map to these is either force-fit into the wrong specialist or has no dispatch target at all.
* **Solution:** Expand the `dead_end_categories` enum to include the new split categories (e.g., separating identity and cloud_container) to prevent misattribution and ensure correct routing.

---

## 2. Ingestion and Provenance Gaps

### Threat Intel Ingestion Pathway Contradiction
* **Issue:** There is a contradiction regarding whether Threat Intel bypasses Quickwit and Kafka. If it skips the preservation layer, the system loses the Daubert-compliant chain-of-custody needed to cryptographically prove what the Threat Attribution agent observed[cite: 1].
* **Solution:** Implement a "Hash-then-Embed" workflow where the Threat Intel payload is first hashed and registered in the Verifiable Conversation Transcript (VCT) ledger before being embedded into the FAISS index[cite: 1].

### Investigator Queries as "Raw Evidence"
* **Issue:** Investigator chat prompts are slated to run through the standard MiniBatchKMeans entropy clustering layer, which makes no architectural sense for natural language inputs[cite: 1].
* **Solution:** Create a specific Kafka/FastMCP bypass mechanism to route natural language queries directly to the Supervisor agent's routing node without running them through entropy clustering[cite: 1].

### Phase 3 Canonical Entity Resolution
* **Issue:** The current Entity Resolver logic relies on DHCP-lease bounded IPs, which completely fails for resolving ephemeral cloud IDs and Kubernetes pods across multi-cloud environments[cite: 1].
* **Solution:** Upgrade the CanonicalEntityResolver to a dual-path architecture that handles stable orchestrator identifiers (e.g., `pod_uid`) alongside traditional IP lease timelines.

---

## 3. Orchestration and Deployment Failures

### The "Air-Gapped" Capability Cliff
* **Issue:** While deploying locally on a single quantized Qwen 7B model is supported, there is no defined architectural fallback logic for what happens when the 7B model completely fails at complex tasks like AST Code Stylometry[cite: 1].
* **Solution:** Implement capability fallback governance in the Supervisor. If a task requires a "full-tier" model but the system is running in "light-tier" air-gapped mode, the Supervisor should flag `degraded_capability_mode` and escalate to the HITL (Human-In-The-Loop) dashboard.

### Rebuff Container Availability
* **Issue:** The architecture relies heavily on Rebuff for prompt injection defense, but it must be independently confirmed as available as a self-hostable Docker image[cite: 1]. If unavailable, the Zero-Trust Guardrail falls back to a degraded regex heuristic, drastically weakening defenses[cite: 1].
* **Solution:** Pre-validate the Rebuff self-hosted image during Stage 1 setup, or implement a secondary offline LLM intent classifier to replace it if air-gapping Rebuff fails[cite: 1].

### Stage 3 Checkpointer Security Risk
* **Issue:** The current implementation uses insecure pickle serialization (which is a major risk for Remote Code Execution) and contains a brittle hardcoded `pending_writes = []` hack that will crash during multi-agent fan-out.
* **Solution:** Replace the custom RedisSaver by installing the official `langgraph-checkpoint-redis` package, ensuring safe JSON serialization and robust asynchronous write retrieval.