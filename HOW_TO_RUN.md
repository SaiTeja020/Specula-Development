# How to Run the Specula Investigation Platform

Welcome to the Specula project! This guide is written for non-technical users to easily start the background systems, fill the database with test evidence, run an automated cybersecurity investigation, and understand the results.

## Step 1: Start the Background Systems (Docker)

Specula uses several background systems to manage data, communicate, and store evidence. You don't need to know exactly how they work, but you do need to turn them on!

Open your terminal (Command Prompt or PowerShell) in the project folder and type:

```powershell
docker compose up -d
```

**What did you just start?**
* **Neo4j (The Brain/Map)**: A database that stores relationships between evidence (like a detective's corkboard with red string).
* **Kafka & Redpanda (The Messengers)**: Allows the different AI agents to securely and instantly pass notes to each other.
* **Redis (The Memory)**: Remembers where the agents paused so they can ask you a question and resume later without losing their place.
* **Quickwit & Chroma (The Search Engines)**: Search tools that let the AI agents scan through thousands of logs in milliseconds.

## Step 2: Prepare the Evidence Database

Now that the systems are running, we need to configure the "Brain" (Neo4j) and fill it with a fake cybersecurity scenario for the AI to investigate.

1. **Set up the Database Schema** (tells the database how to organize evidence):
   ```powershell
   python scripts/neo4j_setup.py
   ```
2. **Inject the Mock Evidence** (inserts the clues for a test case named "RAG-TEST-CASE-001"):
   ```powershell
   python scripts/seed_rag_test_data.py
   ```

## Step 3: Run the AI Investigation

With the evidence in place, it's time to wake up the AI agents and ask them to solve the case.

Type the following command, then press **Enter**:

```powershell
python scripts/run_investigation.py --case-id "RAG-TEST-CASE-001" --query "Investigate suspicious network activity involving this host."
```

*(Note: If the system hangs on Windows, you can use the "Safe Mode" command instead:)*
```powershell
$env:SPECULA_DISABLE_NEURAL="1"; python scripts/run_investigation.py --case-id "RAG-TEST-CASE-001" --query "Investigate suspicious network activity involving this host."
```

## Step 4: What to Expect During the Run

Once you press enter, the AI agents will begin communicating with each other to solve the case. Here is what is happening behind the scenes:

1. **The Orchestrator:** A central manager agent receives your query and decides which specialists to wake up (e.g., Network Forensics, Log Analysis).
2. **The Specialists:** These agents dig through the evidence database to find clues.
3. **The Debate (HITL - Human in the Loop):** Sometimes, the agents might disagree on the evidence, or they might try to make a decision that requires human approval. 

### Human Approval Needed!
If the system encounters a critical decision, it will **pause** and ask for your input. You will see a prompt like this on your screen:

```text
SPECULA HITL — HUMAN REVIEW REQUIRED
Case: RAG-TEST-CASE-001
Thread: thread-...
Options: approve / reject / clarify
Your decision: 
```

* **Type `approve`** if you want the agents to proceed with their current plan.
* **Type `reject`** to stop them and tell them they are on the wrong path.
* **Type `clarify`** if you want to provide more context.

## Step 5: Understanding the Final Output

After the agents finish their investigation, a specialized "Synthesis" agent will take all the highly technical forensic data and write a plain-English summary for you.

At the very end of the terminal output, you will see the final report. It will look like this:

```text
======================================================================
SPECULA INVESTIGATION RESULT
======================================================================
Case ID  : RAG-TEST-CASE-001
Status   : completed
Query    : Investigate suspicious network activity involving this host.

----------------------------------------------------------------------
ANSWER
----------------------------------------------------------------------
=== FORENSIC INVESTIGATION REPORT ===
Case: RAG-TEST-CASE-001
Classification: External APT Compromise
Severity: Critical
Findings: The system detected 15 evidence artifacts indicating that the host was compromised via an external vulnerability. Lateral movement was observed across 4 domains.
Recommendation: Immediate containment of the affected host and a reset of compromised credentials.
======================================================================
```

### How to Read the Report:
* **Classification:** What kind of attack or event occurred (e.g., Malware, Insider Threat).
* **Severity:** How urgent the situation is (e.g., Low, Medium, High, Critical).
* **Findings:** A simple, jargon-free summary of exactly what the agents discovered.
* **Recommendation:** The immediate next steps you or your IT team should take to fix the problem.

## Step 6: Shutting Down

Once you are done, you can cleanly shut down all the background systems so they don't consume memory on your computer.

```powershell
docker compose down
```

That's it! You have successfully run a multi-agent digital forensics investigation from start to finish.
