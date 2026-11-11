# Security isolation plan — approval draft

Status: PROPOSED, NOT APPLIED. 11 November 2026, Asia/Calcutta.
No ACL, identity, Docker mount, credential, service or evaluator-file change is authorized by this document.

## Observed deployment

- Parent source: `C:\Users\DELL\Specula-skeleton`, branch `skeleton`, commit `b9b2012edaed8da5062113ddc9982e3c33b27983`; tracked tree clean at inspection.
- Docker Engine 29.0.1 is now available, with zero running containers. This differs from the earlier audit's unavailable daemon; it was not started by this remediation.
- Docker Desktop processes run as `DESKTOP-N08P1L3\DELL`. No active Specula/uvicorn or Ollama process was observed. Ollama loopback `/api/version` refused the connection. No inference was requested.
- Existing image: `specula-skeleton-hitl-api@sha256:51b60fd7b1eba332efcfbbce0eff039bb12b2e31ddefd171ff67f5eca5e58b69`, created 2026-10-27; working directory `/app`; no explicit image user (Docker's default is root). Its source predates the inspected November commit. It is NOT approved as the evaluation image.
- `..\docker-compose.local.yml` binds `./src`, `./data`, `./data/analytics`, `./data/private`, and reuses named checkpoints/Kafka/Redis/Quickwit/Neo4j volumes. It also points inference to the host. These are development settings, not a validated evaluation boundary.
- `07_Evaluation_Artifacts/evaluator_only` has protected inheritance and allows DELL, SYSTEM and CodexSandboxOffline. Descendants are not uniformly restricted: the OpTC ground-truth PDF also allows CodexSandboxUsers and other SIDs. Prior recursive audit found 48 files with extra grants. A same-account host runtime is not isolated by this arrangement.

## Proposed boundary

Use a NEW deployment, not a Compose override merged into the development stack. Prefer a dedicated Linux VM with no Windows project-folder sharing, clipboard/file redirection or host management API exposed to workers. A separate non-administrator host identity `SpeculaEval` is proposed if Windows-host execution is retained; its SID does not yet exist or have approval. It must not belong to Administrators or have Docker-daemon access. A coordinator controls the VM/daemon; evaluated workers do not.

Worker containers run as UID:GID `10001:10001`. Runtime code and approved dependencies are baked into a reviewed immutable image; no parent project/source/acquisition directory is bind-mounted. Only a separately reviewed release of `02_Benchmarks/CFA_Bench/agent_evidence` may be mounted at `/evidence/agent_evidence`, read-only. That directory is a candidate, not yet approved: content leakage, hardlinks/reparse points and normalization compatibility still require validation.

The evaluator and scoring process stays outside the worker VM/network. Original repositories, answer keys, task JSON, original filename maps, scoring scripts with answers, manifests exposing label-bearing paths, this report directory and backups must never be copied into the worker image or evidence release. Existing originals and original hashes remain intact.

## Exact proposed changes — execute only after explicit approval

1. Create a separate evaluation staging area and dedicated runtime identity/VM. Do not modify the development Compose files or stop/reconfigure existing services. The curator retains DELL access; the worker identity receives no evaluator access.
2. Export ONLY allowlisted runtime source from commit `b9b2012edaed8da5062113ddc9982e3c33b27983` into a new image build context. Exclude `.git`, `.env*`, tests, fixtures, scripts, data, output, credentials, original benchmark clones, acquisition reports and answer-bearing assets. Audit the resulting image filesystem, including inherited layers. The current October image must not silently supply stale source or caches. Exact new image digest and dependency image pins remain UNRESOLVED until an approved build/inventory; no build or installation has occurred.
3. Create a NEW standalone Compose project `specula-eval`, using the constraints below. Do not combine it with `docker-compose.local.yml`. The snippet is a proposal, not a launchable complete stack: unresolved image/entrypoint fields intentionally prevent deployment.

```yaml
name: specula-eval
services:
  worker:
    image: ${APPROVED_EVAL_IMAGE_DIGEST:?image inventory and approval required}
    user: "10001:10001"
    working_dir: /app
    read_only: true
    privileged: false
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 256
    init: true
    restart: "no"
    pull_policy: never
    environment:
      HOME: /tmp
      TMPDIR: /tmp
      PYTHONDONTWRITEBYTECODE: "1"
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700
      - /run/specula:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700
    volumes:
      - type: bind
        source: ${APPROVED_AGENT_EVIDENCE_RELEASE:?review and approval required}
        target: /evidence/agent_evidence
        read_only: true
        bind:
          create_host_path: false
    networks: [eval_internal]
networks:
  eval_internal:
    internal: true
```

4. Define fresh, separately pinned model, Neo4j, Kafka, Redis, Chroma, Quickwit and checkpoint services on the private evaluation network as actually required by the selected harness. Do not reuse any development volume, case database, index, embedding collection, prompt cache, logs or model conversational cache. No host ports, host networking, Docker socket, named pipe, host gateway, external network, browser/search service, SSH/SMB path, credential directory or host-service URL is permitted for workers. An internal network alone is not proof of host/management-plane isolation: test those paths in the chosen VM/runtime.
5. Review nonsecret configuration and use evaluation-only service credentials under the coordinator. Do not mount `data/private` or load the parent `.env`. The inspected Ollama adapter accepts only localhost/127.0.0.1/::1/host.docker.internal, so an arbitrary private service name would fail. Preferred exact topology for an approval-stage full stack: put `inference` on `eval_internal`, replace the worker's `networks` entry with `network_mode: "service:inference"`, and set `SPECULA_OLLAMA_BASE_URL=http://127.0.0.1:11434` for the worker. This shares a private network namespace, not a filesystem or evaluator volume. It requires an approved pinned inference image and model-only weight release; no prior conversation/cache state. Validate this topology, non-root permissions and fresh-service DNS from the actual worker before use. Do not use the existing host Ollama endpoint. The initial snippet above remains a restrictions profile, not the final full-stack launch file; service images, resource needs and adapter integration remain BLOCKED pending approval and verification.
6. Optional host defense in depth, requiring separate approval: capture every existing evaluator SDDL and owner, then replace broad descendant grants with an exact curator/SYSTEM allowlist, preserving legitimate curator ownership and verifying each descendant. Resolve SIDs explicitly; do not blindly delete unknown grants or add a deny ACE for DELL, who remains the curator. A separate worker identity must be denied effective read/list/traverse access. Backups containing evaluator material require the same boundary. No ACL edits or user creation have been performed.

Compose semantics were checked against [Docker service documentation](https://docs.docker.com/reference/compose-file/services/) and [network documentation](https://docs.docker.com/reference/compose-file/networks/). Resource limits here are proposed safety limits, not measured system capacity or an approved experiment budget.

## Leakage controls and required tests

| Surface | Required control and evidence before passing |
| --- | --- |
| Files, symlinks, junctions, hardlinks | Reject all reparse points/symlinks and unexplained multiple-link files in the evidence release; canonical paths must remain under the exact read root. Mount table must show only the allowlist. Test `..`, absolute Windows/Linux paths, alternate separators, symlink escape and file-URI reads. |
| Working directory/image | `/app` contains reviewed runtime code only; no host CWD or parent directory bind. Inspect all image files/layers and configuration for fixture answers, cached cases and credentials. |
| Temporary files/logs | Fresh tmpfs and fresh per-run output storage. No reused host TEMP, logs or prior reports. Outputs go to a coordinator-owned collector without an agent-readable evaluator backchannel. |
| Tool/API access | Use the actual Specula worker and tool processes, not just a shell probe. Attempt evaluator reads through every filesystem, execution, upload, follow-up, retrieval and case API; require explicit rejection/no content. Disable unsupported tools. |
| Search, graph, vectors, embeddings | Fresh stores initially empty. Index only approved evidence IDs/hashes and separately approved reference-only corpus. Inspect membership after ingestion. No prior cases, answer-bearing documents, experiment reports or cross-case retrieval. Separate stores per condition/repeat unless a frozen protocol explicitly controls reuse. |
| Network/model | Deny host paths, Docker API/socket, management plane, evaluator endpoints and external search/egress. Permit only required fresh evaluation services. No hosted fallback or model pulls. |
| Actual identity | Capture host SID, container UID/GID, capabilities, mounts, network endpoints, image digest and process identity for worker AND helper services. Non-admin/non-root assertions must pass. |
| Positive/negative access controls | As that actual identity/runtime, read an approved evidence file and match its public SHA-256. Attempt open/list/read of CFA task labels, original repository, filename map, NIST/OpTC answer keys and an evaluator-only canary; all must fail without disclosing content. Check direct, traversal, tool/API and retrieval routes. A missing file alone does not prove every alternative route is denied. |

Required negative targets include `07_Evaluation_Artifacts/evaluator_only/CFA-bench/data/tasks/data.json`, `CFA_evidence_mapping.csv`, `OpTC/OpTCRedTeamGroundTruth.pdf`, all original benchmark repositories and parent synthetic keys at `..\output\evaluation-pilot\case-*-answer-key.json`. Original CFA clone filenames and task/result files are not evidence inputs.

## Approval and rollback boundary

Approve the deployment design, identity/VM, exact service images, sanitized release and any endpoint compatibility changes first. Then approve a bounded access-control preflight; this is not approval for a full experiment or an analyst decision. Preserve ACL exports and hashes before any approved permission changes. Rollback must restore only newly changed security configuration and leave original evidence untouched; never reset existing stores or restore stale data into a new evaluation runtime.

Effective isolation is currently FAIL for same-account host access and BLOCKED for the proposed runtime because it has not been deployed or tested. No permitted-evidence/denied-label test has been claimed for an actual Specula evaluation runtime. The default Docker user/image age and model endpoint constraints are unresolved deployment gates, not silently fixed configuration.
