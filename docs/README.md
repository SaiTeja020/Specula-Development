# Documentation map

Start with [project status](PROJECT_STATUS.md) for verified work, open work and current limits. Use [PROGRESS.md](../PROGRESS.md) for task states and execution history and [DECISIONS.md](../DECISIONS.md) for architectural decisions.

## Current operational references

| Document | Use it for |
| --- | --- |
| [Local remediation](local_remediation.md) | Current authorization, evidence/report and restart behavior; local commands. |
| [Local model testing](local_model_testing.md) | Ollama selector and no-billable-GCP boundary. |
| [Model runtime matrix](model_runtime_matrix.md) | Configured roles and unverified production assignments. |
| [Operations runbook](operations_runbook.md) | Starting, recovering and operating the local stack; production gates still needed. |
| [Readiness results](readiness_results.md) | Earlier gate results plus the later local remediation update. |
| [Local validation](local_validation.md) | Synthetic fixture and component verification. |

## Historical design and diagnostic records

`full_application_run.md` records the defects found before the October 7 remediation and links to the later result. The architecture, ingestion, supervisor, vector retrieval, FAISS and stage implementation plans in this directory are historical design inputs. They should be checked against `PROJECT_STATUS.md`, `PROGRESS.md` and the current code before treating a claim as implemented. The administrative Word summaries in the repository root are also earlier snapshots.

Runtime artifacts in `data/verification` are ignored by Git and intentionally retained. `data/private`, `data/checkpoints`, and `quarantine` contain settings or evidence and are not repository cleanup targets.
