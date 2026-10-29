# Documentation map

This folder contains project context, architecture and operating references.
Task states and execution history live in [PROGRESS.md](../PROGRESS.md);
architectural decisions live in [DECISIONS.md](../DECISIONS.md).
Design documents describe intended capabilities; check source and the tracker for current support.

## Project context

| Document | Purpose |
| --- | --- |
| [Master document](Master%20doc.md) | Project goals, forensic model and overall design. |
| [Architecture](architecture_v4.html) | System structure and intended feature coverage. |
| [Input sources](specula_input_sources.svg) | Evidence-source overview. |
| [Ingestion pipeline](Specula_Ingestion_Pipeline.md) | Preservation, normalization and ingestion concepts. |
| [Runtime harness](specula_runtime_harness.md) | Runtime design and coordination rationale. |

## Operating and format references

| Document | Purpose |
| --- | --- |
| [Operations runbook](operations_runbook.md) | Startup, recovery, backups and acceptance gates. |
| [Local runtime](local_remediation.md) | Authorization, checkpoints and recovery commands. |
| [Local validation](local_validation.md) | Build and repeatable verification commands. |
| [Local models](local_model_testing.md) | Ollama configuration and testing boundaries. |
| [Model matrix](model_runtime_matrix.md) | Default selectors and optional provider configuration. |
| [ZIP uploads](ZIP_LOG_UPLOADS.md) | Evidence archive structure and supported inputs. |
| [Permission exports](access_snapshot_format.md) | Access-evidence schema and examples. |
| [Follow-up acquisition](followup_acquisition.md) | Bounded local audit collection and safeguards. |
| [Examination reports](EXAMINATION_REPORTS.md) | Court and technical report content and limitations. |
| [CAPE integration](cape_integration.md) | Sandbox connector configuration and receipt handling. |
| [Sandbox setup](malware_sandbox_setup.md) | Isolated malware-analysis environment requirements. |

Evidence, credentials, checkpoints and verification artifacts under `data/` are outside this documentation index.
