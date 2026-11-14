# Current model testing — Ollama, 2026-10-07

Current user instruction selects the installed local `qwen3:8b` model. No Gemini or hosted attribution endpoint is selected by the local Docker override. Existing Gemini configuration labels/adapters are historical optional integrations, not the selected runtime.

The application dispatcher supports `SPECULA_LLM_BACKEND=ollama` and `SPECULA_THREAT_ATTRIBUTION_BACKEND=ollama`. Host testing defaults to `http://127.0.0.1:11434`; Docker uses `http://host.docker.internal:11434`. The adapter verifies the selected model is installed locally, rejects cloud/remote models and external endpoints, disables proxies/redirects, and has no hosted fallback or automatic download. It uses the documented [Ollama chat API](https://docs.ollama.com/api/chat).

Run only the scoped current tests:

```powershell
.\venv\Scripts\pytest.exe tests/agents/test_ollama_backend.py tests/agents/test_threat_attribution_agent.py tests/test_skeleton_graph.py -q -p no:cacheprovider --basetemp=.pytest-tmp-ollama-contract
.\venv\Scripts\pytest.exe -m live_infra tests/integration/test_ollama_live.py tests/integration/test_live_services.py -k "not external_ingestion_or_model_endpoint" -q -p no:cacheprovider
```

The live test runs actual local inference through the role dispatcher and the evidence-bound attribution explanation contract, with explicit graph/corpus doubles for that contract test. Earlier complete investigation evidence used stubs and must retain that label; it does not establish a full investigation with every worker using Ollama.

## GCP cost boundary

gcloud CLI reports an active login and a selected project. This is local authentication/configuration evidence, not proof of Python Application Default Credentials or live audit ingestion. No GCP service call, API activation, resource creation or billing change was performed for this update. GCP ingestion remains deferred under the user's no-billable-services constraint.

**Do not run** the legacy `scripts/check_external_services.py` or the `test_external_ingestion_or_model_endpoint` tests under the current policy. The terminal approval for replacing that script was declined; it still contains the earlier hosted model/Cloud Logging probes. The current scoped test command excludes them. Historical Gemini quota errors are not blockers for current Ollama testing.
