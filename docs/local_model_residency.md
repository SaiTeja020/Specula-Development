# Local embedding and generation residency

Case-evidence embeddings default to CPU (`options.num_gpu=0`) and a 15-minute
keep-alive. This avoids competing with the local 8B generation model for GPU
memory. Generation context, output budgets, serialization and cooldown are
unchanged. Both host ingestion and container retrieval use the same adapter.

The installed embedding model name/digest, vector dimensions, case filters and
collection identity remain unchanged. Existing evidence and vector collections
are not deleted or automatically reindexed. CPU/GPU results need numerical
compatibility checks rather than an assumption of bit-identical output.

`SPECULA_EMBEDDING_NUM_GPU=-1` restores automatic placement. Non-negative integer
values request that many GPU layers; invalid values fail before network access.
Apply environment overrides to each host/container process using the adapter.
Long-running Python services must load the updated source before using it.

## Local verification

Use the installed local Ollama server and models; the probe downloads nothing
and creates no case, analyst decision or database write:

```powershell
venv/Scripts/python.exe -m pytest tests/test_case_semantic_index.py tests/agents/test_ollama_backend.py -q
venv/Scripts/python.exe scripts/verify_local_model_residency.py --compare-auto
```

The probe warms generation with its existing 8K context, then alternates automatic
and CPU embeddings with short structured chat requests. It records embedding wall
times, generation load times, model digests, vector dimensions/cosines and
`/api/ps` residency. The CPU rounds require zero embedding VRAM and a resident GPU
generation model. CPU/automatic embedding cosine similarity must be at least
0.999 on the three fixed inputs. Repeat CPU rounds check warm behavior.

Default output is `data/verification/model-residency/live.json`. Partial/failure
receipts are retained. Without `--compare-auto`, only CPU placement is checked.
The probe refuses unrelated resident models. Comparison mode may evict/reload
the two selected local models; run it when their other workloads are idle.

These are small residency/compatibility measurements, not an end-to-end latency,
retrieval accuracy, thermal or enterprise-capacity benchmark. CPU placement uses
system RAM and CPU time; available capacity and scheduler settings still matter.

## Observed local probe (10 November 2026)

Ollama 0.13.3, installed `qwen3:8b` and `qwen3-embedding:0.6b`, three fixed short
inputs, 8K generation context and 32-token structured chat budget:

| Embedding placement | Embedding batch wall time | Next generation load time | Residency after embeddings |
| --- | --- | --- | --- |
| Automatic | 48.05 s | 81.36 s | Generation evicted; embeddings on GPU |
| CPU, first round | 1.10 s | 0.14 s | Embeddings on CPU; generation on GPU |
| CPU, repeated round | 0.24 s | 0.12 s | Both remain resident |

All vectors had 1,024 dimensions. CPU/automatic cosines ranged from 0.999566 to
0.999673; vectors are numerically close, not bit-identical. This does not prove
unchanged retrieval ranking for near ties. Initial generation warmup was 78.49 s
and is reported separately from the table. One automatic and two CPU rounds
establish this local observation only. Receipt: `data/verification/model-residency/live.json`.

Ollama documents [embedding options and load timings](https://docs.ollama.com/api/embed)
and [memory-based residency and keep-alive behavior](https://docs.ollama.com/faq).
The `num_gpu` runner option is defined in its
[API types](https://github.com/ollama/ollama/blob/v0.13.3/api/types.go).
