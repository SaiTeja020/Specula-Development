"""
Specula Offline Threat-Intel Index Build Script.

Fetches MITRE ATT&CK STIX + NVD CVE data, embeds all records, trains a
fresh FAISS IndexIVFPQ, and writes the artifacts atomically.

Run on a schedule (daily) or manually after first install:

    python scripts/build_threat_intel_index.py

NVD API key (optional, increases rate limit from 5 to 50 req/30 s):
    set NVD_API_KEY=your-key-here

Or pass it directly:
    python scripts/build_threat_intel_index.py --nvd-api-key YOUR_KEY

Other options:
    --attack-version   ATT&CK STIX bundle version (default: 15.1)
    --nvd-start-date   ISO date for CVE window start (e.g. 2022-01-01T00:00:00.000)
    --nvd-end-date     ISO date for CVE window end
    --nvd-severity     Filter CVEs by severity: LOW | MEDIUM | HIGH | CRITICAL
    --output-dir       Directory to write artifacts (default: data/threat_intel)
    --nlist            FAISS IVF cell count (default: 100; tune with 4*sqrt(N))
    --m                FAISS PQ subquantizers (default: 16; dimension must be divisible)
    --bits             FAISS PQ bits per code (default: 8)
    --no-nvd           Skip NVD CVE fetch (ATT&CK only)
    --no-attack        Skip ATT&CK STIX fetch (NVD only)

Reference: faiss_threat_intel_implementation_plan.md §4
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import time

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ingestion.indexing.threat_intel_sources import (
    AttackStixFetcher,
    NvdCveFetcher,
    ThreatIntelRecord,
)
from src.ingestion.indexing.known_attacks_fetcher import KnownAttacksExcelFetcher
from src.ingestion.indexing.vector_store import EmbeddingGenerator
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.schemas.threat_intel_metadata import ThreatIntelRecordMetadata

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("build_threat_intel_index")

# Load .env so NVD_API_KEY and other env vars are available without
# needing to set them manually in the shell each time.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — rely on shell env vars


# ---------------------------------------------------------------------------
# Artifact file names (must match threat_intel_index.py constants)
# ---------------------------------------------------------------------------
_FAISS_INDEX_FILE = "faiss_index.bin"
_ID_MAP_FILE = "faiss_id_map.json"
_METADATA_FILE = "metadata_store.json"
_MANIFEST_FILE = "build_manifest.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _embed_records(
    records: list[ThreatIntelRecord],
    gen: EmbeddingGenerator,
) -> tuple[list, list[dict]]:
    """
    Sanitize, embed, and build metadata for all records.

    Returns:
        (vectors_list, metadata_list)
        where vectors_list[i] is a List[float] and metadata_list[i] is a dict.
    """
    vectors = []
    metadata_dicts = []

    for i, record in enumerate(records):
        if i % 500 == 0 and i > 0:
            logger.info("Embedding progress: %d / %d records", i, len(records))

        # Security gate: sanitize external text before embedding
        sanitized = sanitize_text(record.embed_text).sanitized_text

        vec = gen.embed(sanitized)
        vectors.append(vec)

        # Validate and build metadata using the Pydantic schema
        meta = ThreatIntelRecordMetadata(
            record_id=record.record_id,
            record_type=record.record_type,
            title=record.title,
            description=sanitized,
            source=record.source,
            source_version=record.source_version,
            tags=record.tags if record.tags else None,
            stix_id=getattr(record, "stix_id", None),
            platforms=getattr(record, "platforms", None),
            is_subtechnique=getattr(record, "is_subtechnique", None),
            parent_technique_id=getattr(record, "parent_technique_id", None),
            created=getattr(record, "created", None),
            last_modified=getattr(record, "last_modified", None),
            url=getattr(record, "url", None),
        )
        metadata_dicts.append(meta.to_dict())

    return vectors, metadata_dicts


def _build_faiss_index(
    vectors: list,
    nlist: int,
    m: int,
    bits: int,
) -> tuple:
    """
    Train and populate a fresh FAISS IndexIVFPQ.

    IMPORTANT: IndexIVFPQ MUST be trained before any vectors can be added.
    This function enforces that by calling index.train() before index.add().

    Returns:
        (faiss_index, id_map)  where id_map is {int_id: record_id_str}
    """
    try:
        import faiss
        import numpy as np
    except ImportError as exc:
        raise RuntimeError(
            "faiss-cpu is not installed. Run: pip install faiss-cpu"
        ) from exc

    dimension = len(vectors[0])
    n = len(vectors)

    logger.info(
        "Building FAISS IndexIVFPQ: dimension=%d, n=%d, nlist=%d, m=%d, bits=%d",
        dimension, n, nlist, m, bits,
    )

    if n < nlist:
        # FAISS requires at least nlist training vectors; reduce nlist if needed
        actual_nlist = max(1, n // 4)
        logger.warning(
            "Corpus size (%d) < nlist (%d). Reducing nlist to %d.",
            n, nlist, actual_nlist,
        )
        nlist = actual_nlist

    vector_matrix = np.array(vectors, dtype="float32")

    quantizer = faiss.IndexFlatIP(dimension)
    index = faiss.IndexIVFPQ(quantizer, dimension, nlist, m, bits)
    index.metric_type = faiss.METRIC_INNER_PRODUCT

    # --- TRAIN STEP (mandatory for IndexIVFPQ) ---
    logger.info("Training FAISS index on %d vectors ...", n)
    index.train(vector_matrix)

    if not index.is_trained:
        raise RuntimeError(
            "FAISS IndexIVFPQ.is_trained is False after training — "
            "this indicates a FAISS internal error."
        )
    logger.info("Training complete.")

    # --- ADD STEP (only safe after training) ---
    index.add(vector_matrix)
    logger.info("Added %d vectors to FAISS index.", index.ntotal)

    # Build int -> string id map (FAISS internal sequential integer IDs)
    id_map = {i: "PLACEHOLDER" for i in range(n)}   # will be filled below

    return index, n


def _write_artifacts_atomic(
    output_dir: str,
    faiss_index,
    id_map: dict[int, str],
    metadata_list: list[dict],
    records: list[ThreatIntelRecord],
    build_meta: dict,
) -> None:
    """
    Write all four artifact files atomically via temp-file + rename.

    Atomic write pattern (plan §4.1 step 8): write to a temp file in the
    same directory, then os.replace() to the final path. This guarantees the
    MCP server never reads a half-written file.
    """
    try:
        import faiss
    except ImportError as exc:
        raise RuntimeError("faiss-cpu is not installed.") from exc

    os.makedirs(output_dir, exist_ok=True)

    # Build string id_map from record list
    str_id_map = {i: rec.record_id for i, rec in enumerate(records)}

    # Build metadata dict indexed by record_id
    metadata_store = {
        rec.record_id: metadata_list[i] for i, rec in enumerate(records)
    }

    def _atomic_write_json(obj, filename: str) -> None:
        target = os.path.join(output_dir, filename)
        fd, tmp = tempfile.mkstemp(dir=output_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            os.replace(tmp, target)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _atomic_write_faiss(index, filename: str) -> None:
        target = os.path.join(output_dir, filename)
        fd, tmp = tempfile.mkstemp(dir=output_dir, suffix=".bin.tmp")
        os.close(fd)
        try:
            faiss.write_index(index, tmp)
            os.replace(tmp, target)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    logger.info("Writing artifacts atomically to %s ...", output_dir)
    _atomic_write_faiss(faiss_index, _FAISS_INDEX_FILE)
    logger.info("  [OK] %s", _FAISS_INDEX_FILE)

    _atomic_write_json(str_id_map, _ID_MAP_FILE)
    logger.info("  [OK] %s", _ID_MAP_FILE)

    _atomic_write_json(metadata_store, _METADATA_FILE)
    logger.info("  [OK] %s", _METADATA_FILE)

    _atomic_write_json(build_meta, _MANIFEST_FILE)
    logger.info("  [OK] %s", _MANIFEST_FILE)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the Specula FAISS threat-intel corpus (offline, scheduled)."
    )
    parser.add_argument(
        "--attack-version",
        default="15.1",
        help="ATT&CK STIX bundle version (default: 15.1)",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        help=(
            "NVD API key. If not provided, NVD_API_KEY env var is checked. "
            "Without a key: rate-limited to 5 req/30 s."
        ),
    )
    parser.add_argument(
        "--nvd-start-date",
        default=None,
        help="CVE pubStartDate filter (ISO-8601, e.g. 2022-01-01T00:00:00.000)",
    )
    parser.add_argument(
        "--nvd-end-date",
        default=None,
        help="CVE pubEndDate filter (ISO-8601)",
    )
    parser.add_argument(
        "--nvd-severity",
        default=None,
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter CVEs by CVSS severity",
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join("data", "threat_intel"),
        help="Output directory for index artifacts (default: data/threat_intel)",
    )
    parser.add_argument(
        "--nlist",
        type=int,
        default=100,
        help="FAISS IVF cell count — tune with 4*sqrt(N) (default: 100)",
    )
    parser.add_argument(
        "--m",
        type=int,
        default=16,
        help="FAISS PQ subquantizer count — dimension must be divisible by m (default: 16)",
    )
    parser.add_argument(
        "--bits",
        type=int,
        default=8,
        help="FAISS PQ bits per code (default: 8)",
    )
    parser.add_argument(
        "--no-nvd",
        action="store_true",
        help="Skip NVD CVE fetch (ATT&CK only)",
    )
    parser.add_argument(
        "--no-attack",
        action="store_true",
        help="Skip ATT&CK STIX fetch (NVD only)",
    )
    args = parser.parse_args()

    build_start = time.time()
    build_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    print(f"\n  Specula FAISS Threat-Intel Index Builder")
    print(f"  Build timestamp : {build_timestamp}")
    print(f"  Output dir      : {args.output_dir}")
    print(f"  ATT&CK version  : {args.attack_version}")
    if not args.no_nvd:
        nvd_key_status = (
            "provided (50 req/30 s)"
            if (args.nvd_api_key or os.environ.get("NVD_API_KEY"))
            else "not set — rate-limited to 5 req/30 s (set NVD_API_KEY to increase)"
        )
        print(f"  NVD API key     : {nvd_key_status}")
    print()

    # ----------------------------------------------------------------
    # Collect records
    # ----------------------------------------------------------------
    all_records: list[ThreatIntelRecord] = []
    source_versions: dict = {}

    if not args.no_attack:
        logger.info("Step 1/4: Fetching ATT&CK records from known_attacks Excel ...")
        fetcher = KnownAttacksExcelFetcher()
        for rec in fetcher.fetch_and_parse():
            all_records.append(rec)
        source_versions["mitre_attack_excel"] = "enterprise-attack-v19.2.xlsx"
        logger.info("ATT&CK: collected %d records.", len(all_records))
    else:
        logger.info("Skipping ATT&CK STIX (--no-attack).")

    nvd_count_start = len(all_records)

    if not args.no_nvd:
        logger.info("Step 2/4: Fetching NVD CVE records ...")
        nvd_fetcher = NvdCveFetcher(
            api_key=args.nvd_api_key or os.environ.get("NVD_API_KEY"),
            pub_start_date=args.nvd_start_date,
            pub_end_date=args.nvd_end_date,
            cvss_severity=args.nvd_severity,
        )
        for rec in nvd_fetcher.fetch_all():
            all_records.append(rec)
        nvd_added = len(all_records) - nvd_count_start
        source_versions["nvd_cve"] = time.strftime("%Y-%m-%d")
        logger.info("NVD CVE: collected %d records.", nvd_added)
    else:
        logger.info("Skipping NVD CVE fetch (--no-nvd).")

    if not all_records:
        logger.error("No records collected. Aborting.")
        sys.exit(1)

    logger.info("Total records to embed: %d", len(all_records))

    # ----------------------------------------------------------------
    # Embed
    # ----------------------------------------------------------------
    logger.info("Step 3/4: Embedding %d records ...", len(all_records))
    gen = EmbeddingGenerator()
    vectors, metadata_list = _embed_records(all_records, gen)

    # ----------------------------------------------------------------
    # Build FAISS index
    # ----------------------------------------------------------------
    logger.info("Step 4/4: Building FAISS IndexIVFPQ ...")
    faiss_index, n_indexed = _build_faiss_index(
        vectors=vectors,
        nlist=args.nlist,
        m=args.m,
        bits=args.bits,
    )

    # ----------------------------------------------------------------
    # Write artifacts atomically
    # ----------------------------------------------------------------
    record_type_counts = {}
    for rec in all_records:
        record_type_counts[rec.record_type] = (
            record_type_counts.get(rec.record_type, 0) + 1
        )

    build_manifest = {
        "build_timestamp": build_timestamp,
        "build_duration_secs": round(time.time() - build_start, 1),
        "total_records": n_indexed,
        "record_type_counts": record_type_counts,
        "source_versions": source_versions,
        "faiss_config": {
            "index_type": "IndexIVFPQ",
            "dimension": len(vectors[0]),
            "nlist": args.nlist,
            "m": args.m,
            "bits": args.bits,
            "metric": "METRIC_INNER_PRODUCT",
        },
        "embedding_model_version": gen.model_version,
    }

    _write_artifacts_atomic(
        output_dir=args.output_dir,
        faiss_index=faiss_index,
        id_map={i: rec.record_id for i, rec in enumerate(all_records)},
        metadata_list=metadata_list,
        records=all_records,
        build_meta=build_manifest,
    )

    elapsed = round(time.time() - build_start, 1)
    print()
    print(f"  [OK] Build complete in {elapsed}s")
    print(f"       Records indexed : {n_indexed}")
    for rtype, count in record_type_counts.items():
        print(f"         {rtype:<25} {count}")
    print(f"       Artifacts in    : {args.output_dir}")
    print()
    print("  To run the MCP server against this corpus:")
    print("    from src.mcp.threat_intel_mcp import ThreatIntelMCPServer")
    print("    server = ThreatIntelMCPServer()")
    print()


if __name__ == "__main__":
    main()
