"""
Specula Memory Extractor.

Orchestrates a full live-memory forensics pipeline:
  1. WinPmem  -- acquires a raw physical memory image from the running system.
  2. Volatility3 -- runs the following plugins against the image:
       - windows.pslist   -> ProcessActivityEvent
       - windows.netscan  -> NetworkActivityEvent
       - windows.malfind  -> DetectionFindingEvent
  3. Serialises all plugin rows to a JSON list consumed by
     src/ingestion/normalization/memory_dump_normalizer.py.

Configuration (environment variables):
  SPECULA_MEMORY_ENABLED   -- "true" to enable (default: false).
  SPECULA_MEMORY_MOCK      -- "true" to skip real acquisition and return
                              synthetic fixture records (default: false).
  SPECULA_WINPMEM_PATH     -- absolute path to winpmem_mini_x64.exe
                              (default: "tools/winpmem_mini_x64.exe").
  SPECULA_VOL3_PATH        -- absolute path to the vol.py entry-point
                              (default: "tools/vol.py").
  SPECULA_MEMORY_DUMP_DIR  -- directory used for the temporary .raw image
                              (default: "data/extracted_logs").
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("SpeculaMemoryExtractor")

# -- Environment config -------------------------------------------------------
_MOCK_MODE: bool = os.environ.get("SPECULA_MEMORY_MOCK", "false").lower() == "true"
_WINPMEM_PATH: str = os.environ.get("SPECULA_WINPMEM_PATH", "tools/winpmem_mini_x64.exe")
_VOL3_PATH: str = os.environ.get("SPECULA_VOL3_PATH", "tools/vol.py")
_DUMP_DIR: str = os.environ.get("SPECULA_MEMORY_DUMP_DIR", "data/extracted_logs")

# Plugins to execute and the label the normalizer uses to branch on.
_PLUGINS: List[Dict[str, str]] = [
    {"vol_plugin": "windows.pslist.PsList",   "label": "pslist"},
    {"vol_plugin": "windows.netscan.NetScan", "label": "netscan"},
    {"vol_plugin": "windows.malfind.Malfind", "label": "malfind"},
]


# -- Internal helpers ---------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _acquire_memory(dump_path: str) -> bool:
    """
    Run winpmem to dump physical memory to *dump_path*.
    Returns True on success, False on failure.

    winpmem requires elevated (Administrator) privileges. The caller
    must ensure the process is running as Administrator, or the acquisition
    will fail with a non-zero exit code.
    """
    winpmem = Path(_WINPMEM_PATH)
    if not winpmem.exists():
        logger.error(
            f"WinPmem not found at '{winpmem}'. "
            "Download winpmem_mini_x64.exe and place it at SPECULA_WINPMEM_PATH, "
            "or set SPECULA_MEMORY_MOCK=true for development without a memory tool."
        )
        return False

    logger.info(f"Acquiring memory image -> {dump_path} (this may take several minutes)...")
    try:
        result = subprocess.run(
            [str(winpmem), dump_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.error(
                f"WinPmem exited with code {result.returncode}: {result.stderr.strip()}"
            )
            return False
        logger.info("Memory acquisition complete.")
        return True
    except Exception as exc:
        logger.error(f"Memory acquisition failed: {exc}")
        return False


def _run_volatility(dump_path: str, plugin: str, label: str) -> List[Dict[str, Any]]:
    """
    Execute one Volatility3 plugin against *dump_path* and return a list of
    normalised row dicts ready for memory_dump_normalizer.normalize().

    Volatility3 renders JSON output with --output-format json.
    """
    vol = Path(_VOL3_PATH)
    if not vol.exists():
        logger.error(
            f"Volatility3 vol.py not found at '{vol}'. "
            "Install Volatility3 and set SPECULA_VOL3_PATH accordingly."
        )
        return []

    cmd = [
        "python", str(vol),
        "-f", dump_path,
        plugin,
        "--output-format", "json",
    ]

    logger.info(f"Running Volatility3 plugin: {plugin}")
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=600
        )
        if res.returncode != 0:
            logger.warning(
                f"Volatility3 {plugin} returned code {res.returncode}: {res.stderr[:300]}"
            )
            return []
        return _parse_vol3_json(res.stdout, label)
    except subprocess.TimeoutExpired:
        logger.error(f"Volatility3 plugin {plugin} timed out after 10 minutes.")
        return []
    except Exception as exc:
        logger.error(f"Volatility3 execution failed for {plugin}: {exc}")
        return []


def _parse_vol3_json(raw_output: str, label: str) -> List[Dict[str, Any]]:
    """
    Parse Volatility3 JSON output (columnar format) into normaliser-ready dicts.

    Volatility3 JSON schema:
      {
        "columns": ["Col1", "Col2", ...],
        "rows":    [[val1,  val2,  ...], ...]
      }
    """
    records: List[Dict[str, Any]] = []
    capture_time = _now_iso()

    try:
        vol_data = json.loads(raw_output)
    except json.JSONDecodeError:
        logger.warning("Volatility3 output is not valid JSON; skipping plugin output.")
        return records

    columns: List[str] = vol_data.get("columns", [])
    rows: List[List[Any]] = vol_data.get("rows", [])

    for row in rows:
        row_dict: Dict[str, Any] = dict(zip(columns, row))
        record = _map_row(row_dict, label, capture_time)
        if record:
            records.append(record)

    logger.info(f"Parsed {len(records)} records from Volatility3 plugin '{label}'.")
    return records


def _map_row(
    row: Dict[str, Any], label: str, capture_time: str
) -> Optional[Dict[str, Any]]:
    """
    Map one Volatility3 plugin row to the schema expected by
    memory_dump_normalizer.normalize(). Returns None for empty rows.
    """
    base: Dict[str, Any] = {
        "plugin": label,
        "capture_time": capture_time,
        # Memory captures have no DC time anchor -- mark timestamps unverified.
        "has_dc_anchor": False,
    }

    if label == "pslist":
        if not row.get("ImageFileName") and not row.get("PID"):
            return None
        base.update({
            "ImageFileName": row.get("ImageFileName", "unknown"),
            "PID":           row.get("PID", 0),
            "PPID":          row.get("PPID"),
            "CommandLine":   row.get("Cmd") or row.get("CommandLine"),
        })

    elif label == "netscan":
        base.update({
            "LocalAddr":   row.get("LocalAddr"),
            "ForeignAddr": row.get("ForeignAddr"),
            "LocalPort":   row.get("LocalPort"),
            "ForeignPort": row.get("ForeignPort"),
            "Proto":       row.get("Proto"),
        })

    elif label == "malfind":
        base.update({
            "process_name": row.get("Process") or row.get("process_name", "unknown"),
            "process_pid":  row.get("PID", 0),
            # Injected memory is always treated as high severity (id=5).
            "severity_id":  5,
            "details":      row,
        })

    else:
        base.update(row)

    return base


# -- Mock fixture -------------------------------------------------------------

def _generate_mock_records() -> List[Dict[str, Any]]:
    """
    Return synthetic records that exercise all three normaliser branches
    (pslist, netscan, malfind). Used when SPECULA_MEMORY_MOCK=true.
    """
    now = _now_iso()
    return [
        # pslist rows ----------------------------------------------------------
        {
            "plugin": "pslist", "capture_time": now, "has_dc_anchor": False,
            "ImageFileName": "lsass.exe",    "PID": 640,  "PPID": 504,
            "CommandLine": None,
        },
        {
            "plugin": "pslist", "capture_time": now, "has_dc_anchor": False,
            "ImageFileName": "svchost.exe",  "PID": 1232, "PPID": 640,
            "CommandLine": "-k netsvcs",
        },
        {
            "plugin": "pslist", "capture_time": now, "has_dc_anchor": False,
            "ImageFileName": "cmd.exe",      "PID": 4512, "PPID": 3200,
            "CommandLine": "cmd.exe /c whoami",
        },
        # netscan rows ---------------------------------------------------------
        {
            "plugin": "netscan", "capture_time": now, "has_dc_anchor": False,
            "LocalAddr": "192.168.1.10", "LocalPort": 49512,
            "ForeignAddr": "10.0.0.1",  "ForeignPort": 445, "Proto": "TCP",
        },
        {
            "plugin": "netscan", "capture_time": now, "has_dc_anchor": False,
            "LocalAddr": "192.168.1.10", "LocalPort": 0,
            "ForeignAddr": None,          "ForeignPort": None, "Proto": "UDP",
        },
        # malfind rows ---------------------------------------------------------
        {
            "plugin": "malfind", "capture_time": now, "has_dc_anchor": False,
            "process_name": "explorer.exe", "process_pid": 3200, "severity_id": 5,
            "details": {
                "VadTag": "VadS",
                "Protection": "PAGE_EXECUTE_READWRITE",
            },
        },
    ]


# -- Public API ---------------------------------------------------------------

def extract_memory_events() -> List[Dict[str, Any]]:
    """
    Top-level entry point called by run_pipeline.py.

    Returns a list of dicts consumed by memory_dump_normalizer.normalize().
    Returns an empty list on unrecoverable failure so the caller can decide
    whether to abort or continue with partial data.

    Behaviour:
      - SPECULA_MEMORY_MOCK=true  -> returns synthetic fixture records instantly.
      - SPECULA_MEMORY_MOCK=false -> acquires live memory with WinPmem, then
                                     runs Volatility3 pslist / netscan / malfind.
    """
    if _MOCK_MODE:
        logger.info(
            "Memory extractor running in MOCK mode -- returning synthetic fixture records."
        )
        records = _generate_mock_records()
        logger.info(f"Mock: generated {len(records)} synthetic memory records.")
        return records

    # -- Live acquisition path ------------------------------------------------
    dump_dir = Path(_DUMP_DIR)
    dump_dir.mkdir(parents=True, exist_ok=True)
    dump_path = str(dump_dir / "specula_live_mem.raw")

    if not _acquire_memory(dump_path):
        logger.error(
            "Memory acquisition failed. "
            "Set SPECULA_MEMORY_MOCK=true for development without WinPmem."
        )
        return []

    all_records: List[Dict[str, Any]] = []
    for plugin_cfg in _PLUGINS:
        rows = _run_volatility(
            dump_path=dump_path,
            plugin=plugin_cfg["vol_plugin"],
            label=plugin_cfg["label"],
        )
        all_records.extend(rows)

    # Clean up the raw image to avoid leaving large forensic artefacts on disk.
    try:
        os.remove(dump_path)
        logger.info(f"Removed temporary memory image: {dump_path}")
    except OSError as exc:
        logger.warning(f"Could not remove temporary memory image '{dump_path}': {exc}")

    logger.info(
        f"Memory extraction complete -- "
        f"{len(all_records)} records across {len(_PLUGINS)} plugins."
    )
    return all_records
