"""Preflight exported log archives without extracting untrusted paths."""
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
from pathlib import PurePosixPath
import stat
from zipfile import BadZipFile, ZipFile

SOURCE_FOLDERS = {"windows": "evtx", "edr": "edr", "memory": "memory",
                  "malware": "malware", "ueba": "ueba", "vuln_scan": "vuln_scan",
                  "gcp_audit": "gcp_audit", "mft": "mft"}
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXPANDED_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_RECORDS = 100000


def records_from_bytes(data: bytes, name: str) -> list[dict]:
    try:
        text = data.decode("utf-8-sig")
        value = ([json.loads(line) for line in text.splitlines() if line.strip()]
                 if name.endswith(".jsonl") else json.loads(text))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"{name}: invalid UTF-8 JSON log") from exc
    records = value if isinstance(value, list) else [value]
    if not records or any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{name}: logs must contain JSON objects or an array of objects")
    return records


def validate_archive(data: bytes) -> dict:
    if not data or len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("ZIP must be nonempty and at most 50 MiB")
    inventory, declared, seen, expanded, total_records = [], {}, set(), 0, 0
    try:
        with ZipFile(BytesIO(data)) as archive:
            if len(archive.infolist()) > 500:
                raise ValueError("ZIP must contain at most 500 entries")
            for item in archive.infolist():
                # ZipInfo normalizes separators on Windows; inspect the original
                # central-directory name before trusting its normalized form.
                name = item.orig_filename
                path = PurePosixPath(name)
                if ("\\" in name or ":" in name or any(ord(char) < 32 for char in name) or path.is_absolute() or
                        any(part in {"..", "."} for part in name.split("/") if part) or
                        stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1):
                    raise ValueError("ZIP contains an unsafe path, symlink or encrypted entry")
                key = name.casefold().rstrip("/")
                if key in seen:
                    raise ValueError("ZIP contains duplicate paths")
                seen.add(key)
                if item.is_dir():
                    continue
                expanded += item.file_size
                if (item.file_size > MAX_FILE_BYTES or expanded > MAX_EXPANDED_BYTES or
                        item.file_size > max(1024 * 1024, item.compress_size * 200)):
                    raise ValueError("ZIP exceeds expanded-size or compression-ratio limits")
                payload = archive.read(item)
                if name == "manifest.json":
                    if len(payload) > 65536:
                        raise ValueError("manifest.json must be at most 64 KiB")
                    declared = json.loads(payload.decode("utf-8-sig"))
                    if not isinstance(declared, dict):
                        raise ValueError("manifest.json must be an object")
                    continue
                if (len(path.parts) < 2 or path.parts[0] not in SOURCE_FOLDERS or
                        path.suffix.lower() not in {".json", ".jsonl"}):
                    raise ValueError(f"{name}: use a supported source folder and .json/.jsonl export")
                records = records_from_bytes(payload, name.lower())
                total_records += len(records)
                if total_records > MAX_RECORDS:
                    raise ValueError("ZIP exceeds 100,000 log records")
                inventory.append({"path": name, "source_type": SOURCE_FOLDERS[path.parts[0]],
                                  "bytes": len(payload), "sha256": sha256(payload).hexdigest(),
                                  "records": len(records)})
    except (BadZipFile, RuntimeError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Unreadable ZIP or manifest") from exc
    if not inventory:
        raise ValueError("ZIP contains no supported logs")
    return {"source": "uploaded_zip", "archive_sha256": sha256(data).hexdigest(),
            "archive_bytes": len(data), "received_at": datetime.now(timezone.utc).isoformat(),
            "files": inventory, "declared_metadata": declared,
            "custody_status": "Receipt recorded; acquisition and prior custody are uploader declarations"}


def archive_batches(path, inventory):
    with ZipFile(path) as archive:
        for item in inventory["files"]:
            yield item["source_type"], records_from_bytes(archive.read(item["path"]), item["path"].lower())
