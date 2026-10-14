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
                  "gcp_audit": "gcp_audit", "mft": "mft", "container":"container", "ad_auth":"ad_auth"}
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXPANDED_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_RECORDS = 100000


class ExaminedArtifactRecord(dict):
    """In-process marker; an uploader cannot create it through JSON fields."""


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
                native = (len(path.parts)>=3 and
                          ((path.parts[:2]==('malware','samples') and path.suffix.lower() in {'.exe','.dll'}) or
                           (path.parts[:2]==('memory','regions') and path.suffix.lower()=='.bin') or
                           (path.parts[:2]==('memory','processes') and path.suffix.lower()=='.dmp')))
                if native:
                    inventory.append({"path":name,"source_type":SOURCE_FOLDERS[path.parts[0]],
                                      "bytes":len(payload),"sha256":sha256(payload).hexdigest(),"records":1,"native_artifact":True})
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
    for item in inventory:
        if item.get('native_artifact'):
            metadata = (declared.get('artifacts') or {}).get(item['path'])
            if not isinstance(metadata,dict) or not metadata.get('timestamp'):
                raise ValueError(item['path']+": manifest.artifacts entry with timestamp is required")
            from .export_aliases import record_timestamp
            record_timestamp(metadata,item['source_type'])
            item['artifact_metadata']=metadata
    return {"source": "uploaded_zip", "archive_sha256": sha256(data).hexdigest(),
            "archive_bytes": len(data), "received_at": datetime.now(timezone.utc).isoformat(),
            "files": inventory, "declared_metadata": declared,
            "custody_status": "Receipt recorded; acquisition and prior custody are uploader declarations"}


def archive_batches(path, inventory):
    with ZipFile(path) as archive:
        for item in inventory["files"]:
            data = archive.read(item['path'])
            if not item.get('native_artifact'):
                yield item["source_type"], records_from_bytes(data,item["path"].lower())
                continue
            from src.agents.forensic_tools import examine_pe,examine_memory_region,examine_minidump
            metadata = item['artifact_metadata']
            if item['source_type']=='malware':
                analysis=examine_pe(data)
                rows=[{**metadata,"severity_id":1,"confidence":"Measured features, no malicious verdict",
                       "sample_name":item['path'],"sha256":item['sha256'],"analysis":analysis,
                       "analysis_origin":analysis['analysis_origin'],"verdict":"unresolved","finding":"Independent PE static features; no malicious verdict"}]
            else:
                analysis=examine_minidump(data) if item['path'].lower().endswith('.dmp') else examine_memory_region(data)
                rows=[{**metadata,"severity_id":1,"capture_observation":True,"plugin":"targeted_memory",
                       "finding":"Targeted memory byte examination status="+analysis['status'],
                       "analysis_origin":analysis['analysis_origin'],"analysis":analysis,"sha256":item['sha256']}]
            yield item['source_type'], [ExaminedArtifactRecord(r) for r in rows]
