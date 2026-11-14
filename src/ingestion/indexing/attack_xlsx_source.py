"""Read the checked-in ATT&CK workbook without third-party spreadsheet packages."""
from __future__ import annotations

import hashlib
from pathlib import Path
import posixpath
import re
import time
from zipfile import ZipFile
import xml.etree.ElementTree as ET

from .threat_intel_sources import ThreatIntelRecord, _TACTIC_ORDER

_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_GROUP = re.compile(r"^G\d{4}$")


def _column(reference: str) -> int:
    letters = re.match(r"[A-Z]+", reference)
    if not letters:
        raise ValueError("Invalid workbook cell reference")
    value = 0
    for letter in letters.group():
        value = value * 26 + ord(letter) - ord("A") + 1
    return value - 1


def _sheet_rows(archive: ZipFile, sheet: str):
    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
    relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    targets = {item.get("Id"): item.get("Target") for item in relationships.findall(f"{{{_PACKAGE_REL}}}Relationship")}
    match = next((item for item in workbook.findall(f"{{{_MAIN}}}sheets/{{{_MAIN}}}sheet")
                  if item.get("name") == sheet), None)
    if match is None:
        raise ValueError(f"ATT&CK workbook is missing the {sheet} sheet")
    target = targets.get(match.get(f"{{{_OFFICE_REL}}}id"))
    if not target:
        raise ValueError(f"ATT&CK workbook has no {sheet} sheet target")
    path = target.lstrip("/") if target.startswith("/") else posixpath.normpath(posixpath.join("xl", target))
    shared = []
    if "xl/sharedStrings.xml" in archive.namelist():
        strings = ET.fromstring(archive.read("xl/sharedStrings.xml"))
        shared = ["".join(part.text or "" for part in item.iter(f"{{{_MAIN}}}t"))
                  for item in strings.findall(f"{{{_MAIN}}}si")]
    with archive.open(path) as source:
        header = None
        for _, element in ET.iterparse(source, events=("end",)):
            if element.tag != f"{{{_MAIN}}}row":
                continue
            cells = {}
            for cell in element.findall(f"{{{_MAIN}}}c"):
                value = cell.find(f"{{{_MAIN}}}v")
                inline = cell.find(f"{{{_MAIN}}}is")
                text = value.text or "" if value is not None else ""
                if cell.get("t") == "s" and text:
                    text = shared[int(text)]
                elif inline is not None:
                    text = "".join(part.text or "" for part in inline.iter(f"{{{_MAIN}}}t"))
                cells[_column(cell.get("r", ""))] = text
            if header is None:
                header = cells
            else:
                yield {name: cells.get(index, "") for index, name in header.items()}
            element.clear()


def load_attack_workbook(path: str | Path) -> tuple[list[ThreatIntelRecord], str]:
    """Return techniques and groups with verified local-file provenance."""
    path = Path(path)
    name = re.fullmatch(r"enterprise-attack-v(\d+\.\d+)\.xlsx", path.name)
    if not name:
        raise ValueError("Expected a versioned Enterprise ATT&CK workbook")
    source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    version = f"ATT&CK-xlsx-v{name.group(1)}"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with ZipFile(path) as archive:
        techniques = {}
        for row in _sheet_rows(archive, "techniques"):
            identity = row.get("ID", "")
            if not _TECHNIQUE.fullmatch(identity):
                continue
            if identity in techniques:
                raise ValueError(f"Duplicate ATT&CK technique: {identity}")
            tactics = [part.strip().lower().replace(" ", "-")
                       for part in row.get("tactics", "").split(",") if part.strip()]
            techniques[identity] = ThreatIntelRecord(
                record_id=identity, record_type="attack_technique", title=row.get("name", ""),
                embed_text=f"{row.get('name', '')}. {row.get('description', '')}",
                source="local_attack_xlsx", source_version=version, tags=tactics,
                source_hash=source_hash, retrieved_at=timestamp, feed_provider="local_attack_xlsx")
        groups = {}
        for row in _sheet_rows(archive, "groups"):
            identity = row.get("ID", "")
            if not _GROUP.fullmatch(identity):
                continue
            if identity in groups:
                raise ValueError(f"Duplicate ATT&CK group: {identity}")
            groups[identity] = ThreatIntelRecord(
                record_id=identity, record_type="attack_group", title=row.get("name", ""),
                embed_text=f"{row.get('name', '')}. {row.get('description', '')}",
                source="local_attack_xlsx", source_version=version,
                source_hash=source_hash, retrieved_at=timestamp, feed_provider="local_attack_xlsx")
        used = {identity: set() for identity in groups}
        for row in _sheet_rows(archive, "relationships"):
            source, target = row.get("source ID", ""), row.get("target ID", "")
            if (row.get("mapping type") == "uses" and source in groups
                    and target in techniques and row.get("source type") == "group"):
                used[source].add(target)
    if not techniques or not groups or not any(used.values()):
        raise ValueError("ATT&CK workbook has no usable technique, group or uses relationships")
    for identity, group in groups.items():
        group.technique_ids = sorted(used[identity])
        group.technique_sequence = sorted(used[identity], key=lambda technique_id: (
            min((_TACTIC_ORDER.index(tactic) for tactic in techniques[technique_id].tags
                 if tactic in _TACTIC_ORDER), default=len(_TACTIC_ORDER)), technique_id))
        group.sequence_basis = "attack_tactic_order" if group.technique_sequence else None
    return list(techniques.values()) + list(groups.values()), source_hash
