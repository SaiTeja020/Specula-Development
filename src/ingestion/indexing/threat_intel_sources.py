"""
Threat-Intel Source Fetchers: MITRE ATT&CK STIX + NVD CVE.

Downloads, parses, and normalises external threat-intelligence feeds into a
common ThreatIntelRecord shape ready for embedding and FAISS indexing.

NVD API is used WITHOUT an API key by default (rate-limited to 5 req/30 s).
To add your key when you get one, set the environment variable:

    set NVD_API_KEY=your-key-here

The code automatically picks it up via:
    NvdCveFetcher(api_key=os.environ.get("NVD_API_KEY"))

Reference: faiss_threat_intel_implementation_plan.md §4
"""

from __future__ import annotations

import logging
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Iterator, List, Optional

import requests

logger = logging.getLogger(__name__)

_TACTIC_ORDER = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
)

# ---------------------------------------------------------------------------
# NVD API configuration
# ---------------------------------------------------------------------------

# Base URL for NVD REST API v2 (CVE endpoint).
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate-limit windows (seconds). Without a key: 5 req / 30 s window.
# With a key: 50 req / 30 s window.
_NVD_WINDOW_SECS = 30
_NVD_REQ_LIMIT_NO_KEY = 5
_NVD_REQ_LIMIT_WITH_KEY = 50

# How many CVEs to fetch per paginated NVD API call (max 2000 per NVD docs).
_NVD_PAGE_SIZE = 2000

# ---------------------------------------------------------------------------
# Shared data shape
# ---------------------------------------------------------------------------


@dataclass
class ThreatIntelRecord:
    """
    Normalised record ready for embedding + FAISS indexing.
    One record = one FAISS vector.
    """

    record_id: str                          # ATT&CK ID (T1059) or CVE ID
    record_type: str                        # "attack_technique" | "attack_group" | "cve"
    title: str                              # Short display name
    embed_text: str                         # Concatenated, pre-sanitised text to embed
    source: str                             # "mitre_attack_stix" | "nvd_cve"
    source_version: str                     # STIX bundle tag or NVD snapshot date
    tags: List[str] = field(default_factory=list)   # Tactic names or CWE IDs
    technique_ids: List[str] = field(default_factory=list)
    technique_sequence: List[str] = field(default_factory=list)
    sequence_basis: Optional[str] = None
    source_hash: Optional[str] = None
    retrieved_at: Optional[str] = None
    feed_provider: Optional[str] = None


# ---------------------------------------------------------------------------
# MITRE ATT&CK STIX fetcher
# ---------------------------------------------------------------------------

# Official GitHub release URL pattern for Enterprise ATT&CK STIX bundles.
# Pin to a specific tag so builds are reproducible.
_ATTACK_STIX_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-{version}.json"
)
_ATTACK_DEFAULT_VERSION = "15.1"


class AttackStixFetcher:
    """
    Downloads the MITRE ATT&CK Enterprise STIX bundle and yields
    ThreatIntelRecord objects for every technique and group.
    """

    def __init__(
        self,
        version: str = _ATTACK_DEFAULT_VERSION,
        url: Optional[str] = None,
        timeout_secs: float = 60.0,
    ) -> None:
        self.version = version
        self.url = url or _ATTACK_STIX_URL_TEMPLATE.format(version=version)
        self.timeout = timeout_secs

    def fetch_bundle(self) -> dict:
        """Download the STIX bundle JSON. Raises requests.RequestException on failure."""
        logger.info("Fetching ATT&CK STIX bundle v%s from %s", self.version, self.url)
        resp = requests.get(self.url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def parse(self, bundle: dict) -> Iterator[ThreatIntelRecord]:
        """Yield ThreatIntelRecord for each attack-pattern (technique) and
        intrusion-set (group) in the bundle."""
        objects = bundle.get("objects", [])
        source_version = f"ATT&CK-v{self.version}"
        source_hash = hashlib.sha256(
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        technique_by_stix_id = {}
        tactic_by_technique = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                technique_id = next((ref.get("external_id") for ref in obj.get("external_references", [])
                                     if ref.get("source_name") == "mitre-attack"), None)
                if technique_id:
                    technique_by_stix_id[obj.get("id")] = technique_id
                    tactic_by_technique[technique_id] = [
                        phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])
                    ]
        group_techniques: dict[str, set[str]] = {}
        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses" or obj.get("revoked"):
                continue
            technique_id = technique_by_stix_id.get(obj.get("target_ref"))
            if technique_id:
                group_techniques.setdefault(obj.get("source_ref"), set()).add(technique_id)

        for obj in objects:
            obj_type = obj.get("type", "")
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            if obj_type == "attack-pattern":
                records = self._parse_technique(obj, source_version)

            elif obj_type == "intrusion-set":
                records = self._parse_group(obj, source_version)
            else:
                continue
            for record in records:
                record.source_hash = source_hash
                record.retrieved_at = retrieved_at
                record.feed_provider = "mitre_attack_stix"
                if obj_type == "intrusion-set":
                    record.technique_ids = sorted(group_techniques.get(obj.get("id"), set()))
                    # ATT&CK does not record a campaign chronology. This is a
                    # canonical tactic progression, explicitly labeled as inferred.
                    record.technique_sequence = sorted(record.technique_ids, key=lambda technique_id: (
                        min((_TACTIC_ORDER.index(tactic) for tactic in tactic_by_technique.get(technique_id, [])
                             if tactic in _TACTIC_ORDER), default=len(_TACTIC_ORDER)),
                        technique_id,
                    ))
                    record.sequence_basis = "attack_tactic_order" if record.technique_sequence else None
                yield record

    # ------------------------------------------------------------------
    # Internal parsers
    # ------------------------------------------------------------------

    def _parse_technique(
        self, obj: dict, source_version: str
    ) -> Iterator[ThreatIntelRecord]:
        """Parse a single ATT&CK attack-pattern STIX object."""
        ext_refs = obj.get("external_references", [])
        technique_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not technique_id:
            return

        name = obj.get("name", "")
        description = obj.get("description", "")
        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactics = [p["phase_name"] for p in kill_chain_phases if "phase_name" in p]

        # Build the embedding text: name + description (procedures are too long / noisy
        # for the embedding budget at 384-d; tactic tags provide structural signal).
        embed_text = f"{name}. {description}".strip()

        yield ThreatIntelRecord(
            record_id=technique_id,
            record_type="attack_technique",
            title=name,
            embed_text=embed_text,
            source="mitre_attack_stix",
            source_version=source_version,
            tags=tactics,
        )

    def _parse_group(
        self, obj: dict, source_version: str
    ) -> Iterator[ThreatIntelRecord]:
        """Parse a single ATT&CK intrusion-set STIX object."""
        ext_refs = obj.get("external_references", [])
        group_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not group_id:
            return

        name = obj.get("name", "")
        description = obj.get("description", "")
        aliases = obj.get("aliases", [])
        aliases_str = ", ".join(aliases) if aliases else ""

        embed_text = f"{name}. {description}. Aliases: {aliases_str}".strip(". ")

        yield ThreatIntelRecord(
            record_id=group_id,
            record_type="attack_group",
            title=name,
            embed_text=embed_text,
            source="mitre_attack_stix",
            source_version=source_version,
            tags=[],
        )

    def fetch_and_parse(self) -> Iterator[ThreatIntelRecord]:
        """Convenience: fetch bundle then parse. Yields ThreatIntelRecord objects."""
        bundle = self.fetch_bundle()
        yield from self.parse(bundle)


# ---------------------------------------------------------------------------
# NVD CVE fetcher
# ---------------------------------------------------------------------------


class NvdCveFetcher:
    """
    Fetches CVE records from the NVD REST API v2 with automatic pagination
    and polite rate-limiting.

    API key configuration
    ---------------------
    Without a key:  rate-limit is 5 requests per 30-second window.
    With a key:     rate-limit is 50 requests per 30-second window.

    To supply a key at runtime:
        fetcher = NvdCveFetcher(api_key=os.environ.get("NVD_API_KEY"))

    Or set the environment variable NVD_API_KEY and it will be picked up
    automatically:
        fetcher = NvdCveFetcher()   # reads NVD_API_KEY from env

    Reference: https://nvd.nist.gov/developers/vulnerabilities
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        cvss_severity: Optional[str] = None,
        timeout_secs: float = 30.0,
    ) -> None:
        """
        Args:
            api_key: NVD API key. If None, checks NVD_API_KEY env var.
                     Operates unauthenticated (rate-limited) if neither is set.
            pub_start_date: ISO-8601 date string for pubStartDate filter
                            (e.g. '2023-01-01T00:00:00.000').
            pub_end_date:   ISO-8601 date string for pubEndDate filter.
            cvss_severity:  Optional CVSS severity filter: 'LOW', 'MEDIUM',
                            'HIGH', 'CRITICAL'.
            timeout_secs:   Per-request HTTP timeout.
        """
        # Key resolution: explicit arg > env var > None (unauthenticated)
        self.api_key: Optional[str] = api_key or os.environ.get("NVD_API_KEY")
        self.pub_start_date = pub_start_date
        self.pub_end_date = pub_end_date
        self.cvss_severity = cvss_severity
        self.timeout = timeout_secs

        # Rate-limit tracking
        self._req_limit = (
            _NVD_REQ_LIMIT_WITH_KEY if self.api_key else _NVD_REQ_LIMIT_NO_KEY
        )
        self._req_count_in_window = 0
        self._window_start = time.monotonic()

        if self.api_key:
            logger.info("NVD fetcher: using API key (50 req/30 s).")
        else:
            logger.info(
                "NVD fetcher: no API key found — rate-limited to 5 req/30 s. "
                "Set NVD_API_KEY env var to increase throughput."
            )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def fetch_all(self) -> Iterator[ThreatIntelRecord]:
        """
        Paginate through the NVD CVE API and yield ThreatIntelRecord per CVE.
        Handles rate-limiting automatically with sleep-and-retry.
        """
        snapshot_date = time.strftime("%Y-%m-%d")
        start_index = 0
        total_results: Optional[int] = None

        while True:
            page = self._fetch_page(start_index)
            if total_results is None:
                total_results = page.get("totalResults", 0)
                logger.info(
                    "NVD CVE fetch: %d total results to retrieve.", total_results
                )

            vulnerabilities = page.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for vuln_wrapper in vulnerabilities:
                record = self._parse_cve(vuln_wrapper, snapshot_date)
                if record is not None:
                    yield record

            start_index += len(vulnerabilities)
            if start_index >= (total_results or 0):
                break

        logger.info("NVD CVE fetch complete. %d records processed.", start_index)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_params(self, start_index: int) -> dict:
        """Build query-string parameters for one NVD API page request."""
        params: dict = {
            "resultsPerPage": _NVD_PAGE_SIZE,
            "startIndex": start_index,
        }
        if self.pub_start_date:
            params["pubStartDate"] = self.pub_start_date
        if self.pub_end_date:
            params["pubEndDate"] = self.pub_end_date
        if self.cvss_severity:
            params["cvssV3Severity"] = self.cvss_severity
        return params

    def _build_headers(self) -> dict:
        """Build HTTP headers, including API key if available."""
        headers: dict = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _enforce_rate_limit(self) -> None:
        """
        Enforce NVD rate-limit policy: sleep until the current 30-second window
        resets if we've hit the per-window request cap.
        """
        now = time.monotonic()
        elapsed = now - self._window_start

        if elapsed >= _NVD_WINDOW_SECS:
            # New window — reset counter
            self._req_count_in_window = 0
            self._window_start = now
            return

        if self._req_count_in_window >= self._req_limit:
            sleep_secs = _NVD_WINDOW_SECS - elapsed + 1.0  # +1 s safety margin
            logger.debug(
                "NVD rate-limit reached (%d/%d). Sleeping %.1f s.",
                self._req_count_in_window,
                self._req_limit,
                sleep_secs,
            )
            time.sleep(sleep_secs)
            self._req_count_in_window = 0
            self._window_start = time.monotonic()

    def _fetch_page(self, start_index: int) -> dict:
        """Fetch one page from NVD API with rate-limit enforcement."""
        self._enforce_rate_limit()
        self._req_count_in_window += 1

        resp = requests.get(
            NVD_CVE_API_URL,
            params=self._build_params(start_index),
            headers=self._build_headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _parse_cve(
        vuln_wrapper: dict, snapshot_date: str
    ) -> Optional[ThreatIntelRecord]:
        """
        Parse a single NVD vulnerability wrapper dict into a ThreatIntelRecord.
        Returns None if the CVE lacks a usable description.
        """
        cve = vuln_wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Pick the first English description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )
        if not description:
            return None

        # CWE tags
        weaknesses = cve.get("weaknesses", [])
        cwe_tags: List[str] = []
        for weakness in weaknesses:
            for desc_item in weakness.get("description", []):
                cwe_val = desc_item.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwe_tags.append(cwe_val)

        # Affected products summary (CPE application names, de-duped, capped)
        configs = cve.get("configurations", [])
        products: List[str] = []
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    # cpe:2.3:a:<vendor>:<product>:...
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        product_name = f"{parts[3]} {parts[4]}"
                        if product_name not in products:
                            products.append(product_name)
                        if len(products) >= 5:
                            break
                if len(products) >= 5:
                    break

        products_str = ", ".join(products) if products else ""
        cwe_str = ", ".join(cwe_tags) if cwe_tags else ""
        embed_text = f"{cve_id}. {description}"
        if cwe_str:
            embed_text += f" Weaknesses: {cwe_str}."
        if products_str:
            embed_text += f" Affected: {products_str}."

        return ThreatIntelRecord(
            record_id=cve_id,
            record_type="cve",
            title=cve_id,
            embed_text=embed_text.strip(),
            source="nvd_cve",
            source_version=snapshot_date,
            tags=cwe_tags,
        )
