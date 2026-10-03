"""
Specula Cloud & Container Forensics Detection Rules Engine (F13b).

Implements 13 parameterized detection rules evaluating OCSF CloudAudit (6003)
and Container runtime activity events (ProcessActivity, NetworkActivity, FileActivity).
"""

from dataclasses import dataclass, field
import html
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from src.schemas.uid_generator import generate_deterministic_uid

BASE_SEVERITY_CONFIDENCE: Dict[str, Tuple[int, float]] = {
    "CRITICAL": (4, 0.90),
    "HIGH":     (3, 0.85),
    "MEDIUM":   (2, 0.75),
    "LOW":      (1, 0.65),
}


@dataclass(frozen=True)
class RuleContext:
    admin_principals: Set[str] = field(default_factory=set)
    registry_allowlist: Set[str] = field(default_factory=set)
    known_ip_baseline: Set[str] = field(default_factory=set)
    expected_egress_images: Set[str] = field(default_factory=set)
    exfil_threshold_count: int = 100
    exfil_window_seconds: int = 300
    rule_version: str = "1.0.0"
    attack_version: str = "v14.1"


@dataclass
class SpecialistFinding:
    finding_uid: str
    case_id: str
    rule_id: str
    rule_version: str
    attack_version: str
    mitre_technique_id: str
    finding_type: str        # "incident" | "posture"
    severity: str            # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: float
    title: str
    summary: str             # Truncated and quoted
    actors: List[str]
    scope: str
    resource_id: Optional[str]
    event_uids: List[str]
    count: int
    first_seen: str
    last_seen: str
    attempt_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_uid": self.finding_uid,
            "case_id": self.case_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "attack_version": self.attack_version,
            "mitre_technique_id": self.mitre_technique_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "summary": self.summary,
            "actors": self.actors,
            "scope": self.scope,
            "resource_id": self.resource_id,
            "event_uids": self.event_uids,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attempt_only": self.attempt_only,
        }


def calculate_confidence(base_severity: str, attempt_only: bool, baseline_matched: bool = True) -> float:
    _, base_conf = BASE_SEVERITY_CONFIDENCE.get(base_severity, (2, 0.75))
    if attempt_only:
        base_conf -= 0.30
    if not baseline_matched:
        base_conf -= 0.10
    return max(0.10, round(base_conf, 2))


def format_summary_field(text: str, max_len: int = 256) -> str:
    if not text:
        return '""'
    cleaned = str(text).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."
    escaped = html.escape(cleaned)
    return f'"{escaped}"'


def _is_failed_event(event: Dict[str, Any]) -> bool:
    if event.get("error_code") or event.get("errorCode") or event.get("status_code", 0) >= 400:
        return True
    if str(event.get("status", "")).lower() in ["failure", "failed", "denied"]:
        return True
    return False


def create_deterministic_finding_uid(
    case_id: str,
    rule_id: str,
    rule_version: str,
    scope: str,
    resource_id: Optional[str],
) -> str:
    return generate_deterministic_uid(
        "cloud_finding",
        {
            "case_id": case_id,
            "rule_id": rule_id,
            "rule_version": rule_version,
            "scope": scope,
            "resource_id": resource_id or "none",
        },
    )


def evaluate_cloud_rules(
    events: List[Dict[str, Any]],
    case_id: str,
    ctx: RuleContext,
) -> List[SpecialistFinding]:
    """Evaluate AWS CloudTrail CloudAudit events against CLOUD-001 through CLOUD-007."""
    findings: List[SpecialistFinding] = []
    
    # Event maps for single-pass aggregation
    rule_groups: Dict[Tuple[str, str, Optional[str]], List[Dict[str, Any]]] = {}

    # Sort events by time ascending, uid tiebreaker
    sorted_events = sorted(
        events,
        key=lambda e: (str(e.get("time") or e.get("eventTime") or ""), str(e.get("uid", ""))),
    )

    for event in sorted_events:
        svc = str(event.get("api_service") or event.get("eventSource") or "").lower()
        op = str(event.get("api_operation") or event.get("eventName") or "")
        actor = event.get("user_identity") or event.get("userIdentity", {}).get("arn") or "unknown_identity"
        scope = str(event.get("cloud_account_id") or event.get("recipientAccountId") or case_id)
        resource_id = event.get("resource_id") or event.get("requestParameters", {}).get("bucketName")

        # CLOUD-001: Defense Evasion
        cloudtrail_ops = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}
        config_ops = {"DeleteConfigRule"}
        sechub_ops = {"DisableSecurityHub"}
        guardduty_ops = {"DeleteDetector"}

        is_c1 = False
        mitre_c1 = "T1562.008"
        if "cloudtrail" in svc and op in cloudtrail_ops:
            is_c1 = True
            mitre_c1 = "T1562.008"
        elif "config" in svc and op in config_ops:
            is_c1 = True
            mitre_c1 = "T1562.001"
        elif "securityhub" in svc and op in sechub_ops:
            is_c1 = True
            mitre_c1 = "T1562.001"
        elif "guardduty" in svc and op in guardduty_ops:
            is_c1 = True
            mitre_c1 = "T1562.001"

        if is_c1:
            key = ("CLOUD-001", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

        # CLOUD-002: Credential Creation
        if "iam" in svc and op in {"CreateAccessKey", "CreateLoginProfile"}:
            key = ("CLOUD-002", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

        # CLOUD-003: Identity Trust Modification
        if "iam" in svc and op in {"CreateSAMLProvider", "CreateOIDCProvider"}:
            key = ("CLOUD-003", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

        # CLOUD-004: Privilege Escalation Policy Modification
        if "iam" in svc and op in {"AttachUserPolicy", "PutUserPolicy", "CreatePolicyVersion"}:
            # Check if targeting non-admin identity
            target = event.get("requestParameters", {}).get("userName") or actor
            if target not in ctx.admin_principals:
                key = ("CLOUD-004", scope, resource_id)
                rule_groups.setdefault(key, []).append(event)
                continue

        # CLOUD-005: Anomaly STS Role Assumption
        if "sts" in svc and op in {"AssumeRole", "AssumeRoleWithSAML"}:
            src_ip = event.get("source_ip") or event.get("sourceIPAddress") or ""
            is_anom_ip = bool(ctx.known_ip_baseline and src_ip not in ctx.known_ip_baseline)
            role_arn = event.get("requestParameters", {}).get("roleArn", "")
            is_cross_account = bool(role_arn and scope and scope not in role_arn)

            if is_anom_ip or is_cross_account:
                key = ("CLOUD-005", scope, resource_id)
                rule_groups.setdefault(key, []).append(event)
                continue

        # CLOUD-006: Public Storage Policy Exposure
        if "s3" in svc and op in {"PutBucketPolicy", "PutBucketAcl", "PutPublicAccessBlock"}:
            req_params = event.get("requestParameters") or {}
            policy_raw = req_params.get("policy")
            is_public_policy = False
            if policy_raw:
                policy_str = str(policy_raw).replace(" ", "")
                if '"Principal":"*"' in policy_str or '"AWS":"*"' in policy_str:
                    is_public_policy = True
            is_public_block_disable = False
            if op == "PutPublicAccessBlock":
                pab = req_params.get("PublicAccessBlockConfiguration") or {}
                if pab.get("BlockPublicAcls") is False or pab.get("RestrictPublicBuckets") is False:
                    is_public_block_disable = True

            if is_public_policy or is_public_block_disable:
                key = ("CLOUD-006", scope, resource_id)
                rule_groups.setdefault(key, []).append(event)
                continue

        # CLOUD-007: Bulk Storage Exfiltration
        if "s3" in svc and op == "GetObject":
            key = ("CLOUD-007", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

    # Process grouped rule events
    for (rule_id, scope, resource_id), ev_list in rule_groups.items():
        if rule_id == "CLOUD-007":
            # Windowed aggregation for CLOUD-007
            if len(ev_list) >= ctx.exfil_threshold_count:
                first_t = ev_list[0].get("time") or ev_list[0].get("eventTime") or ""
                last_t = ev_list[-1].get("time") or ev_list[-1].get("eventTime") or ""
                uids = [e.get("uid") for e in ev_list if e.get("uid")]
                actors = list({e.get("user_identity") or "unknown" for e in ev_list})
                any_attempt = any(_is_failed_event(e) for e in ev_list)
                conf = calculate_confidence("HIGH", attempt_only=any_attempt)
                summary_raw = f"Bulk GetObject exfiltration of {len(ev_list)} objects from bucket {resource_id or 'unknown'}"

                finding_uid = create_deterministic_finding_uid(case_id, rule_id, ctx.rule_version, scope, resource_id)
                findings.append(
                    SpecialistFinding(
                        finding_uid=finding_uid,
                        case_id=case_id,
                        rule_id=rule_id,
                        rule_version=ctx.rule_version,
                        attack_version=ctx.attack_version,
                        mitre_technique_id="T1530",
                        finding_type="incident",
                        severity="HIGH",
                        confidence=conf,
                        title="Bulk Storage Exfiltration Detected",
                        summary=format_summary_field(summary_raw),
                        actors=actors,
                        scope=scope,
                        resource_id=resource_id,
                        event_uids=uids,
                        count=len(ev_list),
                        first_seen=first_t,
                        last_seen=last_t,
                        attempt_only=any_attempt,
                    )
                )
            continue

        # Non-windowed cloud rules
        first_t = ev_list[0].get("time") or ev_list[0].get("eventTime") or ""
        last_t = ev_list[-1].get("time") or ev_list[-1].get("eventTime") or ""
        uids = [e.get("uid") for e in ev_list if e.get("uid")]
        actors = list({e.get("user_identity") or "unknown" for e in ev_list})
        any_attempt = any(_is_failed_event(e) for e in ev_list)

        title = "Cloud Security Anomaly Detected"
        summary_raw = f"Cloud audit rule {rule_id} triggered across {len(ev_list)} events"
        f_type = "incident"
        mitre_id = "T1562.008"
        base_sev = "HIGH"

        if rule_id == "CLOUD-001":
            title = "Cloud Defense Evasion Attempt"
            summary_raw = f"Audit trail or security service tampering detected: {ev_list[0].get('api_operation')}"
            base_sev = "CRITICAL"
            mitre_id = "T1562.008"
        elif rule_id == "CLOUD-002":
            title = "Unauthenticated IAM Credential Creation"
            summary_raw = f"New IAM access key or login profile created by {actors[0]}"
            base_sev = "HIGH"
            mitre_id = "T1098.001"
        elif rule_id == "CLOUD-003":
            title = "Identity Provider Trust Modification"
            summary_raw = f"External SAML/OIDC identity provider created"
            base_sev = "HIGH"
            mitre_id = "T1484.002"
        elif rule_id == "CLOUD-004":
            title = "Privilege Escalation Policy Modification"
            summary_raw = f"IAM policy attached to non-admin principal by {actors[0]}"
            base_sev = "HIGH"
            mitre_id = "T1098.003"
        elif rule_id == "CLOUD-005":
            title = "Anomaly STS Role Assumption"
            summary_raw = f"Role assumed from untrusted source IP or cross-account"
            base_sev = "LOW"
            mitre_id = "T1078.004"
        elif rule_id == "CLOUD-006":
            title = "Public Storage Policy Exposure"
            summary_raw = f"S3 bucket policy modified to allow public access on {resource_id}"
            base_sev = "MEDIUM"
            mitre_id = "T1530"
            f_type = "posture"

        conf = calculate_confidence(base_sev, attempt_only=any_attempt)
        finding_uid = create_deterministic_finding_uid(case_id, rule_id, ctx.rule_version, scope, resource_id)

        findings.append(
            SpecialistFinding(
                finding_uid=finding_uid,
                case_id=case_id,
                rule_id=rule_id,
                rule_version=ctx.rule_version,
                attack_version=ctx.attack_version,
                mitre_technique_id=mitre_id,
                finding_type=f_type,
                severity=base_sev,
                confidence=conf,
                title=title,
                summary=format_summary_field(summary_raw),
                actors=actors,
                scope=scope,
                resource_id=resource_id,
                event_uids=uids,
                count=len(ev_list),
                first_seen=first_t,
                last_seen=last_t,
                attempt_only=any_attempt,
            )
        )

    return findings


def evaluate_container_rules(
    events: List[Dict[str, Any]],
    case_id: str,
    ctx: RuleContext,
) -> List[SpecialistFinding]:
    """Evaluate Container runtime events (Process, Network, File) against CONTAINER-001 through CONTAINER-006."""
    findings: List[SpecialistFinding] = []
    rule_groups: Dict[Tuple[str, str, Optional[str]], List[Dict[str, Any]]] = {}

    sorted_events = sorted(
        events,
        key=lambda e: (str(e.get("time") or e.get("raw_source_timestamp") or ""), str(e.get("uid", ""))),
    )

    for event in sorted_events:
        container_meta = event.get("container") or {}
        namespace = container_meta.get("namespace") or "default"
        pod_name = container_meta.get("pod_name") or container_meta.get("container_id") or "unknown_pod"
        scope = f"{namespace}/{pod_name}"
        resource_id = container_meta.get("container_id")

        p_name = str(event.get("process_name") or "").lower()
        cmd = str(event.get("command_line") or "").lower()
        parent_p = str(event.get("parent_process_name") or "").lower()
        pid = int(event.get("process_pid", 1))
        file_path = str(event.get("file_path") or "").lower()
        dst_ip = str(event.get("dst_ip") or "")
        img_name = str(container_meta.get("image_name") or "").lower()

        # CONTAINER-005: Crypto-Mining Process
        mining_keywords = ["xmrig", "minerd", "cgminer", "stratum+tcp"]
        if any(k in p_name or k in cmd for k in mining_keywords):
            key = ("CONTAINER-005", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

        # CONTAINER-006: Privileged Container Escape Attempt
        escape_keywords = ["nsenter", "unshare --mount", "/dev/mem", "/dev/kmem"]
        if any(k in cmd or k in file_path for k in escape_keywords):
            key = ("CONTAINER-006", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

        # CONTAINER-001: Interactive Shell in Container
        if p_name in {"sh", "bash", "zsh", "dash"}:
            is_runtime_parent = parent_p in {"runc", "containerd-shim", "docker-containerd-shim", "crio"}
            if is_runtime_parent or pid != 1:
                key = ("CONTAINER-001", scope, resource_id)
                rule_groups.setdefault(key, []).append(event)
                continue

        # CONTAINER-002: Volatile Binary Execution
        volatile_paths = ["/tmp/", "/var/tmp/", "/dev/shm/"]
        if any(p in cmd or p in file_path for p in volatile_paths):
            key = ("CONTAINER-002", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

        # CONTAINER-003: Suspicious Container Egress
        if dst_ip and not dst_ip.startswith(("10.", "172.16.", "192.168.", "127.")):
            if img_name not in ctx.expected_egress_images:
                key = ("CONTAINER-003", scope, resource_id)
                rule_groups.setdefault(key, []).append(event)
                continue

        # CONTAINER-004: Container Credential Access
        cred_paths = ["/var/run/secrets/kubernetes.io", "/root/.aws", "/etc/shadow"]
        if any(cp in file_path or cp in cmd for cp in cred_paths):
            key = ("CONTAINER-004", scope, resource_id)
            rule_groups.setdefault(key, []).append(event)
            continue

    for (rule_id, scope, resource_id), ev_list in rule_groups.items():
        first_t = ev_list[0].get("time") or ev_list[0].get("raw_source_timestamp") or ""
        last_t = ev_list[-1].get("time") or ev_list[-1].get("raw_source_timestamp") or ""
        uids = [e.get("uid") for e in ev_list if e.get("uid")]
        actors = list({e.get("container", {}).get("pod_name") or "container_workload" for e in ev_list})
        any_attempt = any(_is_failed_event(e) for e in ev_list)

        title = "Container Security Anomaly Detected"
        summary_raw = f"Container rule {rule_id} triggered on {scope}"
        mitre_id = "T1059"
        base_sev = "MEDIUM"

        if rule_id == "CONTAINER-001":
            title = "Interactive Shell Execution in Container"
            summary_raw = f"Interactive shell spawned in container pod {scope}"
            base_sev = "MEDIUM"
            mitre_id = "T1059.004"
        elif rule_id == "CONTAINER-002":
            title = "Volatile Binary Execution in Container"
            summary_raw = f"Binary execution from volatile path in pod {scope}"
            base_sev = "MEDIUM"
            mitre_id = "T1059"
        elif rule_id == "CONTAINER-003":
            title = "Suspicious Container Outbound Egress"
            summary_raw = f"Container pod {scope} initiated outbound connection to external IP"
            base_sev = "LOW"
            mitre_id = "T1071.001"
        elif rule_id == "CONTAINER-004":
            title = "Container Credential / Secret Access"
            summary_raw = f"Sensitive secret file access in pod {scope}"
            base_sev = "HIGH"
            fp = str(ev_list[0].get("file_path") or "")
            if "kubernetes.io" in fp:
                mitre_id = "T1552.007"
            elif ".aws" in fp:
                mitre_id = "T1552.001"
            else:
                mitre_id = "T1003.008"
        elif rule_id == "CONTAINER-005":
            title = "Crypto-Mining Process Executed"
            summary_raw = f"Crypto-mining process identified in pod {scope}"
            base_sev = "HIGH"
            mitre_id = "T1496"
        elif rule_id == "CONTAINER-006":
            title = "Privileged Container Escape Attempt"
            summary_raw = f"Container escape technique executed in pod {scope}"
            base_sev = "CRITICAL"
            mitre_id = "T1611"

        conf = calculate_confidence(base_sev, attempt_only=any_attempt)
        finding_uid = create_deterministic_finding_uid(case_id, rule_id, ctx.rule_version, scope, resource_id)

        findings.append(
            SpecialistFinding(
                finding_uid=finding_uid,
                case_id=case_id,
                rule_id=rule_id,
                rule_version=ctx.rule_version,
                attack_version=ctx.attack_version,
                mitre_technique_id=mitre_id,
                finding_type="incident",
                severity=base_sev,
                confidence=conf,
                title=title,
                summary=format_summary_field(summary_raw),
                actors=actors,
                scope=scope,
                resource_id=resource_id,
                event_uids=uids,
                count=len(ev_list),
                first_seen=first_t,
                last_seen=last_t,
                attempt_only=any_attempt,
            )
        )

    return findings
