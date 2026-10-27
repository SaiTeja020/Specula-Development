"""Explicit aliases for exported JSON logs; original evidence is preserved separately."""
from copy import deepcopy
from datetime import datetime
from pathlib import PureWindowsPath


def _alias(record, target, *names):
    if record.get(target) not in (None, ""):
        return
    for name in names:
        if record.get(name) not in (None, ""):
            record[target] = record[name]
            return


def record_timestamp(record, source):
    system = record.get("System") or {}
    if not isinstance(system, dict):
        raise ValueError("System must be a JSON object")
    nested = system.get("TimeCreated") or {}
    if isinstance(nested, dict):
        nested = nested.get("SystemTime")
    names = ("TimeCreated", "timestamp", "event_time", "eventTime", "time", "capture_time",
             "detonation_time", "scan_time", "LastRecordChange", "eventTimestamp", "TimeGenerated")
    stamp = next((record[name] for name in names if record.get(name)), nested)
    if source == "evtx" and nested:
        stamp = nested
    if source == "mft" and record.get("LastRecordChange"):
        stamp = record["LastRecordChange"]
    if source=='kubernetes_audit':stamp=record.get('stageTimestamp') or record.get('requestReceivedTimestamp') or stamp
    if source == "gcp_audit" and not stamp and isinstance(record.get("protoPayload"), dict):
        stamp = record["protoPayload"].get("timestamp")
    if not stamp and source == "mft":
        stamp = record.get("standard_information_modified")
    if not isinstance(stamp, str) or not stamp.strip():
        raise ValueError("Missing event timestamp; supply timestamp (ISO 8601 with UTC offset)")
    if not stamp.startswith("/Date("):
        try:
            moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("Invalid timestamp; use ISO 8601 with UTC offset") from None
        if moment.tzinfo is None:
            raise ValueError("Timestamp must include a UTC offset")
    return stamp


def adapt_export(record, source, filename=""):
    if source=='ad_auth':
        return adapt_export(record,'evtx',filename or 'Security.json')
    result = deepcopy(record)
    stamp = record_timestamp(result, source)
    for target in ("timestamp", "TimeCreated", "eventTime", "LastRecordChange"):
        if result.get(target) in (None, ""):
            result[target] = stamp
    _alias(result, "host_name", "host", "hostname", "MachineName")
    if not result.get("host_name") and isinstance(result.get("System"), dict):
        result["host_name"] = result["System"].get("Computer")
    _alias(result, "user_name", "user", "username")
    _alias(result, "process_name", "process", "image")
    _alias(result, "process_pid", "pid")
    _alias(result, "parent_process_name", "parent_process", "parent_image")
    _alias(result, "file_path", "path")
    _alias(result, "file_hash_sha256", "sha256")
    _alias(result, "src_ip", "source_ip")
    _alias(result, "dst_ip", "destination_ip")
    _alias(result, "dst_port", "destination_port")
    _alias(result, "src_port", "source_port")
    _alias(result, "bytes_in", "bytes_received")
    _alias(result, "bytes_out", "bytes_sent")
    if "severity_id" not in result and isinstance(result.get("severity"), str):
        severities = {"unknown": 0, "info": 1, "informational": 1, "low": 2,
                      "medium": 3, "high": 4, "critical": 5, "fatal": 6}
        severity = result["severity"].lower()
        if severity not in severities:
            raise ValueError("Unknown severity; use info, low, medium, high, critical or severity_id")
        result["severity_id"] = severities[severity]

    if source == "evtx":
        system = result.get("System") or {}
        if isinstance(system.get("TimeCreated"), str):
            system["TimeCreated"] = {"SystemTime": system["TimeCreated"]}
        if isinstance(system.get("Provider"), str):
            system["Provider"] = {"Name": system["Provider"]}
        if system.get("Provider") is not None and not isinstance(system["Provider"], dict):
            raise ValueError("System.Provider must be an object or provider-name string")
        result["System"] = system
        _alias(result, "Id", "event_id", "EventID")
        _alias(result, "MachineName", "host_name")
        _alias(result, "Message", "message")
        if not result.get("ProviderName") and not (result.get("System") or {}).get("Provider"):
            hint = str(result.get("channel") or filename).lower()
            if "sysmon" in hint:
                result["ProviderName"] = "Microsoft-Windows-Sysmon"
            elif "security" in hint:
                result["ProviderName"] = "Microsoft-Windows-Security-Auditing"
        data = result.setdefault("EventData", {})
        if not isinstance(data, dict):
            raise ValueError("EventData must be a JSON object")
        fields = {"Image": "image", "ParentImage": "parent_image", "CommandLine": "command_line",
                  "ProcessId": "pid", "ParentProcessId": "parent_pid", "TargetUserName": "user",
                  "IpAddress": "source_ip", "LogonType": "logon_type", "Status": "status",
                  "DestinationIp": "destination_ip", "DestinationPort": "destination_port",
                  "SourceIp": "source_ip", "SourcePort": "source_port", "Protocol": "protocol",
                  "TargetFilename": "path"}
        for target, alias in fields.items():
            if target not in data and alias in result:
                data[target] = result[alias]
        if "TargetFilename" not in data and "target_filename" in result:
            data["TargetFilename"] = result["target_filename"]
        if not result.get("Id") and not (result.get("System") or {}).get("EventID"):
            raise ValueError("Missing Windows event identifier; supply event_id or Id")
    elif source == "gcp_audit":
        resource = result.get("resource", {})
        if isinstance(resource, str):
            result["resource_name"] = resource
            resource = {}
            result["resource"] = resource
        if not isinstance(resource, dict):
            raise ValueError("resource must be an object or resource-name string")
        labels = resource.setdefault("labels", {})
        proto = result.setdefault("protoPayload", {})
        if not isinstance(labels, dict) or not isinstance(proto, dict):
            raise ValueError("resource.labels and protoPayload must be JSON objects")
        for target, alias in (("methodName", "method"), ("resourceName", "resource_name")):
            if target not in proto and alias in result:
                proto[target] = result[alias]
        for block, target, alias in (("authenticationInfo", "principalEmail", "principal_email"),
                                     ("requestMetadata", "callerIp", "caller_ip")):
            nested = proto.setdefault(block, {})
            if not isinstance(nested, dict):
                raise ValueError(f"protoPayload.{block} must be a JSON object")
            if target not in nested and alias in result:
                nested[target] = result[alias]
        if "project_id" not in labels and "project_id" in result:
            labels["project_id"] = result["project_id"]
    elif source == "mft":
        path = PureWindowsPath(str(result.get("path") or result.get("file_path") or ""))
        if path.name:
            result.setdefault("FileName", path.name)
            result.setdefault("ParentPath", str(path.parent))
        _alias(result, "Created0x10", "standard_information_created")
        _alias(result, "Created0x30", "filename_created")
    elif source == "edr":
        kind = str(result.get("event_type", "")).lower()
        result["event_type"] = {"process_start": "process_create", "file_create": "file_write"}.get(kind, kind)
        if kind == "credential_access":
            result["event_type"] = "detection"
            result.setdefault("alert_title", result.get("detection") or "Source-reported credential access")
            result.setdefault("details", deepcopy(record))
            result.setdefault("confidence", "Unspecified")
        _alias(result, "alert_title", "detection")
    elif source == "memory":
        _alias(result, "PID", "pid")
        _alias(result, "ImageFileName", "process")
    elif source == "ueba" and "artifact_type" not in result and "event_type" not in result:
        if "event" not in result:
            raise ValueError("UEBA requires artifact_type, event_type or event")
        result["artifact_type"] = "ueba_observation"
        result["anomaly_name"] = "Source-reported UEBA activity: " + str(result["event"])
        result.setdefault("verdict", str(result.get("baseline_status") or "Unspecified"))
        result.setdefault("severity_id", 1)
        result.setdefault("confidence", "Unspecified")
    elif source == "vuln_scan":
        _alias(result, "cvss_score", "cvss", "cve_score")
    elif source == "malware":
        _alias(result, "verdict", "classification")
        result.setdefault("verdict", "Unspecified")
        result.setdefault("confidence", "Unspecified")
    return result
