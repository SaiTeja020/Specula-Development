"""Case evidence observations and validated model review; no free-text facts."""
import json
import base64
import re
import time
from datetime import datetime, timezone

from .config import get_llm


def decode_record(record):
    result = dict(record)
    for key in ("details", "unmapped", "user", "src_endpoint", "dst_endpoint", "traffic", "dns"):
        if isinstance(result.get(key), str):
            try:
                result[key] = json.loads(result[key])
            except ValueError:
                pass
    return result


def records(state):
    return [decode_record(row) for row in (state.get("evidence_collection") or {}).get("records", [])]


def current_findings(state):
    findings=state.get('findings',[])
    start=max((i for i,f in enumerate(findings) if f.get('agent_role')=='supervisor'),default=0)
    return findings[start:]


def current_traces(state):
    traces=state.get('agent_traces',[])
    start=max((i for i,t in enumerate(traces) if t.get('agent_role')=='supervisor'),default=0)
    return traces[start:]


def observation(event):
    endpoint = event.get("dst_endpoint") or {}
    endpoint = endpoint if isinstance(endpoint, dict) else {}
    user = event.get("user") or {}
    user = user if isinstance(user, dict) else {}
    parts = [event.get("process_name"), event.get("command_line"), event.get("file_path"),
             event.get("finding_title") or event.get("finding_info"), event.get("api_operation")]
    identity = user.get("name") or event.get("user_name") or event.get("source_user_name")
    if identity:
        parts.append("user=" + str(identity))
    destination = endpoint.get("ip_address") or event.get("dst_ip")
    if destination:
        parts.append(f"destination={destination}:{endpoint.get('port') or event.get('dst_port') or '?'}")
    if event.get("bytes_out"):
        parts.append(f"bytes_out={event['bytes_out']}")
    raw = context(event)
    if raw:
        fields = {key: raw[key] for key in ("event_id", "status", "operation_result", "result_status", "change_ticket",
                  "restore_job_id", "job_id", "finding", "baseline_status", "ntp_offset_seconds", "clock_state") if key in raw}
        if event.get("api_operation"):
            fields["operation_outcome"] = outcome(raw)
        if fields:
            parts.append("source context=" + json.dumps(fields, sort_keys=True))
    return "; ".join(str(part) for part in parts if part) or f"Recorded OCSF class {event.get('class_uid')}"


def context(event):
    unmapped = event.get("unmapped") or {}
    raw = unmapped.get("source_context") if isinstance(unmapped, dict) else None
    raw = raw if isinstance(raw, dict) else event.get("details") or {}
    if not isinstance(raw, dict):
        raw = {}
    nested = raw.get("details") or {}
    return {**(nested if isinstance(nested, dict) else {}), **raw}


def instant(value):
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return moment.astimezone(timezone.utc) if moment.tzinfo else None
    except ValueError:
        return None


def outcome(raw):
    proto = raw.get("protoPayload") or {}
    status = proto.get("status") or {} if isinstance(proto, dict) else {}
    if isinstance(status, dict) and "code" in status:
        return "confirmed" if status["code"] == 0 else "failed"
    value = str(raw.get("operation_result") or raw.get("outcome") or raw.get("result") or raw.get("status") or "").lower()
    if raw.get("exit_code") not in (None, 0) or value in {"access_denied", "access is denied", "failure", "failed", "connection_refused", "prevented", "blocked"}:
        return "failed"
    if raw.get("exit_code") == 0 or value in {"success", "successful", "established", "approved"}:
        return "confirmed"
    return "unknown"


def detections(state, role):
    events = records(state)
    result = []
    def related(event, predicate, seconds=120):
        host, moment = event.get("canonical_host_id"), instant(event.get("time"))
        return [row for row in events if host and row.get("canonical_host_id") == host
                and moment and instant(row.get("time")) and abs((instant(row["time"])-moment).total_seconds()) <= seconds
                and predicate(row, context(row))]
    def add(event, code, summary, technique=None, refs=None, classification="suspicious", operation_outcome="unknown"):
        result.append({"agent_role": role, "finding_type": code, "pattern": code,
                       "case_id": state.get("case_id"), "trace_id": state.get("trace_id"),
                       "summary": summary, "dfkg_refs": refs or [event["uid"]],
                       "event_time": event.get("time"), "timestamp": event.get("time"),
                       "canonical_host_id": event.get("canonical_host_id"),
                       "classification": classification, "operation_outcome": operation_outcome,
                       "severity_id": 1 if classification in {"benign", "negative", "failed", "context"} else 3,
                       "attacks": [technique] if technique and classification == "suspicious" else [], "source": "validated_case_rule"})
    for event in events:
        cmd = str(event.get("command_line") or "")
        raw = context(event)
        source = event.get("source_type")
        if role == "log_analysis":
            if re.search(r"powershell.*-(?:encodedcommand|enc)\b", cmd, re.I):
                approved = related(event, lambda row, data: data.get("change_ticket") and data.get("result") == "approved")
                decoded = ""
                match = re.search(r"-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]+)", cmd, re.I)
                if match:
                    try:
                        decoded = base64.b64decode(match[1], validate=True).decode("utf-16le")[:500]
                    except (ValueError, UnicodeError):
                        pass
                benign = bool(approved) and bool(re.fullmatch(r"Write-Output\s+['\"][^'\"]*['\"]", decoded.strip(), re.I))
                add(event, "encoded_powershell", "Encoded PowerShell observed. Decoded content (data only): " + (decoded or "unavailable") +
                    ("; source-reported approved deployment is corroborating counter-evidence." if benign else "; execution context and intent require review."),
                    "T1059.001", [event["uid"]]+[r["uid"] for r in approved], "benign" if benign else "suspicious")
            if re.search(r"wevtutil\s+(?:cl|clear-log)\s+Security\b", cmd, re.I):
                cleared = related(event, lambda row, data: row.get("source_event_id") == 1102)
                denied = related(event, lambda row, data: outcome(data) == "failed" and "clear" in str(row.get("finding_title", "")).lower())
                code = "security_log_cleared" if cleared else "security_log_clear_failed" if denied else "security_log_clear_attempt"
                text = "Security log clearing corroborated by event 1102; authorization and intent remain unresolved." if cleared else "Security-log clear attempt failed: source reports access denied." if denied else "Command attempts Security-log clearing; outcome unknown."
                add(event, code, text, "T1070.001", [event["uid"]]+[r["uid"] for r in cleared+denied],
                    "failed" if denied and not cleared else "suspicious", "confirmed" if cleared else "failed" if denied else "unknown")
            if event.get("source_event_id") == 1102 and not related(event, lambda row, data: bool(re.search(r"wevtutil.*Security", str(row.get("command_line", "")), re.I))):
                add(event, "security_log_cleared", "Security log clearing recorded by event 1102; authorization and intent unknown.", "T1070.001", operation_outcome="confirmed")
            si, fn = instant(event.get("si_created")), instant(event.get("fn_created"))
            if si and fn and abs((si-fn).total_seconds()) > 86400:
                restores = related(event, lambda row, data: raw.get("restore_job_id") and data.get("restore_job_id") == raw["restore_job_id"] and outcome(data) == "confirmed")
                add(event, "timestamp_inconsistency", f"SI={si.isoformat()} disagrees with FN={fn.isoformat()}. " +
                    ("Matching source-reported restore job explains preserved timestamps; not confirmed timestomping." if restores else "Possible metadata manipulation; copying/restoration must be ruled out."),
                    "T1070.006", [event["uid"]]+[r["uid"] for r in restores], "benign" if restores else "suspicious")
            proc = str(event.get("process_name") or "")
            if "\\programdata\\" in proc.lower() and proc.lower().endswith(".exe"):
                add(event, "unusual_executable_location", f"Executable launched from ProgramData: {proc}; location alone does not establish malware.")
            if source == "edr" and event.get("class_uid") == 2004 and raw.get("event_type") != "credential_access":
                title = str(event.get("finding_title") or raw.get("detection") or "Source observation")
                state_outcome = outcome(raw)
                classification = "failed" if state_outcome == "failed" or raw.get("action") == "prevented" else "benign" if raw.get("change_ticket") or raw.get("mfa_result") == "success" else "context"
                details = {k:raw[k] for k in ("result", "exit_code", "action", "process_created", "change_ticket", "restore_job_id", "job_id", "ticket", "mfa_result", "ntp_offset_seconds", "clock_state", "destination_ip") if k in raw}
                add(event, "source_operation_context", title+"; source context="+json.dumps(details, sort_keys=True), classification=classification, operation_outcome=state_outcome)
            if source == "edr" and event.get("class_uid") == 4001 and outcome(raw) == "failed":
                add(event, "network_connection_failed", "Source reports refused/failed connection to " + str(raw.get("destination_ip")) + ":" + str(raw.get("destination_port")), classification="failed", operation_outcome="failed")
            if source == "vuln_scan":
                status = str(raw.get("status", "unknown"))
                add(event, "source_vulnerability_context", str(raw.get("cve")) + "; source scan status="+status+"; scanner="+str(raw.get("scanner"))+". Exposure does not prove exploitation; scores are not attack-path probabilities.",
                    classification="benign" if status in {"mitigated", "not_vulnerable"} else "unresolved")
        elif role == "memory_forensics" and (raw.get("plugin") or source == "memory"):
            examination = (event.get('unmapped') or {}).get('examination')
            if examination:
                add(event,'independent_memory_examination', 'Offline memory examination: '+json.dumps({
                    k:examination.get(k) for k in ('analysis_origin','plugin','status','coverage','reason','tool_version','sha256','bytes_examined','entropy','pe_features','regions','modules','thread_count')},sort_keys=True),
                    classification='context' if examination.get('status')=='complete' else 'unresolved')
                continue
            finding = str(raw.get("finding") or event.get("source_finding") or event.get("finding_title"))
            classification = "negative" if raw.get("result_status") == "negative" else "benign" if "JIT" in finding else "unresolved"
            add(event, "source_memory_finding", "Source-reported memory observation: " + finding + "; coverage="+str(raw.get("coverage", "unknown")),
                classification=classification)
        elif role == "identity" and (raw.get("event_type") == "credential_access" or event.get("source_event_type") == "credential_access"):
            failed = outcome(raw) == "failed"
            benign = bool(raw.get("change_ticket")) and raw.get("operation") == "QueryInformation"
            add(event, "source_credential_access", "Source reports " + str(raw.get("operation")) + " on " + str(raw.get("target_process") or "credential-related process") +
                ("; operation denied, extraction not established." if failed else "; source-reported authorized diagnostic context." if benign else "; completed extraction not established."),
                classification="failed" if failed else "benign" if benign else "suspicious", operation_outcome=outcome(raw))
        elif role == "cloud_container" and source == "gcp_audit":
            operation = str(event.get("api_operation"))
            status = outcome(raw)
            if "CreateServiceAccountKey" in operation:
                add(event, "service_account_key_failed" if status == "failed" else "service_account_key_creation", "Service-account key request " + status + " for " + str(event.get("user_identity")) + "; authorization and intent require review.",
                    classification="failed" if status == "failed" else "suspicious", operation_outcome=status)
            else:
                add(event, "source_cloud_operation", operation+"; outcome="+status+"; principal="+str(event.get("user_identity"))+"; resource="+str(raw.get("resource")), classification="context", operation_outcome=status)
        elif role == 'cloud_container' and source=='container':
            add(event,'container_operation', 'Recorded container operation: '+json.dumps({k:raw.get(k) for k in
                ('container_id','image_name','namespace','pod_name','command_line','privileged','result','change_ticket')},sort_keys=True)+
                '; source-declared privileges do not prove container escape.',
                classification='unresolved' if raw.get('privileged') else 'context', operation_outcome=outcome(raw))
        elif role == "malware_stylometry":
            features = (event.get('unmapped') or {}).get('examination') or {}
            if features.get('analysis_origin') == 'independent_static_examination':
                add(event, 'independent_pe_features', 'Independent static examination: '+json.dumps({
                    k:features.get(k) for k in ('sha256','machine','instruction_count','sections','imports','tools','status','coverage')},sort_keys=True),
                    classification='context')
                continue
            if event.get("source_finding") and "unsigned" in str(event["source_finding"]).lower():
                add(event, "source_unsigned_executable", "Source reports unsigned executable: " + str(event["source_finding"]) + "; no malware-family attribution.")
            elif source == "malware":
                verdict = str(raw.get("verdict") or raw.get("classification") or "unknown")
                add(event, "source_specimen_assessment", "Source specimen="+str(raw.get("sample_name"))+"; sha256="+str(raw.get("sha256"))+"; verdict="+verdict+"; confidence="+str(raw.get("confidence"))+". Imported analysis is not an independent binary examination.", classification="benign" if verdict == "benign" else "unresolved")
        elif role == "insider_threat" and (event.get("source_baseline_status") or raw.get("baseline_status")) == "anomalous":
            add(event, "source_behavior_anomaly", "Source behavioral anomaly: " + str(raw.get("event") or event.get("source_event_type")) + "; insider identity/intent not established.")
    if role == "identity":
        for event in events:
            raw=context(event);data=raw.get('EventData') or {}
            eid=event.get('source_event_id') or raw.get('event_id') or raw.get('Id')
            if eid in {4672,4768,4769,4776}:
                add(event,'identity_audit_context',f"Identity audit event {eid}; protocol={event.get('auth_protocol')}; "
                    f"encryption={data.get('TicketEncryptionType') or raw.get('ticket_encryption_type')}; "
                    'special privileges or legacy encryption are review context, not proof of credential theft.',classification='context')
        failed = {}
        for event in sorted(events, key=lambda row: instant(row.get("time")) or datetime.max.replace(tzinfo=timezone.utc)):
            if event.get("class_uid") != 3002:
                continue
            src = (event.get("src_endpoint") or {}).get("ip_address")
            key = (event.get("canonical_host_id"), (event.get("user") or {}).get("name"), src)
            if not all(key):
                continue
            if event.get("source_event_id") == 4625:
                failed.setdefault(key, []).append(event)
            if event.get("source_event_id") == 4624 and failed.get(key):
                prior = [row for row in failed[key] if instant(row.get("time")) and instant(event.get("time")) and 0 <= (instant(event["time"])-instant(row["time"])).total_seconds() <= 900]
                if prior:
                    reset_ticket = context(event).get("password_reset_ticket")
                    resets = related(event, lambda row, data: reset_ticket and data.get("ticket") == reset_ticket and data.get("mfa_result") == "success")
                    add(event, "failed_logons_followed_by_success", f"{len(prior)} failed logons followed by successful logon for {key[1]} from {src}. " + ("Matching reset/MFA records are source-reported authorization counter-evidence." if resets else "Possible credential compromise; count alone does not prove brute force."),
                        "T1078", [row["uid"] for row in prior]+[event["uid"]]+[r["uid"] for r in resets], "benign" if resets else "suspicious")
    return result


def review(role, state, facts):
    from .evidence_review import review as run_review
    return run_review(role, state, facts, get_llm(role, case_id=state.get("case_id", "unknown")))


def specialist(role, category, state):
    facts = detections(state, role)
    from .evidence_correlations import correlate
    facts += [f for f in correlate(state)['findings'] if f['agent_role']==role]
    if role == 'insider_threat':
        from .behavior_analysis import behavioral_observations
        facts += behavioral_observations(state)
    if role == 'malware_stylometry':
        from .forensic_tools import opcode_similarity
        samples = [e for e in records(state) if (e.get('unmapped') or {}).get('examination',{}).get('analysis_origin')=='independent_static_examination']
        for i,a in enumerate(samples):
            for b in samples[i+1:]:
                score = opcode_similarity(a['unmapped']['examination'],b['unmapped']['examination'])
                if score is not None:
                    facts.append({'agent_role':role,'finding_type':'measured_opcode_similarity','summary':f"Sample opcode-frequency cosine similarity={score:.4f}; shared instruction distributions do not establish malware family or authorship.",
                        'dfkg_refs':[a['uid'],b['uid']],'event_time':b.get('time'),'classification':'context','canonical_host_id':None,
                        'source':'validated_case_rule','operation_outcome':'unknown','attacks':[]})
    from .investigative_review import investigate
    trace = investigate(role,state,facts,get_llm(role,case_id=state.get('case_id','unknown')))
    if role in {'memory_forensics','malware_stylometry'}:
        examined = [(e.get('unmapped') or {}).get('examination') for e in records(state)
                    if e.get('source_type') == ('memory' if role=='memory_forensics' else 'malware')]
        trace['examination_coverage']={'native_examinations':sum(bool(e) for e in examined),
                                     'imported_records':sum(not e for e in examined),
                                     'unavailable':sum(bool(e) and e.get('status')!='complete' for e in examined)}
    from .kafka_utils import ROLE_TOPIC_MAP, publish_finding
    for fact in facts:
        if ROLE_TOPIC_MAP.get(role):
            publish_finding(ROLE_TOPIC_MAP[role], fact, state.get("trace_id"))
    return {"findings": facts, "agent_traces": [trace], "specialists_completed": [category]}


def timeline(state):
    from .timeline_reconstruction import reconstruct
    reconstruction=reconstruct(state)
    events=reconstruction['events']
    for event in events:
        event["attacks"] = sorted({technique for finding in current_findings(state)
                                  if finding.get("source") == "validated_case_rule" and event["uid"] in finding.get("dfkg_refs", [])
                                  for technique in finding.get("attacks", [])})
    facts=[{'summary':e['summary'],'canonical_host_id':e['hosts'][0] if len(e['hosts'])==1 else None,
            'dfkg_refs':e['dfkg_refs']} for e in reconstruction['episodes']]
    facts+=[{'summary':'Clock uncertainty for '+host+': '+json.dumps(samples,sort_keys=True)+'. Raw times remain unchanged.',
             'canonical_host_id':host,'dfkg_refs':[s['evidence_uid'] for s in samples]} for host,samples in reconstruction['clock_observations'].items()]
    if not facts:
        facts=[{'summary':f'{len(events)} preserved events; no source-key episode or clock model is supported. Raw chronology is retained.',
                'canonical_host_id':None,'dfkg_refs':[e['uid'] for e in events]}] if events else []
    trace = review("timeline_reconstruction", state, facts)
    trace['review_unit']='correlated_episode_or_clock_observation'
    trace['preserved_event_count']=len(events)
    reconstruction['summary']=f"{len(events)} cited events; {len(reconstruction['episodes'])} source-correlated episodes and {len(reconstruction['relations'])} explicit relationships. Raw times preserved; metadata/capture times and clock models are labelled."
    trace['reconstruction']={'episodes':len(reconstruction['episodes']),'relationships':len(reconstruction['relations']),
                             'clock_hosts':len(reconstruction['clock_observations'])}
    return {"case_status": "synthesis", "timeline": reconstruction, "agent_traces": [trace]}


def activity_graph(state):
    allowed = {row["uid"] for row in records(state)}
    facts = [fact for fact in current_findings(state) if fact.get("source") == "validated_case_rule" and fact.get("dfkg_refs") and set(fact["dfkg_refs"]) <= allowed]
    facts = deduplicate(state, facts)
    facts.sort(key=lambda fact: (instant(fact.get("event_time")) or datetime.max.replace(tzinfo=timezone.utc), fact["finding_type"]))
    nodes, edges, last = [], [], {}
    for index, fact in enumerate(facts):
        uid = f"observation-{index}"
        nodes.append({"id": uid, "label": fact["finding_type"], "summary": fact["summary"], "time": fact.get("event_time"), "dfkg_refs": fact["dfkg_refs"],
                      "canonical_host_id": fact.get("canonical_host_id"), "classification": fact.get("classification", "unresolved"),
                      "operation_outcome": fact.get("operation_outcome", "unknown")})
        host = fact.get("canonical_host_id")
        if host and host in last and instant(nodes[int(last[host].split('-')[-1])]["time"]) and instant(fact.get("event_time")) and instant(nodes[int(last[host].split('-')[-1])]["time"]) < instant(fact.get("event_time")):
            edges.append({"id": f"edge-{index}", "source": last[host], "target": uid, "type": "PRECEDES",
                          "dfkg_refs": sorted(set(nodes[int(last[host].split('-')[-1])]["dfkg_refs"] + fact["dfkg_refs"]))})
        if host:
            last[host] = uid
    trace = review("dag", state, facts)
    from .relational_graph import enrich
    graph=enrich(state,nodes,edges)
    trace['graph_construction']={'observations':len(nodes),'source_relations':graph['relation_count'],
                                 'candidate_paths':len(graph['activity_paths'])}
    return {"attack_graph":graph,'agent_traces':[trace]}


def deduplicate(state, facts):
    """Coalesce equivalent observations, retaining every supporting citation."""
    byuid = {row["uid"]: row for row in records(state)}
    groups = {}
    for original in facts:
        fact = dict(original)
        hosts = {byuid[uid].get("canonical_host_id") for uid in fact.get("dfkg_refs", []) if uid in byuid}
        if not fact.get("canonical_host_id") and len(hosts) == 1:
            fact["canonical_host_id"] = hosts.pop()
        moment = instant(fact.get("event_time"))
        key = (fact.get("finding_type"), fact.get("canonical_host_id"), moment,
               fact.get("classification"), fact.get("operation_outcome"), fact.get("summary"))
        if key not in groups:
            groups[key] = fact
        else:
            groups[key]["dfkg_refs"] = sorted(set(groups[key]["dfkg_refs"]) | set(fact["dfkg_refs"]))
    return list(groups.values())


def debate_facts(state):
    allowed = {row["uid"] for row in records(state)}
    return deduplicate(state, [f for f in current_findings(state) if f.get("source") == "validated_case_rule"
                       and f.get("dfkg_refs") and set(f["dfkg_refs"]) <= allowed])
