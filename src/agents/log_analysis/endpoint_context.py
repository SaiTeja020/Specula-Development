"""Cited persistence lifecycles and script-block data reconstruction, never execution."""
from collections import defaultdict
from hashlib import sha256
import json
import re
from xml.etree import ElementTree

from ..case_analysis import context, records
from .detection_rules import load_signatures


def analyze(state):
    signatures = load_signatures()
    findings = []
    blocks = defaultdict(list)
    def add(rows, finding_kind, summary, classification='context', technique=None, **details):
        refs = sorted({r['uid'] for r in rows})
        findings.append({'agent_role': 'log_analysis', 'source': 'validated_case_rule',
            'finding_type': finding_kind, 'pattern': finding_kind, 'summary': summary, 'dfkg_refs': refs,
            'canonical_host_id': rows[0].get('canonical_host_id'), 'event_time': rows[0].get('time'),
            'timestamp': rows[0].get('time'), 'case_id': state.get('case_id'),
            'classification': classification, 'operation_outcome': 'unknown',
            'attacks': [technique] if technique and classification == 'suspicious' else [],
            'analysis_details': details})
    for row in records(state):
        raw = context(row)
        data = raw.get('EventData') or raw.get('event_data') or {}
        data = data if isinstance(data, dict) else {}
        system = raw.get('System') or {}
        system = system if isinstance(system, dict) else {}
        provider = raw.get('ProviderName') or system.get('Provider') or ''
        provider = provider.get('Name', '') if isinstance(provider, dict) else str(provider)
        eid = row.get('source_event_id') or raw.get('Id') or raw.get('event_id') or system.get('EventID')
        try:
            eid = int(eid)
        except (ValueError, TypeError):
            eid = None
        family = ('security' if 'Security-Auditing' in provider else
                  'service_control_manager' if provider == 'Service Control Manager' else None)
        definition = signatures.get('endpoint_lifecycle', {}).get(family, {}).get(eid)
        if definition:
            name = data.get(definition['name_field'])
            command = data.get(definition.get('command_field')) or ''
            task_xml = data.get('TaskContent')
            coverage = 'Recorded source fields only.'
            if isinstance(task_xml, str) and task_xml:
                if len(task_xml.encode()) > 65536 or re.search(r'<!DOCTYPE|<!ENTITY', task_xml, re.I):
                    coverage = 'Task XML unavailable: unsafe declarations or size limit.'
                else:
                    try:
                        tree = ElementTree.fromstring(task_xml)
                        commands = [node.text or '' for node in tree.iter()
                                    if node.tag.rsplit('}', 1)[-1] in {'Command', 'Arguments'}]
                        command = ' '.join(commands)[:4096]
                    except ElementTree.ParseError:
                        coverage = 'Task XML unavailable: malformed source content.'
            suspicious = bool(re.search(r'(?i)\\(?:ProgramData|Users\\Public)\\|-(?:enc|encodedcommand)\b', str(command)))
            add([row], 'source_persistence_lifecycle',
                f"Source reports {definition['kind']} {definition['action']}: {name or 'name unavailable'}; "
                f"configured command={command or 'unavailable'}. Registration/configuration does not establish execution or intent.",
                'suspicious' if suspicious else 'context',
                'T1053.005' if definition['kind'] == 'scheduled_task' else 'T1543.003',
                kind=definition['kind'], action=definition['action'], name=name, command=command, coverage=coverage)
        command = str(row.get('command_line') or '')[:16384]
        for rule in signatures.get('command_observations', []):
            if re.search(rule['regex'], command):
                add([row], rule['pattern'], 'Recorded command attempts ' + rule['pattern'].replace('_', ' ') +
                    ': ' + command[:1000] + '. Successful system changes and authorization are not established by command text.',
                    'suspicious', rule['technique'])
        if eid == 4104 and 'PowerShell' in provider and isinstance(data.get('ScriptBlockText'), str):
            # No shared host => no cross-record reassembly, even when block IDs match.
            host = row.get('canonical_host_id')
            block = str(data.get('ScriptBlockId') or row['uid'])
            blocks[(host or row['uid'], block)].append((row, data))
    for (host, block), parts in sorted(blocks.items(), key=lambda item: str(item[0])):
        numbered = {}
        totals = set()
        valid = True
        for row, data in parts:
            if data.get('MessageNumber') is None or data.get('MessageTotal') is None:
                valid = False
            try:
                number, total = int(data.get('MessageNumber', 1)), int(data.get('MessageTotal', 1))
                if not 1 <= number <= total <= 128:
                    raise ValueError('Invalid script fragment counts')
            except (ValueError, TypeError):
                valid = False
                continue
            text = data['ScriptBlockText']
            if number in numbered and numbered[number] != text:
                valid = False
            numbered[number] = text
            totals.add(total)
        complete = valid and len(totals) == 1 and set(numbered) == set(range(1, next(iter(totals), 0)+1))
        text = ''.join(numbered[n] for n in sorted(numbered))
        complete = complete and len(text.encode()) <= 65536
        indicators = [name for name, pattern in [('download_string', r'\bDownloadString\b'),
            ('invoke_expression', r'\b(?:Invoke-Expression|IEX)\b'), ('base64_decode', r'\bFromBase64String\b')]
            if re.search(pattern, text[:65536], re.I)]
        add([row for row, _ in parts], 'reconstructed_script_block',
            f'Source PowerShell script block {block}: reconstruction={"complete" if complete else "partial"}; '
            f'fragments={len(numbered)}; text indicators={", ".join(indicators) or "none matched"}. '
            'Script logging and textual indicators do not independently establish successful execution or malicious intent.',
            'suspicious' if indicators else 'context', 'T1059.001', script_block_id=block,
            reconstruction_complete=complete, text_sha256=sha256(text.encode()).hexdigest(),
            recorded_text=text[:4096], indicators=indicators, fragments=len(numbered))
    return findings
