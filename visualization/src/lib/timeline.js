const labels = { 4624: 'Sign-in succeeded', 4625: 'Sign-in failed', 4672: 'Special privileges recorded',
  4688: 'Process started', 1102: 'Security log cleared' };

function object(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  try { const parsed = JSON.parse(value); return parsed && typeof parsed === 'object' ? parsed : {}; }
  catch { return {}; }
}

export function utcTime(value) {
  if (value == null || value === '' || typeof value === 'boolean') return null;
  if (typeof value === 'string' && !/(Z|[+-]\d\d:\d\d)$/i.test(value)) return null;
  const date = new Date(typeof value === 'number' && Math.abs(value) < 1e11 ? value * 1000 : value);
  return Number.isFinite(date.valueOf()) ? date.toISOString() : null;
}

const basename = value => String(value || '').split(/[\\/]/).filter(Boolean).at(-1);

export function buildTimeline(snapshot) {
  const records = snapshot?.evidence_collection?.records || [];
  const byId = new Map(records.filter(r => r.uid || r.event_uid).map(r => [r.uid || r.event_uid, r]));
  const reconstructed = snapshot?.timeline?.events || [];
  const rows = reconstructed.length ? reconstructed : records;
  return rows.map((entry, index) => {
    const refs = entry.dfkg_refs || [entry.uid || entry.event_uid].filter(Boolean);
    const original = byId.get(entry.uid || refs[0]) || {};
    const row = { ...original, ...entry };
    const context = object(object(row.unmapped).source_context);
    const sourceEvent = row.source_event_id ?? context.event_id;
    const time = utcTime(row.recorded_time ?? row.time ?? row.event_time ?? row.timestamp);
    const metadata = row.time_basis === 'file_metadata' || !!row.si_created;
    const capture = row.time_basis === 'memory_capture' || row.source_type === 'memory';
    const process = basename(row.process_name);
    const src = object(row.src_endpoint || row.src_endpoint_json);
    const dst = object(row.dst_endpoint || row.dst_endpoint_json);
    const user = row.source_user_name || row.user_name || object(row.user).name || context.user;
    const host = row.host_name || row.canonical_host_id || context.host || 'Host not recorded';
    let category = 'Observation', title = 'Activity recorded';
    if (metadata) { category = 'File metadata'; title = 'File timestamp recorded'; }
    else if (capture) { category = 'Memory'; title = 'Memory observation captured'; }
    else if (labels[sourceEvent] && row.source_type !== 'gcp_audit') {
      category = [4624, 4625, 4672].includes(Number(sourceEvent)) ? 'Identity' : 'Endpoint';
      title = labels[sourceEvent];
    } else if (row.api_operation) { category = 'Cloud'; title = `Cloud operation: ${row.api_operation}`; }
    else if (row.class_uid === 4001) { category = 'Network'; title = 'Network activity recorded'; }
    else if (process) {
      category = 'Endpoint'; title = `${process} — ${Number(sourceEvent) === 1 ? 'process started' : 'process activity'}`;
    } else if (row.file_path || row.file_name) { category = 'File'; title = `File activity: ${basename(row.file_path || row.file_name)}`; }
    else if (row.finding_title || row.finding_info) { title = 'Source alert recorded'; }
    const contextText = [user && `Account: ${user}`,
      src.ip || src.ip_address || row.src_ip ? `From ${src.ip || src.ip_address || row.src_ip}` : '',
      dst.ip || dst.ip_address || row.dst_ip ? `To ${dst.ip || dst.ip_address || row.dst_ip}` : '',
      process && !title.includes(process) ? `Process: ${process}` : '',
    ].filter(Boolean).join(' · ');
    const details = [
      ['Process', row.process_name], ['Parent process', row.parent_process_name], ['Command', row.command_line],
      ['File', row.file_path || row.file_name], ['Account', user], ['Source event ID', sourceEvent],
      ['Outcome', row.source_outcome || context.status || context.operation_result],
      ['OCSF class', row.class_uid], ['Original recorded time', row.recorded_time ?? row.time ?? row.event_time ?? row.timestamp],
      ['File creation ($SI)', row.si_created || row.file_dates?.si_created],
      ['File creation ($FN)', row.fn_created || row.file_dates?.fn_created],
    ].filter(([, value]) => value !== undefined && value !== null && value !== '' && typeof value !== 'object');
    return { id: entry.uid || entry.event_uid || refs[0] || `record-${index}`, refs, time,
      day: time?.slice(0, 10) || 'Time unavailable', category, title, context: contextText, host, details,
      metadata, capture, uncertain: !!row.clock_uncertainty?.length || row.clock_skew_unverified === true,
      derivedTime: utcTime(row.derived_time),
      note: [row.finding_title, object(row.finding_info).title, context.finding].find(value => typeof value === 'string') || '',
    };
  }).sort((a, b) => (a.time || '9999').localeCompare(b.time || '9999') || a.id.localeCompare(b.id));
}
