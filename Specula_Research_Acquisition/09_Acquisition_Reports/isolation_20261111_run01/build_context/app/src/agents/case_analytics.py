"""Atomic per-case DuckDB snapshots; authorized readers never execute supplied SQL."""
import json
import os
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
from threading import RLock

_write_lock = RLock()


def case_path(case_id):
    directory = Path(os.getenv("SPECULA_ANALYTICS_DIR", "data/analytics"))
    return directory / (sha256(case_id.encode()).hexdigest()+".duckdb")


def write_case_analytics(case_id, events, findings=(), traces=()):
    import duckdb
    target = case_path(case_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.stem+"-"+uuid4().hex+".pending")
    from .case_analysis import context
    with _write_lock:
        try:
            with duckdb.connect(str(temp)) as db:
                db.execute("CREATE TABLE case_metadata(case_id VARCHAR PRIMARY KEY)")
                db.execute("INSERT INTO case_metadata VALUES (?)", [case_id])
                db.execute("CREATE TABLE events(uid VARCHAR PRIMARY KEY, recorded_time TIMESTAMPTZ, class_uid INTEGER, "
                           "source VARCHAR, host VARCHAR, severity INTEGER, original_context JSON, normalized_event JSON)")
                rows = [(e['uid'], e.get('time'), e.get('class_uid'), e.get('source_type'), e.get('canonical_host_id'),
                         e.get('severity_id'), json.dumps(context(e),default=str),json.dumps(e,default=str))
                        for e in {e['uid']:e for e in events}.values()]
                if rows:
                    db.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)", rows)
                db.execute("CREATE TABLE findings(sequence INTEGER PRIMARY KEY, agent VARCHAR, classification VARCHAR, "
                           "outcome VARCHAR, recorded_time TIMESTAMPTZ, summary VARCHAR, citations JSON)")
                if findings:
                    db.executemany("INSERT INTO findings VALUES (?,?,?,?,?,?,?)", [
                        (i,f.get('agent_role'),f.get('classification'),f.get('operation_outcome'),f.get('event_time'),
                         f.get('summary'),json.dumps(f.get('dfkg_refs',[]))) for i,f in enumerate(findings)])
                db.execute("CREATE TABLE agent_runs(sequence INTEGER PRIMARY KEY, agent VARCHAR, model VARCHAR, "
                           "action VARCHAR, validated BOOLEAN, trace JSON)")
                if traces:
                    db.executemany("INSERT INTO agent_runs VALUES (?,?,?,?,?,?)", [
                        (i,t.get('agent_role'),t.get('model_used'),t.get('action'),t.get('model_output_validated'),
                         json.dumps(t,default=str)) for i,t in enumerate(traces)])
                db.execute("CREATE VIEW timeline AS SELECT uid,recorded_time,source,host,class_uid FROM events "
                           "ORDER BY recorded_time,uid")
                assert db.execute("SELECT count(*) FROM events").fetchone()[0] == len(rows)
            os.replace(temp,target)
        finally:
            temp.unlink(missing_ok=True)
    return {"status":"verified","case_id":case_id,"events":len(rows),"findings":len(findings),"agent_runs":len(traces)}


def case_analytics_view(case_id):
    import duckdb
    path = case_path(case_id)
    if not path.is_file():
        return {"status":"unavailable","source":"duckdb","case_id":case_id,"tables":[],
                "detail":"Case analytics have not been indexed"}
    with duckdb.connect(str(path),read_only=True) as db:
        assert db.execute("SELECT case_id FROM case_metadata").fetchone()[0] == case_id
        totals = {t:db.execute("SELECT count(*) FROM "+t).fetchone()[0]
                  for t in ('events','findings','agent_runs','timeline')}
        sources = dict(db.execute("SELECT source,count(*) FROM events GROUP BY source ORDER BY source").fetchall())
        hosts = dict(db.execute("SELECT coalesce(host,'unknown'),count(*) FROM events GROUP BY host ORDER BY host").fetchall())
        classifications = dict(db.execute("SELECT coalesce(classification,'unclassified'),count(*) FROM findings GROUP BY classification").fetchall())
        timeline = [{"uid":r[0],"time":str(r[1]),"source":r[2],"host":r[3],"class_uid":r[4]}
                    for r in db.execute("SELECT * FROM timeline LIMIT 300").fetchall()]
    return {"status":"success","source":"duckdb","case_id":case_id,"scope":"case",
            "tables":[{"name":t,"rows":n} for t,n in totals.items()],
            "metrics":{"sources":sources,"hosts":hosts,"classifications":classifications},
            "timeline":timeline,"display_limit":300}


def analytics_catalog_view():
    import duckdb
    directory = case_path("").parent
    cases = []
    for path in directory.glob("*.duckdb"):
        with duckdb.connect(str(path), read_only=True) as db:
            cases.append({"case_id":db.execute("SELECT case_id FROM case_metadata").fetchone()[0],
                          "events":db.execute("SELECT count(*) FROM events").fetchone()[0]})
    return {"status":"success","source":"duckdb","tables":["events","findings","agent_runs","timeline"],
            "cases":cases,"metrics":{"indexed_cases":len(cases)}}
