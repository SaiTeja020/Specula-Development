from src.graph.process_lineage import process_identity, resolve_parent_links
from src.schemas.ocsf_events import ProcessActivity
from src.schemas.ocsf_phase2_events import ProcessActivityEvent


def event(uid, pid, image, time, **kw):
    return dict(uid=uid, class_uid=1007, activity_id=1, canonical_host_id="host-A",
                process_pid=pid, process_name=image, time=time, **kw)


def test_parent_fields_and_instance_identity():
    for cls in [ProcessActivity, ProcessActivityEvent]:
        assert {"parent_process_uid", "parent_process_guid", "process_guid"} <= cls.model_fields.keys()
    assert process_identity("host-A", pid=4) is None
    assert process_identity(None, guid="G") is None
    assert process_identity("host-A", guid="G") == process_identity("host-A", guid="g")
    assert process_identity("host-A", pid=4, start="t1") != process_identity("host-A", pid=4, start="t2")
    assert process_identity("host-A", guid="g") != process_identity("host-B", guid="g")


def test_lineage_pid_reuse_host_time_and_guid():
    first = event("p1", 4, "good.exe", "2026-10-13T00:00:00Z")
    reused = event("p2", 4, "other.exe", "2026-10-13T00:02:00Z")
    child = event("c", 8, "child.exe", "2026-10-13T00:03:00Z", parent_process_pid=4, parent_process_name="good.exe")
    assert resolve_parent_links([first, reused, child]) == []
    child["parent_process_name"] = "other.exe"
    links = resolve_parent_links([first, reused, child])
    assert links[0]["parent"] == "p2"
    child["canonical_host_id"] = "host-B"
    assert resolve_parent_links([first, reused, child]) == []
    child["canonical_host_id"] = "host-A"
    child["parent_process_guid"] = "G1"
    first["process_guid"] = "G1"
    reused["process_guid"] = "G2"
    assert resolve_parent_links([first, reused, child])[0]["parent"] == "p1"
    child["time"] = first["time"]
    assert resolve_parent_links([first, child]) == []
    child['time']='2026-10-13T00:03:00Z'
    termination=event('end',4,'good.exe','2026-10-13T00:02:30Z')
    termination['activity_id']=2
    assert resolve_parent_links([first,termination,child])==[]


def test_ambiguous_lifetimes_are_not_linked():
    a = event("a", 4, "p.exe", "2026-10-13T00:00:00Z")
    b = event("b", 4, "p.exe", "2026-10-13T00:00:00Z")
    c = event("c", 8, "c.exe", "2026-10-13T00:01:00Z", parent_process_pid=4, parent_process_name="p.exe")
    assert resolve_parent_links([a, b, c]) == []
