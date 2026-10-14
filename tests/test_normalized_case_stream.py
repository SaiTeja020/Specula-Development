import json
from types import SimpleNamespace
import pytest
from src.ingestion.broker.case_stream import publish_normalized_case,decode_normalized_message,index_normalized_batch
from src.ingestion.broker.kafka_producer import serialize_event


def event():
    return {'uid':'uid','case_id':'first-case','trace_id':'trace','ocsf_version':'1.2.0','class_uid':1007,
            'category_uid':1,'activity_id':1,'severity_id':1,'time':'2026-10-14T00:00:00Z',
            'raw_source_timestamp':'2026-10-14T00:00:00Z','clock_skew_offset_ms':0,'clock_skew_unverified':True,
            'security_scan_degraded':False,'is_summary':False,'canonical_host_id':'host-A','process_name':'p.exe','process_pid':2}


def test_delivery_receipt_case_scope_and_wire_formats():
    sent=[]
    class Producer:
        def produce(self,topic,**kw):
            sent.append(json.loads(kw['value']))
            kw['on_delivery'](None,SimpleNamespace(partition=lambda:0,offset=lambda:len(sent)))
        def poll(self,*a):pass
        def flush(self,*a):return 0
    receipt=publish_normalized_case('second-case',[event(),event()],producer=Producer())
    assert receipt['acknowledged']==1 and sent[0]['case_id']=='second-case'
    assert decode_normalized_message(json.dumps(event()).encode())['uid']=='uid'
    assert decode_normalized_message(serialize_event(event()))['uid']=='uid'
    class Failed(Producer):
        def flush(self,*a):return 1
    with pytest.raises(RuntimeError):publish_normalized_case('A',[event()],producer=Failed())


def test_consumer_indexes_case_scoped_full_events_without_compression():
    writes=[];indexed=[]
    graph=SimpleNamespace(execute=lambda query,params:writes.append((query,params)))
    index=SimpleNamespace(index=lambda case,rows:indexed.append((case,rows)) or {'status':'verified'})
    a=event();b={**event(),'uid':'other','case_id':'B'}
    index_normalized_batch([a,b],graph,index)
    assert {case for case,_ in indexed}=={'first-case','B'}
    assert any('HAS_EVENT' in q for q,p in writes)
    assert sum(len(rows) for _,rows in indexed)==2
