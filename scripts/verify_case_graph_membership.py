"""Real Neo4j shared-case/type isolation oracle; all writes roll back."""
from uuid import uuid4
from src.graph.neo4j_client import Neo4jClient
from src.agents.case_graph import read_case_graph


def main():
    prefix = "membership-oracle-" + uuid4().hex
    client = Neo4jClient()
    try:
        with client._driver.session() as session:
            tx = session.begin_transaction()
            try:
                tx.run("CREATE (a:Case {uid:$a}),(b:Case {uid:$b}), "
                       "(e:Event {uid:$e,canonical_host_id:$h,trace_id:$trace}), "
                       "(p:Process {uid:$e,case_id:$a}), (h:Host {uid:$h}), "
                       "(u:Process {uid:$unrelated,case_id:$b}), "
                       "(f:File {uid:$file,case_id:$a}), (fe:Event {uid:$file}) "
                       "CREATE (a)-[:HAS_EVENT]->(e),(b)-[:HAS_EVENT]->(e), "
                       "(b)-[:HAS_EVENT]->(fe), (p)-[:RUNS_ON {trace_id:$trace}]->(h)",
                       a=prefix+"A", b=prefix+"B", e=prefix+"E", h=prefix+"H", trace=prefix,
                       unrelated=prefix+"unrelated", file=prefix+"file").consume()
                view = read_case_graph(tx, prefix+"B")
                assert view["totals"]["Process"] == 1 and view["totals"]["Host"] == 1
                assert view["totals"]["File"] == 1 and view["totals"]["Event"] == 2
                assert not any(n["properties"].get("uid") == prefix+"unrelated" for n in view["nodes"])
                assert any(e["type"] == "RUNS_ON" for e in view["edges"])
                from src.agents.agent_graph import persist_case_analysis
                class Projection:
                    def execute_query(self,query,**params):
                        return list(tx.run(query,**params)),None,None
                state={'timeline':{'events':[{'uid':prefix+'E','time':'2026-10-14T00:00:00Z','dfkg_refs':[prefix+'E']}]},
                       'attack_graph':{'nodes':[{'id':'one','label':'observed activity','dfkg_refs':[prefix+'E']}], 'edges':[], 'source_relations':[
                         {'id':prefix+'relation','source':prefix+'E','target':prefix+'file',
                          'type':'SAME_FILE_PATH','dfkg_refs':[prefix+'E',prefix+'file'],'basis':{'path':'source-file'},'limitations':['source reported']},
                         {'id':prefix+'foreign','source':prefix+'E','target':prefix+'unrelated',
                          'type':'FOREIGN','dfkg_refs':[prefix+'E',prefix+'unrelated'],'basis':{}}]}}
                persist_case_analysis(Projection(),prefix+'B',state)
                persist_case_analysis(Projection(),prefix+'B',state)
                view=read_case_graph(tx,prefix+'B')
                assert view['totals']['TimelineEntry']==view['totals']['Observation']==1
                assert len([e for e in view['edges'] if e['type']=='CITES'])==2
                assert len([e for e in view['edges'] if e['type']=='SAME_FILE_PATH'])==1
                assert not any(e['type']=='FOREIGN' for e in view['edges'])
                print("PASS: shared evidence resolves typed nodes, missing tags and File; unrelated case-tagged process excluded; actual edges retained.")
            finally:
                tx.rollback()
    finally:
        client.close()


if __name__ == "__main__":
    main()
