"""Evidence-grounded acyclic activity paths; no inferred exploit probabilities."""
from collections import defaultdict
from .case_analysis import records,instant,observation
from .evidence_correlations import correlate


def enrich(state,nodes,edges):
    source={e['uid']:e for e in records(state)};result=correlate(state)
    linked={u for r in result['relations'] for u in r['dfkg_refs']}
    evidence=[];relations=[]
    def rank(uid):return (instant(source[uid]['time']),uid)
    for uid in sorted(linked,key=rank):
        event=source[uid]
        evidence.append({'id':'evidence-'+uid,'evidence_uid':uid,'node_kind':'evidence','label':'source_event',
            'summary':observation(event),'time':event['time'],'dfkg_refs':[uid],
            'canonical_host_id':event.get('canonical_host_id'),'classification':'source_evidence','operation_outcome':'source_recorded'})
    for r in result['relations']:
        a,b=sorted([r['source'],r['target']],key=rank)
        relations.append({'id':'relation-'+r['id'],'source':'evidence-'+a,'target':'evidence-'+b,
            'type':r['type'],'dfkg_refs':r['dfkg_refs'],'basis':r['basis'],'causal':False,
            'source_role_uid':r['source'],'target_role_uid':r['target'],'limitations':r['limitations']})
    # Show which actual source records support an observation; citations are
    # separate from the directed path edges and are not exploitation steps.
    citations=[{'source':'evidence-'+u,'target':n['id'],'type':'CITES_OBSERVATION'}
               for n in nodes for u in n['dfkg_refs'] if u in linked]
    adjacency=defaultdict(list);incoming=defaultdict(int)
    for r in relations:adjacency[r['source']].append(r['target']);incoming[r['target']]+=1
    longest={n['id']:[n['id']] for n in evidence}
    for n in evidence:
        for target in adjacency[n['id']]:
            candidate=longest[n['id']]+[target]
            if len(candidate)>len(longest[target]):longest[target]=candidate
    paths=[{'nodes':longest[n['id']],'basis':'longest_supported_source_relation_chain','causal':False,
            'probability':None,'limitations':['This chain is a candidate activity progression, not a verified exploit or single-actor attribution.']}
           for n in evidence if incoming[n['id']] and not adjacency[n['id']]]
    return {'nodes':[{**n,'node_kind':'observation'} for n in nodes]+evidence,'edges':edges+relations,
            'citation_links':citations,'activity_paths':paths,'source_relations':result['relations'],
            'observation_count':len(nodes),'related_evidence_count':len(evidence),
            'relation_count':len(relations),'kind':'source_correlated_activity','exploit_path_status':'unavailable',
            'limitations':['Temporal and source-key relationships carry their evidence basis; causal exploitation is not inferred.',
                           'Calibrated probabilities require separate reviewed exploit topology.']}
