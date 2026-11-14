"""Copy only a hash-verified reference-only corpus, never a case index."""
import collections,hashlib,json,shutil
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
source=ROOT.parent/'data/threat_intel'
manifest=json.loads((source/'build_manifest.json').read_text(encoding='utf-8'))
metadata=json.loads((source/'metadata_store.json').read_text(encoding='utf-8'))
assert len(metadata)==873
assert collections.Counter(x['record_type'] for x in metadata.values())=={'attack_technique':697,'attack_group':176}
allowed={'record_id','record_type','title','description','source','source_version','embedding_model_version',
         'tags','technique_ids','technique_sequence','sequence_basis','source_hash','retrieved_at','feed_provider'}
assert all(set(row)<=allowed and row['source']=='local_attack_xlsx' for row in metadata.values())
expected={'faiss_index.bin','faiss_id_map.json','metadata_store.json'}
assert set(manifest['artifact_hashes'])==expected
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
target=RUN/'agent_evidence/reference_only'
target.mkdir()
files=[]
for name in sorted(expected|{'build_manifest.json'}):
    path=source/name
    digest=sha(path)
    if name in expected:assert digest==manifest['artifact_hashes'][name]
    dest=target/name
    assert not dest.exists()
    shutil.copy2(path,dest)
    assert sha(dest)==digest
    files.append({'source':str(path),'local_path':str(dest),'bytes':dest.stat().st_size,'sha256':digest})
receipt={'status':'PASS','scope':'static reference package integrity/type/field audit only; not loaded or queried',
         'files':files,'reference_records':873,'record_types':dict(collections.Counter(x['record_type'] for x in metadata.values())),
         'source_versions':manifest['source_versions'],'build_timestamp':manifest['build_timestamp'],
         'embedding_model_version':manifest['embedding_model_version'],
         'limitation':'Frozen older reference corpus; no freshness rewrite, no live FAISS execution or independent source-workbook revalidation in this preparation.'}
with (RUN/'reference_preparation_receipt.json').open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2)
print(json.dumps({'reference_records':873,'bytes':sum(x['bytes'] for x in files),'status':'PASS','runtime_execution':False}))
