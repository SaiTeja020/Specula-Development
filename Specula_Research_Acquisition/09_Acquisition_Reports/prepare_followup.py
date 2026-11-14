import json,re
from pathlib import Path
from fetch_official import ROOT
m=ROOT/'09_Acquisition_Reports/source_metadata'
c=json.loads((m/'attack_commit.json').read_text())['sha']
jobs=[{'url':f'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{c}/enterprise-attack/enterprise-attack-19.2.json','relative':'02_Benchmarks/MITRE_ATTACK/enterprise-attack-19.2.json','limit':64*1024*1024}]
for file in ['README.md','LICENSE.txt']:
 jobs.append({'url':f'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{c}/{file}','relative':'02_Benchmarks/MITRE_ATTACK/'+file})
jobs.append({'url':'https://drive.google.com/drive/u/0/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa','relative':'01_Forensic_Datasets/OpTC/documentation/public_drive_folder.html'})
jobs.append({'url':'https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html','relative':'01_Forensic_Datasets/NIST_Data_Leakage/source.html'})
for slug,url in [
 ('M57-Patents','https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/'),
 ('CERT','https://api.figshare.com/v2/articles/12841247/versions/1'),
 ('CIC-IDS2017','https://www.unb.ca/cic/datasets/ids-2017.html'),
 ('CSE-CIC-IDS2018','https://www.unb.ca/cic/datasets/ids-2018.html')]:
 jobs.append({'url':url,'relative':f'01_Forensic_Datasets/{slug}/source'+('.json' if slug=='CERT' else '.html')})
# Exact checklist paper sources; metadata first, no publisher access bypass.
for ident in ['2409.02572','2005.11401','2210.03629','2404.16130','1806.04356']:
 jobs.append({'url':'https://arxiv.org/abs/'+ident,'relative':'03_Research_Papers/'+ident+'/metadata.html'})
for slug,url in [('ISO_27037','https://www.iso.org/standard/44381.html'),('ISO_27041','https://www.iso.org/standard/44405.html'),('ISO_27042','https://www.iso.org/search.html?q=ISO%2FIEC+27042'),('ISO_27043','https://www.iso.org/search.html?q=ISO%2FIEC+27043'),('NIST_AI_600-1','https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf'),('MITRE_documentation','https://attack.mitre.org/'),('OCSF_documentation','https://schema.ocsf.io/'),('CFTT','https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt')]:
 jobs.append({'url':url,'relative':'05_Standards_Documentation/'+slug+'/source'+('.pdf' if url.endswith('.pdf') else '.html')})
with (ROOT/'09_Acquisition_Reports/followup_jobs.json').open('x') as f:json.dump(jobs,f,indent=2)
print(len(jobs),'followup jobs')
