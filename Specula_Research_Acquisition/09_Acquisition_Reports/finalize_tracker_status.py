import collections,csv,json
from pathlib import Path
from fetch_official import ROOT
report=ROOT/'09_Acquisition_Reports'
receipt=json.loads((report/'final_verification_receipt.json').read_text())
assert receipt['result']=='PASS'
data=json.loads((report/'campaign_input.json').read_text(encoding='utf-8'))
for row in data['checklist']:
 if row['category'].startswith('8.'):
  row['acquisition_status']='CREATED — VERIFIED'
  row['verification_status']='PASS: executable campaign oracle; hashes/formats/coverage/cache checks, plus visual PDF/workbook review'
data['summary']['status_counts']=dict(collections.Counter(r['acquisition_status'] for r in data['checklist']))
for relative,value in [('09_Acquisition_Reports/campaign_input.json',data),('09_Acquisition_Reports/campaign_summary.json',data['summary'])]:
 p=ROOT/relative;b=report/'final_status_predecessors'/p.name;b.parent.mkdir(exist_ok=True);assert not b.exists();p.rename(b)
 with p.open('x',encoding='utf-8') as f:json.dump(value,f,indent=2)
p=ROOT/'00_Master_Inventory/checklist_status.csv';b=report/'final_status_predecessors/checklist_status.csv';assert not b.exists();p.rename(b)
with p.open('x',encoding='utf-8-sig',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(data['checklist'][0]));w.writeheader();w.writerows(data['checklist'])
p=ROOT/'00_Master_Inventory/master_acquisition_tracker.xlsx';b=report/'final_status_predecessors/master_acquisition_tracker.xlsx';assert not b.exists();p.rename(b)
p=report/'final_verification_receipt.json';b=report/'final_status_predecessors/verification_before_pcap.json';assert not b.exists();p.rename(b)
print('Verified deliverable statuses recorded; prior reports preserved')
