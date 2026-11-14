"""Independent bounded NTFS 3.x resident FILE record timestamp examination."""
from datetime import datetime,timedelta,timezone
from hashlib import sha256
from collections import defaultdict
import struct


def reconstruct_paths(rows):
    """Derive volume-relative paths only from intact sequence-bound parents in this fragment."""
    by_reference=defaultdict(list)
    for row in rows:
        reference=row['analysis']['record_reference']
        if reference is not None:by_reference[reference].append(row)
    remaining=100000
    for row in rows:
        exam=row['analysis'];paths=[];reasons=set();steps=0
        pending=[(row,[],[],[])]
        while pending:
            current,parts,references,digests=pending.pop()
            info=current['analysis'];reference=info['record_reference']
            if remaining<=0 or len(paths)>=16:
                reasons.add('path_examination_budget');break
            remaining-=1;steps+=1
            if reference is None:reasons.add('record_identity_unavailable');continue
            if reference in references:reasons.add('parent_cycle');continue
            if len(references)>=64:reasons.add('parent_depth_limit');continue
            if len(by_reference[reference])!=1:reasons.add('ambiguous_record_reference');continue
            if not info['record_in_use']:reasons.add('record_not_in_use');continue
            if info['base_record_reference'] or 0x20 in info['attribute_types']:
                reasons.add('extension_attributes_unresolved');continue
            if 0xc0 in info['attribute_types']:reasons.add('reparse_target_unresolved');continue
            references=references+[reference];digests=digests+[info['sha256']]
            names=info['filename_attributes']
            # Prefer long names while preserving actual POSIX/hard-link alternatives.
            preferred=[name for name in names if name['namespace']!=2 or not any(
                other['namespace'] in {1,3} and other['parent_reference']==name['parent_reference'] for other in names)]
            for name in preferred or names:
                if info['record_number']==5 and info['record_is_directory'] and name['parent_reference']==reference and name['name']=='.':
                    path='\\'+'\\'.join(reversed(parts))
                    if len(path)>4096:reasons.add('path_length_limit');continue
                    paths.append({'volume_relative_path':path,'record_references':references,
                                  'record_sha256':digests})
                    continue
                if (not name['name'] or name['name'] in {'.','..'} or
                        any(char in name['name'] for char in '\\/:\x00') or name['namespace'] not in {0,1,2,3}):
                    reasons.add('unsupported_filename_component');continue
                parent=by_reference.get(name['parent_reference'],[])
                if not parent:
                    reasons.add('parent_missing_or_sequence_mismatch');continue
                if len(parent)!=1:reasons.add('ambiguous_parent_reference');continue
                if not parent[0]['analysis']['record_is_directory']:
                    reasons.add('parent_not_directory');continue
                if len(pending)>=64:reasons.add('path_branch_limit');continue
                pending.append((parent[0],parts+[name['name']],references,digests))
        paths=sorted({entry['volume_relative_path']:entry for entry in paths}.values(),key=lambda p:p['volume_relative_path'])
        status=('partial' if paths and reasons else 'ambiguous' if len(paths)>1 else 'resolved' if paths else 'unavailable')
        exam['path_reconstruction']={'status':status,'paths':paths,'unresolved_reasons':sorted(reasons),
            'references_examined':steps,'scope':'Volume-relative source parent references in this preserved fragment; no drive letter, journal continuity or current filesystem state inferred.'}
        if status=='resolved':
            path=paths[0]['volume_relative_path']
            # Existing OCSF file_path carries the source parent directory, not a fabricated drive.
            row['ParentPath']=path.rsplit('\\',1)[0] or '\\'


def recorded_parent_relations(events,case_id):
    """Project source parent links with case, host, volume, artifact and sequence isolation."""
    index=defaultdict(list);native=[];relations=[]
    for event in events:
        exam=(event.get('unmapped') or {}).get('examination') or {}
        if (exam.get('analysis_origin')!='independent_ntfs_file_record_examination' or
                not event.get('canonical_host_id') or not exam.get('artifact_sha256') or
                not exam.get('volume_id') or exam.get('record_reference') is None):continue
        key=(event['canonical_host_id'],exam['volume_id'],exam['artifact_sha256'])
        index[(*key,exam['record_reference'])].append(event);native.append((event,exam,key))
    for event,exam,key in native:
        if not exam['record_in_use'] or len(index[(*key,exam['record_reference'])])!=1:continue
        for reference in sorted({name['parent_reference'] for name in exam['filename_attributes']}):
            candidates=index.get((*key,reference),[])
            if len(candidates)!=1:continue
            parent=candidates[0];info=parent['unmapped']['examination']
            if parent['uid']==event['uid'] or not info['record_in_use'] or not info['record_is_directory']:continue
            kind='RECORDED_NTFS_PARENT'
            relations.append({'id':sha256((case_id+kind+parent['uid']+event['uid']).encode()).hexdigest(),
                'type':kind,'source':parent['uid'],'target':event['uid'],'dfkg_refs':[parent['uid'],event['uid']],
                'basis':{'host':key[0],'volume_id':key[1],'artifact_sha256':key[2],
                         'parent_record_reference':reference,'child_record_reference':exam['record_reference']},
                'causal':False,'source_reported':True,
                'limitations':['Recorded directory parent reference in a preserved fragment; no execution, current filesystem state or malicious causation established.']})
    return relations


def filetime(value):
    if not value:return None
    try:return (datetime(1601,1,1,tzinfo=timezone.utc)+timedelta(microseconds=value//10)).isoformat()
    except OverflowError:raise ValueError('NTFS FILETIME is outside supported range') from None


def examine_records(data,metadata):
    size=metadata.get('record_size',1024)
    if size not in {1024,4096} or metadata.get('ntfs_version') not in {'3.0','3.1'}:
        raise ValueError('Native MFT requires declared NTFS 3.0/3.1 and 1024/4096-byte records')
    if not metadata.get('volume_id') or not data or len(data)>25*1024*1024 or len(data)%size:
        raise ValueError('Native MFT requires volume_id and complete bounded FILE records')
    first=metadata.get('first_record_number')
    if first is not None and (type(first) is not int or not 0<=first<2**48 or first+len(data)//size>2**48):
        raise ValueError('first_record_number must identify a valid contiguous MFT record range')
    rows=[];errors=[];total=len(data)//size;artifact_digest=sha256(data).hexdigest()
    for index in range(min(total,4096)):
        original=data[index*size:(index+1)*size];record=bytearray(original)
        try:
            if record[:4]!=b'FILE':raise ValueError('Missing FILE signature')
            offset,count=struct.unpack_from('<HH',record,4)
            if not 2<=count<=9 or offset+count*2>size or size%(count-1):raise ValueError('Invalid update sequence array')
            sector=size//(count-1)
            if sector not in {512,4096}:raise ValueError('Unsupported FILE sector layout')
            marker=record[offset:offset+2]
            for part in range(1,count):
                end=part*sector
                if record[end-2:end]!=marker:raise ValueError('Torn FILE record update sequence')
                record[end-2:end]=record[offset+part*2:offset+part*2+2]
            attr=struct.unpack_from('<H',record,20)[0];used=struct.unpack_from('<I',record,24)[0]
            if not 48<=attr<used<=size or attr%8:raise ValueError('Invalid FILE attribute extent')
            if offset<40 or offset+count*2>attr:raise ValueError('Update sequence array overlaps header/attributes')
            si=None;names=[];attribute_types=[];terminated=False
            while attr+8<=used:
                kind,length=struct.unpack_from('<II',record,attr)
                if kind==0xffffffff:terminated=True;break
                if length<24 or length%8 or attr+length>used:raise ValueError('Invalid attribute length')
                attribute_types.append(kind)
                if not record[attr+8] and kind in {0x10,0x30}:
                    n,start=struct.unpack_from('<IH',record,attr+16)
                    if start<24 or start+n>length:raise ValueError('Invalid resident attribute value')
                    value=record[attr+start:attr+start+n]
                    if kind==0x10:
                        if n<32 or si is not None:raise ValueError('Invalid STANDARD_INFORMATION')
                        si=[filetime(v) for v in struct.unpack_from('<QQQQ',value)]
                    else:
                        if n<66 or 66+value[64]*2>n:raise ValueError('Invalid FILE_NAME')
                        names.append({'name':value[66:66+value[64]*2].decode('utf-16le'),
                            'namespace':value[65],'parent_reference':struct.unpack_from('<Q',value)[0],
                            'dates':[filetime(v) for v in struct.unpack_from('<QQQQ',value,8)]})
                attr+=length
            if not terminated or not si or not names or not si[2]:raise ValueError('Required resident timestamps/name/end marker unavailable')
            name=sorted(names,key=lambda n:n['namespace'] not in {1,3})[0]
            sequence=struct.unpack_from('<H',record,16)[0]
            number=(struct.unpack_from('<I',record,44)[0] if metadata['ntfs_version']=='3.1'
                    else first+index if first is not None else None)
            if metadata['ntfs_version']=='3.1' and first is not None and number!=first+index:
                raise ValueError('FILE record number disagrees with declared contiguous range')
            rows.append({'FileName':name['name'],'LastRecordChange':si[2],
                'Created0x10':si[0],'Created0x30':name['dates'][0],
                'analysis':{'analysis_origin':'independent_ntfs_file_record_examination','status':'complete',
                    'sha256':sha256(original).hexdigest(),'artifact_sha256':artifact_digest,
                    'record_index_in_fragment':index,'sequence_number':sequence,
                    'record_number':number,'record_reference':None if number is None else (sequence<<48)|number,
                    'record_number_source':('native_header' if metadata['ntfs_version']=='3.1' else
                                            'declared_contiguous_range' if first is not None else 'unavailable'),
                    'base_record_reference':struct.unpack_from('<Q',record,32)[0],
                    'record_is_directory':bool(struct.unpack_from('<H',record,22)[0]&2),
                    'volume_id':metadata['volume_id'],'si_dates':si,'filename_attributes':names,
                    'record_in_use':bool(struct.unpack_from('<H',record,22)[0]&1),'attribute_types':attribute_types,
                    'coverage':'Resident FILE attributes and bounded sequence-bound parent paths within this fragment. Drive letters, extension/reparse targets, journal continuity, acquisition authenticity and intentional timestomping are not established.'}})
        except (ValueError,UnicodeError,struct.error) as error:
            if len(errors)<20:errors.append({'record_index':index,'reason':str(error)})
    partial=bool(errors) or total>4096
    for row in rows:
        row['analysis'].update(status='partial' if partial else 'complete',records_in_fragment=total,
                              records_examined=min(total,4096),parse_error_sample=errors,records_omitted=max(0,total-4096))
    if not rows:raise ValueError('No supported intact resident FILE records found')
    reconstruct_paths(rows)
    return rows
