"""Independent scorer: no recovery imports, no runtime fallback, owned files only."""
import hashlib
import importlib.util
from pathlib import Path
import struct

REVISION=3


def golden_blob(text,message_id):
    # This is the independent fixture writer, not a recovery implementation.
    path=Path(__file__).resolve().parents[1]/'build_telegram_native_fixtures.py'
    spec=importlib.util.spec_from_file_location('telegram_benchmark_gold_writer',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.message(text,mid=message_id,dialog=77)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def text_sha(value):
    return sha(value.encode('utf-8')) if isinstance(value,str) else None


def confirmed(row):
    return (row.get('app')=='Telegram' and row.get('application_confirmed') is True and
            row.get('evidence_kind') in ('backup','previous','export') and
            row.get('message_id') is not None and row.get('chat_id') is not None)


def rolling(data,little,a=0,b=0):
    for offset in range(0,len(data),8):
        x,y=struct.unpack(('<' if little else '>')+'II',data[offset:offset+8])
        a=(a+x+b)&0xffffffff;b=(b+y+a)&0xffffffff
    return a,b


def snapshot_sha(wal_path,commit_frame):
    """Rebuild independently from checksummed WAL pages through this commit."""
    raw=wal_path.read_bytes()
    if type(commit_frame) is not int or not 1<=commit_frame<=262144 or len(raw)<32:
        raise ValueError('WAL_COMMIT_INVALID')
    magic,version,page,_,one,two,a,b=struct.unpack('>8I',raw[:32])
    if magic not in (0x377f0682,0x377f0683) or version!=3007000 or page<512 or page>65536 or page&(page-1):
        raise ValueError('WAL_HEADER_INVALID')
    if rolling(raw[:24],magic==0x377f0682)!=(a,b):
        raise ValueError('WAL_HEADER_CHECKSUM')
    overlay={};pages=0
    for number in range(1,commit_frame+1):
        at=32+(number-1)*(24+page);part=raw[at:at+24+page]
        if len(part)!=24+page:
            raise ValueError('WAL_TORN_FRAME')
        target,pages,salt1,salt2,want1,want2=struct.unpack('>6I',part[:24])
        if not 1<=target<=262144 or pages>262144 or (salt1,salt2)!=(one,two):
            raise ValueError('WAL_FRAME_INVALID')
        a,b=rolling(part[:8]+part[24:],magic==0x377f0682,a,b)
        if (a,b)!=(want1,want2):
            raise ValueError('WAL_FRAME_CHECKSUM')
        overlay[target]=part[24:]
        if pages:
            overlay={key:value for key,value in overlay.items() if key<=pages}
    if not pages or any(number not in overlay for number in range(1,pages+1)):
        raise ValueError('WAL_MISSING_PREIMAGE')
    return sha(b''.join(overlay[number] for number in range(1,pages+1)))


def prefix_proof(row,case,source):
    try:
        frame=row.get('wal_commit_frame');prefix=row.get('wal_validated_prefix_bytes')
        wal=source.with_name(source.name+'-wal');page=case['page_size'];step=24+page
        return (row.get('message_id')==21 and row.get('chat_id')==(-88 if case['topic'] else 77) and
            row.get('recovery_status')=='committed_wal_prefix_snapshot' and
            row.get('evidence_kind')=='backup' and row.get('previous_version') is False and
            row.get('deleted') is None and row.get('wal_current_state_confirmed') is False and
            row.get('wal_snapshot_latest_known_commit') is True and row.get('wal_tail_reason')==case['tail_reason'] and
            row.get('wal_proof')=='all_pages_from_validated_wal' and
            row.get('wal_db_sha256')==case['source_sha256'] and row.get('wal_sha256')==case['wal_sha256'] and
            type(prefix) is int and 32<prefix<wal.stat().st_size and (prefix-32)%step==0 and
            type(frame) is int and 1<=frame<=(prefix-32)//step and
            row.get('source_record','').endswith('@wal_commit:'+str(frame)) and
            row.get('snapshot_id')=='wal:'+case['wal_sha256']+':commit:'+str(frame) and
            row.get('wal_snapshot_sha256')==snapshot_sha(wal,frame))
    except (OSError,ValueError,KeyError,TypeError,struct.error):
        return False


def overflow_proof(row,case,source):
    try:
        ranges=row.get('sqlite_payload_ranges');wanted=row.get('sqlite_payload_length')
        if (row.get('sqlite_overflow_chain_verified') is not True or row.get('deleted') is not None or
            row.get('recovery_status')!='deleted_supported_by_evidence' or row.get('evidence_kind')!='backup' or
            row.get('message_id')!=case['message_id'] or row.get('chat_id')!=77 or
            row.get('source_sha256')!=case['source_sha256'] or
            not isinstance(ranges,list) or not 2<=len(ranges)<=4096 or type(wanted) is not int or not 0<wanted<=64*1024**2):
            return False
        raw=source.read_bytes();page=int.from_bytes(raw[16:18],'big');page=65536 if page==1 else page
        usable=page-raw[20]
        minimum=((usable-12)*32//255)-23
        proposed=minimum+(wanted-minimum)%(usable-4)
        local=proposed if proposed<=usable-35 else minimum
        if wanted<=usable-35 or ranges[0].get('bytes')!=local:
            return False
        trunk=int.from_bytes(raw[32:36],'big');trunks=set();leaves=set()
        while trunk:
            if trunk in trunks or not 1<=trunk<=len(raw)//page:
                return False
            trunks.add(trunk);at=(trunk-1)*page;count=int.from_bytes(raw[at+4:at+8],'big')
            if count>(page-8)//4:
                return False
            leaves.update(int.from_bytes(raw[at+8+i*4:at+12+i*4],'big') for i in range(count))
            trunk=int.from_bytes(raw[at:at+4],'big')
        cursor=0;parts=[];physical=[];pages=[]
        for index,part in enumerate(ranges):
            if any(type(part.get(key)) is not int for key in ('logical_offset','bytes','sqlite_page','physical_byte_offset')):
                return False
            logical,size,number,offset=(part[key] for key in ('logical_offset','bytes','sqlite_page','physical_byte_offset'))
            if (logical!=cursor or not 0<size<=page or number<1 or part.get('physical_source')!='db' or
                    part.get('wal_frame') is not None or offset<0 or offset+size>len(raw) or
                    offset//page+1!=number or (offset+size-1)//page+1!=number):
                return False
            if parts and (number not in leaves or number in trunks or number in pages):
                return False
            next_page=ranges[index+1].get('sqlite_page') if index+1<len(ranges) else 0
            if index==0:
                if offset+size+4>(number-1)*page+usable or int.from_bytes(raw[offset+size:offset+size+4],'big')!=next_page:
                    return False
            elif (offset!=(number-1)*page+4 or size!=min(wanted-cursor,usable-4) or
                    int.from_bytes(raw[(number-1)*page:(number-1)*page+4],'big')!=next_page):
                return False
            parts.append(raw[offset:offset+size]);physical.append((offset,offset+size));pages.append(number);cursor+=size
        intervals=sorted(physical)
        gold=golden_blob(row.get('text'),case['message_id'])
        return (cursor==wanted and sha(b''.join(parts))==row.get('sqlite_payload_sha256') and
            text_sha(row.get('text'))==case['expected_text_sha256'] and sha(gold)==case['expected_tl_sha256'] and
            b''.join(parts).count(gold)==1 and
            row.get('sqlite_overflow_pages')==pages[1:] and row.get('sqlite_record_length')==len(parts[0]) and
            row.get('sqlite_record_sha256')==sha(parts[0]) and all(left[1]<=right[0] for left,right in zip(intervals,intervals[1:])))
    except (OSError,ValueError,KeyError,TypeError,IndexError):
        return False


def search_target(record,targets,require_proof=False):
    """Match the bounded view to a full archived target, including truncation."""
    for target in targets:
        if any(record.get(key)!=target.get(key) for key in ('app','application_confirmed','message_id','chat_id','source_record','snapshot_id','record_kind','recovery_status','evidence_kind','deleted','previous_version')):
            continue
        if require_proof:
            fields=(('wal_db_sha256','wal_sha256','wal_snapshot_sha256','wal_commit_frame','wal_proof','wal_tail_reason',
                'wal_validated_prefix_bytes','wal_snapshot_latest_known_commit','wal_current_state_confirmed')
                if target.get('recovery_status')=='committed_wal_prefix_snapshot' else
                ('sqlite_payload_length','sqlite_payload_sha256','sqlite_payload_ranges','sqlite_overflow_pages',
                 'sqlite_overflow_chain_verified','sqlite_record_length','sqlite_record_sha256','native_tl_body_sha256'))
            if any(record.get(key)!=target.get(key) for key in fields):
                continue
        text=target['text'];shown=record.get('text')
        if len(text)>65536:
            if shown==text[:65536] and record.get('text_truncated') is True and record.get('text_length')==len(text):
                return True
        elif shown==text and not record.get('text_truncated'):
            return True
    return False


def score(kind,case,source,rows,searches,completed):
    expected=case.get('expected_text_sha256') or text_sha(case['latest_text'])
    exact=[row for row in rows if text_sha(row.get('text'))==expected]
    gold_mid=case['message_id'] if kind=='overflow' else 21
    gold_chat=77 if kind=='overflow' else -88 if case['topic'] else 77
    attributed=[row for row in exact if confirmed(row) and row.get('message_id')==gold_mid and row.get('chat_id')==gold_chat]
    expected_attributed=kind=='overflow' or case['expected_prefix_records']==1 or case['name'] in ('normal-valid-wal','valid-uncommitted-tail')
    expected_prefix=kind=='wal' and case['expected_prefix_records']==1
    verified_prefix=[row for row in attributed if kind=='wal' and prefix_proof(row,case,source)]
    verified_overflow=[row for row in attributed if kind=='overflow' and overflow_proof(row,case,source)]
    search_results={}
    for name,reply in searches.items():
        records=reply.get('records',[])
        search_results[name]=dict(status=reply.get('status'),total=reply.get('total'),
            exact_target_views=sum(search_target(row,exact) for row in records),
            attributed_target_views=sum(confirmed(row) and search_target(row,attributed) for row in records),
            full_proof_target_views=sum(search_target(row,verified_prefix+verified_overflow,require_proof=True) for row in records))
    return dict(expected_text_sha256=expected,expected_attributed_target=expected_attributed,
        expected_prefix=expected_prefix,expected_overflow=kind=='overflow',
        observed_full_exact_text_count=len(exact) if completed else None,
        observed_attributed_target_count=len(attributed) if completed else None,
        verified_prefix_count=len(verified_prefix) if completed else None,
        verified_overflow_count=len(verified_overflow) if completed else None,
        unexpected_confirmed_target=any(confirmed(row) for row in exact) and not expected_attributed,
        confirmed_target_with_wrong_gold_ids=sum(confirmed(row) and (row.get('message_id')!=gold_mid or row.get('chat_id')!=gold_chat) for row in exact),
        corrupt_or_uncommitted_tail_promoted=sum(confirmed(row) and 'UNCOMMITTED_OR_CORRUPT_TAIL_MUST_NOT_BE_HISTORY' in row.get('text','') for row in rows),
        target_categories=sorted({row.get('evidence_kind','') for row in exact}),
        target_deleted_values=sorted({str(row.get('deleted')) for row in exact}),
        unknown_deletion_for_all_attributed=all(row.get('deleted') is None for row in attributed),
        searches=search_results)
