# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only LVM2 text metadata, linear/striped/mirror logical images.

Raw physical-volume images only. Checksums identify intact metadata, not its
owner or a deletion. Missing/stale members and unequal mirrors are rejected.
No auto-activation, mounting, kernel device mapper or source writes are used.
"""
import bisect
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import zlib

from recovery_io import RecoveryIOError, atomic, atomic_bytes, digest, plain, read_only, writer_lock
from resumable_copy import stage, publish

SEED = 0xf597a6cf
MAX_METADATA = 4 * 1024 * 1024
TOKEN = re.compile(r'[A-Za-z0-9_.+\-]{1,128}\Z')


def _fail(code='LVM_METADATA_INVALID'):
    raise RecoveryIOError(code)


def _number(value, low=0, high=2**63-1):
    if type(value) is not int or not low <= value <= high:
        _fail()
    return value


def _crc(data):
    return zlib.crc32(data, SEED ^ 0xffffffff) ^ 0xffffffff


def _read(source, offset, length):
    if offset < 0 or length < 0 or length > MAX_METADATA or offset > source['bytes']-length:
        _fail('LVM_SOURCE_TRUNCATED')
    source['handle'].seek(offset)
    data = source['handle'].read(length)
    if len(data) != length:
        _fail('LVM_SOURCE_TRUNCATED')
    return data


def _descriptors(data, at):
    result=[]
    while at <= 512-16:
        offset,size=struct.unpack_from('<QQ',data,at);at+=16
        if not offset and not size:return result,at
        if not offset:_fail()
        result.append((offset,size))
        if len(result)>8:_fail('LVM_LAYOUT_UNSUPPORTED')
    _fail()


def _physical(source):
    prefix=_read(source,0,min(2048,source['bytes']))
    labels=[at for at in range(0,len(prefix)-511,512) if prefix[at:at+8]==b'LABELONE']
    if len(labels)!=1:_fail('LVM_RAW_PHYSICAL_VOLUME_REQUIRED')
    at=labels[0];label=prefix[at:at+512]
    sector,checksum,offset=struct.unpack_from('<QII',label,8)
    if sector!=at//512 or label[24:32]!=b'LVM2 001' or checksum!=_crc(label[20:]):
        _fail('LVM_LABEL_CHECKSUM_FAILED')
    if not 32<=offset<=512-72:_fail()
    identifier=label[offset:offset+32].decode('ascii','strict')
    if not re.fullmatch('[A-Za-z0-9]{32}',identifier):_fail()
    declared=struct.unpack_from('<Q',label,offset+32)[0]
    if declared<2048 or declared>source['bytes'] or declared%512:_fail('LVM_SOURCE_TRUNCATED')
    areas,next_at=_descriptors(label,offset+40)
    metadata,_=_descriptors(label,next_at)
    if len(areas)!=1 or not metadata:_fail('LVM_LAYOUT_UNSUPPORTED')
    raw_copies=[]
    for begin,size in metadata:
        if size<1024 or begin%512 or size%512 or begin>declared-size:_fail()
        header=_read(source,begin,512)
        if (struct.unpack_from('<I',header)[0]!=_crc(header[4:]) or
                header[4:20]!=b' LVM2 x[5A%r0N*>' or struct.unpack_from('<I',header,20)[0]!=1 or
                struct.unpack_from('<QQ',header,24)!=(begin,size)):
            _fail('LVM_METADATA_CHECKSUM_FAILED')
        locations=[]
        for entry in range(40,512-23,24):
            off,length,check,flags=struct.unpack_from('<QQII',header,entry)
            if not off and not length:break
            if flags or not 512<=off<size or not 1<=length<=min(MAX_METADATA,size-512):_fail('LVM_LAYOUT_UNSUPPORTED')
            first=min(length,size-off)
            raw=_read(source,begin+off,first)
            if first<length:raw+=_read(source,begin+512,length-first)
            if _crc(raw)!=check:_fail('LVM_METADATA_CHECKSUM_FAILED')
            locations.append(raw)
        if not locations or len(locations)>1:_fail('LVM_LAYOUT_UNSUPPORTED')
        raw_copies.extend(locations)
    if any(raw!=raw_copies[0] for raw in raw_copies):_fail('LVM_METADATA_COPIES_DISAGREE')
    raw=raw_copies[0]
    if not raw.endswith(b'\0') or raw.count(b'\0')!=1:_fail()
    text=raw[:-1].decode('ascii','strict')
    if len(text.splitlines())>32000 or max(map(len,text.splitlines()),default=0)>16384:_fail('LVM_METADATA_LIMIT')
    depth=0
    for character in text:
        depth+=int(character=='{')-int(character=='}')
        if not 0<=depth<=64:_fail('LVM_METADATA_LIMIT')
    if depth:_fail()
    from dissect.volume.lvm.physical import parse_metadata
    parsed=parse_metadata(text)
    groups=[(name,value) for name,value in parsed.items() if isinstance(value,dict)]
    if len(groups)!=1 or parsed.get('contents')!='Text Format Volume Group' or parsed.get('version')!=1:_fail('LVM_VERSION_UNSUPPORTED')
    name,group=groups[0]
    if not TOKEN.fullmatch(name) or group.get('format')!='lvm2' or group.get('flags') or 'READ' not in group.get('status',[]):_fail('LVM_LAYOUT_UNSUPPORTED')
    if set(group.get('status',[]))-{'RESIZEABLE','READ','WRITE'}:_fail('LVM_LAYOUT_UNSUPPORTED')
    source.update(pv_id=identifier,data_area=areas[0],metadata_sha256=hashlib.sha256(raw).hexdigest(),group=group,group_name=name)
    return source


class Logical(io.RawIOBase):
    def __init__(self,size,read_at):
        self.size,self.read_at,self.position=size,read_at,0
    def readable(self):return True
    def seekable(self):return True
    def seek(self,offset,whence=0):
        value=offset if whence==0 else self.position+offset if whence==1 else self.size+offset if whence==2 else -1
        if value<0:raise ValueError('negative seek')
        self.position=value;return value
    def tell(self):return self.position
    def read(self,length=-1):
        length=max(0,self.size-self.position) if length is None or length<0 else min(length,max(0,self.size-self.position))
        if length>MAX_METADATA:_fail('LVM_READ_LIMIT')
        data=self.read_at(self.position,length) if length else b''
        if len(data)!=length:_fail('LVM_SOURCE_TRUNCATED')
        self.position+=length;return data


class VolumeGroup:
    def __init__(self,sources):
        if any(s['metadata_sha256']!=sources[0]['metadata_sha256'] for s in sources):_fail('LVM_METADATA_COPIES_DISAGREE')
        self.group=sources[0]['group'];self.name=sources[0]['group_name'];self.sources=sources
        self.extent=_number(self.group.get('extent_size'),1,2**30)*512
        if self.extent&(self.extent-1):_fail()
        self.pvs=self.group.get('physical_volumes');self.lvs=self.group.get('logical_volumes')
        if not isinstance(self.pvs,dict) or not 1<=len(self.pvs)<=32 or not isinstance(self.lvs,dict) or not 1<=len(self.lvs)<=1024:_fail('LVM_METADATA_LIMIT')
        available={s['pv_id']:s for s in sources}
        if len(available)!=len(sources):_fail('LVM_DUPLICATE_MEMBER')
        self.physical={}
        for name,pv in self.pvs.items():
            if not TOKEN.fullmatch(name) or not isinstance(pv,dict):_fail()
            identifier=pv.get('id','').replace('-','')
            if identifier not in available:_fail('LVM_MEMBERS_MISSING')
            source=available.pop(identifier)
            start=_number(pv.get('pe_start'),1)*512
            count=_number(pv.get('pe_count'),1)
            declared=_number(pv.get('dev_size'),1)*512
            area,area_size=source['data_area']
            if (declared>source['bytes'] or start!=area or count*self.extent>source['bytes']-start or
                    area_size and count*self.extent>area_size):_fail('LVM_SOURCE_TRUNCATED')
            self.physical[name]=(source,start,count)
        if available:_fail('LVM_UNEXPECTED_MEMBER')
        self.opened={};self.thin_budget=[4096,262144];self.unavailable=[]

    def open(self,name,stack=()):
        if name in stack or len(stack)>=32:_fail('LVM_METADATA_CYCLE')
        if name in self.opened:return self.opened[name]
        lv=self.lvs.get(name)
        if not isinstance(lv,dict) or not TOKEN.fullmatch(name) or lv.get('flags') or 'READ' not in lv.get('status',[]):_fail('LVM_LAYOUT_UNSUPPORTED')
        count=_number(lv.get('segment_count'),1,1024)
        segments=[];end=0
        for n in range(1,count+1):
            segment=lv.get('segment'+str(n))
            if not isinstance(segment,dict):_fail()
            start=_number(segment.get('start_extent'))*self.extent
            length=_number(segment.get('extent_count'),1)*self.extent
            if start!=end or length>2**63-1-end:_fail()
            end+=length
            kind=segment.get('type')
            if kind=='striped':
                stripes=segment.get('stripes');amount=_number(segment.get('stripe_count'),1,32)
                if not isinstance(stripes,list) or len(stripes)!=amount*2 or length%amount:_fail()
                unit=length if amount==1 else _number(segment.get('stripe_size'),1,2**21)*512
                if unit&(unit-1) or length%(unit*amount):_fail('LVM_LAYOUT_UNSUPPORTED')
                members=[]
                for i in range(amount):
                    pvname,extent=stripes[2*i:2*i+2]
                    if pvname not in self.physical:_fail()
                    source,base,capacity=self.physical[pvname];extent=_number(extent)
                    if extent*self.extent+length//amount>capacity*self.extent:_fail('LVM_SOURCE_TRUNCATED')
                    members.append((source,base+extent*self.extent))
                def read_striped(offset,size,members=members,unit=unit):
                    pieces=[]
                    while size:
                        stripe,within=divmod(offset,unit);member=stripe%len(members);row=stripe//len(members)
                        take=min(size,unit-within);source,base=members[member]
                        pieces.append(_read(source,base+row*unit+within,take));offset+=take;size-=take
                    return b''.join(pieces)
                reader=read_striped
            elif kind=='mirror':
                mirrors=segment.get('mirrors');amount=_number(segment.get('mirror_count'),2,32)
                if segment.get('mirror_log') or segment.get('extents_moved') or not isinstance(mirrors,list) or len(mirrors)!=amount*2:_fail('LVM_LAYOUT_UNSUPPORTED')
                legs=[]
                for i in range(amount):
                    leg=self.open(mirrors[2*i],stack+(name,));base=_number(mirrors[2*i+1])*self.extent
                    if base>leg.size-length:_fail()
                    legs.append((leg,base))
                def read_mirror(offset,size,legs=legs):
                    first=legs[0][0].read_at(legs[0][1]+offset,size)
                    if any(leg.read_at(base+offset,size)!=first for leg,base in legs[1:]):_fail('LVM_MIRRORS_DISAGREE')
                    return first
                reader=read_mirror
            elif kind=='thin':
                if count!=1 or start!=0:_fail('LVM_THIN_STATE_UNSUPPORTED')
                pool_name=segment.get('thin_pool');pool_lv=self.lvs.get(pool_name)
                if not isinstance(pool_lv,dict) or pool_lv.get('segment_count')!=1:_fail('LVM_THIN_STATE_UNSUPPORTED')
                pool=pool_lv.get('segment1')
                if not isinstance(pool,dict) or pool.get('type')!='thin-pool':_fail('LVM_THIN_STATE_UNSUPPORTED')
                metadata=self.open(pool.get('metadata'),stack+(name,))
                data=self.open(pool.get('pool'),stack+(name,))
                from storage_lvm_thin import ThinMapping
                mapping=ThinMapping(metadata,data,pool,segment,length,self.thin_budget)
                reader=mapping.read_at
            else:_fail('LVM_SEGMENT_UNSUPPORTED')
            segments.append((start,length,reader))
        starts=[s[0] for s in segments]
        def read_at(offset,length):
            parts=[]
            while length:
                index=bisect.bisect_right(starts,offset)-1
                if index<0:_fail()
                begin,size,reader=segments[index];within=offset-begin;take=min(length,size-within)
                if take<=0:_fail()
                parts.append(reader(within,take));offset+=take;length-=take
            return b''.join(parts)
        result=Logical(end,read_at);self.opened[name]=result;return result

    def volumes(self):
        result=[]
        for name,lv in self.lvs.items():
            if not isinstance(lv,dict):_fail()
            if 'VISIBLE' not in lv.get('status',[]):continue
            if lv.get('segment_count')==1 and isinstance(lv.get('segment1'),dict) and lv['segment1'].get('type')=='thin-pool':continue
            try:
                volume=self.open(name)
                result.append({'kind':'LVM','name':self.name+'/'+name,'identifier':lv['id'],'offset_bytes':0,'length_bytes':volume.size})
            except RecoveryIOError as error:
                self.unavailable.append({'volume':self.name+'/'+name,'code':str(error)})
        return result


def handle_lvm(request,emit=None):
    try:
        if not isinstance(request,dict):_fail('INVALID_REQUEST')
        if request.get('operation') not in ('lvm_probe','lvm'):_fail('INVALID_REQUEST')
        options=request.get('options',{})
        paths=request.get('sources')
        if not isinstance(options,dict) or not isinstance(paths,list) or not 1<=len(paths)<=32:_fail('INVALID_REQUEST')
        resume=options.get('resume',False)
        if type(resume) is not bool:_fail('INVALID_REQUEST')
        with contextlib.ExitStack() as stack:
            sources=[]
            for value in paths:
                path=plain(value,True)
                if path.suffix.lower()=='.partial':_fail('INVALID_SOURCE')
                stream=stack.enter_context(read_only(path));size=os.fstat(stream.fileno()).st_size
                if size<2048 or size%512:_fail('LVM_SOURCE_TRUNCATED')
                identity=digest(stream,emit)
                physical=_physical({'path':str(path),'handle':stream,'bytes':size,'sha256':identity})
                if sources and physical['metadata_sha256']==sources[0]['metadata_sha256']:
                    physical['group']=sources[0]['group']
                sources.append(physical)
            group=VolumeGroup(sources);volumes=group.volumes()
            if request.get('operation')=='lvm_probe':
                return {'status':'partial' if group.unavailable else 'complete','code':'OK' if volumes else 'UNSUPPORTED_FORMAT','volumes':volumes,
                        'warnings':sorted({item['code'] for item in group.unavailable}) if volumes else ['LVM_NO_SUPPORTED_LOGICAL_VOLUMES'],
                        'unavailable_volumes':group.unavailable}
            identifier=options.get('volume_id')
            names=[name for name,lv in group.lvs.items() if lv.get('id')==identifier and 'VISIBLE' in lv.get('status',[])]
            if len(names)!=1:_fail('INVALID_REQUEST')
            volume=group.open(names[0]);maximum=options.get('max_output_bytes',32*1024**3)
            if type(maximum) is not int or not 1<=maximum<=1024**5 or volume.size>maximum:_fail('LVM_OUTPUT_LIMIT')
            destination=plain(request.get('destination'))
            for source in sources:
                if Path(source['path']).is_relative_to(destination) or destination==Path(source['path']):_fail('INVALID_DESTINATION')
            if destination.exists() and (not destination.is_dir() or any(destination.iterdir()) and not resume):_fail('INVALID_DESTINATION')
            destination.mkdir(parents=True,exist_ok=True)
            stack.enter_context(writer_lock(destination/'lvm.lock'))
            binding={'format':'LVM2','reader':1,'sources':[{k:s[k] for k in ('path','bytes','sha256','pv_id','metadata_sha256')} for s in sources],
                     'volume_id':identifier,'volume_bytes':volume.size,'max_output_bytes':maximum}
            image=destination/'lvm.dd'
            staged=stage(volume,volume.size,image,binding,resume,emit,'lvm-copy',destination/'lvm-resume.json')
            if any(digest(s['handle'])!=s['sha256'] for s in sources):_fail('SOURCE_CHANGED')
            report={'schema':1,'status':'complete','format':'LVM2','source_binding':binding,'image_sha256':staged['sha256'],
                    'group':group.name,'volume':names[0],'resumed_bytes':staged['resumed_bytes'],
                    'validation':'metadata-crc-and-checked-mapping-mirror-legs-compared',
                    'limitations':['NO_DELETION_GUARANTEE','NO_RESHAPE_CACHE_RAID_INTEGRITY_OR_DAMAGED_METADATA_RECONSTRUCTION','THIN_SELECTED_MAPPING_CHECKED_ALLOCATION_REFCOUNTS_NOT_CERTIFIED']}
            atomic(destination/'lvm-report.json',report)
            atomic_bytes(destination/'lvm.dd.sha256',(staged['sha256']+'  lvm.dd\n').encode('ascii'))
            publish(staged,image)
            return {'status':'complete','code':'OK','image':'lvm.dd','bytes':volume.size,'image_sha256':staged['sha256'],'report':'lvm-report.json','warnings':[]}
    except RecoveryIOError as error:
        return {'status':'error','code':str(error),'warnings':[]}
    except (ValueError,TypeError,KeyError,UnicodeError,OverflowError,RecursionError):
        return {'status':'error','code':'LVM_METADATA_INVALID','warnings':[]}
    except ImportError:
        return {'status':'error','code':'DEPENDENCY_MISSING','warnings':[]}
    except OSError:
        return {'status':'error','code':'IO_ERROR','warnings':[]}
    except Exception:
        return {'status':'error','code':'LVM_METADATA_INVALID','warnings':[]}
