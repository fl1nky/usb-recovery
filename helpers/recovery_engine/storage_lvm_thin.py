# SPDX-License-Identifier: AGPL-3.0-or-later
"""Checked selected dm-thin mappings; never infer a hole from a failed lookup.

Layout/checksum constants: Linux v6.12 dm-thin-metadata.c, dm-btree-spine.c
and dm-block-manager.c. Only v2 clean, ordinary 4096-byte metadata is accepted.
Allocation/refcount space maps are not certified and no free-block undelete
is attempted. The selected device's complete mapping tree is checked first.
"""
import struct

from recovery_io import RecoveryIOError


def _fail(code='LVM_THIN_METADATA_INVALID'):
    raise RecoveryIOError(code)


def _table():
    result=[]
    for value in range(256):
        for _ in range(8):value=(value>>1)^(0x82f63b78 if value&1 else 0)
        result.append(value)
    return tuple(result)


CRC_TABLE=_table()


def crc32c_raw(data):
    value=0xffffffff
    for byte in data:value=CRC_TABLE[(value^byte)&255]^(value>>8)
    return value


class ThinMapping:
    MAX_NODES=4096
    MAX_ENTRIES=262144

    def __init__(self,metadata,data,pool,segment,length,budget=None):
        from dissect.volume.dm.c_dm import c_dm
        self.metadata,self.data,self.nodes=metadata,data,{}
        self.budget=budget if budget is not None else [self.MAX_NODES,self.MAX_ENTRIES]
        if metadata.size<4096:_fail()
        raw=metadata.read_at(0,4096)
        if len(raw)!=4096 or struct.unpack_from('<I',raw)[0]!=(crc32c_raw(raw[4:])^160774):_fail('LVM_THIN_CHECKSUM_FAILED')
        sb=c_dm.thin_disk_superblock(raw)
        if sb.magic!=27022010 or sb.version!=2:_fail('LVM_THIN_VERSION_UNSUPPORTED')
        if sb.flags or sb.held_root or sb.compat_flags or sb.compat_ro_flags or sb.incompat_flags:_fail('LVM_THIN_STATE_UNSUPPORTED')
        if sb.blocknr!=0 or sb.metadata_block_size!=8 or not 1<=sb.metadata_nr_blocks<=metadata.size//4096:_fail()
        self.metadata_blocks=int(sb.metadata_nr_blocks)
        self.block_size=int(sb.data_block_size)*512
        if (not 512<=self.block_size<=64*1024*1024 or self.block_size&(self.block_size-1) or
                pool.get('chunk_size')*512!=self.block_size or pool.get('transaction_id')!=sb.trans_id):_fail('LVM_THIN_STATE_UNSUPPORTED')
        data_blocks=struct.unpack_from('<Q',bytes(sb.data_space_map_root))[0]
        if not 1<=data_blocks<=data.size//self.block_size:_fail()
        device=segment.get('device_id')
        if type(device) is not int or not 0<=device<(1<<24):_fail()
        details=self.tree(int(sb.device_details_root),24)
        roots=self.tree(int(sb.data_mapping_root),8)
        if device not in details or device not in roots:_fail('LVM_THIN_DEVICE_MISSING')
        expected=struct.unpack_from('<Q',details[device])[0]
        entries=self.tree(int.from_bytes(roots[device],'little'),8)
        if len(entries)!=expected:_fail()
        self.mapping={}
        for logical,value in entries.items():
            physical=int.from_bytes(value,'little')>>24
            if logical>=(length+self.block_size-1)//self.block_size or physical>=data_blocks:_fail()
            self.mapping[logical]=physical

    def node(self,address,value_size):
        if not 0<address<self.metadata_blocks:_fail()
        if address not in self.nodes:
            if len(self.nodes)>=self.MAX_NODES or self.budget[0]<=0:_fail('LVM_THIN_METADATA_LIMIT')
            self.budget[0]-=1
            raw=self.metadata.read_at(address*4096,4096)
            if len(raw)!=4096 or struct.unpack_from('<I',raw)[0]!=(crc32c_raw(raw[4:])^121107):_fail('LVM_THIN_CHECKSUM_FAILED')
            self.nodes[address]=raw
        raw=self.nodes[address]
        _,flags,block,entries,maximum,width,padding=struct.unpack_from('<IIQIIII',raw)
        if (flags not in (1,2) or block!=address or padding or not 1<=maximum<=4096 or entries>maximum or
                width!=(8 if flags==1 else value_size) or 32+maximum*(8+width)>4096 or flags==1 and not entries):_fail()
        keys=list(struct.unpack_from('<'+'Q'*entries,raw,32))
        if any(a>=b for a,b in zip(keys,keys[1:])):_fail()
        base=32+maximum*8
        values=[raw[base+i*width:base+(i+1)*width] for i in range(entries)]
        return flags,keys,values

    def tree(self,root,width):
        output={};pending=[(root,0,None,None)];visited=set()
        while pending:
            address,depth,low,high=pending.pop()
            if address in visited or depth>64:_fail('LVM_THIN_METADATA_CYCLE')
            visited.add(address)
            flags,keys,values=self.node(address,width)
            if any(low is not None and k<low or high is not None and k>=high for k in keys):_fail()
            if flags==1:
                for i,(key,value) in enumerate(zip(keys,values)):
                    pending.append((int.from_bytes(value,'little'),depth+1,key,keys[i+1] if i+1<len(keys) else high))
            else:
                for key,value in zip(keys,values):
                    if key in output or len(output)>=self.MAX_ENTRIES or self.budget[1]<=0:_fail('LVM_THIN_METADATA_LIMIT')
                    self.budget[1]-=1
                    output[key]=value
        return output

    def read_at(self,offset,length):
        pieces=[]
        while length:
            block,within=divmod(offset,self.block_size);take=min(length,self.block_size-within)
            physical=self.mapping.get(block)
            # Absence is known only after the full mapping tree was checked.
            # Stop at this block so a later mapped block cannot become zeros.
            pieces.append(bytes(take) if physical is None else self.data.read_at(physical*self.block_size+within,take))
            offset+=take;length-=take
        return b''.join(pieces)
