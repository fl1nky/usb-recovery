"""Turn only the synthetic regular .dd into a deleted, fragmented NTFS fixture.

Before use, create AdvancedNtfs.dd using mkntfs and ntfscp on an ordinary file.
No mounted volume, raw Windows device, or real user file is accepted or modified.
"""
from pathlib import Path
import struct, hashlib, json

root = Path(__file__).resolve().parent
image = root / 'AdvancedNtfs.dd'
assert image.is_file() and not image.is_symlink() and image.stat().st_size == 64 * 1024 * 1024
u16 = lambda b, o: struct.unpack_from('<H', b, o)[0]
u32 = lambda b, o: struct.unpack_from('<I', b, o)[0]
u64 = lambda b, o: struct.unpack_from('<Q', b, o)[0]

def decode_runs(data):
    runs=[]; pos=0; lcn=0
    while data[pos]:
        tag=data[pos]; pos+=1; a=tag&15; b=tag>>4
        length=int.from_bytes(data[pos:pos+a], 'little'); pos+=a
        delta=int.from_bytes(data[pos:pos+b], 'little', signed=True); pos+=b
        lcn+=delta; runs.append((lcn,length))
    return runs

def encode_runs(runs):
    result=bytearray(); previous=0
    for lcn,length in runs:
        delta=lcn-previous; previous=lcn
        length_bytes=length.to_bytes(max(1,(length.bit_length()+7)//8),'little')
        dsize=next(n for n in range(1,9) if -(1<<(8*n-1))<=delta<(1<<(8*n-1)))
        delta_bytes=delta.to_bytes(dsize,'little',signed=True)
        result.append((len(delta_bytes)<<4)|len(length_bytes)); result.extend(length_bytes); result.extend(delta_bytes)
    result.append(0); return result

with image.open('r+b') as stream:
    def read_at(offset,size):
        stream.seek(offset); b=stream.read(size); assert len(b)==size; return b
    def write_at(offset,data):
        assert 0<=offset<=image.stat().st_size-len(data); stream.seek(offset); stream.write(data)
    boot=read_at(0,512); assert boot[3:11]==b'NTFS    '
    cluster=u16(boot,11)*boot[13]; mft=u64(boot,48)*cluster
    record_size=1<<(-struct.unpack_from('b',boot,64)[0])
    def attributes(record):
        o=u16(record,20)
        while u32(record,o)!=0xffffffff:
            size=u32(record,o+4); assert size>=24 and o+size<=len(record)
            yield o,u32(record,o),record[o:o+size]; o+=size
    def attr_record(index,kind):
        record=read_at(mft+index*record_size,record_size)
        assert record[:4]==b'FILE'
        return record,next(x for x in attributes(record) if x[1]==kind)
    target=None
    for index in range(16,256):
        record=read_at(mft+index*record_size,record_size)
        if record[:4]!=b'FILE': continue
        if 'grandma-photo.jpg'.encode('utf-16le') in record:
            target=index; break
    assert target is not None
    record,(offset,kind,dataattr)=attr_record(target,0x80)
    assert dataattr[8]==1
    oldruns=decode_runs(dataattr[u16(dataattr,32):]); length=u64(dataattr,48)
    payload=b''.join(read_at(lcn*cluster,n*cluster) for lcn,n in oldruns)[:length]
    expected=(root/'photorec-20261011T231546120952Z'/'fixtures'/'expected.jpg').read_bytes()
    assert payload==expected
    _,(_,_,volumeattr)=attr_record(6,0x80)
    assert volumeattr[8]==1
    volruns=decode_runs(volumeattr[u16(volumeattr,32):])
    def bit_location(runs,bit):
        byte=bit//8
        for lcn,n in runs:
            extent=n*cluster
            if byte<extent:return lcn*cluster+byte
            byte-=extent
        raise AssertionError('bitmap exhausted')
    def free_bit(runs,bit):
        o=bit_location(runs,bit); current=read_at(o,1)[0];write_at(o,bytes([current&~(1<<(bit%8))]))
    blocks=(length+cluster-1)//cluster
    assert blocks>=2
    start=oldruns[0][0]; far=start+1000
    assert far+blocks<image.stat().st_size//cluster
    for c in range(far,far+blocks-1):
        o=bit_location(volruns,c);assert read_at(o,1)[0]&(1<<(c%8))==0
    newruns=[(start,1),(far,blocks-1)]
    write_at(far*cluster,payload[cluster:]+b'\0'*(blocks*cluster-length))
    mapping=encode_runs(newruns); runoffset=u16(dataattr,32)
    if runoffset+len(mapping)>len(dataattr):
        grow=((runoffset+len(mapping)+7)//8)*8-len(dataattr)
        assert u32(record,24)+grow<510
        attr_end=offset+len(dataattr)
        updated=bytearray(record[:attr_end]+b'\0'*grow+record[attr_end:-grow])
        struct.pack_into('<I',updated,offset+4,len(dataattr)+grow)
        struct.pack_into('<I',updated,24,u32(record,24)+grow)
        write_at(mft+target*record_size,updated)
        dataattr=bytes(updated[offset:offset+len(dataattr)+grow])
    write_at(mft+target*record_size+offset+runoffset,mapping+b'\0'*(len(dataattr)-runoffset-len(mapping)))
    flags=u16(record,22); assert flags&1
    write_at(mft+target*record_size+22,struct.pack('<H',flags&~1))
    _,(bitoff,_,mftbitmap)=attr_record(0,0xb0)
    if mftbitmap[8]==0:
        o=mft+bitoff+u16(mftbitmap,20)+target//8; current=read_at(o,1)[0]
        write_at(o,bytes([current&~(1<<(target%8))]))
    else:
        free_bit(decode_runs(mftbitmap[u16(mftbitmap,32):]),target)
    for lcn,n in oldruns+newruns:
        for c in range(lcn,lcn+n):free_bit(volruns,c)
    stream.flush()

report={'regular_image':str(image),'record':target,'expected_name':'grandma-photo.jpg','expected_sha256':hashlib.sha256(expected).hexdigest(),'length':length,'old_runs':oldruns,'fragmented_deleted_runs':newruns,'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest()}
(root/'AdvancedNtfs.fixture.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report))
