# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic ReFS structural regressions, not Windows-formatted volume evidence.

Layouts are based on libyal/libfsrefs and xbqt/forefst primary documentation.
Native-volume and independent extraction evidence is recorded separately; these
writer-defined images cannot independently establish native compatibility.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct

def sha256_bytes(data): return hashlib.sha256(data).hexdigest()
def copy_native_metadata(source, destination):
    source=Path(source);destination=Path(destination)
    manifest=source/'native_metadata.json'
    if not manifest.exists(): return
    meta=json.loads(manifest.read_text(encoding='utf-8-sig'))
    destination.mkdir(parents=True,exist_ok=True)
    for item in meta['fixtures']:
        name=item['file']
        if Path(name).name!=name: raise ValueError('Native metadata path is not a basename')
        data=(source/name).read_bytes()
        if len(data)!=item['bytes'] or sha256_bytes(data)!=item['sha256']: raise ValueError('Native metadata hash mismatch')
        (destination/name).write_bytes(data)
    (destination/'native_metadata.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
def crc32c(data, seed=0xffffffff):
    for b in data:
        seed ^= b
        for _ in range(8): seed = (seed >> 1) ^ (0x82f63b78 if seed & 1 else 0)
    return seed ^ 0xffffffff
def crc64_nvme(data, seed=0xffffffffffffffff):
    for b in data:
        seed ^= b
        for _ in range(8): seed = (seed >> 1) ^ (0x9a6c9329ac4bc9b5 if seed & 1 else 0)
    result = seed ^ 0xffffffffffffffff
    return 0xabbaffffabbaffff if result == 0xabbaffffabbafffe else result

def row(key, value, flags=0):
    size = (16 + len(key) + len(value) + 7) & ~7
    result = bytearray(size)
    struct.pack_into('<I6H', result, 0, size, 16, len(key), flags, 16+len(key), len(value), 0)
    result[16:16+len(key)] = key
    result[16+len(key):16+len(key)+len(value)] = value
    return result

def node(records, major=3, header=b'', level=0, total_size=None):
    hdr = 32 if major == 1 else 40
    start = 40 + len(header)
    packed = [row(*r) for r in records]
    needed = start + hdr + sum(map(len,packed)) + 4*len(records)
    result = bytearray(total_size or ((needed+7)&~7))
    struct.pack_into('<I', result, 0, start)
    struct.pack_into('<H', result, 4, 40)
    result[40:40+len(header)] = header
    offsets=[]; at=start+hdr
    for r in packed:
        offsets.append(at-start);result[at:at+len(r)] = r;at+=len(r)
    end=at-start; array=len(result)-start-4*len(records)
    struct.pack_into('<III',result,start,hdr,end,array-end)
    result[start+12]=level;result[start+13]=1 if level else 2
    struct.pack_into('<III',result,start+16,array,len(records),array+len(records)*4)
    if major==3:struct.pack_into('<I',result,start+32,array+len(records)*4)
    for i,off in enumerate(offsets):struct.pack_into('<I',result,start+array+i*4,off | (0xffff0000 if major==3 else 0))
    return result

class ReFSVolumeBuilder:
    def __init__(self, major=3, minor=14, cluster_size=4096, total_clusters=2048, sector_size=512, checksum_type=2):
        self.major=major;self.minor=minor;self.cluster_size=cluster_size;self.sector_size=sector_size
        self.meta_block_size=16384 if major==1 else cluster_size
        self.page_size=16384 if self.meta_block_size==4096 else self.meta_block_size
        self.header_size=48 if major==1 else 80
        self.checksum_type=checksum_type
        self.ref_size=24 if major==1 else (72 if checksum_type==4 else 48)
        self.page_blocks={}
        self.image=bytearray(total_clusters*cluster_size)
    def address(self,label): return label*4 if self.major==3 and self.cluster_size==4096 and label>=33 else label
    def digest(self,data,kind=None):
        kind=self.checksum_type if kind is None else kind
        if kind==1:return struct.pack('<I',crc32c(data))
        if kind==2:return struct.pack('<Q',crc64_nvme(data))
        if kind==4:return hashlib.sha256(data).digest()
        return b''
    def write_vbr(self, sector_offset=0, backup=False):
        b=bytearray(self.sector_size);b[:3]=b'\xebR\x90';b[3:11]=b'ReFS\0\0\0\0';b[16:20]=b'FSRS'
        struct.pack_into('<QII',b,24,len(self.image)//self.sector_size,self.sector_size,self.cluster_size//self.sector_size)
        b[40]=self.major;b[41]=self.minor;struct.pack_into('<Q',b,64,0x4000000)
        b[510:512]=b'\x55\xaa';self.image[sector_offset:sector_offset+len(b)]=b
    def write_block_ref(self,target,offset,block_num,expected_crc=None,crc_type=None,physical=False):
        kind=self.checksum_type if crc_type is None else crc_type
        number=block_num if physical else self.address(block_num)
        slots=1 if self.major==1 else 4
        for i in range(slots):
            numbers=self.page_blocks.get(block_num)
            n=numbers[i] if numbers and not physical else number+i if number and i<self.page_size//self.meta_block_size and not physical else number if i==0 else 0
            struct.pack_into('<Q',target,offset+i*8,n)
        d=offset+(8 if self.major==1 else 32)
        digest=expected_crc
        if digest is None:kind=0;digest=b''
        if isinstance(digest,int):digest=struct.pack('<I' if kind==1 else '<Q',digest)
        struct.pack_into('<HBBHH',target,d,0,kind,8,len(digest),0)
        target[d+8:d+8+len(digest)]=digest
    def seal_self(self,b,at,size,number,kind=1,corrupt=False):
        struct.pack_into('<II',b,self.header_size+(40 if b[:4]==b'SUPB' or self.major==1 and number==30 else 8),at,size)
        b[at:at+size]=bytes(size)
        digest=self.digest(b,kind)
        if corrupt:digest=bytes([digest[0]^1])+digest[1:]
        self.write_block_ref(b,at,number,digest,kind,physical=True)
    def meta_header(self,b,number,signature):
        if self.major==1:struct.pack_into('<Q',b,0,number)
        else:b[:4]=signature;struct.pack_into('<I',b,4,2);struct.pack_into('<Q',b,32,number)
    def write_superblock(self,primary_chkp=31,secondary_chkp=32,seq=1):
        b=bytearray(self.meta_block_size);self.meta_header(b,30,b'SUPB');h=self.header_size
        struct.pack_into('<QII',b,h+24,seq,128 if self.major==1 else 192,2)
        cp=128 if self.major==1 else 192;struct.pack_into('<QQ',b,cp,primary_chkp,secondary_chkp)
        at=144 if self.major==1 else 208;size=24 if self.major==1 else 48
        self.seal_self(b,at,size,30)
        self.image[30*self.meta_block_size:31*self.meta_block_size]=b
    def write_checkpoint(self,block_num,seq,tree0_block,tree0_crc=None,tree7_block=0,tree7_crc=None,corrupt=False,**kwargs):
        b=bytearray(self.meta_block_size);self.meta_header(b,block_num,b'CHKP');h=self.header_size
        struct.pack_into('<HH',b,h+4,self.major,self.minor);struct.pack_into('<Q',b,h+16,seq)
        count=1 if self.major==1 else 8;cp=h+16+(24 if self.major==1 else 48)
        struct.pack_into('<I',b,cp,count);base=512
        for i in range(count):struct.pack_into('<I',b,cp+4+i*4,base+i*self.ref_size)
        self.write_block_ref(b,base,tree0_block,tree0_crc)
        if tree7_block:self.write_block_ref(b,base+7*self.ref_size,tree7_block,tree7_crc)
        self.seal_self(b,256,24 if self.major==1 else 48,block_num,corrupt=corrupt)
        off=block_num*self.meta_block_size;self.image[off:off+len(b)]=b
    def write_btree_leaf(self,block_num,records,corrupt=False,level=0):
        b=bytearray(self.page_size);number=self.address(block_num);self.meta_header(b,number,b'MSB+')
        b[self.header_size:]=node(records,self.major,level=level,total_size=len(b)-self.header_size)
        checksum=self.digest(b)
        if corrupt:b[-1]^=1
        numbers=self.page_blocks.get(block_num)
        if numbers:
            for i,n in enumerate(numbers):
                off=n*self.meta_block_size;self.image[off:off+self.meta_block_size]=b[i*self.meta_block_size:(i+1)*self.meta_block_size]
        else:
            off=number*self.meta_block_size;self.image[off:off+len(b)]=b
        return checksum
    def build_object_record_key(self,object_id):return struct.pack('<QQ',0,object_id)
    def build_object_record_value(self,target_block,expected_crc=None):
        prefix=0 if self.major==1 else 32
        v=bytearray(max(48,prefix+self.ref_size));self.write_block_ref(v,prefix,target_block,expected_crc);return bytes(v)
    def build_container_record(self,container_id,physical_start_cluster,cluster_count=None):
        v=bytearray(224 if self.cluster_size==65536 or self.checksum_type==4 else 160)
        struct.pack_into('<Q',v,0,container_id);struct.pack_into('<I',v,24,cluster_count or 0x4000000//self.cluster_size)
        struct.pack_into('<QQ',v,len(v)-16,physical_start_cluster,cluster_count or 0x4000000//self.cluster_size)
        return bytes(v[:16]),bytes(v)
    def build_dir_entry_record(self,name,entry_type,child_object_id=0,payload=b'',is_resident=True,cluster_extents=None,compressed=False):
        key=struct.pack('<HH',0x30,entry_type)+name.encode('utf-16le',errors='surrogatepass');ft=133443264000000000
        if entry_type==2:
            v=bytearray(72);struct.pack_into('<Q',v,0 if self.major==1 else 8,child_object_id)
            struct.pack_into('<I',v,64,0x10 if self.major==1 else 0x10000000);return key,bytes(v)
        fh=bytearray(128);struct.pack_into('<QQQQI',fh,0,ft,ft,ft,ft,0x820 if compressed else 0x20)
        struct.pack_into('<QQ',fh,64,len(payload),len(payload))
        if self.major==1:
            ak=struct.pack('<QI',44+len(payload),0x80)+b'\0\0'
            if is_resident:
                av=bytearray(44)+payload;struct.pack_into('<III',av,0,0,44,len(payload))
            else:
                rh=bytearray(96);struct.pack_into('<I',rh,0,1);struct.pack_into('<Q',rh,20,len(payload))
                runs=[(struct.pack('<QQ',log//16384,cnt),struct.pack('<QQQ',log//16384,cnt,phys//4)) for log,cnt,phys in cluster_extents]
                av=node(runs,1,bytes(rh))
        elif is_resident:
            ak=struct.pack('<QIHH',60+len(payload),0x80000001,0x80,0x000e)
            av=bytearray(60)+payload;struct.pack_into('<III',av,0,0,len(av)-12,12);struct.pack_into('<I',av,12,48)
            struct.pack_into('<QQQ',av,24,len(payload),len(payload),len(payload))
        else:
            ak=bytearray(40);struct.pack_into('<IHHI',ak,8,0x80000002,0x80,0x000e,0x1000)
            runs=[]
            for logical,count,physical in cluster_extents:
                run=bytearray(24);struct.pack_into('<QHHIII',run,0,physical,0x50,24,logical//self.cluster_size,0,count);runs.append(run)
            n=40+sum(map(len,runs))+4*len(runs);av=bytearray(136+n);struct.pack_into('<I',av,0,136)
            struct.pack_into('<QQQ',av,48,len(payload),len(payload),len(payload))
            nh=136;end=40+sum(map(len,runs));struct.pack_into('<III',av,nh,40,end,0)
            struct.pack_into('<II',av,nh+16,end,len(runs));struct.pack_into('<I',av,nh+32,end+len(runs)*4)
            at=nh+40
            for i,run in enumerate(runs):
                av[at:at+24]=run;struct.pack_into('<I',av,nh+end+i*4,(at-nh)|0xffff0000);at+=24
        return key,bytes(node([(bytes(ak),bytes(av))],self.major,bytes(fh)))
    def write_raw_data(self,cluster,data):self.image[cluster*self.cluster_size:cluster*self.cluster_size+len(data)]=data
    def finalize(self):return bytes(self.image)

def basic(major=3,checksum_type=2,cluster_size=4096,version=14):
    b=ReFSVolumeBuilder(major,2 if major==1 else version,cluster_size=cluster_size,checksum_type=checksum_type)
    b.write_vbr();return b

def finish(b,records,seq0=10,seq1=9,corrupt_leaf=False):
    dr=b.write_btree_leaf(34,records,corrupt=corrupt_leaf)
    ob=b.write_btree_leaf(33,[(b.build_object_record_key(0x600),b.build_object_record_value(34,dr))])
    ct=b.write_btree_leaf(35,[b.build_container_record(2,800)]) if b.major==3 else None
    b.write_superblock();b.write_checkpoint(31,seq0,33,ob,35 if ct else 0,ct);b.write_checkpoint(32,seq1,33,ob,35 if ct else 0,ct)
    return b

def generate_fixtures(destination):
    destination.mkdir(parents=True,exist_ok=True)
    manifest={'version':2,'provenance':'Synthetic structural regressions only. Native evidence and independent content oracle are separate.','cases':[]}
    def save(name,b,payload=None,target=None,outcome='recover',**extra):
        data=b.finalize();(destination/(name+'.dd')).write_bytes(data)
        case=dict(name=name,image=name+'.dd',sha256=sha256_bytes(data),outcome=outcome,expected_version=f'{b.major}.{b.minor}',**extra)
        if target is not None:case.update(target_name=target,payload_sha256=sha256_bytes(payload))
        manifest['cases'].append(case)
    for major in (1,3):
        b=basic(major);p=b'Legacy documented inline structure' if major==1 else b'Inline stream on ReFS 3.14'
        finish(b,[b.build_dir_entry_record('hello.txt',1,payload=p)]);save('refs-v12-minimal' if major==1 else 'refs-v314-minimal',b,p,'hello.txt')
    b=basic();p=bytes(range(256))*37;b.write_raw_data(100,p[:4096]);b.write_raw_data(200,p[4096:])
    finish(b,[b.build_dir_entry_record('fragmented.bin',1,payload=p,is_resident=False,cluster_extents=[(0,1,100),(4096,2,200)])]);save('refs-v314-discontiguous',b,p,'fragmented.bin')
    b=basic();b.page_blocks[34]=[136,900,902,904];p=b'Four page slots in a non-contiguous order'
    finish(b,[b.build_dir_entry_record('scattered.txt',1,payload=p)]);save('refs-four-page-slots',b,p,'scattered.txt')
    b=basic();p=b'Translated from container 2';b.write_raw_data(810,p)
    finish(b,[b.build_dir_entry_record('container.bin',1,payload=p,is_resident=False,cluster_extents=[(0,1,0x10000+10)])]);save('refs-container',b,p,'container.bin')
    b=basic();p=b'Nested directory'
    child=b.write_btree_leaf(36,[b.build_dir_entry_record('report.txt',1,payload=p)])
    root=b.write_btree_leaf(34,[b.build_dir_entry_record('Docs',2,child_object_id=0x701)])
    ob=b.write_btree_leaf(33,[(b.build_object_record_key(0x600),b.build_object_record_value(34,root)),(b.build_object_record_key(0x701),b.build_object_record_value(36,child))])
    b.write_superblock();b.write_checkpoint(31,10,33,ob);b.write_checkpoint(32,9,33,ob);save('refs-nested-dirs',b,p,'report.txt',expected_path='Docs/report.txt')
    b=basic(checksum_type=4,cluster_size=65536);p=b'Independent checksum algorithm selection';finish(b,[b.build_dir_entry_record('sha256.txt',1,payload=p)]);save('refs-sha256-64k',b,p,'sha256.txt')
    b=basic();p=b'Backup VBR';finish(b,[b.build_dir_entry_record('backup.txt',1,payload=p)]);b.write_vbr(len(b.image)-512);b.image[:512]=bytes(512);save('refs-backup-vbr',b,p,'backup.txt')
    b=basic();p=b'Clock 43';finish(b,[b.build_dir_entry_record('active.txt',1,payload=p)],42,43);save('refs-checkpoint-pingpong',b,p,'active.txt')
    b=basic();finish(b,[b.build_dir_entry_record('bad.txt',1,payload=b'bad')],corrupt_leaf=True);save('refs-corrupted-crc',b,outcome='reject')
    b=basic();finish(b,[b.build_dir_entry_record('compressed.bin',1,payload=b'data',compressed=True)]);save('refs-unsupported-compression',b,outcome='reject')
    b=basic();p='Unicode 🚀'.encode();finish(b,[b.build_dir_entry_record('Project🚀Plan.txt',1,payload=p)]);save('refs-unicode-surrogates',b,p,'Project🚀Plan.txt')
    b=basic();finish(b,[b.build_dir_entry_record('live.txt',1,payload=b'live')]);p=b'Unreferenced structural candidate'
    b.write_btree_leaf(80,[b.build_dir_entry_record('unreferenced.txt',1,payload=p)]);save('refs-unreferenced-salvage',b,p,'unreferenced.txt',outcome='salvage')
    (destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    (destination/'PROVENANCE.txt').write_text(manifest['provenance']+'\n',encoding='utf-8')
    copy_native_metadata(Path(__file__).resolve().parent/'fixtures'/'refs',destination)
    print(f"Generated {len(manifest['cases'])} structural ReFS fixtures")
    return manifest

def package_fixtures(source: Path, destination: Path):
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8-sig"))
    destination.mkdir(parents=True, exist_ok=True)
    manifest["compressed_images"] = {}
    for case in manifest["cases"]:
        name = case["image"]
        if Path(name).name != name: raise ValueError("Fixture image must be a basename")
        data = (source / name).read_bytes()
        if sha256_bytes(data) != case['sha256']: raise ValueError("Fixture source hash mismatch")
        target = destination / (name + ".gz")
        with target.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as comp:
                comp.write(data)
        manifest["compressed_images"][name] = {
            "archive": target.name,
            "archive_sha256": sha256_bytes(target.read_bytes()),
            "bytes": len(data),
        }
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "PROVENANCE.txt").write_text(
        "Synthetic structural regressions only; not independent native-volume evidence.\n",
        encoding="utf-8",
    )
    copy_native_metadata(source,destination)
    print(f"Packaged {len(manifest['compressed_images'])} fixtures to {destination}")


def extract_fixtures(source: Path, destination: Path):
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8-sig"))
    destination.mkdir(parents=True, exist_ok=True)
    images = manifest.get("compressed_images", {})
    if images:
        for name, details in images.items():
            if Path(name).name != name or Path(details['archive']).name != details['archive']:
                raise ValueError("Fixture paths must be basenames")
            archive = source / details["archive"]
            if sha256_bytes(archive.read_bytes()) != details['archive_sha256']:
                raise ValueError("Compressed fixture hash mismatch")
            target = destination / name
            if target.exists():
                try:
                    target.chmod(0o666)
                except Exception:
                    pass
            with gzip.open(archive, "rb") as comp:
                expected = details['bytes']
                if not 0 < expected <= 128 * 1024 * 1024: raise ValueError("Fixture size outside extraction bound")
                data = comp.read(expected + 1)
                case = next(c for c in manifest['cases'] if c['image'] == name)
                if len(data) != expected or sha256_bytes(data) != case['sha256']:
                    raise ValueError("Extracted fixture hash or size mismatch")
                target.write_bytes(data)
    else:
        # If not compressed, copy .dd files
        for case in manifest["cases"]:
            name = case["image"]
            target = destination / name
            if target.exists():
                try:
                    target.chmod(0o666)
                except Exception:
                    pass
            shutil.copy2(source / name, target)
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    copy_native_metadata(source,destination)
    print(f"Extracted {len(manifest['cases'])} fixtures to {destination}")


def main():
    parser = argparse.ArgumentParser(description="ReFS test fixture generator and packager.")
    parser.add_argument("--destination", type=Path, help="Target directory for generated or extracted fixtures.")
    parser.add_argument("--package", type=Path, help="Package fixtures into target directory with .gz compression.")
    parser.add_argument("--extract", type=Path, help="Extract packaged fixtures from source directory.")
    args = parser.parse_args()

    if args.extract and args.destination:
        extract_fixtures(args.extract, args.destination)
    elif args.package:
        temp_dir = Path(".build/temp-refs-fixtures")
        generate_fixtures(temp_dir)
        package_fixtures(temp_dir, args.package)
        shutil.rmtree(temp_dir, ignore_errors=True)
    elif args.destination:
        generate_fixtures(args.destination)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
