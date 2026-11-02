# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic negative regressions. Does not prove native compatibility."""
from pathlib import Path
import argparse
import json
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.refs_fixture_generator import basic, finish, sha256_bytes, node, row

def make_adv_fixtures(dest):
    dest.mkdir(parents=True, exist_ok=True)
    cases=[]
    def base():
        b=basic();finish(b,[b.build_dir_entry_record('control.txt',1,payload=b'controlled exact bytes')]);return b
    def save(name,b,files=0,**expected):
        data=b.finalize();filename=name+'.dd';(dest/filename).write_bytes(data)
        cases.append(dict(name=name,image=filename,sha256=sha256_bytes(data),files=files,**expected))
    b=base();b.image[0:512]=bytes(512);save('adv-vbr-both-corrupt',b,volumes=0)
    b=base();struct.pack_into('<II',b.image,32,0,0);save('adv-vbr-invalid-geom',b,volumes=0,skip='invalid_vbr_geometry')
    b=base();b.image[40]=2;save('adv-version-2',b,reason='unsupported_refs_major_version_2')
    b=base();b.image[30*4096+260]^=1;save('adv-superblock-self-crc',b,reason='superblock_unreadable_or_corrupt')
    b=base();b.image[31*4096+256+34]=0;b.image[32*4096+256+34]=0;save('adv-checkpoint-no-checksum',b,reason='all_checkpoints_corrupt')
    b=base();b.image[32*4096+500]^=1;save('adv-checkpoint-fallback',b,files=1,warning='checkpoint_crc_corrupted_fallback_used')
    b=basic(checksum_type=4,cluster_size=65536);finish(b,[b.build_dir_entry_record('sha256-bad.txt',1,payload=b'blocked')],corrupt_leaf=True);save('adv-sha256-bit-corrupt',b,warning='metadata_checksum_mismatch')
    for name,kind,zero in [('adv-root-no-checksum',0,False),('adv-root-unknown-checksum',3,False),('adv-root-zero-checksum',2,True)]:
        b=base()
        for number in (31,32):
            offset=number*4096;page=bytearray(b.image[offset:offset+4096]);page[512+34]=kind
            if zero:page[512+40:512+48]=bytes(8)
            b.seal_self(page,256,48,number);b.image[offset:offset+4096]=page
        save(name,b,warning='metadata_checksum_mismatch')
    b=basic();p=b'cannot read past source';finish(b,[b.build_dir_entry_record('oob.bin',1,payload=p,is_resident=False,cluster_extents=[(0,1,0xffffffffffffffff)])]);save('adv-extent-oob',b,skip='data_extent_layout_or_coverage_unsupported')
    b=basic();finish(b,[b.build_dir_entry_record('gap.bin',1,payload=b'x'*8192,is_resident=False,cluster_extents=[(0,1,100),(8192,1,200)])]);save('adv-extent-gap',b,skip='data_extent_layout_or_coverage_unsupported')
    b=base();pageAt=b.address(34)*4096;page=bytearray(b.image[pageAt:pageAt+b.page_size]);h=b.header_size+struct.unpack_from('<I',page,b.header_size)[0]
    array=struct.unpack_from('<I',page,h+16)[0];rec=h+(struct.unpack_from('<I',page,h+array)[0]&65535)
    struct.pack_into('<H',page,rec+10,0xfff0);crc=b.digest(page);b.image[pageAt:pageAt+len(page)]=page
    ob=b.write_btree_leaf(33,[(b.build_object_record_key(0x600),b.build_object_record_value(34,crc))]);b.write_checkpoint(31,10,33,ob);b.write_checkpoint(32,9,33,ob)
    save('adv-record-value-outside-row',b,skip='metadata_record_invalid')

    def attribute_record(b):
        key,value=b.build_dir_entry_record('extent-proof.bin',1,payload=b'X',is_resident=False,cluster_extents=[(0,1,100)])
        start=struct.unpack_from('<I',value,0)[0]
        array=struct.unpack_from('<I',value,start+16)[0]
        rec=start+(struct.unpack_from('<I',value,start+array)[0]&65535)
        ko,kl=struct.unpack_from('<HH',value,rec+4);vo,vl=struct.unpack_from('<HH',value,rec+10)
        return key,bytes(value[40:168]),bytes(value[rec+ko:rec+ko+kl]),bytearray(value[rec+vo:rec+vo+vl])
    def finish_attribute(b,key,header,ak,av):
        b.write_raw_data(100,b'X')
        finish(b,[(key,bytes(node([(ak,bytes(av))],3,header)))])
    # These images have valid parent checksums. The final 24-byte extent row is
    # deliberately only partially inside the node's declared data area.
    for data_end in range(40,65):
        b=basic();key,header,ak,av=attribute_record(b)
        struct.pack_into('<I',av,136+4,data_end)
        finish_attribute(b,key,header,ak,av)
        save('adv-extent-data-end-'+str(data_end),b,files=1 if data_end==64 else 0,
             review_case=True,baseline_9a8_live=0 if data_end==40 else 1,
             **({} if data_end==64 else {'skip':'data_extent_layout_or_coverage_unsupported'}))
    b=basic();key,header,ak,av=attribute_record(b)
    struct.pack_into('<I',av,132,40)
    struct.pack_into('<II',av,136+16,0xfffffffc,1)
    struct.pack_into('<I',av,136+32,0)
    finish_attribute(b,key,header,ak,av)
    save('adv-extent-array-addition-wrap',b,review_case=True,baseline_9a8_live=1,skip='data_extent_layout_or_coverage_unsupported')

    # A valid extent child is held behind a branch whose value fits the entire
    # node but runs outside the branch's own declared generic row.
    for declared in (16,63,64,0xfffffff0):
        b=basic();key,header,ak,av=attribute_record(b)
        child=bytearray(b.page_size);b.meta_header(child,b.address(36),b'MSB+')
        struct.pack_into('<I',child,b.header_size,40);nh=b.header_size+40
        array=b.page_size-nh-4
        struct.pack_into('<III',child,nh,40,64,array-64)
        struct.pack_into('<II',child,nh+16,array,1);struct.pack_into('<I',child,nh+32,array+4)
        struct.pack_into('<QHHIII',child,nh+40,100,0x50,24,0,0,1)
        struct.pack_into('<I',child,nh+array,40|0xffff0000)
        child_at=b.address(36)*b.meta_block_size;b.image[child_at:child_at+len(child)]=child
        ref=bytearray(b.ref_size);b.write_block_ref(ref,0,36,b.digest(child))
        branch=row(b'',bytes(ref));struct.pack_into('<I',branch,0,declared)
        av=av[:136]+bytearray(40+len(branch)+4);nh=136;end=40+len(branch)
        struct.pack_into('<III',av,nh,40,end,0);av[nh+12]=1;av[nh+13]=1
        struct.pack_into('<II',av,nh+16,end,1);struct.pack_into('<I',av,nh+32,end+4)
        av[nh+40:nh+40+len(branch)]=branch;struct.pack_into('<I',av,nh+end,40|0xffff0000)
        finish_attribute(b,key,header,ak,av)
        save('adv-extent-branch-own-row-'+str(declared),b,files=1 if declared==64 else 0,
             review_case=True,baseline_9a8_live=1,
             **({} if declared==64 else {'skip':'data_extent_layout_or_coverage_unsupported'}))

    for kind,length in ((1,0x00010004),(2,0x00010008),(2,0xffff0008),(4,0x00010020)):
        b=basic(checksum_type=kind);finish(b,[b.build_dir_entry_record('length-proof.bin',1,payload=b'X')])
        for number in (31,32):
            offset=number*b.meta_block_size;page=bytearray(b.image[offset:offset+b.meta_block_size])
            struct.pack_into('<I',page,512+36,length)
            b.seal_self(page,256,48,number);b.image[offset:offset+len(page)]=page
        save('adv-checksum-u32-'+str(kind)+'-'+str(length),b,review_case=True,baseline_9a8_live=1,warning='metadata_checksum_mismatch')

    # The first container is missing while a later one survives. Explicitly map
    # metadata, so the only failed translation is the file's missing container 2.
    b=basic();b.write_raw_data(33,b'X')
    record=b.build_dir_entry_record('missing-container.bin',1,payload=b'X',is_resident=False,cluster_extents=[(0,1,33)])
    dr=b.write_btree_leaf(34,[record]);obj=bytearray(b.build_object_record_value(34,dr))
    struct.pack_into('<4Q',obj,32,160,161,162,163)
    ob=b.write_btree_leaf(33,[(b.build_object_record_key(0x600),bytes(obj))])
    ct=b.write_btree_leaf(35,[b.build_container_record(3,300,8),b.build_container_record(9,132,8),b.build_container_record(10,136,8)])
    b.write_superblock()
    for number in (31,32):
        b.write_checkpoint(number,10 if number==31 else 9,33,ob,35,ct)
        offset=number*b.meta_block_size;page=bytearray(b.image[offset:offset+b.meta_block_size])
        struct.pack_into('<4Q',page,512,144,145,146,147)
        b.seal_self(page,256,48,number);b.image[offset:offset+len(page)]=page
    save('adv-missing-first-container',b,review_case=True,baseline_9a8_live=1,skip='data_extent_layout_or_coverage_unsupported')
    (dest/'manifest.json').write_text(json.dumps({'version':2,'cases':cases},indent=2),encoding='utf-8')
    return cases

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--destination',type=Path,default=Path('.build/refs-adversarial-fixtures'))
    args=parser.parse_args();print('Generated',len(make_adv_fixtures(args.destination)),'negative structural fixtures')
