"""Owned real-SQLite WAL snapshots and independent tail mutations.

Android schema/TL field order: official Telegram commit
4de548e79fed27f1a66fbdff84223321838fe925. No recovery parser is imported.
The source database has secure_delete=ON, as in that Android implementation.
Fixtures do not represent an actual phone, account, or recovered cloud history.
"""
from pathlib import Path
import hashlib
import json
import sqlite3
import struct
import sys
import tempfile

from build_telegram_native_fixtures import message, DATE

LATEST = 'Последний сохранённый WAL: рецепт прабабушки 🥧\nдве строки'
OLD = 'Earlier committed recipe before the last edit'
UNTRUSTED = 'UNCOMMITTED_OR_CORRUPT_TAIL_MUST_NOT_BE_HISTORY'
COLUMNS = 'mid INTEGER,uid INTEGER,read_state INTEGER,send_state INTEGER,date INTEGER,data BLOB,out INTEGER,ttl INTEGER,media INTEGER,replydata BLOB,imp INTEGER,mention INTEGER,forwards INTEGER,replies_data BLOB,thread_reply_id INTEGER,is_channel INTEGER,reply_to_message_id INTEGER,custom_params BLOB,group_id INTEGER,reply_to_story_id INTEGER'
TOPIC_COLUMNS = 'mid INTEGER,uid INTEGER,topic_id INTEGER,read_state INTEGER,send_state INTEGER,date INTEGER,data BLOB,out INTEGER,ttl INTEGER,media INTEGER,replydata BLOB,imp INTEGER,mention INTEGER,forwards INTEGER,replies_data BLOB,thread_reply_id INTEGER,is_channel INTEGER,reply_to_message_id INTEGER,custom_params BLOB,reply_to_story_id INTEGER'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def checksum(data, little, first=0, second=0):
    words = struct.unpack(('<' if little else '>') + 'I'*(len(data)//4), data)
    for at in range(0,len(words),2):
        first = (first+words[at]+second) % 2**32
        second = (second+words[at+1]+first) % 2**32
    return first,second


def append_uncommitted(wal, records):
    magic,_,page,_,salt1,salt2,first,second = struct.unpack('>8I',wal[:32])
    if len(wal)>32:
        first,second = struct.unpack('>2I',wal[-page-8:-page])
    result = wal
    for number,body in records:
        prefix = struct.pack('>2I',number,0)
        first,second = checksum(prefix+body,magic==0x377f0682,first,second)
        result += prefix+struct.pack('>4I',salt1,salt2,first,second)+body
    return result


def make_database(path, *, topic=False, checkpoint_schema=False, page_size=4096):
    db=sqlite3.connect(path)
    db.execute('PRAGMA page_size='+str(page_size))
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('PRAGMA secure_delete=ON')
    table='messages_topics' if topic else 'messages_v2'
    columns=TOPIC_COLUMNS if topic else COLUMNS
    db.execute('CREATE TABLE '+table+'('+columns+',PRIMARY KEY('+('mid,topic_id,uid' if topic else 'mid,uid')+'))')
    db.commit()
    if checkpoint_schema:
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    uid=-88 if topic else 77
    def body(text):
        return message(text,mid=21,dialog=abs(uid),kind='channel' if topic else 'user')
    names='mid,uid,date,data'+(',topic_id' if topic else '')
    values=[21,uid,DATE,body(OLD)]+([7] if topic else [])
    db.execute('INSERT INTO '+table+'('+names+') VALUES('+','.join('?' for _ in values)+')',values)
    db.commit()
    db.execute('UPDATE '+table+' SET data=? WHERE mid=21',(body(LATEST),))
    db.commit()
    assert db.execute('SELECT data FROM '+table).fetchone()[0]==body(LATEST)
    return db,table,body


def build(destination):
    destination=Path(destination).resolve()
    destination.mkdir(parents=True,exist_ok=False)
    cases=[]
    def save(name,main,wal,expected,reason,*,topic=False,page_size=4096):
        folder=destination/name;folder.mkdir()
        (folder/'cache4.db').write_bytes(main)
        (folder/'cache4.db-wal').write_bytes(wal)
        cases.append(dict(name=name,path=name+'/cache4.db',source_sha256=sha(main),wal_sha256=sha(wal),
                          expected_prefix_records=expected,tail_reason=reason,latest_text=LATEST,topic=topic,page_size=page_size))
    with tempfile.TemporaryDirectory(prefix='owned-wal-writer-') as temporary:
        scratch=Path(temporary)
        for topic in (False,True):
            path=scratch/('topic.db' if topic else 'normal.db')
            db,table,body=make_database(path,topic=topic)
            try:
                main=path.read_bytes();wal=Path(str(path)+'-wal').read_bytes()
                page=int.from_bytes(wal[8:12],'big');frame=24+page
                if topic:
                    save('topic-torn-tail',main,wal+b'\x44\x55\x66',1,'torn_frame',topic=True)
                    continue
                save('normal-valid-wal',main,wal,0,None)
                save('torn-after-commit',main,wal+b'\xaa\xbb\xcc',1,'torn_frame')
                broken_main=bytearray(main);broken_main[100]=0xff
                save('corrupt-base-torn-tail',bytes(broken_main),wal+b'\xaa\xbb',1,'torn_frame')
                invalid=bytearray(wal);invalid[24]^=0x40
                save('bad-header-checksum',main,bytes(invalid),0,None)
                invalid=bytearray(wal);invalid[56+100]^=0x40
                save('bad-first-frame-no-resync',main,bytes(invalid),0,'frame_checksum')
                db.execute('UPDATE '+table+' SET data=? WHERE mid=21',(body(UNTRUSTED),));db.commit()
                newer=Path(str(path)+'-wal').read_bytes()
                assert newer.startswith(wal) and len(newer)>len(wal)
                invalid=bytearray(newer);invalid[len(wal)+24+100]^=0x40
                save('checksum-after-commit',main,bytes(invalid),1,'frame_checksum')
                invalid=bytearray(newer);invalid[len(wal)+8]^=0x40
                save('salt-after-commit',main,bytes(invalid),1,'salt_mismatch')
                invalid=bytearray(newer);invalid[len(wal):len(wal)+4]=b'\0'*4
                save('page-bounds-after-commit',main,bytes(invalid),1,'page_bounds')
                records=[]
                for at in range(len(wal),len(newer),frame):
                    records.append((int.from_bytes(newer[at:at+4],'big'),newer[at+24:at+frame]))
                save('valid-uncommitted-tail',main,append_uncommitted(wal,records),0,None)
                # A real multi-page commit supplies valid intermediate frames;
                # physically cut the second frame to simulate a torn tail.
                db.execute('UPDATE '+table+' SET data=? WHERE mid=21',(body(UNTRUSTED*500),));db.commit()
                large=Path(str(path)+'-wal').read_bytes()
                pending=[]
                for at in range(len(newer),len(large),frame):
                    pending.append((int.from_bytes(large[at:at+4],'big'),large[at+24:at+frame]))
                assert len(pending)>1
                tail=append_uncommitted(wal,pending)
                save('partial-uncommitted-transaction',main,tail[:len(wal)+frame+frame//2],1,'torn_frame')
                # Header-valid frames with no commit do not prove any snapshot.
                first=int.from_bytes(wal[32:36],'big'),wal[56:56+page]
                save('no-committed-frame',main,append_uncommitted(wal[:32],[first])+b'\xaa',0,'torn_frame')
            finally:
                db.close()
        path=scratch/'checkpointed.db';db,table,body=make_database(path,checkpoint_schema=True)
        try:
            save('missing-page-preimage',path.read_bytes(),Path(str(path)+'-wal').read_bytes()+b'\xaa\xbb',0,'torn_frame')
        finally:
            db.close()
        for page in (512,65536):
            path=scratch/('page-'+str(page)+'.db');db,_,_=make_database(path,page_size=page)
            try:
                save('torn-tail-'+str(page),path.read_bytes(),Path(str(path)+'-wal').read_bytes()+b'\xaa',1,'torn_frame',page_size=page)
            finally:
                db.close()
    manifest=dict(schema=1,sqlite_version=sqlite3.sqlite_version,
        scope='Owned SQLite transactions with official Android-shaped schemas; tail mutations only, no devices or personal data',
        android_commit='4de548e79fed27f1a66fbdff84223321838fe925',generator_sha256=sha(Path(__file__).read_bytes()),cases=cases)
    (destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    return manifest


if __name__=='__main__':
    result=build(sys.argv[1])
    print('Generated owned WAL-tail corpus: '+str(len(result['cases']))+' cases')
