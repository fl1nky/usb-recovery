"""Owned SQLite fixtures; independent wire writer, no recovery imports.

Official Telegram Android 6.2.0 commit f424ea165af4e868391b24640d2e715d1a45ce3c:
MessagesStorage.java creates the 12-column messages table and packs channel IDs
into its SQL primary key; TLRPC.java TL_message (0x452c0e65) defines profile 114.
Profile 118 is independently serialized for backward-compatible table tests.
"""
from pathlib import Path
import hashlib
import json
import shutil
import sqlite3
import struct

PIN='f424ea165af4e868391b24640d2e715d1a45ce3c'
DATE=1591350000
SCHEMA='mid INTEGER PRIMARY KEY,uid INTEGER,read_state INTEGER,send_state INTEGER,date INTEGER,data BLOB,out INTEGER,ttl INTEGER,media INTEGER,replydata BLOB,imp INTEGER,mention INTEGER'


def word(value):
    return struct.pack('<I',value&0xffffffff)


def string(value):
    raw=value.encode('utf-8')
    head=bytes([len(raw)]) if len(raw)<254 else b'\xfe'+len(raw).to_bytes(3,'little')
    return head+raw+b'\0'*(-(len(head)+len(raw))%4)


def message(text,*,mid=21,peer=77,kind='user',sender=77,date=DATE,profile=114,out=False,
            reply=None,via=None,views=None,forwards=0,edit=None,author=None,grouped=None,boolean_flags=0,tail=True):
    flags=boolean_flags|(256 if sender is not None else 0)|(2 if out else 0)
    for bit,value in ((8,reply),(2048,via),(1024,views),(32768,edit),(65536,author),(131072,grouped)):
        if value is not None:flags|=bit
    result=word({114:0x452c0e65,118:0xf52e6b7f}[profile])+word(flags)+word(mid)
    if sender is not None:result+=word(sender)
    result+=word({'user':0x9db1bc6d,'chat':0xbad0e5bb,'channel':0xbddde532}[kind])+word(peer)
    if via is not None:result+=word(via)
    if reply is not None:result+=word(reply)
    result+=word(date)+string(text)
    if views is not None:
        result+=word(views)
        if profile==118:result+=word(forwards)
    if edit is not None:result+=word(edit)
    if author is not None:result+=string(author)
    if grouped is not None:result+=struct.pack('<q',grouped)
    return result+(string(' ') if tail else b'')


def stored_mid(mid,kind='user',peer=77):
    return mid|(peer<<32) if kind=='channel' else mid


def create(path,*,profile=114,wal=False):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    connection=sqlite3.connect(path)
    connection.execute('PRAGMA secure_delete=ON')
    if wal:
        connection.execute('PRAGMA journal_mode=WAL');connection.execute('PRAGMA wal_autocheckpoint=0')
    connection.execute('CREATE TABLE messages('+SCHEMA+')');connection.commit()
    rows=[dict(mid=21,uid=77,kind='user',peer=77,sender=77,out=False,text='Прабабушка: старый рецепт 🥧\nдве строки'),
          dict(mid=22,uid=99,kind='user',peer=99,sender=77,out=True,text='Outgoing legacy recipe'),
          dict(mid=23,uid=-88,kind='channel',peer=88,sender=77,out=False,text='Channel recipe before real SQL DELETE'),
          dict(mid=24,uid=-55,kind='chat',peer=55,sender=77,out=False,text='Basic group recipe'),
          dict(mid=25,uid=-88,kind='channel',peer=88,sender=None,out=False,text='Unknown channel author stays unknown')]
    for row in rows:
        row['stored_mid']=stored_mid(row['mid'],row['kind'],row['peer'])
        blob=message(row['text'],mid=row['mid'],kind=row['kind'],peer=row['peer'],sender=row['sender'],out=row['out'],profile=profile)
        connection.execute('INSERT INTO messages(mid,uid,date,data) VALUES(?,?,?,?)',(row['stored_mid'],row['uid'],DATE,blob))
    connection.commit()
    if wal:
        connection.execute('UPDATE messages SET data=? WHERE mid=21',(message('Current legacy recipe',profile=profile),))
        connection.execute('DELETE FROM messages WHERE mid=?',(stored_mid(23,'channel',88),));connection.commit()
        supplied=path.parent/'provided';supplied.mkdir()
        for suffix in ('','-wal'):shutil.copyfile(str(path)+suffix,str(supplied/path.name)+suffix)
        connection.close();path=supplied/path.name
    else:connection.close()
    return path,rows


def build(destination):
    root=Path(destination);root.mkdir(parents=True,exist_ok=False);cases=[]
    for profile in (114,118):
        for wal in (False,True):
            name=('wal-' if wal else 'active-')+str(profile)
            path,rows=create(root/name/'cache4.db',profile=profile,wal=wal)
            files={path.name:hashlib.sha256(path.read_bytes()).hexdigest()}
            sidecar=Path(str(path)+'-wal')
            if sidecar.is_file():files[sidecar.name]=hashlib.sha256(sidecar.read_bytes()).hexdigest()
            cases.append(dict(name=name,path=path.relative_to(root).as_posix(),profile=profile,wal=wal,source_files=files,
                targets=[dict(message_id=row['mid'],sqlite_stored_mid=row['stored_mid'],chat_id=row['uid'],
                    text_sha256=hashlib.sha256(row['text'].encode()).hexdigest()) for row in rows]))
    result=dict(schema=1,android_commit=PIN,scope='Owned SQLite/TL official-layout fixtures, not devices or personal accounts',cases=cases)
    (root/'manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    import sys
    build(sys.argv[1])
