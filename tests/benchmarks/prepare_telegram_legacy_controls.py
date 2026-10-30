"""Owned negative controls; uses only the independent official-layout writer."""
from pathlib import Path
import hashlib,json,sqlite3,sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from build_telegram_legacy_fixtures import SCHEMA,DATE,message,stored_mid,word


def build(destination):
    root=Path(destination);root.mkdir(parents=True,exist_ok=False);cases=[]
    for name in ('wrong-channel-high-bits','wrong-dialog','wrong-date','unsupported-114-media','nonofficial-schema'):
        folder=root/name;folder.mkdir();source=folder/'cache4.db'
        text='Owned negative control '+name
        raw=message(text,mid=23,peer=88,kind='channel')
        mid=stored_mid(23,'channel',99 if name=='wrong-channel-high-bits' else 88)
        uid=-99 if name=='wrong-dialog' else -88
        date=DATE+1 if name=='wrong-date' else DATE
        if name=='unsupported-114-media':raw=raw[:4]+word(256|512)+raw[8:]
        db=sqlite3.connect(source)
        try:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('CREATE TABLE messages('+(SCHEMA if name!='nonofficial-schema' else 'mid INTEGER,uid INTEGER,date INTEGER,data BLOB')+')')
            db.execute('INSERT INTO messages(mid,uid,date,data) VALUES(?,?,?,?)',(mid,uid,date,raw));db.commit()
        finally:db.close()
        cases.append(dict(name=name,path=name+'/cache4.db',profile=114,wal=False,
            source_files={source.name:hashlib.sha256(source.read_bytes()).hexdigest()},
            targets=[dict(message_id=23,chat_id=-88,sqlite_stored_mid=stored_mid(23,'channel',88),
                text_sha256=hashlib.sha256(text.encode()).hexdigest(),query='negative control '+name)],
            expected_confirmed=False))
    (root/'manifest.json').write_text(json.dumps(dict(schema=1,scope='Owned negative SQL/TL association controls',cases=cases),indent=2),encoding='utf-8',newline='\n')


if __name__=='__main__':build(sys.argv[1])
