"""Developer-only controlled CLR/SQLite corpus producer; imports no product code."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import zipfile


def produce(destination):
    destination=Path(destination)
    destination.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='postbox-layout-writer-') as temporary:
        work=Path(temporary);exe=work/'writer.exe';raw=work/'rows.json'
        source=Path(__file__).with_name('PostboxWriter.cs')
        compiler=Path(os.environ['WINDIR'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        subprocess.run([str(compiler),'/nologo','/reference:System.Web.Extensions.dll','/out:'+str(exe),str(source)],check=True)
        subprocess.run([str(exe),str(raw)],check=True)
        rows=json.loads(raw.read_text('utf-8'))
        inputs=work/'inputs';inputs.mkdir()
        def database(path):
            path.parent.mkdir(parents=True,exist_ok=True)
            db=sqlite3.connect(path)
            db.execute('CREATE TABLE t0 (key INTEGER PRIMARY KEY, value BLOB)')
            db.execute('CREATE TABLE t4 (key BLOB PRIMARY KEY, value BLOB) WITHOUT ROWID')
            db.execute('CREATE TABLE t7 (key BLOB PRIMARY KEY, value BLOB)')
            db.execute('INSERT INTO t0 VALUES (?,?)',(1,struct.pack('<i',25)))
            return db
        def insert(db,row):
            key,value,index=(base64.b64decode(row[name]) for name in ('key','value','index'))
            db.execute('INSERT INTO t7 VALUES (?,?)',(key,value))
            db.execute('INSERT INTO t4 VALUES (?,?)',(key[:12]+key[16:],index))
        positive=inputs/'positive/db_sqlite'
        with database(positive) as db:
            for row in rows:insert(db,row)
        db.close()
        for name in ('version','unlinked','index-date','index-direction','unknown-flags','trailing','truncated','view','empty','t4-schema'):
            path=inputs/'controls'/name/'db_sqlite';path.parent.mkdir(parents=True)
            shutil.copyfile(positive,path)
            with sqlite3.connect(path) as db:
                if name=='version':db.execute('UPDATE t0 SET value=? WHERE key=1',(struct.pack('<i',26),))
                elif name=='unlinked':db.execute('DELETE FROM t4')
                elif name=='index-date':db.execute('UPDATE t4 SET value=?',(b'\x02'+struct.pack('<i',1),))
                elif name=='index-direction':db.execute('UPDATE t4 SET value=?',(b'\x00'+struct.pack('<i',1740000005),))
                elif name=='view':db.execute('ALTER TABLE t7 RENAME TO payloads');db.execute('CREATE VIEW t7 AS SELECT * FROM payloads')
                elif name=='t4-schema':db.execute('DROP TABLE t4');db.execute('CREATE TABLE t4(key BLOB,value BLOB)')
                elif name=='empty':db.execute('DELETE FROM t4');db.execute('DELETE FROM t7')
                else:
                    for key,value in db.execute('SELECT key,value FROM t7').fetchall():
                        value=bytearray(value)
                        if name=='unknown-flags':value[9]=128
                        elif name=='trailing':value.extend(b'junk')
                        elif name=='truncated':value=value[:25]
                        db.execute('UPDATE t7 SET value=? WHERE key=?',(bytes(value),key))
        # Ordinary SQLite records/WAL, no simulated snapshots. Schema creation,
        # insertion and deletion are separate actual committed transactions.
        working=work/'wal.db'
        db=database(working);db.commit();db.close()
        db=sqlite3.connect(working);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
        db.execute('VACUUM');db.commit()
        insert(db,rows[0]);db.commit()
        db.execute('DELETE FROM t7');db.execute('DELETE FROM t4');db.commit()
        target=inputs/'wal/db_sqlite';target.parent.mkdir()
        for suffix in ('','-wal','-shm'):shutil.copyfile(str(working)+suffix,str(target)+suffix)
        db.close()
        archive=destination/'controlled-layout.zip'
        inventory=[]
        with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as output:
            for path in sorted(inputs.rglob('*')):
                if not path.is_file():continue
                data=path.read_bytes();name=path.relative_to(inputs).as_posix()
                inventory.append(dict(path=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
                info=zipfile.ZipInfo(name,(2026,11,13,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;output.writestr(info,data)
        manifest=dict(schema=1,fixture_kind='controlled_CLR_writer_and_native_SQLite_not_phone_capture_or_Swift_execution',
            upstream_commit='1423d5381fcdaaef85565755b087fbed6a4ed97d',sqlite_version=sqlite3.sqlite_version,
            producer_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),sources=inventory,
            archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            expected=[{k:v for k,v in row.items() if k not in ('key','index','value')} for row in rows])
        (destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n','utf-8')
        print(json.dumps(dict(files=len(inventory),archive_sha256=manifest['archive_sha256'],manifest_sha256=hashlib.sha256((destination/'manifest.json').read_bytes()).hexdigest())))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--destination',required=True);produce(parser.parse_args().destination)
