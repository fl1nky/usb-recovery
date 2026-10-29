using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Published, hash-pinned upstream test images. The executable under test calls
// the actual frozen worker through redirected stdin; no Python is required.
public static class StoragePipelineTests
{
    public sealed class FixtureRow { public string id,file,compressed_sha256,raw_sha256;public long compressed_bytes,raw_bytes; }
    public sealed class FixtureManifest { public int schema;public string package,version,source_commit,license,license_sha256,copyright_sha256;public FixtureRow[] fixtures; }
    static int checks,sequence;static string work,project,fixtures;
    const string ApfsSecret="password",BdeSecret="password12!@",Recovery="284867-596541-514998-422114-660297-261613-215424-199408";
    const string KnownLzfse="5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f";
    const string KnownBdePrefix="d90b6e46f837d9b2f25c7ebca4cf42d6c17dbd08fc7f2ef1a8aed7d149becf75";
    static readonly Dictionary<string,string[]> Pins=new Dictionary<string,string[]>{
        {"apfs/case_sensitive",new[]{"0c2cf324cf6cd8d7b8e1f75e3c1c0f70a107479f30cfc601ebe0d4e357f7d019","8e7ae7cb2b6d27c48f465635d000aa4a5004cbc21cf5777b681f7369c414ccc2"}},
        {"apfs/encrypted",new[]{"9780647470fd4a818c0c7ae86f70f2b7d39c48a5ccf2f89f0f2bd47d35915f1d","fbf5c6854f37b7f8b9170aef5aaaba60cd91c4ecb80e121479370c486a68d21f"}},
        {"apfs/snapshot",new[]{"63dedb8142c17e6ab6709c9fe2c37c695f1caa617946bc8d499087c5299dcf2b","21fc98a4708ed18542b20177d1c6bae3a6dc07bdf742a747fceecfe284d33019"}},
        {"apfs/corrupt",new[]{"672c556cb370c4ae547e69b822d1896a2327fcb392eeba19f3d73414382cc80f","a11d94826610518f797d51b2a8838cdb9fdf101eec8d4a132c60a0735d977e08"}},
        {"bde/aes_128",new[]{"da584b3633e23b0b2890d35cf93a6485882d8ec750e130fec24db581a81f654d","431b64f49955e88c1aefc11eed09377865465a5bfc0a9bcb92589244b11b4467"}},
        {"bde/recovery_password",new[]{"9999adc2a6d1c8b0248974236f4d0a0d4fe9be45d77ebab041865289c6eef00e","8e42a7575c43a7ef313f6eb7bc4ca46ef66da854bd21f3c6c9c81717920134a3"}}
    };
    static void Check(bool condition,string text){checks++;if(!condition)throw new Exception(text);}
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=64*1024*1024,RecursionLimit=128};}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string Hash(byte[] value){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(value)).Replace("-","").ToLowerInvariant();}
    static string Output(string label){return Path.Combine(work,(++sequence).ToString("D3")+"-"+label);}
    static Dictionary<string,object> Record(object value){return value as Dictionary<string,object>;}
    static string Value(Dictionary<string,object> row,string key){object value;return row.TryGetValue(key,out value)?Convert.ToString(value):null;}
    static List<Dictionary<string,object>> Records(string root)
    {
        var rows=Json().DeserializeObject(File.ReadAllText(Path.Combine(root,"storage-candidates.json"),Encoding.UTF8))as IEnumerable;
        Check(rows!=null,"APFS candidate metadata is a published sequence");return rows.Cast<object>().Select(Record).ToList();
    }
    static string Load(string family,string id)
    {
        string folder=Path.Combine(fixtures,family);var manifest=Json().Deserialize<FixtureManifest>(File.ReadAllText(Path.Combine(folder,"manifest.json"),Encoding.UTF8));
        Check(manifest.schema==1&&manifest.license=="AGPL-3.0-or-later"&&manifest.source_commit==(family=="apfs"?"badd7a83b00791d9ede741e300de2295c2527dd1":"c03d2dc5ece7a53cb6ef76c3567d63e6c9ab12ee"),"published exact source and license provenance "+family);
        Check(Hash(Path.Combine(folder,"LICENSE"))==manifest.license_sha256&&Hash(Path.Combine(folder,"COPYRIGHT"))==manifest.copyright_sha256&&File.Exists(Path.Combine(folder,"NOTICE.txt")),"upstream license/copyright bytes preserved "+family);
        FixtureRow row=manifest.fixtures.Single(f=>f.id==id);string[] pins=Pins[family+"/"+id];string compressed=RecoveryCatalog.SafeFile(folder,row.file);
        Check(row.compressed_sha256==pins[0]&&row.raw_sha256==pins[1]&&Hash(compressed)==pins[0]&&new FileInfo(compressed).Length==row.compressed_bytes,"compressed fixture matches literal known SHA256 "+family+"/"+id);
        Check(row.raw_bytes>0&&row.raw_bytes<=64L*1024*1024,"fixture decompression has explicit safe size bound");
        string path=Path.Combine(work,"input-"+family+"-"+(id=="recovery_password"?"recovery":id)+".dd");
        using(var input=File.OpenRead(compressed))using(var gzip=new GZipStream(input,CompressionMode.Decompress))using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
            var buffer=new byte[1024*1024];int count;long total=0;while((count=gzip.Read(buffer,0,buffer.Length))>0){if(count>row.raw_bytes-total)throw new IOException("Pinned fixture expanded beyond its stated length.");output.Write(buffer,0,count);total+=count;}Check(total==row.raw_bytes,"raw fixture has exact pinned length "+family+"/"+id);
        }
        Check(Hash(path)==pins[1],"raw fixture matches literal independent SHA256 "+family+"/"+id);return path;
    }
    static StorageVolumeInfo Probe(string source,string kind)
    {
        string before=Hash(source);HelperResult result;using(var timeout=new CancellationTokenSource(240000))result=StorageRecovery.Probe(source,timeout.Token);
        Check(result.Status=="complete"&&result.Code=="OK"&&result.Volumes.Count(v=>v.Kind==kind)==1,"real frozen source dispatcher discovers "+kind+" status="+result.Status+" code="+result.Code+" volumes="+String.Join(",",result.Volumes.Select(v=>v.Kind)));
        var volume=result.Volumes.Single(v=>v.Kind==kind);Check(volume.OffsetBytes==0&&volume.LengthBytes==new FileInfo(source).Length,"probe preserves exact raw volume range "+kind);Check(Hash(source)==before,"probe never changes source "+kind);return volume;
    }
    static StoragePreparedResult Prepare(string kind,string source,string destination,StorageVolumeInfo volume,Dictionary<string,string> secrets,bool snapshots,List<RecoveryStageProgress> observed=null,int maximumSnapshots=1024)
    {
        string before=Hash(source);StoragePreparedResult result;
        using(var timeout=new CancellationTokenSource(240000))result=StorageRecovery.Prepare(kind,source,destination,volume,secrets,snapshots,512L*1024*1024,timeout.Token,stage=>{if(observed!=null)observed.Add(stage);},maximumSnapshots);
        Check(Hash(source)==before,"preparation preserves entire original source "+kind);return result;
    }
    static void NoSecrets(string root,params string[] secrets)
    {
        if(!Directory.Exists(root))return;
        var metadata=new HashSet<string>(new[]{"apfs-report.json","storage-candidates.json","apfs-candidates.journal.jsonl","bitlocker-report.json","source-image.json","result.json","files-index.json","files-index.csv","Все файлы.html","photos-index.json","Фотографии.html","export-manifest.json","scan-stages.json","search-options.json","recovery-session.json"},StringComparer.OrdinalIgnoreCase);
        foreach(string path in Directory.EnumerateFiles(root,"*",SearchOption.AllDirectories)){
            string relative=path.Substring(root.Length+1).Replace('\\','/');if(relative.StartsWith("apfs-files/",StringComparison.Ordinal))continue;
            if(!metadata.Contains(Path.GetFileName(path))&&!path.EndsWith(".log",StringComparison.OrdinalIgnoreCase))continue;
            string text=File.ReadAllText(path,Encoding.UTF8);foreach(string secret in secrets.Where(s=>!String.IsNullOrEmpty(s))){
                // The short upstream password is an ordinary English word. Check
                // serialized values, not unrelated words such as password hints.
                string needle=secret.Length<10?Json().Serialize(secret):secret;
                Check(!text.Contains(needle),"provided fixture secret absent from metadata/log "+relative);
            }
        }
    }
    static void Failure(string kind,string source,StorageVolumeInfo volume,Dictionary<string,string> secret,string expectedSecret)
    {
        string output=Output("rejected"),before=Hash(source);bool rejected=false;try{Prepare(kind,source,output,volume,secret,true);}catch(IOException error){rejected=true;Check(!error.Message.Contains(expectedSecret),"authentication diagnostic does not echo supplied secret");}
        Check(rejected,"wrong or absent supplied key cannot produce success "+kind);Check(Hash(source)==before,"rejected authentication leaves source unchanged "+kind);
        Check(!File.Exists(Path.Combine(output,"result.json"))&&!File.Exists(Path.Combine(output,"storage-candidates.json"))&&!File.Exists(Path.Combine(output,"decrypted.dd"))&&!File.Exists(Path.Combine(output,"decrypted-prefix.dd")),"authentication failure publishes no successful catalog or image "+kind);
        NoSecrets(output,expectedSecret);
    }
    static void ValidateApfs(string source,string output,List<Dictionary<string,object>> records)
    {
        string sourceHash=Hash(source);bool valid=records.All(r=>r!=null&&Value(r,"source_sha256")==sourceHash&&Value(r,"filesystem")=="APFS"&&Value(r,"validation")=="metadata-checksum-and-readable-stream"&&Value(r,"volume_id").Length>0&&r.ContainsKey("record_id")&&r["record_id"]!=null&&r["physical_ranges"]==null&&File.Exists(RecoveryCatalog.SafeFile(output,Value(r,"path")))&&Hash(RecoveryCatalog.SafeFile(output,Value(r,"path")))==Value(r,"sha256"));
        Check(valid,"all real APFS outputs have exact hashes and source/volume/record provenance without guessed physical extents");
        var index=RecoveryCatalog.Load(output);Check(index.Candidates==records.Count&&index.Items.Count==records.Select(r=>Value(r,"sha256")).Distinct().Count(),"catalog deduplicates only identical output bytes and retains candidate count");
        Check(index.Items.All(i=>i.OriginalLocations.Count>0&&i.OriginalLocations.All(l=>l.FileSystem=="APFS"&&!String.IsNullOrEmpty(l.VolumeId)&&l.VolumeOffset==0)),"APFS provenance reaches every catalog entry");
        Check(!records.Any(r=>Value(r,"original_path").Contains("symlink")),"APFS symbolic links are not followed");
    }
    static void PlainAndEncryptedApfs()
    {
        string plain=Load("apfs","case_sensitive"),encrypted=Load("apfs","encrypted");var plainVolume=Probe(plain,"APFS");string output=Output("apfs-live");var observed=new List<RecoveryStageProgress>();var prepared=Prepare("APFS",plain,output,plainVolume,new Dictionary<string,string>(),false,observed);var records=Records(output);
        Check(prepared.Catalog==output&&!prepared.Partial&&records.Count==20,"real plaintext macOS image becomes an APFS archive");ValidateApfs(plain,output,records);
        Check(records.All(r=>Value(r,"origin")=="existing"&&r["snapshot_id"]==null&&r["deleted"]is bool&&!(bool)r["deleted"]),"live referenced files never claimed to be deleted");
        var known=records.Single(r=>Value(r,"original_path")=="/dir/file");Check(File.ReadAllBytes(RecoveryCatalog.SafeFile(output,Value(known,"path"))).SequenceEqual(Encoding.UTF8.GetBytes("\uf8ff File System\n")),"upstream independently known UTF8 plaintext exact");Check(records.Any(r=>Value(r,"original_path")=="/dir/compressed-lzfse-fork"&&Value(r,"sha256")==KnownLzfse),"known LZFSE fork SHA256 exact through frozen worker");
        var index=RecoveryCatalog.Load(output);Check(index.Items.Any(i=>i.OriginalLocations.Any(l=>l.Path=="/dir/file")&&i.OriginalLocations.Any(l=>l.Path=="/hardlink")),"identical hardlink aliases retain both original paths after dedup");
        string exported=Output("apfs-export");Directory.CreateDirectory(exported);string exportRoot=RecoveryCatalog.ExportPreservingFolders(output,exported,index.Items,CancellationToken.None);Check(File.Exists(Path.Combine(exportRoot,"export-manifest.json")),"APFS folder-preserving export publishes provenance manifest");Check(Directory.EnumerateFiles(exported,"*",SearchOption.AllDirectories).Any(f=>new FileInfo(f).Length==Encoding.UTF8.GetByteCount("\uf8ff File System\n")&&Hash(f)==Hash(Encoding.UTF8.GetBytes("\uf8ff File System\n"))),"APFS exported known payload remains exact");
        Check(observed.All(s=>s.Total<=0||s.Completed>=0&&s.Completed<=s.Total),"APFS progress uses observed bounded totals");
        var encryptedVolume=Probe(encrypted,"APFS");string decrypted=Output("apfs-unlocked");var unlocked=Prepare("APFS",encrypted,decrypted,encryptedVolume,new Dictionary<string,string>{{"password",ApfsSecret}},false);var unlockedRecords=Records(decrypted);
        Check(!unlocked.Partial&&unlockedRecords.Count==20&&unlockedRecords.Any(r=>Value(r,"sha256")==KnownLzfse),"provided APFS password unlocks real encrypted XTS files including LZFSE fork");ValidateApfs(encrypted,decrypted,unlockedRecords);NoSecrets(decrypted,ApfsSecret);NoSecrets(output,ApfsSecret);NoSecrets(exported,ApfsSecret);
        Failure("APFS",encrypted,encryptedVolume,new Dictionary<string,string>{{"password","Incorrect-DO-NOT-LOG-7931"}},"Incorrect-DO-NOT-LOG-7931");Failure("APFS",encrypted,encryptedVolume,new Dictionary<string,string>(),"Missing-DO-NOT-LOG-8371");
    }
    static void Snapshots()
    {
        string source=Load("apfs","snapshot");var volume=Probe(source,"APFS");string output=Output("apfs-history");var prepared=Prepare("APFS",source,output,volume,new Dictionary<string,string>(),true,null,3);var records=Records(output);ValidateApfs(source,output,records);
        var previous=records.Where(r=>Value(r,"original_path")=="/file").ToArray();Check(prepared.Partial&&previous.Length==3&&previous.All(r=>Value(r,"origin")=="previous-version"&&r["deleted"]==null&&r["snapshot_id"]!=null&&r["snapshot_xid"]!=null),"bounded actual snapshot versions retain transaction identity, unknown deletion state and honest partial status");
        Check(new HashSet<string>(previous.Select(r=>Value(r,"snapshot_name"))).SetEquals(new[]{"Snapshot 509","Snapshot 510","Snapshot 511"}),"recent-snapshot preference selects independently published latest versions");Check(File.ReadAllText(Path.Combine(output,"apfs-report.json")).Contains("APFS_SNAPSHOT_LIMIT_REACHED"),"bounded snapshot enumeration explicitly reports its limit");Check(previous.All(r=>File.ReadAllBytes(RecoveryCatalog.SafeFile(output,Value(r,"path"))).SequenceEqual(Encoding.UTF8.GetBytes(Value(r,"snapshot_name")+"\n"))),"every historical payload exactly equals independently documented Snapshot N newline");Check(!records.Any(r=>Value(r,"original_path")=="/file"&&Value(r,"origin")=="existing"),"historical file is actually absent from live directory");
        var index=RecoveryCatalog.Load(output);Check(index.Items.Any(i=>i.OriginalLocations.Any(l=>l.Status=="apfs_snapshot_path"&&!String.IsNullOrEmpty(l.SnapshotId))),"snapshot identity and previous-version category survive C# catalog conversion");Check(prepared.Catalog==output,"snapshot result is reviewable in ordinary result browser");
        string liveOnly=Output("apfs-current");Prepare("APFS",source,liveOnly,volume,new Dictionary<string,string>(),false);Check(!Records(liveOnly).Any(r=>Value(r,"original_path")=="/file"),"disabling snapshots does not invent the missing live file");
    }
    static void CheckBde(string source,StoragePreparedResult prepared,string secret,bool knownHash)
    {
        Check(prepared.Partial&&Path.GetFileName(prepared.Image)=="decrypted-prefix.dd"&&!File.Exists(Path.Combine(prepared.Directory,"decrypted.dd")),"truncated upstream encrypted fixture never becomes a complete decrypted volume");
        using(var stream=File.OpenRead(prepared.Image)){var header=new byte[512];Check(stream.Read(header,0,header.Length)==header.Length&&Encoding.ASCII.GetString(header,3,8)=="NTFS    "&&header[510]==0x55&&header[511]==0xAA,"known independent NTFS boot bytes decrypt exactly");stream.Position=8192;var mft=new byte[8];Check(stream.Read(mft,0,8)==8&&mft.SequenceEqual(new byte[]{70,73,76,69,48,0,3,0}),"known MFT bytes decrypt beyond virtualized boot sector");}
        string actual=Hash(prepared.Image);Check(File.ReadAllText(prepared.Checksum).Trim().Split(' ')[0]==actual,"materialized decrypted prefix checksum exact");if(knownHash)Check(actual==KnownBdePrefix,"whole available AES128 prefix matches the recorded reference SHA256");
        var report=Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(prepared.Directory,"bitlocker-report.json"),Encoding.UTF8));var origin=Record(report["source"]);var authentication=Record(report["authentication"]);Check(Value(report,"completeness")=="available_prefix"&&Value(origin,"sha256")==Hash(source)&&Convert.ToBoolean(origin["unchanged"]),"prefix/source completeness preserved in actual BitLocker report");Check(Value(authentication,"data_sectors")=="not_authenticated_by_bitlocker","key authentication is never promoted to a whole-volume integrity claim");NoSecrets(prepared.Directory,secret);
    }
    static void CheckpointFallback()
    {
        string source=Load("apfs","corrupt");var volume=Probe(source,"APFS");string output=Output("apfs-checkpoint");var prepared=Prepare("APFS",source,output,volume,new Dictionary<string,string>(),false);var records=Records(output);ValidateApfs(source,output,records);
        Check(records.Count>0&&records.All(r=>Convert.ToBoolean(r["checkpoint_fallback"])&&Value(r,"checkpoint_xid")=="302"&&Value(r,"origin")=="previous-version"&&r["deleted"]==null&&r["snapshot_id"]==null),"real corrupt fixture uses known older checkpoint302 without inventing snapshot or deletion");
        var index=RecoveryCatalog.Load(output);Check(index.Items.All(i=>i.OriginalLocations.All(l=>l.Status=="apfs_checkpoint_path"&&l.CheckpointId=="302"&&l.SnapshotId==null)),"C# catalog keeps checkpoint identity distinct from snapshot identity");Check(prepared.Catalog==output,"older validated checkpoint remains reviewable");
    }
    static void BitLocker()
    {
        string aes=Load("bde","aes_128"),recovery=Load("bde","recovery_password");var volume=Probe(aes,"BitLocker");string output=Output("bde-unlocked");var progress=new List<RecoveryStageProgress>();var prepared=Prepare("BitLocker",aes,output,volume,new Dictionary<string,string>{{"password",BdeSecret}},false,progress);CheckBde(aes,prepared,BdeSecret,true);Check(progress.Any(s=>s.Total>0)&&progress.All(s=>s.Total<=0||s.Completed>=0&&s.Completed<=s.Total),"actual decrypt progress is finite and byte-bounded");
        Failure("BitLocker",aes,volume,new Dictionary<string,string>{{"password","Incorrect-BDE-DO-NOT-LOG-7132"}},"Incorrect-BDE-DO-NOT-LOG-7132");
        var recoveryVolume=Probe(recovery,"BitLocker");var recovered=Prepare("BitLocker",recovery,Output("bde-recovered"),recoveryVolume,new Dictionary<string,string>{{"recovery_password",Recovery}},false);CheckBde(recovery,recovered,Recovery,false);
        string bad="284878-596541-514998-422114-660297-261613-215424-199408";Failure("BitLocker",recovery,recoveryVolume,new Dictionary<string,string>{{"recovery_password",bad}},bad);
    }
    public static int Main(string[] args)
    {
        bool passed=false;try{
            project=Path.GetFullPath(args[0]);string packaged=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"tests","StorageFixtures");fixtures=Directory.Exists(packaged)?packaged:Path.Combine(project,"tests","StorageFixtures");work=Path.Combine(project,".build","storage-pipeline-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            Check(File.Exists(HelperClient.Executable),"actual packaged frozen helper exists");PlainAndEncryptedApfs();Snapshots();CheckpointFallback();BitLocker();passed=true;
            Console.WriteLine("PASS StoragePipeline: "+checks+" checks; real frozen helper and pinned published APFS live/encrypted/recent snapshots, BitLocker passphrase/recovery key, negative authentication, source hashes, provenance/dedup/export, secret-free metadata and explicitly partial decrypted images. No Python, network or user devices required.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
        finally{if(passed&&work!=null&&Path.GetFullPath(work).StartsWith(Path.Combine(project,".build","storage-pipeline-"),StringComparison.OrdinalIgnoreCase))try{Directory.Delete(work,true);}catch(IOException){}catch(UnauthorizedAccessException){}}
    }
}
