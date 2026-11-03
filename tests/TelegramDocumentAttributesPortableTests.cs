using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using UsbRecovery;

// Actual public API acceptance on independent inputs; never a device claim.
public static class TelegramDocumentAttributesPortableTests
{
    const string Commit="4de548e79fed27f1a66fbdff84223321838fe925";
    const string Manifest="73e02a818c974582952ee3b07c3b0c8db37d8d2abb105644bb4a893714711fee";
    const string ZipHash="7ae8796ca41cd2f2cccb5be21eb9b4268b96ab6e60480dfdb9fe522b5b6a6971";
    const string Png="iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAIAAAB7QOjdAAAADUlEQVR42mP4zwAE/wEHAAH/PX2MSQAAAABJRU5ErkJggg==";
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=2*1024*1024};
    static readonly string[] Cached={"doc-cached-png","doc-two-photo-thumbs"};
    static readonly List<object> Runs=new List<object>();
    static Dictionary<string,Dictionary<string,object>> positives,controls,sqlite;
    static string project,work,inputs,context;
    static CancellationToken phase;
    static Stopwatch clock;
    static int checks,analyses;
    static void Check(bool value,string reason){checks++;if(!value)throw new Exception((context??"setup")+": "+reason);}
    static object Get(Dictionary<string,object> row,string key){object value;return row.TryGetValue(key,out value)?value:null;}
    static string Str(Dictionary<string,object> row,string key){return Get(row,key) as string;}
    static long Num(object value){return Convert.ToInt64(value,CultureInfo.InvariantCulture);}
    static List<Dictionary<string,object>> Rows(object value){return ((IEnumerable)value).Cast<Dictionary<string,object>>().ToList();}
    static Dictionary<string,object> Read(string path){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path,Encoding.UTF8));}
    static string Hex(byte[] value){return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();}
    static string Hash(byte[] value){using(var sha=SHA256.Create())return Hex(sha.ComputeHash(value));}
    static string Hash(string path){using(var stream=File.OpenRead(path))using(var sha=SHA256.Create())return Hex(sha.ComputeHash(stream));}
    static string Safe(string root,string relative)
    {
        Check(!String.IsNullOrEmpty(relative)&&relative.Length<240&&!Path.IsPathRooted(relative)&&!relative.Contains('\\'),"bounded relative forward-slash path");
        Check(relative.Split('/').All(p=>p!=""&&p!="."&&p!=".."&&p.IndexOf(':')<0),"no path traversal, stream or empty component");
        return RecoveryCatalog.SafeFile(root,relative);
    }
    static void Plain(string path)
    {
        var file=new FileInfo(Path.GetFullPath(path));Check(file.Exists&&(file.Attributes&FileAttributes.ReparsePoint)==0,"regular existing input");
        for(var parent=file.Directory;parent!=null;parent=parent.Parent)Check((parent.Attributes&FileAttributes.ReparsePoint)==0,"no reparse ancestor");
    }
    static Dictionary<string,string> Binding(string root)
    {
        return Directory.GetFiles(root,"*",SearchOption.AllDirectories).ToDictionary(p=>p.Substring(root.Length+1),Hash,StringComparer.OrdinalIgnoreCase);
    }
    static bool Same(Dictionary<string,string> a,Dictionary<string,string> b){return a.Count==b.Count&&a.All(p=>b.ContainsKey(p.Key)&&b[p.Key]==p.Value);}
    static T Guard<T>(Func<CancellationToken,T> action)
    {
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(phase)){
            stop.CancelAfter(TimeSpan.FromMinutes(4));long remaining=900000-clock.ElapsedMilliseconds;if(remaining<=0)throw new TimeoutException("Phase watchdog");
            var task=Task.Run(()=>action(stop.Token));if(Task.WaitAny(new Task[]{task},(int)Math.Min(270000,remaining))<0){stop.Cancel();throw new TimeoutException("Public call watchdog; completion unconfirmed");}
            return task.GetAwaiter().GetResult();
        }
    }
    static void BindAndExtract()
    {
        string root=Path.Combine(project,"tests","fixtures","telegram-document-attributes"),manifest=Path.Combine(root,"manifest.json");Plain(manifest);Check(Hash(manifest)==Manifest,"exact independent31/171 manifest");
        var pinned=Read(manifest);var members=Rows(pinned["files"]);
        Check(Str(pinned,"telegram_commit")==Commit&&Num(pinned["native_cases"])==31&&Num(pinned["mutation_controls"])==171&&Num(pinned["expected_text_slots"])==30,"pinned native profile counts");
        Check(members.Count==4&&new HashSet<string>(members.Select(m=>Str(m,"path"))).SetEquals(new[]{"oracle.json.gz","native-sqlite-cases.zip","oracle-sources.tar.gz","LICENSE"}),"exact four canonical payloads");
        foreach(var member in members){string file=Safe(root,Str(member,"path"));Plain(file);Check(new FileInfo(file).Length==Num(member["bytes"])&&Hash(file)==Str(member,"sha256"),"complete independent payload bytes");}
        byte[] raw;using(var input=File.OpenRead(Path.Combine(root,"oracle.json.gz")))using(var gzip=new GZipStream(input,CompressionMode.Decompress))using(var output=new MemoryStream()){
            byte[] buffer=new byte[8192];int n;while((n=gzip.Read(buffer,0,buffer.Length))>0){phase.ThrowIfCancellationRequested();Check(output.Length<=1024*1024-n,"bounded oracle expansion");output.Write(buffer,0,n);}raw=output.ToArray();
        }
        Check(raw.Length==Num(pinned["uncompressed_json_bytes"])&&Hash(raw)==Str(pinned,"uncompressed_json_sha256"),"complete raw oracle hash/length");
        var oracle=Json.Deserialize<Dictionary<string,object>>(new UTF8Encoding(false,true).GetString(raw));
        positives=Rows(oracle["positive_cases"]).ToDictionary(r=>Str(r,"name"),StringComparer.Ordinal);controls=Rows(oracle["mutation_controls"]).ToDictionary(r=>Str(r,"name"),StringComparer.Ordinal);
        sqlite=Rows(oracle["sqlite_sources"]).ToDictionary(r=>Str(r,"case"),StringComparer.Ordinal);
        Check(Num(oracle["schema"])==1&&Str(oracle,"telegram_commit")==Commit&&positives.Count==31&&controls.Count==171&&sqlite.Count==202&&positives.Values.Sum(r=>Num(r["expected_text_slots"]))==30,"complete native+control inventories");
        Check(Hash(Encoding.UTF8.GetBytes(Str(oracle,"sql_schema")))==Str(oracle,"sql_schema_sha256"),"native SQL schema raw hash");
        foreach(var row in positives.Values.Concat(controls.Values)){
            string name=Str(row,"name");byte[] blob=Convert.FromBase64String(Str(row,"blob_base64"));Check(blob.Length==Num(row["bytes"])&&Hash(blob)==Str(row,"blob_sha256"),"whole golden BLOB pin "+name);
            Check(sqlite.ContainsKey(name)&&Str(sqlite[name],"native_blob_sha256")==Str(row,"blob_sha256")&&Str(sqlite[name],"path")==name+"/cache4.db","native SQLite exact BLOB binding "+name);
            if(positives.ContainsKey(name))Check(Hash(blob.Take((int)Num(row["tl_bytes"])).ToArray())==Str(row,"tl_body_sha256"),"independent full TL body pin "+name);
            else Check(positives.ContainsKey(Str(row,"parent"))&&Str(row,"native_parent_blob_sha256")==Str(positives[Str(row,"parent")],"blob_sha256")&&Num(row["expected_native_text_slots"])==0,"control parent and zero native expectation "+name);
        }
        string zip=Path.Combine(root,"native-sqlite-cases.zip");Check(Hash(zip)==ZipHash,"native ZIP exact transport");Directory.CreateDirectory(inputs);long total=0;var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var byPath=sqlite.Values.ToDictionary(r=>Str(r,"path"),StringComparer.Ordinal);
        using(var archive=new ZipArchive(File.OpenRead(zip),ZipArchiveMode.Read)){
            Check(archive.Entries.Count==202,"exact202 ZIP members");
            foreach(var entry in archive.Entries){phase.ThrowIfCancellationRequested();string relative=entry.FullName;
                Check(byPath.ContainsKey(relative)&&seen.Add(relative)&&relative.Split('/').Length==2&&relative.EndsWith("/cache4.db",StringComparison.Ordinal),"unique declared SQLite member only");
                int mode=(entry.ExternalAttributes>>16)&0xf000;Check((mode==0||mode==0x8000)&&(entry.ExternalAttributes&(int)FileAttributes.ReparsePoint)==0,"no ZIP link/device/reparse entry");
                var proof=byPath[relative];Check(entry.Length==Num(proof["bytes"])&&entry.Length>0&&entry.Length<=4*1024*1024&&total<=16*1024*1024-entry.Length,"bounded exact decompressed size");total+=entry.Length;
                string category=positives.ContainsKey(Str(proof,"case"))?"current":"controls";string destination=Safe(inputs,category+"/"+relative);Directory.CreateDirectory(Path.GetDirectoryName(destination));
                using(var source=entry.Open())using(var output=new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
                    byte[] buffer=new byte[8192];long copied=0;int n;while((n=source.Read(buffer,0,buffer.Length))>0){phase.ThrowIfCancellationRequested();Check(copied<=entry.Length-n,"bounded ZIP stream");output.Write(buffer,0,n);copied+=n;}Check(copied==entry.Length,"complete ZIP stream");
                }
                Check(Hash(destination)==Str(proof,"sha256"),"extracted DB exact SHA");File.SetAttributes(destination,File.GetAttributes(destination)|FileAttributes.ReadOnly);Plain(destination);
            }
        }
        Check(seen.SetEquals(byPath.Keys)&&Binding(inputs).Count==202,"all202 inputs extracted exactly once");
    }
    static void NoLimits(IEnumerable<string> warnings){foreach(string warning in warnings??new string[0])Check(warning==null||new[]{"LIMIT","BUDGET","TIMEOUT","CANCEL","INCOMPLETE"}.All(w=>warning.IndexOf(w,StringComparison.OrdinalIgnoreCase)<0),"no incomplete/limited success: "+warning);}
    static HelperResult Analyze(string source,string archive)
    {
        context=Path.GetFileName(archive);var before=Binding(source);analyses++;var watch=Stopwatch.StartNew();
        var result=Guard(token=>TelegramAnalysisService.AnalyzeSelected(archive,source,"",false,token,m=>{}));
        Check((result.Status=="complete"||result.Status=="partial")&&File.Exists(Path.Combine(archive,"messages.jsonl"))&&!File.Exists(Path.Combine(archive,"job.incomplete"))&&!Directory.Exists(archive+".work"),"public analysis finishes and cleans scratch");NoLimits(result.Warnings);
        Check(Same(before,Binding(source)),"all selected source bytes remain unchanged");
        var acquisition=Rows(Read(Path.Combine(archive,"acquisition.json"))["Files"]);var originals=Directory.GetFiles(source,"*",SearchOption.AllDirectories);
        Check(acquisition.Count==originals.Length,"every selected physical file acquired");
        foreach(string file in originals){var found=acquisition.Where(r=>String.Equals(Path.GetFullPath(Str(r,"OriginalPath")),file,StringComparison.OrdinalIgnoreCase)).ToList();Check(found.Count==1&&Str(found[0],"Status")=="complete"&&Num(found[0]["Size"])==new FileInfo(file).Length&&Str(found[0],"Sha256")==Hash(file),"source acquisition complete size/SHA");}
        Runs.Add(new{source=source,archive=archive,status=result.Status,native_records=result.NativeRecords,messages=result.Messages,readable_sources=result.ReadableSources,seconds=watch.Elapsed.TotalSeconds,source_before=before,source_after=Binding(source)});return result;
    }
    static bool Native(ArchiveMessage row){return row.application_confirmed==true&&new[]{"tl_message","tl_message_caption","sqlite_deleted_record","sqlite_deleted_caption"}.Contains(row.record_kind)&&row.evidence_kind!="fragment"&&row.provenance_verification!="provided_archive_metadata";}
    static List<ArchiveMessage> Search(string archive,string query="",bool regex=false,string evidence="")
    {
        var result=new List<ArchiveMessage>();long total=-1;
        do{long offset=result.Count;var page=Guard(token=>ArchiveSearchService.Search(archive,"Telegram",query,evidence,offset,token,regex));
            Check((page.status=="complete"||page.status=="partial")&&page.records!=null&&page.offset==offset,"public search page");NoLimits(page.warnings);if(total<0)total=page.total;
            Check(total>=0&&total<=10000&&page.total==total&&(page.records.Count>0||total==0),"bounded progressing stable search total");result.AddRange(page.records);
        }while(result.Count<total);
        Check(result.Count==total&&result.Select(r=>r.archive_record_key).Distinct().Count()==result.Count&&result.All(r=>!String.IsNullOrEmpty(r.archive_record_key)),"all distinct full-text locators");return result;
    }
    static void Full(string archive,ArchiveMessage row)
    {
        var text=new StringBuilder();long offset=0;for(int pages=0;pages<65;pages++){
            long requested=offset;var page=Guard(token=>ArchiveSearchService.ReadPage(archive,row.archive_record_key,requested,token));
            Check(page.status=="complete"&&page.text_offset==offset&&page.next_offset>=offset,"public full-text page protocol");text.Append(page.text);offset=page.next_offset;
            if(page.eof){Check(offset==page.text_length&&text.ToString()==row.text,"exact complete Unicode native text");return;}Check(page.next_offset>requested,"full text advances");
        }throw new Exception("Full-text pagination exceeded bounded fixture text");
    }
    static void Weak(IEnumerable<ArchiveMessage> rows)
    {
        foreach(var row in rows){Check(row.evidence_kind=="fragment"&&new[]{"memory_fragment","typed_tl_fragment","sqlite_residual_fragment","sqlite_wal_residual","sqlite_rollback_fragment"}.Contains(row.record_kind),"weak fragments remain explicitly separate");
            Check(row.application_confirmed==(row.record_kind=="memory_fragment"?false:true)&&row.chat_id==null&&row.chat_name==null&&row.message_id==null&&row.sender_id==null&&row.sender_name==null&&row.timestamp==null&&row.timestamp_raw==null,"fragment does not borrow SQL identity/author/date");
            Check(row.deleted==null&&row.wal_proof==null&&row.rollback_content_authenticity_verified!=true&&(row.residual_sources==null||row.residual_sources.Length==0),"memory/fragments do not prove native deletion");}
    }
    static string Source(string category,string name){return Safe(inputs,category+"/"+Str(sqlite[name],"path"));}
    static void Current()
    {
        string archive=Path.Combine(work,"current");var summary=Analyze(Path.Combine(inputs,"current"),archive);var all=Search(archive);var native=all.Where(Native).ToList();Weak(all.Where(r=>!Native(r)));
        Check(summary.ReadableSources==31&&native.Count==30&&summary.NativeRecords==30&&summary.HistoryMessages==30&&summary.Messages==all.Count&&summary.FragmentRecords==all.Count-30&&summary.DeletedSupportedRecords==0,"31 readable sources,30 native text slots,one intentionally empty");
        var bySource=positives.Keys.ToDictionary(name=>Source("current",name),name=>name,StringComparer.OrdinalIgnoreCase);var seen=new HashSet<string>();
        foreach(var row in native){string file=Path.GetFullPath(row.source_file);Check(bySource.ContainsKey(file),"native row exact preselected DB source");string name=bySource[file];var expected=positives[name];var message=(Dictionary<string,object>)expected["expected"];var sql=(Dictionary<string,object>)expected["exact_sql"];var sender=(Dictionary<string,object>)message["from_peer"];
            Check(seen.Add(name)&&row.text==Str(message,"text")&&row.text_field=="message"&&row.record_kind=="tl_message"&&Num(row.chat_id)==Num(sql["uid"])&&Num(row.message_id)==Num(sql["mid"]),"native exact text/SQL identity/field role once");
            Check(row.native_constructor=="0x7600b9d3"&&Num(row.native_layer)==232&&row.native_tl_body_sha256==Str(expected,"tl_body_sha256")&&row.source_sha256==Str(sqlite[name],"sha256"),"exact full body/source/native profile pins");
            byte[] path=Encoding.UTF8.GetBytes(file.Replace('/','\\').ToLowerInvariant());Check(row.identity_scope=="telegram-db:"+Hash(path),"native DB identity scope");
            DateTimeOffset time;Check(DateTimeOffset.TryParse(row.timestamp as string,CultureInfo.InvariantCulture,DateTimeStyles.None,out time)&&time.ToUniversalTime()==new DateTimeOffset(1970,1,1,0,0,0,TimeSpan.Zero).AddSeconds(Num(sql["date"]))&&row.sender_id is string&&(string)row.sender_id==Str(sender,"kind")+":"+Num(sender["id"]).ToString(CultureInfo.InvariantCulture),"exact observed author/date");
            Check(row.sender_name==null&&row.chat_name==null&&row.evidence_kind=="backup"&&row.deleted==null&&row.provenance_verification!="provided_archive_metadata","unknown names/deletion remain unknown");
            bool cached=Cached.Contains(name);Check(row.media_kind=="document"&&row.media_id==Str(expected,"document_id")&&Num(row.thumbnail_count)==(cached?1:0)&&row.media_status==(cached?"cached_thumbnail_available":"document_reference_only")&&(row.attachments??new string[0]).Length==(cached?1:0),"thumbnail is distinct from reference-only original attachment");
            foreach(string marker in new[]{"ATTRIBUTE_FILENAME_","ATTRIBUTE_TITLE_","ATTRIBUTE_PERFORMER_","OPAQUE_THUMB_"})Check(!row.text.Contains(marker),"metadata not promoted into native chat text");
            if(cached)Check(Hash(Safe(archive,row.attachments[0]))==Hash(Convert.FromBase64String(Png)),"cached PNG exact original bytes");Full(archive,row);
        }
        Check(seen.SetEquals(positives.Where(p=>Num(p.Value["expected_text_slots"])==1).Select(p=>p.Key)),"all30 independent text identities covered,empty metadata creates no message");
        foreach(var query in new[]{new[]{"recipe","literal"},new[]{"doc-cached-png","literal"},new[]{"recipe[\\s\\S]*第二行","regex"}}){bool regex=query[1]=="regex";var found=Search(archive,query[0],regex);Weak(found.Where(r=>!Native(r)));
            var expected=new HashSet<string>(positives.Values.Where(p=>Num(p["expected_text_slots"])==1&&(regex?Regex.IsMatch(Str((Dictionary<string,object>)p["expected"],"text"),query[0]):Str((Dictionary<string,object>)p["expected"],"text").IndexOf(query[0],StringComparison.OrdinalIgnoreCase)>=0)).Select(p=>Str(p,"tl_body_sha256")));
            Check(new HashSet<string>(found.Where(Native).Select(r=>r.native_tl_body_sha256)).SetEquals(expected)&&found.Count(Native)==expected.Count,"literal/Regex independent expected native body set");}
        foreach(string marker in new[]{"ATTRIBUTE_FILENAME_","ATTRIBUTE_TITLE_","ATTRIBUTE_PERFORMER_","OPAQUE_THUMB_"})Check(!Search(archive,marker).Any(Native),"metadata-only search never yields native text");
        Check(Search(archive,"",false,"deleted").Count==0,"current record presence does not prove deletion");
        var attachments=Rows(Read(Path.Combine(archive,"attachment-metadata.json"))["attachments"]);string pngHash=Hash(Convert.FromBase64String(Png));var image=attachments.Where(r=>Str(r,"sha256")==pngHash&&Str(r,"kind")=="cached_thumbnail").ToList();
        Check(attachments.Count==1&&image.Count==1&&Num(image[0]["size"])==Convert.FromBase64String(Png).Length&&Hash(Safe(archive,Str(image[0],"path")))==pngHash,"only one content-deduplicated exact cached PNG attachment");
        var origins=Rows(image[0]["sources"]);Check(origins.Count==2,"exactly two declared native thumbnail origins, no invented origin");foreach(string name in Cached){string suffix=name=="doc-cached-png"?"/document.thumbs[0]":"/document.thumbs[1]";var found=origins.Where(r=>String.Equals(Path.GetFullPath(Str(r,"source_file")),Source("current",name),StringComparison.OrdinalIgnoreCase)&&Str(r,"source_record").EndsWith(suffix,StringComparison.Ordinal)).ToList();
            Check(found.Count==1&&Str(found[0],"source_sha256")==Str(sqlite[name],"sha256")&&Str(found[0],"offset_kind")=="sqlite_tl_blob_relative","both original document.thumbs origins survive deduplication");
            byte[] blob=Convert.FromBase64String(Str(positives[name],"blob_base64")),png=Convert.FromBase64String(Png);long at=Num(found[0]["blob_offset"]);Check(at>=0&&at<=blob.Length-png.Length&&blob.Skip((int)at).Take(png.Length).SequenceEqual(png),"origin range replays exact independent native PNG bytes");}
    }
    static void Negatives()
    {
        string archive=Path.Combine(work,"controls");var summary=Analyze(Path.Combine(inputs,"controls"),archive);var all=Search(archive);Weak(all.Where(r=>!Native(r)));
        Check(summary.ReadableSources==171&&!all.Any(Native)&&summary.NativeRecords==0&&summary.HistoryMessages==0&&summary.Messages==all.Count&&summary.FragmentRecords==all.Count&&summary.DeletedSupportedRecords==0,"all171 malformed/scope sources opened,zero native messages");
    }
    static void HiddenMemory()
    {
        string root=Path.Combine(work,"owned-dump"),folder=Path.Combine(root,".hidden","cache"),file=Path.Combine(folder,"memory.bin");Directory.CreateDirectory(folder);
        File.SetAttributes(Directory.GetParent(folder).FullName,File.GetAttributes(Directory.GetParent(folder).FullName)|FileAttributes.Hidden);
        var known=positives["video-all-optional"];byte[] blob=Convert.FromBase64String(Str(known,"blob_base64"));using(var output=new FileStream(file,FileMode.CreateNew)){output.Write(new byte[513],0,513);output.Write(blob,0,blob.Length);output.Write(new byte[200],0,200);}File.SetAttributes(file,FileAttributes.ReadOnly|FileAttributes.Hidden);
        Check((File.GetAttributes(Directory.GetParent(folder).FullName)&FileAttributes.Hidden)!=0&&(File.GetAttributes(file)&FileAttributes.Hidden)!=0,"fixture exercises actual Windows-hidden folder and file");
        string archive=Path.Combine(work,"hidden-memory");var summary=Analyze(root,archive);var all=Search(archive);Weak(all);Check(summary.NativeRecords==0&&!all.Any(Native),"recursive memory presence is not native SQL history");
        var typed=all.Where(r=>r.record_kind=="typed_tl_fragment"&&r.native_tl_body_sha256==Str(known,"tl_body_sha256")).ToList();Check(typed.Count==1,"deep native attribute body retained once as unassigned structured fragment");var row=typed[0];
        Check(row.text==Str((Dictionary<string,object>)known["expected"],"text")&&Num(row.byte_offset)==513&&Num(row.byte_length)==Num(known["tl_bytes"])&&row.source_sha256==Hash(file)&&String.Equals(Path.GetFullPath(row.source_file),file,StringComparison.OrdinalIgnoreCase),"exact memory text/body/range/source hash");Full(archive,row);
    }
    static void Canceled()
    {
        string output=Path.Combine(work,"pre-canceled");using(var stop=new CancellationTokenSource()){stop.Cancel();bool canceled=false;try{TelegramAnalysisService.AnalyzeSelected(output,Path.Combine(inputs,"current"),"",false,stop.Token,m=>{});}catch(OperationCanceledException){canceled=true;}
            Check(canceled&&!Directory.Exists(output)&&!Directory.Exists(output+".work"),"public pre-cancel creates no archive/scratch");}
    }
    static Dictionary<string,string> Sources()
    {
        var result=Binding(Path.Combine(project,"tests","fixtures","telegram-document-attributes"));
        foreach(string file in new[]{"tests/TelegramDocumentAttributesPortableTests.cs","tests/TelegramDocumentAttributesPortableTests.ps1","tests/FrameworkTarget.cs","helpers/recovery_engine/telegram_tl.py","helpers/recovery_engine/telegram_auto.py","helpers/recovery_engine/engine.py","helpers/recovery_engine/archive_search.py","helpers/recovery_engine/archive_text.py","src/Recovery/Infrastructure/TelegramAnalysisService.cs","src/Recovery/Infrastructure/HelperClient.cs","src/Recovery/Infrastructure/ApplicationPaths.cs","src/Recovery/UI/ArchiveSearchPanel.cs"})result.Add("@source/"+file,Hash(Safe(project,file)));
        return result;
    }
    static Dictionary<string,string> Runtime(string helper,string app,string harness)
    {
        var result=Binding(Path.GetDirectoryName(helper));foreach(string file in new[]{app,harness,app+".config",harness+".config"}){Plain(file);result.Add("@entry/"+Path.GetFileName(file),Hash(file));}return result;
    }
    public static int Main(string[] args)
    {
        Exception failure=null;Dictionary<string,string> sourceBefore=null,inputBefore=null,runtimeBefore=null,sourceAfter=null,inputAfter=null,runtimeAfter=null;string helper=null,app=null,harness=null;CancellationTokenSource stop=null;
        try{
            if(args.Length!=1)throw new ArgumentException("Expected project directory");project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","telegram-document-attributes-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);inputs=Path.Combine(work,"inputs");
            stop=new CancellationTokenSource(TimeSpan.FromMinutes(15));phase=stop.Token;clock=Stopwatch.StartNew();sourceBefore=Sources();BindAndExtract();inputBefore=Binding(inputs);
            helper=HelperClient.Executable;app=typeof(RecoveryCore).Assembly.Location;harness=typeof(TelegramDocumentAttributesPortableTests).Assembly.Location;runtimeBefore=Runtime(helper,app,harness);
            Canceled();Current();Negatives();HiddenMemory();phase.ThrowIfCancellationRequested();
        }catch(Exception error){failure=error;}
        finally{
            context="final immutable bindings";try{
                if(inputBefore!=null){inputAfter=Binding(inputs);Check(Same(inputBefore,inputAfter)&&Directory.GetFiles(inputs,"*",SearchOption.AllDirectories).All(f=>(File.GetAttributes(f)&FileAttributes.ReadOnly)!=0),"every202 extracted source remains exact/read-only");}
                if(sourceBefore!=null){sourceAfter=Sources();Check(Same(sourceBefore,sourceAfter),"all oracle/source/wrapper bytes unchanged");}
                if(runtimeBefore!=null){runtimeAfter=Runtime(helper,app,harness);Check(Same(runtimeBefore,runtimeAfter),"all runtime dependencies/app/harness/config bytes unchanged");}
            }catch(Exception error){if(failure==null)failure=error;else failure=new AggregateException(failure,error);}if(stop!=null)stop.Dispose();
            if(work!=null)try{File.WriteAllText(Path.Combine(work,"acceptance.json"),Json.Serialize(new{schema=1,status=failure==null?"PASS":"FAIL",scope="Actual public Telegram analysis/search/full-text APIs; owned31/171 native inputs and hidden memory; no device/server/paid or full attachment recovery claim",checks=checks,analyses=analyses,oracle_manifest_sha256=Manifest,zip_sha256=ZipHash,app=app,helper=helper,harness=harness,source_before=sourceBefore,source_after=sourceAfter,input_before=inputBefore,input_after=inputAfter,runtime_before=runtimeBefore,runtime_after=runtimeAfter,runs=Runs,error=failure==null?null:failure.ToString()}),new UTF8Encoding(false));}catch(Exception error){if(failure==null)failure=error;}
        }
        if(failure!=null){Console.Error.WriteLine(failure);return 1;}Console.WriteLine("PASS TelegramDocumentAttributesPortable: "+checks+" checks;31 native sources/30 exact texts,171 controls/zero native,2 cached PNG origins,keyword/Regex/fulltext,hidden-memory separation,cancel and immutable bindings. No device or paid-tool claim.");return 0;
    }
}
