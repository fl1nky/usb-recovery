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
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using UsbRecovery;

// Mandatory actual packaged public API acceptance. Never run the old helper.
public static class TelegramDocumentDescriptorPortableTests
{
    const string Commit="4de548e79fed27f1a66fbdff84223321838fe925";
    const string OracleManifest="8b2d3c7b6fe1f259607ef18987bcd51625412aad9a59c747f72980b212f712f7";
    const string CompatibilityManifest="27075f5e9ca95c54c0e07163bdf22d3756cdc7ef756e1baeff3fffa415d10f33";
    const string CorpusManifest="799f8beebdae559417726f53d396ea36172e463d82e2869293bb6789904d7585";
    const string CorpusZip="b49b62b0c45eca231eb4da8c9bdd00d156c2ac5ed210f1f1dc1a29ded6fd7d49";
    const string CorpusProducer="5271f29ccb6770ffd67b5373c06dd028d36f2dbae55a543cbdd93fdbe84b65cc";
    const string Factory="bef894bb21c46198ef3617c1f974db40dce52fae9f2051a7e50e73368697c4da";
    const string SqliteFactory="3936357e1a2dee4e4fe9bd7d7c422b35f6cea0724dc7a0df7da93b396b2da205";
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static Dictionary<string,Dictionary<string,object>> oracle,controls,compatibility;
    static Dictionary<string,object> corpus,files;
    static string project,work,fixtures,context;
    static int checks,analyses;
    static CancellationToken phase;
    static Stopwatch clock;
    static readonly List<object> runs=new List<object>();
    static void Check(bool value,string why){checks++;if(!value)throw new Exception((context??"setup")+": "+why);}
    static object Get(Dictionary<string,object> row,string key){object v;return row.TryGetValue(key,out v)?v:null;}
    static string Str(Dictionary<string,object> row,string key){return Get(row,key) as string;}
    static long Num(object value){return Convert.ToInt64(value,CultureInfo.InvariantCulture);}
    static List<Dictionary<string,object>> List(object value){return ((IEnumerable)value).Cast<Dictionary<string,object>>().ToList();}
    static Dictionary<string,object> Read(string file){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file,Encoding.UTF8));}
    static string Hash(string file){using(var input=File.OpenRead(file))using(var sha=SHA256.Create())return Hex(sha.ComputeHash(input));}
    static string Hex(byte[] value){return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();}
    static string HashBytes(byte[] value,int count){using(var sha=SHA256.Create())return Hex(sha.ComputeHash(value,0,count));}
    static bool H64(string value){return value!=null&&value.Length==64&&value.All(c=>c>='0'&&c<='9'||c>='a'&&c<='f');}
    static string Safe(string root,string relative)
    {
        Check(!String.IsNullOrEmpty(relative)&&relative.Length<400&&!Path.IsPathRooted(relative)&&!relative.Contains('\\'),"only bounded forward-slash relative paths");
        Check(relative.Split('/').All(p=>p!=""&&p!="."&&p!=".."&&p.IndexOf(':')<0),"no traversal, empty segments or stream names");
        return RecoveryCatalog.SafeFile(root,relative);
    }
    static void Plain(string path)
    {
        var file=new FileInfo(Path.GetFullPath(path));
        Check(file.Exists&&(file.Attributes&FileAttributes.ReparsePoint)==0,"plain existing input file");
        for(var dir=file.Directory;dir!=null;dir=dir.Parent)Check((dir.Attributes&FileAttributes.ReparsePoint)==0,"no input ancestor redirects outside the owned corpus");
    }
    static Dictionary<string,string> Binding(string root)
    {
        return Directory.GetFiles(root,"*",SearchOption.AllDirectories).ToDictionary(p=>p.Substring(root.Length+1),Hash,StringComparer.OrdinalIgnoreCase);
    }
    static bool Same(Dictionary<string,string> a,Dictionary<string,string> b){return a.Count==b.Count&&a.All(p=>b.ContainsKey(p.Key)&&b[p.Key]==p.Value);}
    static T Guard<T>(Func<CancellationToken,T> action)
    {
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(phase)){
            stop.CancelAfter(TimeSpan.FromMinutes(4)+TimeSpan.FromSeconds(45));
            int remaining=(int)Math.Min(300000,1200000-clock.ElapsedMilliseconds);
            if(remaining<=0)throw new TimeoutException("Twenty-minute phase watchdog; no completion inferred");
            var task=Task.Run(()=>action(stop.Token));
            if(Task.WaitAny(new Task[]{task},remaining)<0){stop.Cancel();throw new TimeoutException("Call/phase watchdog; completion and cleanup unconfirmed");}
            return task.GetAwaiter().GetResult();
        }
    }
    static List<Dictionary<string,object>> Parts(Dictionary<string,object> value)
    {
        var result=new List<Dictionary<string,object>>();
        if(Get(value,"expected_native_parts")!=null&&Num(value["expected_native_parts"])==0)return result;
        var expected=(Dictionary<string,object>)value["expected"];string text=Str(expected,"text"),caption=Str(value,"expected_legacy_caption");
        if(!String.IsNullOrEmpty(text))result.Add(new Dictionary<string,object>{{"text",text},{"text_field","message"},{"supplemental",false}});
        if(!String.IsNullOrEmpty(caption)&&caption!=text)result.Add(new Dictionary<string,object>{{"text",caption},{"text_field","media.legacy_caption"},{"supplemental",!String.IsNullOrEmpty(text)}});
        return result;
    }
    // retained_media_records_v1 changes record retention, never frozen text-slot goldens.
    static List<Dictionary<string,object>> CurrentParts(Dictionary<string,object> value)
    {
        var result=Parts(value);
        if(result.Count==0&&Get(value,"document_id")!=null){
            Check(String.IsNullOrEmpty(Str((Dictionary<string,object>)value["expected"],"text")),"retained media-only record has exact empty native text");
            result.Add(new Dictionary<string,object>{{"text",""},{"text_field","message"},{"supplemental",false}});
        }
        return result;
    }
    static void Wire(Dictionary<string,object> item)
    {
        byte[] blob=Convert.FromBase64String(Str(item,"blob_base64"));long body=Num(item["tl_bytes"]);
        Check(body>0&&body<=blob.Length&&blob.Length==Num(item["bytes"])&&HashBytes(blob,blob.Length)==Str(item,"blob_sha256")&&HashBytes(blob,(int)body)==Str(item,"tl_body_sha256"),"complete independent native BLOB and measured TL prefix have their exact SHA/length");
    }
    static void BindOracle()
    {
        string root=Path.Combine(project,"tests","fixtures","telegram-document-descriptor"),manifest=Path.Combine(root,"manifest.json");Plain(manifest);
        Check(Hash(manifest)==OracleManifest,"hard-pinned official Java manifest");var pinned=Read(manifest);var members=List(pinned["files"]);
        Check(Num(pinned["schema"])==1&&Num(pinned["positive_cases"])==21&&Num(pinned["mutation_controls"])==42&&Str(pinned,"telegram_commit")==Commit&&members.Count==3&&new HashSet<string>(members.Select(m=>Str(m,"path"))).SetEquals(new[]{"oracle.json.gz","oracle-sources.tar.gz","LICENSE"}),"exact native oracle profile and three canonical members");
        foreach(var member in members){string file=Safe(root,Str(member,"path"));Plain(file);Check(new FileInfo(file).Length==Num(member["bytes"])&&Hash(file)==Str(member,"sha256"),"native oracle member bytes remain exact");}
        byte[] raw;
        using(var input=File.OpenRead(Path.Combine(root,"oracle.json.gz")))using(var gzip=new GZipStream(input,CompressionMode.Decompress))using(var output=new MemoryStream()){
            byte[] buffer=new byte[8192];int n;while((n=gzip.Read(buffer,0,buffer.Length))>0){phase.ThrowIfCancellationRequested();Check(output.Length<=2*1024*1024-n,"bounded oracle expansion");output.Write(buffer,0,n);}raw=output.ToArray();
        }
        Check(raw.Length==Num(pinned["uncompressed_json_bytes"])&&HashBytes(raw,raw.Length)==Str(pinned,"uncompressed_json_sha256"),"oracle full raw JSON length/hash");
        var payload=Json.Deserialize<Dictionary<string,object>>(new UTF8Encoding(false,true).GetString(raw));var positives=List(payload["positive_cases"]);var negatives=List(payload["mutation_controls"]);
        Check(Num(payload["schema"])==1&&Str(payload,"commit")==Commit&&positives.Count==21&&negatives.Count==42&&positives.Select(p=>Str(p,"name")).Distinct().Count()==21&&negatives.Select(p=>Str(p,"name")).Distinct().Count()==42,"all native and negative cases, without replacement");
        byte[] sql=Encoding.UTF8.GetBytes(Str(payload,"sql_schema"));Check(HashBytes(sql,sql.Length)==Str(pinned,"native_sql_schema_sha256"),"exact official native SQL schema");
        oracle=positives.ToDictionary(p=>Str(p,"name"),StringComparer.Ordinal);controls=negatives.ToDictionary(p=>Str(p,"name"),StringComparer.Ordinal);
        foreach(var item in positives)Wire(item);
        foreach(var item in negatives){Wire(item);Check(oracle.ContainsKey(Str(item,"parent"))&&Str(item,"native_parent_blob_sha256")==Str(oracle[Str(item,"parent")],"blob_sha256")&&Num(item["expected_native_parts"])==0&&new[]{"parser_reject","scope_reject"}.Contains(Str(item,"expected_outcome")),"negative expectation and exact native parent are independently pinned");}
        Check(Parts(oracle["descriptor-empty-text"]).Count==0&&Parts(oracle["legacy-empty-two-text-slots"]).Count==2,"filename never becomes text; distinct legacy slots remain separate");
    }
    static List<Dictionary<string,object>> Cases(string category){return List(corpus["cases"]).Where(p=>Str(p,"category")==category).ToList();}
    static void BindCompatibility()
    {
        string root=Path.Combine(project,"tests","fixtures","telegram-document-attributes-compatibility"),manifest=Path.Combine(root,"manifest.json");Plain(manifest);
        Check(Hash(manifest)==CompatibilityManifest,"hard-pinned supplemental native compatibility manifest");
        var pinned=Read(manifest);var members=List(pinned["files"]);
        var names=new HashSet<string>(new[]{3,4,6,7,8}.Select(bit=>"reject-media-flags-bit"+bit));
        Check(Str(pinned,"source_fixture_manifest_sha256")==OracleManifest&&Num(pinned["explicit_compatibility_upgrades"])==5&&members.Count==4&&new HashSet<string>(members.Select(m=>Str(m,"path"))).SetEquals(new[]{"compatibility.json.gz","oracle-sources.tar.gz","LICENSE","README.md"}),"exact five-only policy and complete native source payload");
        foreach(var member in members){string file=Safe(root,Str(member,"path"));Plain(file);Check(new FileInfo(file).Length==Num(member["bytes"])&&Hash(file)==Str(member,"sha256"),"compatibility proof member bytes remain exact");}
        byte[] raw;
        using(var input=File.OpenRead(Path.Combine(root,"compatibility.json.gz")))using(var gzip=new GZipStream(input,CompressionMode.Decompress))using(var output=new MemoryStream()){
            byte[] buffer=new byte[8192];int n;while((n=gzip.Read(buffer,0,buffer.Length))>0){phase.ThrowIfCancellationRequested();Check(output.Length<=1024*1024-n,"bounded compatibility expansion");output.Write(buffer,0,n);}raw=output.ToArray();
        }
        Check(raw.Length==Num(pinned["uncompressed_json_bytes"])&&HashBytes(raw,raw.Length)==Str(pinned,"uncompressed_json_sha256"),"complete independent compatibility JSON bytes");
        var payload=Json.Deserialize<Dictionary<string,object>>(new UTF8Encoding(false,true).GetString(raw));
        var proofs=List(payload["cases"]);var native=List(payload["native_results"]).ToDictionary(p=>Str(p,"name"),StringComparer.Ordinal);
        var policy=(Dictionary<string,object>)payload["policy"];
        Check(Str(payload,"old_fixture_manifest_sha256")==OracleManifest&&proofs.Count==6&&native.Count==6&&new HashSet<string>(((IEnumerable)policy["upgrade_control_names"]).Cast<string>()).SetEquals(names),"supplement preserves old oracle and names only five upgrades");
        compatibility=new Dictionary<string,Dictionary<string,object>>(StringComparer.Ordinal);
        foreach(var proof in proofs.Where(p=>names.Contains(Str(p,"name")))){
            string name=Str(proof,"name");var old=controls[name];var known=new Dictionary<string,object>(oracle[Str(old,"parent")]);foreach(var item in old)known[item.Key]=item.Value;
            var outputs=(Dictionary<string,object>)native[name]["outputs"];var blob=(Dictionary<string,object>)outputs["blob"];var body=(Dictionary<string,object>)outputs["body"];
            Check(Num(old["expected_native_parts"])==0&&Str(old,"parent")=="descriptor-filename"&&Str(native[name],"scope")=="WHOLE_BLOB_NATIVE_EXACT"&&Str(proof,"blob_sha256")==Str(old,"blob_sha256")&&Str(blob,"sha256")==Str(old,"blob_sha256")&&Str(proof,"tl_body_sha256")==Str(old,"tl_body_sha256")&&Str(body,"sha256")==Str(old,"tl_body_sha256")&&Num(proof["tl_bytes"])==Num(old["tl_bytes"]),"exact historical control independently reserialized as a complete native body/BLOB");
            Check(Json.Serialize(proof["exact_sql"])==Json.Serialize(known["exact_sql"])&&Json.Serialize(proof["expected_message"])==Json.Serialize(known["expected"]),"same independent native field and SQL expectations");
            Wire(known);known["expected_native_parts"]=1;compatibility.Add(name,known);
        }
        Check(new HashSet<string>(compatibility.Keys).SetEquals(names),"no omitted, duplicate or extra compatibility upgrade; old goldens unchanged");
    }
    static Dictionary<string,object> FileProof(string relative){return (Dictionary<string,object>)files[relative];}
    static void ExtractCorpus()
    {
        string root=Path.Combine(project,"tests","fixtures","telegram-document-descriptor-portable"),manifest=Path.Combine(root,"manifest.json"),zip=Path.Combine(root,"native-cases.zip");Plain(manifest);Plain(zip);
        Check(Hash(manifest)==CorpusManifest&&Hash(zip)==CorpusZip,"hard-pinned native SQLite corpus manifest and ZIP");corpus=Read(manifest);files=(Dictionary<string,object>)corpus["files"];
        Check(Num(corpus["schema"])==1&&Str(corpus,"telegram_commit")==Commit&&Str(corpus,"oracle_manifest_sha256")==OracleManifest&&Str(corpus,"generator_sha256")==CorpusProducer&&Str(corpus,"source_factory_sha256")==Factory&&Str(corpus,"original_sqlite_factory_sha256")==SqliteFactory,"native corpus binds exact independent oracle and source producer/factories");
        foreach(var pair in new[]{new[]{"build_telegram_descriptor_portable_corpus.py",CorpusProducer},new[]{"build_telegram_document_descriptor_fixtures.py",Factory},new[]{"build_telegram_document_empty_fixtures.py",SqliteFactory}}){string p=Path.Combine(project,"tests",pair[0]);Plain(p);Check(Hash(p)==pair[1],"complete fixture source factory binding");}
        var archive=(Dictionary<string,object>)corpus["archive"];Check(Str(archive,"path")=="native-cases.zip"&&Num(archive["bytes"])==new FileInfo(zip).Length&&Str(archive,"sha256")==CorpusZip&&new FileInfo(zip).Length<1024*1024,"bounded ZIP transport bytes");
        var cases=List(corpus["cases"]);Check(cases.Count==66&&cases.Select(p=>Str(p,"category")+"/"+Str(p,"name")).Distinct().Count()==66&&Cases("current").Count==21&&Cases("controls").Count==42&&Cases("history").Count==1&&Cases("residual").Count==1&&Cases("versions").Count==1,"all66 native sources mandatory exactly once");
        Check(new HashSet<string>(Cases("current").Select(p=>Str(p,"name"))).SetEquals(oracle.Keys)&&new HashSet<string>(Cases("controls").Select(p=>Str(p,"name"))).SetEquals(controls.Keys),"no current or negative case substituted or omitted");
        var expectedFiles=new HashSet<string>(StringComparer.Ordinal);
        foreach(var item in cases){
            string category=Str(item,"category"),name=Str(item,"name"),database=Str(item,"database"),variant=Str(item,"variant");
            if(category=="versions")Check(name=="versions"&&variant=="versions"&&database=="versions/cache4.db"&&((IEnumerable)item["oracle_names"]).Cast<string>().SequenceEqual(new[]{"descriptor-id-zero","descriptor-id-negative"}),"versions use exact preselected independently serialized bodies");
            else{
                Check(database==category+"/"+name+"/cache4.db"&&variant==(category=="current"||category=="controls"?"current":category),"native source path/category/variant exact");
                Check(category=="controls"?Str(item,"control_name")==name&&Str(item,"oracle_name")==Str(controls[name],"parent"):Get(item,"control_name")==null&&Str(item,"oracle_name")==name,"case directly binds its independent native parent");
                if(category=="history"||category=="residual")Check(name=="descriptor-filename","snapshots bind the exact filename descriptor, not synthetic text");
            }
            expectedFiles.Add(database);if(category=="history"||category=="residual"||category=="versions"){expectedFiles.Add(database+"-wal");expectedFiles.Add(database+"-shm");}
        }
        Check(files.Count==72&&expectedFiles.SetEquals(files.Keys),"the complete native DB/WAL/SHM fileset is exact");
        Directory.CreateDirectory(fixtures);long total=0;var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using(var input=File.OpenRead(zip))using(var reader=new ZipArchive(input,ZipArchiveMode.Read)){
            Check(reader.Entries.Count==72,"ZIP has no undeclared or duplicate entries");
            foreach(var entry in reader.Entries){phase.ThrowIfCancellationRequested();string relative=entry.FullName;
                Check(files.ContainsKey(relative)&&seen.Add(relative)&&!relative.EndsWith("/",StringComparison.Ordinal),"exact unique regular ZIP member name");
                int mode=(entry.ExternalAttributes>>16)&0xf000;Check((mode==0||mode==0x8000)&&(entry.ExternalAttributes&(int)FileAttributes.ReparsePoint)==0,"no links/devices/reparse ZIP entries");
                var proof=FileProof(relative);Check(proof.Count==2&&H64(Str(proof,"sha256"))&&entry.Length==Num(proof["bytes"])&&entry.Length>0&&entry.Length<=4*1024*1024&&total<=16*1024*1024-entry.Length,"bounded exact decompressed length");total+=entry.Length;
                string output=Safe(fixtures,relative);Directory.CreateDirectory(Path.GetDirectoryName(output));
                using(var source=entry.Open())using(var destination=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
                    byte[] buffer=new byte[8192];long bytes=0;int n;while((n=source.Read(buffer,0,buffer.Length))>0){phase.ThrowIfCancellationRequested();Check(bytes<=entry.Length-n,"ZIP stream cannot expand beyond its pinned length");destination.Write(buffer,0,n);bytes+=n;}Check(bytes==entry.Length,"ZIP stream complete");
                }
                Check(Hash(output)==Str(proof,"sha256"),"extracted input exact SHA");File.SetAttributes(output,File.GetAttributes(output)|FileAttributes.ReadOnly);Plain(output);
            }
        }
        Check(seen.SetEquals(expectedFiles)&&Binding(fixtures).Count==72,"safe extraction publishes exactly all72 immutable input files");
        foreach(var item in Cases("current"))Check(Occurrences(File.ReadAllBytes(Safe(fixtures,Str(item,"database"))),Convert.FromBase64String(Str(oracle[Str(item,"oracle_name")],"blob_base64")))==1,"native SQLite positive contains the entire independent BLOB exactly once");
    }
    static int Occurrences(byte[] haystack,byte[] needle)
    {
        int count=0;for(int at=0;at<=haystack.Length-needle.Length;at++){if((at&4095)==0)phase.ThrowIfCancellationRequested();int i=0;while(i<needle.Length&&haystack[at+i]==needle[i])i++;if(i==needle.Length)count++;}return count;
    }
    static void NoLimits(IEnumerable<string> warnings)
    {
        foreach(string warning in warnings??new string[0])Check(warning==null||new[]{"LIMIT","BUDGET","TIMEOUT","CANCEL","INCOMPLETE"}.All(word=>warning.IndexOf(word,StringComparison.OrdinalIgnoreCase)<0),"limited/incomplete work cannot pass as accepted exhaustive case coverage: "+warning);
    }
    static HelperResult Analyze(string source,string output)
    {
        context=Path.GetFileName(output);analyses++;var timer=Stopwatch.StartNew();bool file=File.Exists(source);var before=file?new Dictionary<string,string>{{Path.GetFileName(source),Hash(source)}}:Binding(source);
        var result=Guard(token=>TelegramAnalysisService.AnalyzeSelected(output,source,"",false,token,message=>{}));
        Check((result.Status=="complete"||result.Status=="partial")&&File.Exists(Path.Combine(output,"messages.jsonl"))&&!File.Exists(Path.Combine(output,"job.incomplete"))&&!Directory.Exists(output+".work"),"public analysis publishes a controlled archive and cleans scratch");NoLimits(result.Warnings);
        var after=file?new Dictionary<string,string>{{Path.GetFileName(source),Hash(source)}}:Binding(source);Check(Same(before,after),"selected source bytes remain immutable");
        runs.Add(new{source=source,archive=output,status=result.Status,code=result.Code,messages=result.Messages,native_records=result.NativeRecords,fragments=result.FragmentRecords,seconds=timer.Elapsed.TotalSeconds,source_before=before,source_after=after});return result;
    }
    static ArchiveSearchResult Search(string archive,string query,long offset=0,bool regex=false,string evidence="")
    {
        var result=Guard(token=>ArchiveSearchService.Search(archive,"Telegram",query,evidence,offset,token,regex));
        Check((result.status=="complete"||result.status=="partial")&&result.records!=null,"controlled public search page");NoLimits(result.warnings);return result;
    }
    static List<ArchiveMessage> All(string archive,string query="",bool regex=false)
    {
        var rows=new List<ArchiveMessage>();long total=-1;
        do{phase.ThrowIfCancellationRequested();var page=Search(archive,query,rows.Count,regex);if(total<0)total=page.total;
            Check(total>=0&&total<=10000&&page.total==total&&page.offset==rows.Count&&(page.records.Count>0||total==0),"bounded pagination keeps exact total and advances");rows.AddRange(page.records);
        }while(rows.Count<total);
        Check(rows.Count==total&&rows.All(r=>!String.IsNullOrEmpty(r.archive_record_key))&&rows.Select(r=>r.archive_record_key).Distinct().Count()==rows.Count,"every returned row is unique and has a full-text locator");return rows;
    }
    static bool Native(ArchiveMessage row){return new[]{"tl_message","tl_message_caption","sqlite_deleted_record","sqlite_deleted_caption"}.Contains(row.record_kind)&&row.application_confirmed==true&&row.evidence_kind!="fragment"&&row.provenance_verification!="provided_archive_metadata";}
    static string Key(ArchiveMessage row){return row.identity_scope+"|"+row.native_tl_body_sha256+"|"+row.text_field;}
    static void Fragments(IEnumerable<ArchiveMessage> rows)
    {
        foreach(var row in rows){bool memory=row.record_kind=="memory_fragment";
            Check(row.evidence_kind=="fragment"&&(memory||new[]{"typed_tl_fragment","sqlite_residual_fragment","sqlite_wal_residual"}.Contains(row.record_kind)),"nonhistory rows have explicit weak fragment classification");
            Check(row.application_confirmed==(memory?false:true)&&row.chat_id==null&&row.chat_name==null&&row.message_id==null&&row.sender_id==null&&row.sender_name==null&&row.timestamp==null&&row.timestamp_raw==null,"type recognition does not invent SQL chat, author, message or date");
            Check(row.deleted==null&&(row.recovery_status==null||row.recovery_status=="unattributed_structured_fragment")&&(row.residual_sources==null||row.residual_sources.Length==0)&&row.wal_proof==null&&row.wal_snapshot_sha256==null&&row.sqlite_record_sha256==null&&row.sqlite_payload_sha256==null&&row.sqlite_overflow_chain_verified!=true&&row.rollback_content_authenticity_verified!=true,"weak fragments never borrow native/deletion proof");
        }
    }
    static void Counts(HelperResult summary,List<ArchiveMessage> all,List<ArchiveMessage> native,int expected,int deleted)
    {
        Check(native.Count==expected&&summary.Messages==all.Count&&summary.NativeRecords==expected&&summary.HistoryMessages==expected&&summary.FragmentRecords==all.Count-native.Count&&summary.DeletedSupportedRecords==deleted&&summary.Media==0,"exact native/fragment summary; rows="+all.Count+",native="+native.Count+",expected="+expected);Fragments(all.Where(r=>!native.Contains(r)));
    }
    static void Acquired(string archive,IEnumerable<string> expected)
    {
        var rows=List(Read(Path.Combine(archive,"acquisition.json"))["Files"]);var paths=expected.ToList();
        Check(rows.Count==paths.Count,"every selected physical source is acquired exactly once");
        foreach(string file in paths){var selected=rows.Where(r=>String.Equals(Path.GetFullPath(Str(r,"OriginalPath")),Path.GetFullPath(file),StringComparison.OrdinalIgnoreCase)).ToList();
            Check(selected.Count==1&&Str(selected[0],"Status")=="complete"&&Num(selected[0]["Size"])==new FileInfo(file).Length&&Str(selected[0],"Sha256")==Hash(file),"selected native input was actually copied completely with exact size/hash: "+file);
        }
    }
    static IEnumerable<string> Members(Dictionary<string,object> item)
    {
        string database=Str(item,"database");return files.Keys.Where(key=>key==database||key==database+"-wal"||key==database+"-shm").Select(key=>Safe(fixtures,key));
    }
    static void Scope(ArchiveMessage row,string database)
    {
        byte[] normalized=Encoding.UTF8.GetBytes(Path.GetFullPath(database).Replace('/','\\').ToLowerInvariant());
        Check(row.identity_scope=="telegram-db:"+HashBytes(normalized,normalized.Length),"exact SQL source scope binds the normalized original DB path");
    }
    static void Part(ArchiveMessage row,Dictionary<string,object> known,bool historical,bool imported=false)
    {
        var parts=CurrentParts(known);var part=parts.Single(p=>Str(p,"text_field")==row.text_field);var expected=(Dictionary<string,object>)known["expected"];var sql=(Dictionary<string,object>)known["exact_sql"];
        Check(row.text==Str(part,"text")&&Num(row.chat_id)==Num(sql["uid"])&&Num(row.message_id)==Num(expected["id"])&&Num(row.native_layer)==Num(known["layer"])&&row.native_constructor==Str(known,"constructor")&&row.native_tl_body_sha256==Str(known,"tl_body_sha256"),"native Unicode field, SQL identity, exact profile and independently measured full body SHA");
        var sender=Get(expected,"from_peer") as Dictionary<string,object>;string wanted=sender==null?null:Str(sender,"kind")+":"+Num(sender["id"]).ToString(CultureInfo.InvariantCulture);
        Check((wanted==null?row.sender_id==null:row.sender_id is string&&(string)row.sender_id==wanted)&&row.sender_name==null&&row.chat_name==null,"observed author and unknown names are exact");
        DateTimeOffset date;long unix=Num(expected["date"]);
        Check(unix==0?row.timestamp==null:DateTimeOffset.TryParse(row.timestamp as string,CultureInfo.InvariantCulture,DateTimeStyles.None,out date)&&date.ToUniversalTime()==new DateTimeOffset(1970,1,1,0,0,0,TimeSpan.Zero).AddSeconds(unix),"date equals independent native message date");
        Check(row.record_kind==((bool)part["supplemental"]?"tl_message_caption":"tl_message")&&row.application_confirmed==true&&row.evidence_kind==(historical?"previous":"backup")&&row.deleted==null,"separate field roles and snapshot category; user deletion remains unknown");
        Check(row.media_kind=="document"&&row.media_status=="document_reference_only"&&row.media_id==Str(known,"document_id")&&row.thumbnail_count!=null&&Num(row.thumbnail_count)==0&&(row.attachments==null||row.attachments.Length==0),"exact opaque signed/zero ID, reference-only status, no invented file bytes");
        Check(!String.IsNullOrEmpty(row.archive_record_key)&&(!imported||row.provenance_verification=="provided_archive_metadata"),"search locator and explicit untrusted reimport category");
    }
    static void Full(string archive,ArchiveMessage row)
    {
        var page=Guard(token=>ArchiveSearchService.ReadPage(archive,row.archive_record_key,0,token));
        Check(page.status=="complete"&&page.eof&&page.text==row.text,"public full-text read returns the exact Unicode slot");
    }
    static void Wal(ArchiveMessage row,string source,Dictionary<string,object> known)
    {
        Check(row.wal_proof=="all_pages_from_validated_wal"&&row.wal_db_sha256==Hash(source)&&row.wal_sha256==Hash(source+"-wal")&&H64(row.wal_snapshot_sha256)&&row.wal_commit_frame!=null&&Num(row.wal_commit_frame)>0,"history binds original DB/WAL hashes and a structurally validated committed snapshot");
        byte[] native=Convert.FromBase64String(Str(known,"blob_base64"));Check(Occurrences(File.ReadAllBytes(source+"-wal"),native)>0,"known complete native BLOB survives in the exact source WAL");
    }
    static void Residual(Dictionary<string,object> origin,string source,Dictionary<string,object> known,ArchiveMessage row)
    {
        Check(Str(origin,"text_field")==row.text_field&&String.Equals(Path.GetFullPath(Str(origin,"source_file")),source,StringComparison.OrdinalIgnoreCase)&&Str(origin,"physical_source")=="wal","residual proof binds the same original WAL and text role");
        long at=Num(origin["physical_byte_offset"]),length=Num(origin["sqlite_record_length"]);string wal=source+"-wal";
        Check(at>=0&&length>0&&length<=4*1024*1024&&at<=new FileInfo(wal).Length-length,"residual physical range lies within original WAL");
        byte[] raw=new byte[(int)length];using(var input=File.OpenRead(wal)){input.Position=at;int n=0;while(n<raw.Length){phase.ThrowIfCancellationRequested();int count=input.Read(raw,n,raw.Length-n);if(count==0)throw new EndOfStreamException();n+=count;}}
        Check(HashBytes(raw,raw.Length)==Str(origin,"sqlite_record_sha256"),"exact physical record replay SHA, not an independent record-boundary oracle");
        Check(Occurrences(raw,Convert.FromBase64String(Str(known,"blob_base64")))==1,"replayed record contains exact complete independent native BLOB once");
    }
    static List<ArchiveMessage> Current()
    {
        string archive=Path.Combine(work,"current");var items=Cases("current");var summary=Analyze(Path.Combine(fixtures,"current"),archive);Acquired(archive,items.SelectMany(Members));
        var all=All(archive);var rows=all.Where(Native).ToList();int expected=oracle.Values.Sum(p=>CurrentParts(p).Count);Counts(summary,all,rows,expected,0);
        var bySource=items.ToDictionary(i=>Safe(fixtures,Str(i,"database")),i=>i,StringComparer.OrdinalIgnoreCase);var actual=new HashSet<string>();
        foreach(var row in rows){Check(bySource.ContainsKey(Path.GetFullPath(row.source_file)),"every native row belongs to a preselected exact current source");var item=bySource[Path.GetFullPath(row.source_file)];string name=Str(item,"oracle_name");var known=oracle[name];Part(row,known,false);Scope(row,Safe(fixtures,Str(item,"database")));
            Check(actual.Add(name+"|"+row.text_field)&&row.source_sha256==Str(FileProof(Str(item,"database")),"sha256"),"every native case/slot occurs once with exact source hash");Full(archive,row);
        }
        var expectedKeys=new HashSet<string>(oracle.SelectMany(p=>CurrentParts(p.Value).Select(part=>p.Key+"|"+Str(part,"text_field"))));
        Check(actual.SetEquals(expectedKeys)&&rows.Select(Key).Distinct().Count()==expected,"all independent text slots/identities, including signed endpoints, appear exactly once");
        Check(rows.Count(row=>Path.GetFileName(Path.GetDirectoryName(row.source_file))=="descriptor-empty-text"&&row.text==""&&row.text_field=="message")==1&&Parts(oracle["descriptor-empty-text"]).Count==0,"native media-only record survives; filename never becomes text");
        foreach(string id in new[]{"0","-1",Int64.MinValue.ToString(CultureInfo.InvariantCulture),Int64.MaxValue.ToString(CultureInfo.InvariantCulture)})Check(rows.Any(r=>r.media_id==id),"actual public DTO/search preserves signed document endpoint "+id);
        foreach(var query in new[]{new[]{"recipe","literal"},new[]{"recipe[\\s\\S]*第二行","regex"}}){
            bool regex=query[1]=="regex";var found=All(archive,query[0],regex);var native=found.Where(Native).ToList();Fragments(found.Where(r=>!native.Contains(r)));
            var wanted=rows.Where(r=>regex?r.text.Contains("recipe")&&r.text.Contains("第二行"):r.text.IndexOf("recipe",StringComparison.OrdinalIgnoreCase)>=0).Select(Key);
            Check(native.Count==wanted.Count()&&new HashSet<string>(native.Select(Key)).SetEquals(wanted),"literal/Regex search exact independently expected field set");
        }
        Check(Search(archive,"",0,false,"deleted").total==0,"current observations never imply supported deletion");
        string html=File.ReadAllText(Path.Combine(archive,"Переписки.html"),Encoding.UTF8);Check(html.Contains("connect-src 'none'")&&!html.Contains("<script src=")&&html.Contains("Сохранилась запись о вложении."),"offline HTML keeps reference-only attachment explanation and no remote fetch");
        Reimport(archive,rows,false);return rows;
    }
    static void Reimport(string archive,List<ArchiveMessage> original,bool historical)
    {
        string output=archive+"-reimport";Analyze(Path.Combine(archive,"messages.jsonl"),output);var all=All(output);var copied=all.Where(r=>r.provenance_verification=="provided_archive_metadata"&&new[]{"tl_message","tl_message_caption"}.Contains(r.record_kind)).ToList();
        Check(!all.Any(Native)&&copied.Count==original.Count&&copied.Select(Key).Distinct().Count()==copied.Count&&new HashSet<string>(copied.Select(Key)).SetEquals(original.Select(Key)),"canonical reimport retains complete unique field set and cannot reauthenticate metadata");
        var byKey=original.ToDictionary(Key);foreach(var row in copied){var prior=byKey[Key(row)];var known=oracle.Values.Single(k=>Str(k,"tl_body_sha256")==row.native_tl_body_sha256);Part(row,known,historical,true);Scope(row,prior.source_file);Check(row.text==prior.text&&row.media_id==prior.media_id&&row.deleted==null&&(!historical||row.recovery_status=="imported_recovery_claim"),"reimport keeps exact text/reference while residual claims remain explicitly unverified");Full(output,row);}
        Fragments(all.Where(r=>!copied.Contains(r)));Check(Search(output,"",0,false,"deleted").total==0,"provided canonical archive cannot enter supported-deletion filter");
    }
    static void Negatives()
    {
        string archive=Path.Combine(work,"controls");var summary=Analyze(Path.Combine(fixtures,"controls"),archive);Acquired(archive,Cases("controls").SelectMany(Members));
        var all=All(archive);var rows=all.Where(Native).ToList();Counts(summary,all,rows,5,0);
        foreach(var pair in compatibility){var known=pair.Value;var selected=rows.Where(r=>r.native_tl_body_sha256==Str(known,"tl_body_sha256")).ToList();Check(selected.Count==1,"each of five independently proved compatibility inputs yields exactly its one text slot");var row=selected[0];Part(row,known,false);var item=Cases("controls").Single(c=>Str(c,"name")==pair.Key);string source=Safe(fixtures,Str(item,"database"));Scope(row,source);Check(String.Equals(Path.GetFullPath(row.source_file),source,StringComparison.OrdinalIgnoreCase)&&row.source_sha256==Hash(source),"compatible input retains its own physical source binding");Full(archive,row);}
        Check(Search(archive,"",0,false,"deleted").total==0,"37 strict controls remain nonnative; five known boolean profiles make no deletion claim");
        Check(summary.ReadableSources==42,"all42 negative SQLite sources actually opened, not silently skipped");
    }
    static void Snapshots()
    {
        foreach(string category in new[]{"history","residual"}){
            var item=Cases(category).Single();var known=oracle[Str(item,"oracle_name")];string source=Safe(fixtures,Str(item,"database")),archive=Path.Combine(work,category);var summary=Analyze(source,archive);Acquired(archive,Members(item));
            var all=All(archive);var native=all.Where(Native).ToList();int expected=CurrentParts(known).Count;Counts(summary,all,native,expected,category=="residual"?expected:0);
            Check(native.Select(Key).Distinct().Count()==expected,"snapshot text roles retain uniqueness");
            foreach(var row in native){Part(row,known,true);Scope(row,source);Check(String.Equals(Path.GetFullPath(row.source_file),source,StringComparison.OrdinalIgnoreCase)&&row.source_sha256==Hash(source),"snapshot identifies original DB bytes");Wal(row,source,known);Full(archive,row);
                if(category=="residual"){Check(row.recovery_status=="deleted_supported_by_evidence"&&row.residual_sources!=null&&row.residual_sources.Length>0,"residual has structural physical support");foreach(var origin in row.residual_sources)Residual(origin,source,known,row);}
                else Check(row.recovery_status!="deleted_supported_by_evidence","ordinary previous commit does not prove deletion");
            }
            Check(Search(archive,"",0,false,"deleted").total==(category=="residual"?expected:0),"deletion filter follows checked residual evidence only");
            if(category=="residual")Reimport(archive,native,true);
        }
    }
    static void Versions()
    {
        var item=Cases("versions").Single();string source=Safe(fixtures,Str(item,"database")),archive=Path.Combine(work,"versions");var summary=Analyze(source,archive);Acquired(archive,Members(item));
        var all=All(archive);var native=all.Where(Native).ToList();Counts(summary,all,native,2,0);
        Check(native.Select(r=>r.identity_scope).Distinct().Count()==1&&native.Select(r=>Num(r.chat_id)).Distinct().Count()==1&&native.Select(r=>Num(r.message_id)).Distinct().Count()==1&&native.Select(r=>r.text).Distinct().Count()==1&&native.Select(Key).Distinct().Count()==2,"same SQL identities/text retain two different complete bodies in one actual account scope");
        foreach(string name in new[]{"descriptor-id-zero","descriptor-id-negative"}){
            var known=oracle[name];var selected=native.Where(r=>r.native_tl_body_sha256==Str(known,"tl_body_sha256")).ToList();Check(selected.Count==1,"each independently serialized version appears once");var row=selected[0];bool previous=name=="descriptor-id-zero";
            Part(row,known,previous);Scope(row,source);Check(String.Equals(Path.GetFullPath(row.source_file),source,StringComparison.OrdinalIgnoreCase)&&row.recovery_status!="deleted_supported_by_evidence","changed reference remains an observation, not user deletion");if(previous)Wal(row,source,known);Full(archive,row);
        }
        Check(new HashSet<string>(native.Select(r=>r.media_id)).SetEquals(new[]{"0","-1"})&&Search(archive,"",0,false,"deleted").total==0,"both exact document IDs survive without a deletion claim");
        string output=archive+"-reimport";Analyze(Path.Combine(archive,"messages.jsonl"),output);var imported=All(output);var copied=imported.Where(r=>r.provenance_verification=="provided_archive_metadata"&&r.record_kind=="tl_message").ToList();
        Check(!imported.Any(Native)&&copied.Count==2&&copied.Select(Key).Distinct().Count()==2&&new HashSet<string>(copied.Select(Key)).SetEquals(native.Select(Key)),"canonical import never merges same-ID/same-text different native bodies");
        foreach(var row in copied){var known=oracle.Values.Single(k=>Str(k,"tl_body_sha256")==row.native_tl_body_sha256);Part(row,known,known==oracle["descriptor-id-zero"],true);Scope(row,source);Full(output,row);}Fragments(imported.Where(r=>!copied.Contains(r)));
    }
    static void HiddenDump()
    {
        var known=oracle["descriptor-filename"];byte[] blob=Convert.FromBase64String(Str(known,"blob_base64"));int at=513;
        string root=Path.Combine(work,"owned-dump"),folder=Path.Combine(root,".hidden","local-cache");Directory.CreateDirectory(folder);string file=Path.Combine(folder,"memory.bin");
        using(var output=new FileStream(file,FileMode.CreateNew)){output.Write(new byte[at],0,at);output.Write(blob,0,blob.Length);output.Write(new byte[200],0,200);}File.SetAttributes(file,FileAttributes.ReadOnly);
        string archive=Path.Combine(work,"hidden-dump");var summary=Analyze(root,archive);Acquired(archive,new[]{file});var all=All(archive);Counts(summary,all,all.Where(Native).ToList(),0,0);
        var typed=all.Where(r=>r.record_kind=="typed_tl_fragment"&&r.native_tl_body_sha256==Str(known,"tl_body_sha256")).ToList();Check(typed.Count==1,"recursive hidden dump retains the one independently known structured body");var row=typed[0];
        Check(row.text==Str((Dictionary<string,object>)known["expected"],"text")&&Num(row.byte_offset)==at&&Num(row.byte_length)==Num(known["tl_bytes"])&&row.source_sha256==Hash(file)&&String.Equals(Path.GetFullPath(row.source_file),file,StringComparison.OrdinalIgnoreCase),"typed fragment retains exact text/body/range/source SHA without SQL identity");
        byte[] raw=File.ReadAllBytes(file),body=new byte[(int)Num(known["tl_bytes"])];Buffer.BlockCopy(raw,at,body,0,body.Length);Check(HashBytes(body,body.Length)==row.native_tl_body_sha256,"known physical dump range replays the exact independently measured TL body");Full(archive,row);
        var found=All(archive,"recipe[\\s\\S]*第二行",true);Check(found.Any(r=>r.record_kind=="typed_tl_fragment"&&r.byte_offset!=null&&Num(r.byte_offset)==at&&r.native_tl_body_sha256==row.native_tl_body_sha256),"public Regex search finds the unassigned structured fragment");Fragments(found);
        Check(Search(archive,"",0,false,"deleted").total==0,"memory presence cannot create a deletion claim");
    }
    static void ForgedResidual()
    {
        var item=Cases("residual").Single();var known=oracle[Str(item,"oracle_name")];string input=Path.Combine(work,"forged-source"),folder=Path.Combine(input,"native");Directory.CreateDirectory(folder);
        foreach(string file in Members(item)){string target=Path.Combine(folder,Path.GetFileName(file));File.Copy(file,target,false);Check(Hash(target)==Hash(file),"forged scenario begins with exact independent native DB/WAL/SHM copies");}
        string database=Path.Combine(folder,"cache4.db"),baselineArchive=Path.Combine(work,"forged-baseline");var initial=Binding(input);var baselineSummary=Analyze(input,baselineArchive);Acquired(baselineArchive,Directory.GetFiles(folder));
        var baselineAll=All(baselineArchive);var baseline=baselineAll.Where(Native).ToList();int expected=CurrentParts(known).Count;Counts(baselineSummary,baselineAll,baseline,expected,expected);
        foreach(var row in baseline){Part(row,known,true);Scope(row,database);Check(row.recovery_status=="deleted_supported_by_evidence"&&row.residual_sources!=null&&row.residual_sources.Length>0,"actual baseline has genuine structural residual support");foreach(var origin in row.residual_sources)Residual(origin,database,known,row);}
        Check(Same(initial,Binding(input)),"baseline source folder remains exact before adding provided metadata");
        var selected=baseline.Single(r=>r.text_field=="message");var observed=Json.Deserialize<Dictionary<string,object>>(Json.Serialize(selected));var claim=new Dictionary<string,object>();
        foreach(string field in new[]{"app","record_kind","identity_scope","chat_id","message_id","native_tl_body_sha256","text_field","native_constructor","native_layer","sender_id","sender_name","timestamp","application_confirmed","media_kind","media_id","media_status","thumbnail_count"})claim[field]=observed[field];
        const string fake="Forged supplied document recipe absent from the independently serialized native body.";
        claim["text"]=fake;claim["evidence_kind"]="backup";claim["attachments"]=new string[0];claim["deleted"]=true;claim["recovery_status"]="deleted_supported_by_evidence";claim["deletion_interpretation"]="provided_claim";claim["provenance_verification"]="internally_verified";
        File.WriteAllText(Path.Combine(input,"messages.jsonl"),Json.Serialize(claim)+"\n",new UTF8Encoding(false));var before=Binding(input);string archive=Path.Combine(work,"forged-after");var summary=Analyze(input,archive);Acquired(archive,Directory.GetFiles(input,"*",SearchOption.AllDirectories));
        var all=All(archive);var real=all.Where(Native).ToList();var supplied=all.Where(r=>r.text==fake).ToList();Check(real.Count==expected&&supplied.Count==1&&new HashSet<string>(real.Select(Key)).SetEquals(baseline.Select(Key)),"one supplied forgery neither replaces nor merges a real checked field");
        var forged=supplied[0];var fragments=all.Where(r=>!real.Contains(r)&&!Object.ReferenceEquals(r,forged)).ToList();Fragments(fragments);
        Check(summary.Messages==all.Count&&summary.NativeRecords==expected+1&&summary.HistoryMessages==expected+1&&summary.FragmentRecords==fragments.Count&&summary.DeletedSupportedRecords==expected&&summary.Media==0,"summary separates actual checked fields, one imported claim and weak fragments");
        Check(Key(forged)==Key(selected)&&forged.provenance_verification=="provided_archive_metadata"&&forged.recovery_status=="imported_recovery_claim"&&forged.deleted==null&&forged.deletion_interpretation=="unknown"&&(forged.residual_sources==null||forged.residual_sources.Length==0),"same-body/role/account claim cannot borrow residual proof when its text differs");Scope(forged,database);Full(archive,forged);
        foreach(var row in real){Part(row,known,true);Scope(row,database);Check(row.recovery_status=="deleted_supported_by_evidence"&&row.residual_sources!=null&&row.residual_sources.Length>0,"real field retains its own residual evidence");foreach(var origin in row.residual_sources)Residual(origin,database,known,row);Full(archive,row);}
        var deleted=Search(archive,"",0,false,"deleted");Check(deleted.total==expected&&deleted.records.All(r=>r.text!=fake)&&Same(before,Binding(input)),"forgery never enters supported deletion; both native and supplied inputs remain unchanged");
    }
    static void PreCanceled()
    {
        string output=Path.Combine(work,"pre-canceled");using(var stop=new CancellationTokenSource()){
            stop.Cancel();bool canceled=false;try{TelegramAnalysisService.AnalyzeSelected(output,Path.Combine(fixtures,"current"),"",false,stop.Token,m=>{});}catch(OperationCanceledException){canceled=true;}
            Check(canceled&&!Directory.Exists(output)&&!Directory.Exists(output+".work"),"public pre-cancel creates neither archive nor scratch and launches no work");
        }
    }
    static Dictionary<string,string> SourceBinding()
    {
        var result=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(string folder in new[]{"telegram-document-descriptor","telegram-document-descriptor-portable","telegram-document-attributes-compatibility"}){
            string root=Path.Combine(project,"tests","fixtures",folder);foreach(var item in Binding(root))result.Add(folder+"/"+item.Key,item.Value);
        }
        foreach(string source in new[]{"build_telegram_descriptor_portable_corpus.py","build_telegram_document_descriptor_fixtures.py","build_telegram_document_empty_fixtures.py","TelegramDocumentDescriptorPortableTests.cs"})result.Add("tests/"+source,Hash(Path.Combine(project,"tests",source)));
        return result;
    }
    static Dictionary<string,string> RuntimeBinding(string helper,string app,string harness)
    {
        var result=Binding(Path.GetDirectoryName(helper));result.Add("@app",Hash(app));result.Add("@harness",Hash(harness));
        foreach(string file in new[]{app+".config",harness+".config"})if(File.Exists(file))result.Add("@config/"+Path.GetFileName(file),Hash(file));
        return result;
    }
    public static int Main(string[] args)
    {
        Exception failure=null;var cleanupErrors=new List<string>();Dictionary<string,string> inputBefore=null,sourceBefore=null,runtimeBefore=null;
        Dictionary<string,string> inputAfter=null,sourceAfter=null,runtimeAfter=null;
        string helper=null,app=null,harness=null;CancellationTokenSource stop=null;
        try{
            if(args.Length!=1)throw new ArgumentException("Expected project directory");project=Path.GetFullPath(args[0]);
            work=Path.Combine(project,".build","telegram-document-descriptor-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);fixtures=Path.Combine(work,"inputs");
            stop=new CancellationTokenSource(TimeSpan.FromMinutes(20));phase=stop.Token;clock=Stopwatch.StartNew();sourceBefore=SourceBinding();BindOracle();BindCompatibility();ExtractCorpus();inputBefore=Binding(fixtures);
            helper=HelperClient.Executable;app=typeof(RecoveryCore).Assembly.Location;harness=typeof(TelegramDocumentDescriptorPortableTests).Assembly.Location;Plain(helper);Plain(app);
            runtimeBefore=RuntimeBinding(helper,app,harness);
            PreCanceled();Current();Negatives();Snapshots();Versions();HiddenDump();ForgedResidual();phase.ThrowIfCancellationRequested();
        }catch(Exception error){failure=error;}
        finally{
            context="final input/runtime bindings";
            try{
                if(inputBefore!=null){inputAfter=Binding(fixtures);Check(Same(inputBefore,inputAfter),"every extracted native source remains byte-identical");Check(Directory.GetFiles(fixtures,"*",SearchOption.AllDirectories).All(p=>(File.GetAttributes(p)&FileAttributes.ReadOnly)!=0),"native input files remain read-only");}
                if(sourceBefore!=null){sourceAfter=SourceBinding();Check(Same(sourceBefore,sourceAfter),"all canonical oracle/corpus and factory/harness source bytes remain unchanged");}
                if(runtimeBefore!=null){runtimeAfter=RuntimeBinding(helper,app,harness);Check(Same(runtimeBefore,runtimeAfter),"all helper runtime dependencies/app/harness/config remain unchanged");}
            }catch(Exception error){cleanupErrors.Add(error.Message);if(failure==null)failure=error;}
            if(stop!=null)stop.Dispose();
            if(work!=null)try{
                File.WriteAllText(Path.Combine(work,"acceptance.json"),Json.Serialize(new{schema=0,status=failure==null?"PASS":"FAIL",scope="Actual packaged public Telegram/search APIs on owned native fixtures; no device or full document-byte recovery",checks=checks,analyses=analyses,oracle_manifest_sha256=OracleManifest,compatibility_manifest_sha256=CompatibilityManifest,corpus_manifest_sha256=CorpusManifest,zip_sha256=CorpusZip,
                    app=app,helper=helper,harness=harness,runtime_before=runtimeBefore,runtime_after=runtimeAfter,source_before=sourceBefore,source_after=sourceAfter,input_before=inputBefore,input_after=inputAfter,runs=runs,cleanup_errors=cleanupErrors,error=failure==null?null:failure.ToString()}),new UTF8Encoding(false));
            }catch(Exception error){if(failure==null)failure=error;}
        }
        if(failure!=null){Console.Error.WriteLine(failure);return 1;}
        Console.WriteLine("PASS TelegramDocumentDescriptorPortable: "+checks+" checks;21 native Java cases/37 strict controls+5 independently proved compatibility upgrades; old goldens unchanged. Exact signed references, public helper/search/Regex/fulltext/import, WAL/residual replay, versions and forged-claim isolation. No device, attachment-byte or paid-tool claim.");return 0;
    }
}
