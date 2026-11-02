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

// Actual packaged-helper test. Source/compile checks alone are not acceptance.
public static class TelegramMediaCacheProfilePortableTests
{
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static int checks;
    static CancellationToken phase;
    static Stopwatch phaseClock;
    static string fixtures,work;
    static string diagnosticContext;
    const string SourceCommit="4de548e79fed27f1a66fbdff84223321838fe925";
    const string OracleManifestSha256="56eb8ab9ed30fb228c7a2ac4eef9c0580d559b47015d88ff3863a69877887070";
    static readonly Dictionary<string,Dictionary<string,object>> BoundOracle=new Dictionary<string,Dictionary<string,object>>(StringComparer.Ordinal);
    static void Check(bool value,string why){checks++;if(!value)throw new Exception((diagnosticContext==null?"":diagnosticContext+": ")+why);}
    static object Get(Dictionary<string,object> row,string key){object value;return row.TryGetValue(key,out value)?value:null;}
    static string Str(Dictionary<string,object> row,string key){return Get(row,key) as string;}
    static long Number(object value){return Convert.ToInt64(value,CultureInfo.InvariantCulture);}
    static List<Dictionary<string,object>> List(object value){return ((IEnumerable)value).Cast<Dictionary<string,object>>().ToList();}
    static Dictionary<string,object> Read(string file){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file,Encoding.UTF8));}
    static string Hash(string file){using(var input=File.OpenRead(file))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string HashBytes(byte[] bytes,int length){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes,0,length)).Replace("-","").ToLowerInvariant();}
    static string Safe(string root,string relative){return RecoveryCatalog.SafeFile(root,relative);}
    static long CodePoints(string text){long count=0;for(int at=0;at<text.Length;at++,count++)if(Char.IsHighSurrogate(text[at])&&at+1<text.Length&&Char.IsLowSurrogate(text[at+1]))at++;return count;}
    static Dictionary<string,string> Binding(string root){return Directory.GetFiles(root,"*",SearchOption.AllDirectories).ToDictionary(path=>path.Substring(root.Length+1),Hash,StringComparer.OrdinalIgnoreCase);}
    static bool Same(Dictionary<string,string> a,Dictionary<string,string> b){return a.Count==b.Count&&a.All(item=>b.ContainsKey(item.Key)&&b[item.Key]==item.Value);}
    static T Guard<T>(Func<CancellationToken,T> action)
    {
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(phase)){
            stop.CancelAfter(TimeSpan.FromMinutes(4)+TimeSpan.FromSeconds(45));
            int remaining=(int)Math.Min(300000,1200000-phaseClock.ElapsedMilliseconds);
            if(remaining<=0)throw new TimeoutException("Hard twenty-minute phase watchdog; no successful result inferred");
            var task=Task.Run(()=>action(stop.Token));
            if(Task.WaitAny(new Task[]{task},remaining)<0){stop.Cancel();throw new TimeoutException("Hard call/phase watchdog: completion and cleanup unconfirmed");}
            return task.GetAwaiter().GetResult();
        }
    }
    static List<Dictionary<string,object>> OracleParts(Dictionary<string,object> item)
    {
        var expected=(Dictionary<string,object>)item["expected"];
        string outer=Str(expected,"text"),caption=Str(item,"expected_legacy_caption");
        var result=new List<Dictionary<string,object>>();
        if(!String.IsNullOrEmpty(outer))result.Add(new Dictionary<string,object>{{"text",outer},{"text_field","message"},{"supplemental",false}});
        if(!String.IsNullOrEmpty(caption)&&caption!=outer)result.Add(new Dictionary<string,object>{{"text",caption},{"text_field","media.legacy_caption"},{"supplemental",!String.IsNullOrEmpty(outer)}});
        return result;
    }
    static void BindCase(Dictionary<string,object> supplied,Dictionary<string,object> oracle,string expectedDatabase)
    {
        Check(Str(supplied,"database")==expectedDatabase&&Number(supplied["layer"])==Number(oracle["layer"])&&
            Str(supplied,"constructor")==Str(oracle,"constructor")&&Str(supplied,"tl_body_sha256")==Str(oracle,"tl_body_sha256"),
            "generated fixture names the exact independent official Message profile/body and expected source path");
        var sql=(Dictionary<string,object>)supplied["exact_sql"];var knownSql=(Dictionary<string,object>)oracle["exact_sql"];
        Check(sql.Count==4&&knownSql.Count==4&&new[]{"uid","mid","date","type"}.All(key=>Number(sql[key])==Number(knownSql[key])),
            "generated SQL expectations equal the pinned oracle, including date and peer relation");
        var actual=List(supplied["text_parts"]);var known=OracleParts(oracle);
        Check(actual.Count==known.Count&&actual.Select((part,index)=>part.Count==3&&Str(part,"text")==Str(known[index],"text")&&
            Str(part,"text_field")==Str(known[index],"text_field")&&Get(part,"supplemental") is bool&&
            (bool)part["supplemental"]==(bool)known[index]["supplemental"]).All(equal=>equal),
            "all expected text, slot and primary/supplemental roles come from the independent oracle");
        BoundOracle.Add(expectedDatabase,oracle);
    }
    static void BindOracle(string project,Dictionary<string,object> generated)
    {
        string bundle=Path.Combine(project,"tests","fixtures","telegram-cache-profiles"),manifestPath=Path.Combine(bundle,"manifest.json");
        Check(Hash(manifestPath)==OracleManifestSha256&&Str(generated,"oracle_manifest_sha256")==OracleManifestSha256&&
            Str(generated,"generator_sha256")==Hash(Path.Combine(project,"tests","build_telegram_media_cache_profile_fixtures.py"))&&
            Number(generated["schema"])==1&&Str(generated,"source_commit")==SourceCommit,
            "native fixture metadata binds the exact pinned oracle manifest and current independent factory bytes");
        var manifest=Read(manifestPath);
        Check(Number(manifest["schema"])==1&&Number(manifest["cases"])==855&&Str(manifest,"telegram_commit")==SourceCommit,
            "independent oracle pins the official serializer commit and all 855 cases");
        var files=List(manifest["files"]);string[] allowed={"oracle.json.gz","oracle-sources.tar.gz","LICENSE"};
        Check(files.Count==3&&files.Select(file=>Str(file,"path")).Distinct().Count()==3&&files.All(file=>allowed.Contains(Str(file,"path"))),
            "pinned oracle bundle contains exactly the documented files");
        foreach(var file in files){string path=Safe(bundle,Str(file,"path"));Check(new FileInfo(path).Length==Number(file["bytes"])&&Hash(path)==Str(file,"sha256"),"pinned independent oracle bundle bytes remain intact");}
        byte[] raw;
        using(var input=File.OpenRead(Path.Combine(bundle,"oracle.json.gz")))using(var gzip=new GZipStream(input,CompressionMode.Decompress))using(var output=new MemoryStream()){
            byte[] buffer=new byte[8192];int read;
            while((read=gzip.Read(buffer,0,buffer.Length))>0){phase.ThrowIfCancellationRequested();Check(output.Length<=2*1024*1024-read,"oracle decompression is bounded");output.Write(buffer,0,read);}
            raw=output.ToArray();
        }
        Check(raw.Length==Number(manifest["uncompressed_json_bytes"]),"decompressed official oracle has the exact pinned length");
        var payload=Json.Deserialize<Dictionary<string,object>>(new UTF8Encoding(false,true).GetString(raw));
        var cases=List(payload["cases"]);
        Check(Number(payload["schema"])==1&&cases.Count==855&&cases.Select(item=>Str(item,"name")).Distinct().Count()==855&&
            cases.Select(item=>Str(item,"constructor")).Distinct().Count()==19&&cases.Select(item=>Str(item,"media_constructor")).Distinct().Count()==5,
            "the pinned independent oracle contains exactly 19 Message profiles and five photo-media constructors");
        foreach(var item in cases){
            byte[] blob=Convert.FromBase64String(Str(item,"blob_base64"));long tl=Number(item["tl_bytes"]);
            Check(blob.Length==Number(item["bytes"])&&tl>0&&tl<=blob.Length&&HashBytes(blob,blob.Length)==Str(item,"blob_sha256")&&
                HashBytes(blob,(int)tl)==Str(item,"tl_body_sha256"),"official serialized BLOB and exact TL-body prefix match their independent digests");
        }
        var oracle=cases.ToDictionary(item=>Str(item,"name"),StringComparer.Ordinal);var current=List(generated["cases"]);
        Check(current.Count==oracle.Count&&current.Select(item=>Str(item,"name")).Distinct().Count()==oracle.Count&&
            current.All(item=>oracle.ContainsKey(Str(item,"name"))),"all 855 exact independent case names are present, without substitution or repetition");
        BoundOracle.Clear();
        foreach(var item in current){string name=Str(item,"name");BindCase(item,oracle[name],"current/"+name+"/cache4.db");}
        var parts=cases.SelectMany(OracleParts).ToList();
        Check(parts.Count==1235&&parts.Count(part=>Str(part,"text_field")=="message")==665&&parts.Count(part=>Str(part,"text_field")=="media.legacy_caption")==570,
            "the independent oracle requires 665 outer-text and 570 legacy-caption records");
        var snapshots=List(generated["snapshot_cases"]);string[] names={"cache-history","primary-current","primary-historical","native-history","native-residual","caption-only"};
        Check(snapshots.Count==6&&snapshots.Select(item=>Str(item,"name")).Distinct().Count()==6&&snapshots.All(item=>names.Contains(Str(item,"name"))),"all six exact independent snapshot variants are mandatory");
        foreach(var item in snapshots){
            string name=Str(item,"name");int mode=name=="caption-only"?1:0;
            var known=cases.Single(candidate=>Number(candidate["layer"])==118&&Str(candidate,"media_constructor")=="0xb5223b0f"&&Number(candidate["mode"])==mode&&Number(candidate["direction"])==3);
            BindCase(item,known,"snapshots/"+name+"/cache4.db");
        }
    }
    static HelperResult Analyze(string source,string output)
    {
        var result=Guard(token=>TelegramAnalysisService.AnalyzeSelected(output,source,"",false,token,message=>{}));
        Check((result.Status=="complete"||result.Status=="partial")&&File.Exists(Path.Combine(output,"messages.jsonl"))&&
            !File.Exists(Path.Combine(output,"job.incomplete"))&&!Directory.Exists(output+".work"),"actual public analysis publishes a complete archive and cleans scratch");
        return result;
    }
    static ArchiveSearchResult Search(string archive,string query,long offset=0,bool regex=false,string evidence="")
    {
        var result=Guard(token=>ArchiveSearchService.Search(archive,"Telegram",query,evidence,offset,token,regex));
        Check((result.status=="complete"||result.status=="partial")&&result.records!=null,"actual helper returns a controlled archive search page");
        return result;
    }
    static List<ArchiveMessage> All(string archive,string query)
    {
        var rows=new List<ArchiveMessage>();long total=-1;
        do{
            var page=Search(archive,query,rows.Count);if(total<0)total=page.total;
            Check(page.total==total&&page.offset==rows.Count&&page.records.Count>0,"pagination retains exact total and advances without gaps");
            rows.AddRange(page.records);
        }while(rows.Count<total);
        Check(rows.Count==total,"all matched archive records were read once");return rows;
    }
    static string Key(ArchiveMessage message){return message.identity_scope+"|"+message.native_tl_body_sha256+"|"+message.text_field;}
    static bool CheckedHistory(ArchiveMessage message,bool native)
    {
        var kinds=native?new[]{"tl_message","tl_message_caption"}:new[]{"telegram_media_cache","telegram_media_cache_caption"};
        return kinds.Contains(message.record_kind)&&message.application_confirmed==true&&
            (message.evidence_kind=="backup"||message.evidence_kind=="previous")&&message.provenance_verification!="provided_archive_metadata";
    }
    static string Counts(string name,List<ArchiveMessage> rows,HelperResult summary)
    {
        return name+" total="+rows.Count+" kinds={"+String.Join(",",rows.GroupBy(row=>row.record_kind??"unknown").Select(group=>group.Key+":"+group.Count()))+
            "} summary(messages="+summary.Messages+",history="+summary.HistoryMessages+",native="+summary.NativeRecords+",fragments="+summary.FragmentRecords+",supported="+summary.DeletedSupportedRecords+")";
    }
    static void VerifyFragmentRows(IEnumerable<ArchiveMessage> fragments)
    {
        foreach(var row in fragments){
            bool memory=row.record_kind=="memory_fragment";
            Check(row.evidence_kind=="fragment"&&(memory||new[]{"typed_tl_fragment","sqlite_residual_fragment","sqlite_wal_residual"}.Contains(row.record_kind)),
                "every nonhistory row is an explicitly typed current-contract fragment, not an ignored archive/history record");
            Check(row.application_confirmed==(memory?false:true)&&row.chat_id==null&&row.chat_name==null&&row.message_id==null&&
                row.sender_id==null&&row.sender_name==null&&row.timestamp==null&&row.timestamp_raw==null,
                "recognized TL fragments may confirm the application, while chat, author, message and date remain unknown");
            Check(row.deleted==null&&(row.recovery_status==null||row.recovery_status=="unattributed_structured_fragment")&&
                (row.residual_sources==null||row.residual_sources.Length==0)&&row.wal_proof==null&&row.wal_snapshot_sha256==null&&
                row.sqlite_record_sha256==null&&row.sqlite_payload_sha256==null&&row.sqlite_overflow_chain_verified!=true&&
                row.rollback_content_authenticity_verified!=true&&row.rollback_proof!="all_pages_from_validated_rollback_journal"&&
                (row.proof==null||row.proof=="supported_tl_body_without_confirmed_table_or_account"||
                    row.proof=="validated_committed_wal_page_and_supported_tl_without_table_context"),
                "fragments carry only their declared weak provenance and never supported deletion or checked native SQL-record proof");
        }
    }
    static void VerifyHistorySet(List<ArchiveMessage> rows,Dictionary<string,object> item)
    {
        var parts=List(item["text_parts"]);
        Check(rows.Count==parts.Count&&rows.Select(Key).Distinct().Count()==parts.Count&&
            new HashSet<string>(rows.Select(row=>row.text_field)).SetEquals(parts.Select(part=>Str(part,"text_field"))),
            "all independent native text-slot identities appear exactly once, without counting or hiding deep-search fragments");
    }
    static void VerifyPart(ArchiveMessage message,Dictionary<string,object> item,bool native,bool historical)
    {
        var parts=List(item["text_parts"]);var expected=parts.Single(part=>Str(part,"text_field")==message.text_field);
        var sql=(Dictionary<string,object>)item["exact_sql"];
        Check(message.text==Str(expected,"text")&&message.text_field!=null,"each text field retains exact original Unicode text without concatenation");
        Check(Number(message.chat_id)==Number(sql["uid"])&&Number(message.message_id)==Number(sql["mid"])&&
            Number(message.native_layer)==Number(item["layer"])&&message.native_constructor==Str(item,"constructor")&&
            message.native_tl_body_sha256==Str(item,"tl_body_sha256"),"SQL keys, exact official constructor and full body hash survive helper and DTO");
        var independent=(Dictionary<string,object>)BoundOracle[Str(item,"database")]["expected"];
        var sender=Get(independent,"from_peer") as Dictionary<string,object>;
        string expectedSender=sender==null?null:Str(sender,"kind")+":"+Number(sender["id"]).ToString(CultureInfo.InvariantCulture);
        Check((expectedSender==null?message.sender_id==null:message.sender_id is string&&(string)message.sender_id==expectedSender)&&message.sender_name==null,
            "sender identity equals the independent original peer; absent sender and absent name remain unknown");
        long date=Number(independent["date"]);DateTimeOffset actualDate;
        Check(date==0?message.timestamp==null:DateTimeOffset.TryParse(message.timestamp as string,CultureInfo.InvariantCulture,DateTimeStyles.None,out actualDate)&&
            actualDate.ToUniversalTime()==new DateTimeOffset(1970,1,1,0,0,0,TimeSpan.Zero).AddSeconds(date),
            "message date equals the independent official input, without inventing an unknown timestamp");
        bool secondary=(bool)expected["supplemental"];
        string kind=native?(secondary?"tl_message_caption":"tl_message"):(secondary?"telegram_media_cache_caption":"telegram_media_cache");
        Check(message.record_kind==kind&&message.application_confirmed==true,"primary and supplemental field kinds remain distinct");
        Check(message.evidence_kind==(historical?"previous":"backup")&&message.deleted==null,"field records retain observed snapshot and unknown user deletion");
        Check(message.media_kind=="photo"&&message.media_status=="photo_reference_only"&&
            (message.attachments==null||message.attachments.Length==0),"photo reference does not create recovered photo bytes");
        Check(!String.IsNullOrEmpty(message.archive_record_key),"each separate text field has its own full-text locator");
    }
    static void VerifyFull(string archive,ArchiveMessage message)
    {
        var page=Guard(token=>ArchiveSearchService.ReadPage(archive,message.archive_record_key,0,token));
        Check(page.status=="complete"&&page.eof&&page.text==message.text&&page.next_offset==CodePoints(message.text),
            "full-text locator returns the exact selected field including astral characters and newline");
    }
    static void VerifySource(Dictionary<string,object> item)
    {
        string database=Safe(fixtures,Str(item,"database")),folder=Path.GetDirectoryName(database);
        foreach(var member in (Dictionary<string,object>)item["source_files"])
            Check(Hash(Safe(folder,member.Key))==(string)member.Value,"native SQLite source bytes match independent fixture receipt");
    }
    static void VerifyResidual(Dictionary<string,object> origin,Dictionary<string,object> item,ArchiveMessage message,string copiedDatabase=null)
    {
        string database=copiedDatabase??Safe(fixtures,Str(item,"database"));
        Check(Str(origin,"text_field")==message.text_field&&String.Equals(Path.GetFullPath(Str(origin,"source_file")),database,StringComparison.OrdinalIgnoreCase)&&
            Str(origin,"physical_source")=="wal","residual proof binds the same text role and the independently supplied native WAL source");
        string sidecar=database+"-wal";long offset=Number(origin["physical_byte_offset"]),length=Number(origin["sqlite_record_length"]);
        Check(offset>=0&&length>0&&length<=4*1024*1024&&offset<=new FileInfo(sidecar).Length-length,
            "reported SQLite record boundary is positive and lies entirely inside the original WAL");
        // Replay the exact record boundary exposed by the source parser. Do not
        // infer a record boundary from a TL signature or a neighboring record.
        byte[] record=new byte[(int)length];
        using(var input=File.OpenRead(sidecar)){
            input.Position=offset;int read=0;
            while(read<record.Length){phase.ThrowIfCancellationRequested();int amount=input.Read(record,read,record.Length-read);if(amount==0)throw new EndOfStreamException();read+=amount;}
        }
        Check(HashBytes(record,record.Length)==Str(origin,"sqlite_record_sha256"),
            "all physical SQLite record bytes replay to their supplied record SHA, as in the independent source fixture contract");
    }
    static void CurrentCorpus(Dictionary<string,object> manifest)
    {
        var cases=List(manifest["cases"]);
        Check(cases.Count==855&&cases.Select(item=>Str(item,"name")).Distinct().Count()==855,
            "all855 official profile/media/text/peer controls are mandatory");
        foreach(var item in cases)VerifySource(item);
        var expected=cases.ToDictionary(item=>Str(item,"name"));
        string archive=Path.Combine(work,"all-current");var summary=Analyze(Path.Combine(fixtures,"current"),archive);
        int count=cases.Sum(item=>List(item["text_parts"]).Count);
        Check(count==1235&&summary.HistoryMessages==count&&summary.NativeRecords==count&&
            summary.DeletedSupportedRecords==0&&summary.Media==0,"855 SQL rows preserve1235 distinct original field records without a deletion/photo claim");
        var rows=All(archive,"recipe");var identities=new HashSet<string>();
        Check(rows.Count==count,"actual search covers every current field");
        foreach(var message in rows){
            string name=Path.GetFileName(Path.GetDirectoryName(message.source_file));
            Check(expected.ContainsKey(name),"every result has a known independent source database");
            var item=expected[name];VerifyPart(message,item,false,false);
            Check(String.Equals(Path.GetFullPath(message.source_file),Safe(fixtures,Str(item,"database")),StringComparison.OrdinalIgnoreCase)&&
                message.source_sha256==(string)((Dictionary<string,object>)item["source_files"])["cache4.db"],"message provenance names the supplied source and exact DB hash");
            Check(identities.Add(Key(message)),"account/body/field identity keeps every field once, including same IDs across sources");
            Check(message.recovery_status=="current_cache_record"&&message.deletion_interpretation=="unknown","current cache status cannot become supported deletion");
        }
        int captions=cases.Sum(item=>List(item["text_parts"]).Count(part=>Str(part,"text_field")=="media.legacy_caption"));
        var regex=Search(archive,"Legacy[\\s\\S]*第二行",0,true);
        Check(regex.total==captions&&regex.records.All(message=>message.text_field=="media.legacy_caption"),"Regex independently finds the legacy-caption field without replacing the outer text");
        Check(Search(archive,"",0,false,"deleted").total==0,"surviving cache fields do not enter the supported-deletion filter");
        foreach(var message in rows.Where(item=>item.text_field=="media.legacy_caption").Take(3).Concat(rows.Where(item=>item.text_field=="message").Take(3)))VerifyFull(archive,message);
        string imported=Path.Combine(work,"all-current-reimport");var transfer=Analyze(Path.Combine(archive,"messages.jsonl"),imported);
        var copied=All(imported,"recipe");
        Check(transfer.HistoryMessages==count&&copied.Count==count,"actual canonical reimport retains every separate field");
        var original=rows.ToDictionary(Key);
        Check(copied.Select(Key).Distinct().Count()==count&&new HashSet<string>(copied.Select(Key)).SetEquals(original.Keys),
            "canonical reimport retains the exact complete identity set without repeating one record in place of another");
        foreach(var message in copied){
            Check(original.ContainsKey(Key(message))&&original[Key(message)].text==message.text&&
                original[Key(message)].record_kind==message.record_kind&&message.provenance_verification=="provided_archive_metadata"&&
                message.deleted==null,"reimport preserves field/body identity and marks the provided archive metadata as unverified");
            string name=Path.GetFileName(Path.GetDirectoryName(original[Key(message)].source_file));VerifyPart(message,expected[name],false,false);
        }
    }
    static void Snapshots(Dictionary<string,object> manifest)
    {
        var cases=List(manifest["snapshot_cases"]);
        Check(cases.Count==6,"all six native/WAL/primary/caption-only controls are mandatory");
        foreach(var item in cases){
            string name=Str(item,"name"),archive=Path.Combine(work,"snapshot-"+name);
            diagnosticContext="snapshot-"+name+" counts unavailable before analysis";
            VerifySource(item);
            var result=Analyze(Safe(fixtures,Str(item,"database")),archive);var all=All(archive,"");
            diagnosticContext=Counts("snapshot-"+name,all,result);
            bool native=name!="cache-history",historical=name=="cache-history"||name=="primary-historical"||name=="native-history"||name=="native-residual";
            var rows=all.Where(message=>CheckedHistory(message,native)).ToList();var fragments=all.Where(message=>!rows.Contains(message)).ToList();
            VerifyHistorySet(rows,item);VerifyFragmentRows(fragments);
            Check(result.Messages==all.Count&&result.HistoryMessages==rows.Count&&result.NativeRecords==rows.Count&&result.FragmentRecords==fragments.Count,
                "summary and complete archive independently distinguish native history from every deep-search fragment");
            foreach(var message in rows){
                VerifyPart(message,item,native,historical);VerifyFull(archive,message);
                if(historical)Check(message.wal_proof=="all_pages_from_validated_wal"&&!String.IsNullOrEmpty(message.wal_snapshot_sha256),"historical fields retain the checked whole-page WAL snapshot");
                if(name.StartsWith("primary-",StringComparison.Ordinal)||name=="caption-only"){
                    Check(message.sources!=null&&message.sources.Length>0&&message.sources.Length<=10,"strong native primary preserves bounded weaker-cache origins");
                    foreach(var origin in message.sources){
                        Check(Str(origin,"text_field")==message.text_field&&Str(origin,"native_tl_body_sha256")==message.native_tl_body_sha256,
                            "additional cache origin binds the same text slot, never another field with the same body digest");
                    }
                }
                if(name=="native-residual"){
                    Check(message.recovery_status=="deleted_supported_by_evidence"&&message.residual_sources!=null&&message.residual_sources.Length>0,
                        "actual native free-page evidence stays attached to its checked historical field");
                    foreach(var origin in message.residual_sources)VerifyResidual(origin,item,message);
                }else Check(message.recovery_status!="deleted_supported_by_evidence","ordinary WAL/cache observation does not invent deletion");
            }
        }
        diagnosticContext=null;
    }
    static void ForgedBody(Dictionary<string,object> manifest)
    {
        diagnosticContext="forged-input counts unavailable before baseline analysis";
        var item=List(manifest["snapshot_cases"]).Single(candidate=>Str(candidate,"name")=="native-residual");
        string source=Safe(fixtures,Str(item,"database")),input=Path.Combine(work,"forged-provided-source"),native=Path.Combine(input,"native");
        Directory.CreateDirectory(native);
        foreach(var member in (Dictionary<string,object>)item["source_files"]){
            Check(new[]{"cache4.db","cache4.db-wal","cache4.db-shm"}.Contains(member.Key),"forged regression copies only the owned native DB/WAL/SHM");
            string original=Safe(Path.GetDirectoryName(source),member.Key),target=Safe(native,member.Key);File.Copy(original,target,false);
            Check(Hash(target)==(string)member.Value,"disposable native source is an exact independent fixture copy");
        }
        string database=Path.Combine(native,"cache4.db");var originalInput=Binding(input);
        diagnosticContext="forged-baseline counts unavailable before analysis";
        var baselineSummary=Analyze(input,Path.Combine(work,"forged-baseline"));var baselineAll=All(Path.Combine(work,"forged-baseline"),"");
        diagnosticContext=Counts("forged-baseline",baselineAll,baselineSummary);
        var baseline=baselineAll.Where(message=>CheckedHistory(message,true)).ToList();
        var baselineFragments=baselineAll.Where(message=>!baseline.Contains(message)).ToList();
        int expected=List(item["text_parts"]).Count;
        VerifyHistorySet(baseline,item);VerifyFragmentRows(baselineFragments);
        Check(expected==2&&baseline.Count==expected&&baselineSummary.Messages==baselineAll.Count&&baselineSummary.HistoryMessages==expected&&
            baselineSummary.NativeRecords==expected&&baselineSummary.FragmentRecords==baselineFragments.Count&&baselineSummary.DeletedSupportedRecords==expected&&Same(originalInput,Binding(input)),
            "same copied folder first establishes both real native fields, supported residuals and unchanged DB/WAL/SHM");
        foreach(var message in baseline){
            VerifyPart(message,item,true,true);
            Check(String.Equals(Path.GetFullPath(message.source_file),database,StringComparison.OrdinalIgnoreCase)&&message.recovery_status=="deleted_supported_by_evidence"&&
                message.residual_sources!=null&&message.residual_sources.Length>0,"baseline identities and physical proof come from the actual copied native database");
            foreach(var origin in message.residual_sources)VerifyResidual(origin,item,message,database);
        }
        var selected=baseline.Single(message=>message.text_field=="message");
        Check(!String.IsNullOrEmpty(selected.identity_scope)&&selected.native_tl_body_sha256==Str(item,"tl_body_sha256"),"forged claim uses the real baseline scope, IDs, body digest and text slot");
        var observed=Json.Deserialize<Dictionary<string,object>>(Json.Serialize(selected));
        var claim=new Dictionary<string,object>();
        foreach(string field in new[]{"app","record_kind","identity_scope","chat_id","message_id","native_tl_body_sha256","text_field","native_constructor","native_layer","sender_id","sender_name","timestamp","application_confirmed"})claim[field]=observed[field];
        const string forgedText="Forged supplied recipe 🥧: this text is absent from the native TL body.";
        claim["text"]=forgedText;claim["evidence_kind"]="backup";claim["attachments"]=new string[0];
        claim["deleted"]=true;claim["recovery_status"]="deleted_supported_by_evidence";claim["deletion_interpretation"]="claimed_by_provided_archive";
        claim["provenance_verification"]="internally_verified";
        // root files are visited before a child directory. This keeps the
        // provided messages.jsonl ahead of native/cache4.db, reproducing the
        // source regression's claim-before-DB order without changing the DB path.
        File.WriteAllText(Path.Combine(input,"messages.jsonl"),Json.Serialize(claim)+"\n",new UTF8Encoding(false));
        var withClaim=Binding(input);string archive=Path.Combine(work,"forged-after");diagnosticContext="forged-after counts unavailable before analysis";
        var summary=Analyze(input,archive);var rows=All(archive,"");diagnosticContext=Counts("forged-after",rows,summary);
        var supplied=rows.Where(message=>message.text==forgedText).ToList();
        Check(supplied.Count==1,"the separately supplied false text is present exactly once and cannot disappear during native/fragment selection");
        var forged=supplied[0];var real=rows.Where(message=>CheckedHistory(message,true)).ToList();
        var fragments=rows.Where(message=>!real.Contains(message)&&!Object.ReferenceEquals(message,forged)).ToList();
        VerifyHistorySet(real,item);VerifyFragmentRows(fragments);
        Check(summary.Messages==rows.Count&&summary.HistoryMessages==expected+1&&summary.NativeRecords==expected+1&&
            summary.FragmentRecords==fragments.Count&&summary.DeletedSupportedRecords==expected,
            "both real native text fields and the separately supplied false text survive; only real fields count as physically supported");
        Check(Key(forged)==Key(selected)&&Number(forged.chat_id)==Number(selected.chat_id)&&Number(forged.message_id)==Number(selected.message_id)&&
            forged.provenance_verification=="provided_archive_metadata"&&forged.recovery_status=="imported_recovery_claim"&&forged.deleted==null&&
            forged.deletion_interpretation=="unknown"&&(forged.residual_sources==null||forged.residual_sources.Length==0),
            "a recognized supplied archive with real scope/body/role cannot borrow native physical proof or its verification flag");
        Check(real.Select(Key).Distinct().Count()==expected&&new HashSet<string>(real.Select(Key)).SetEquals(baseline.Select(Key)),
            "forged text neither replaces a checked field nor creates duplicate native identities");
        foreach(var message in real){
            VerifyPart(message,item,true,true);var previous=baseline.Single(prior=>Key(prior)==Key(message));
            Check(message.text==previous.text&&message.source_file==previous.source_file&&message.source_sha256==previous.source_sha256&&
                message.wal_sha256==previous.wal_sha256&&message.wal_snapshot_sha256==previous.wal_snapshot_sha256&&
                Number(message.wal_commit_frame)==Number(previous.wal_commit_frame)&&message.recovery_status=="deleted_supported_by_evidence"&&
                message.residual_sources!=null&&message.residual_sources.Length>0,"checked historical fields retain their original text, source, full WAL proof and residual support");
            foreach(var origin in message.residual_sources)VerifyResidual(origin,item,message,database);
        }
        var deleted=Search(archive,"",0,false,"deleted");
        Check(deleted.total==expected&&deleted.records.All(message=>message.text!=forgedText),"supplied false text never enters the actual supported-deletion search category");
        foreach(var message in real.Concat(new[]{forged}))VerifyFull(archive,message);
        Check(Same(withClaim,Binding(input)),"both analyses leave the exact copied DB/WAL/SHM and supplied JSONL unchanged");
        File.WriteAllText(Path.Combine(work,"forged-vector.json"),Json.Serialize(new{Scope=selected.identity_scope,selected.chat_id,selected.message_id,
            selected.native_tl_body_sha256,selected.text_field,ExpectedNativeFields=expected,ExpectedSeparateProvidedFields=1,Before=originalInput,After=withClaim}),new UTF8Encoding(false));
        diagnosticContext=null;
    }
    public static int Main(string[] args)
    {
        try{
            if(args.Length!=1)throw new ArgumentException("Expected project directory");
            string project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","telegram-media-cache-profile-fixtures-current");
            work=Path.Combine(project,".build","telegram-profile-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            using(var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(20))){
                phase=timeout.Token;phaseClock=Stopwatch.StartNew();
                var before=Binding(fixtures);var manifest=Read(Path.Combine(fixtures,"manifest.json"));BindOracle(project,manifest);
                Check(File.Exists(HelperClient.Executable),"actual packaged helper is available");
                string helper=Hash(HelperClient.Executable),app=Hash(typeof(RecoveryCore).Assembly.Location);
                CurrentCorpus(manifest);Snapshots(manifest);ForgedBody(manifest);
                Check(Same(before,Binding(fixtures))&&Hash(HelperClient.Executable)==helper&&Hash(typeof(RecoveryCore).Assembly.Location)==app,
                    "all native inputs and tested runtime binaries stay byte-identical");
                phase.ThrowIfCancellationRequested();
            }
            Console.WriteLine("PASS TelegramMediaCacheProfilePortable: "+checks+" checks;855 official-Java profile/media/peer cases,1235 exact separate text fields, actual helper/search/Regex/fulltext/reimport, native WAL/primary/residual role binding, forged provided-body rejection and immutable owned sources. No Android/iPhone/device or paid-tool claim.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
