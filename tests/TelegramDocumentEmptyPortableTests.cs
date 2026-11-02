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

// Run only against a newly built packaged app/helper, under the offline gate.
public static class TelegramDocumentEmptyPortableTests
{
    const string Commit="4de548e79fed27f1a66fbdff84223321838fe925";
    const string OracleManifest="d73a082ea9484dc168fe55d8e9b2db5ad4f31c696ccd4d44b96838ac8fcbbf1f";
    const string SourceFactory="3936357e1a2dee4e4fe9bd7d7c422b35f6cea0724dc7a0df7da93b396b2da205";
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static Dictionary<string,Dictionary<string,object>> oracle;
    static int checks;
    static string fixtures,work,context;
    static CancellationToken phase;
    static Stopwatch clock;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception((context==null?"":context+": ")+why);}
    static object Get(Dictionary<string,object> row,string key){object value;return row.TryGetValue(key,out value)?value:null;}
    static string Str(Dictionary<string,object> row,string key){return Get(row,key) as string;}
    static long Num(object value){return Convert.ToInt64(value,CultureInfo.InvariantCulture);}
    static List<Dictionary<string,object>> List(object value){return ((IEnumerable)value).Cast<Dictionary<string,object>>().ToList();}
    static Dictionary<string,object> Read(string path){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path,Encoding.UTF8));}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string HashBytes(byte[] bytes,int count){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes,0,count)).Replace("-","").ToLowerInvariant();}
    static string Safe(string root,string relative){return RecoveryCatalog.SafeFile(root,relative);}
    static Dictionary<string,string> Binding(string root){return Directory.GetFiles(root,"*",SearchOption.AllDirectories).ToDictionary(path=>path.Substring(root.Length+1),Hash,StringComparer.OrdinalIgnoreCase);}
    static bool Same(Dictionary<string,string> a,Dictionary<string,string> b){return a.Count==b.Count&&a.All(item=>b.ContainsKey(item.Key)&&b[item.Key]==item.Value);}
    static T Guard<T>(Func<CancellationToken,T> action)
    {
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(phase)){
            stop.CancelAfter(TimeSpan.FromMinutes(4)+TimeSpan.FromSeconds(45));
            int remaining=(int)Math.Min(300000,1200000-clock.ElapsedMilliseconds);
            if(remaining<=0)throw new TimeoutException("Hard twenty-minute phase watchdog; no successful result inferred");
            var task=Task.Run(()=>action(stop.Token));
            if(Task.WaitAny(new Task[]{task},remaining)<0){stop.Cancel();throw new TimeoutException("Hard call/phase watchdog: completion and cleanup unconfirmed");}
            return task.GetAwaiter().GetResult();
        }
    }
    static List<Dictionary<string,object>> Parts(Dictionary<string,object> item)
    {
        var expected=(Dictionary<string,object>)item["expected"];
        string text=Str(expected,"text"),caption=Str(item,"expected_legacy_caption");
        var result=new List<Dictionary<string,object>>();
        if(!String.IsNullOrEmpty(text))result.Add(new Dictionary<string,object>{{"text",text},{"text_field","message"},{"supplemental",false}});
        if(!String.IsNullOrEmpty(caption)&&caption!=text)result.Add(new Dictionary<string,object>{{"text",caption},{"text_field","media.legacy_caption"},{"supplemental",!String.IsNullOrEmpty(text)}});
        return result;
    }
    static void BindCase(Dictionary<string,object> item,string category,string variant,string name,string oracleName)
    {
        Check(Str(item,"name")==name&&Str(item,"oracle_name")==oracleName&&Str(item,"variant")==variant&&Str(item,"database")==category+"/"+name+"/cache4.db","fixture paths and variants are exact, preselected independent inputs");
        var known=oracle[oracleName];var sql=(Dictionary<string,object>)item["exact_sql"];var original=(Dictionary<string,object>)known["exact_sql"];
        Check(sql.Count==3&&original.Count==3&&new[]{"mid","uid","date"}.All(key=>Num(sql[key])==Num(original[key]))&&
            Num(item["layer"])==Num(known["layer"])&&Str(item,"constructor")==Str(known,"constructor")&&Str(item,"tl_body_sha256")==Str(known,"tl_body_sha256"),"all expected SQL keys, Message profile and body SHA equal the pinned official oracle");
        var actual=List(item["text_parts"]);var expected=Parts(known);
        Check(actual.Count==expected.Count&&actual.Select((part,index)=>part.Count==3&&Str(part,"text")==Str(expected[index],"text")&&Str(part,"text_field")==Str(expected[index],"text_field")&&Get(part,"supplemental") is bool&&(bool)part["supplemental"]==(bool)expected[index]["supplemental"]).All(equal=>equal),"text, Unicode and separate primary/caption roles are bound independently of the generated golden");
        var source=(Dictionary<string,object>)item["source_sql"];
        Check(source.Count==3&&new[]{"mid","uid","date"}.All(key=>Num(source[key])==(name=="bad-mid"&&key=="mid"?42:name=="bad-date"&&key=="date"?1790000001:name=="bad-uid"&&key=="uid"?909:Num(original[key]))),"only the declared invalid SQL field differs from its independent wire record");
    }
    static void BindOracle(string project,Dictionary<string,object> manifest)
    {
        string bundle=Path.Combine(project,"tests","fixtures","telegram-document-empty"),path=Path.Combine(bundle,"manifest.json");
        Check(Hash(path)==OracleManifest&&Str(manifest,"oracle_manifest_sha256")==OracleManifest&&Str(manifest,"source_commit")==Commit&&Num(manifest["schema"])==1&&
            Str(manifest,"generator_sha256")==Hash(Path.Combine(project,"tests","build_telegram_document_portable_fixtures.py"))&&
            Str(manifest,"source_factory_sha256")==SourceFactory&&Hash(Path.Combine(project,"tests","build_telegram_document_empty_fixtures.py"))==SourceFactory,"fresh fixture receipt binds both exact factories and the hard-pinned independent oracle manifest");
        var pinned=Read(path);var members=List(pinned["files"]);string[] allowed={"oracle.json.gz","oracle-sources.tar.gz","LICENSE"};
        Check(Num(pinned["schema"])==1&&Num(pinned["cases"])==167&&Str(pinned,"telegram_commit")==Commit&&members.Count==3&&new HashSet<string>(members.Select(item=>Str(item,"path"))).SetEquals(allowed),"official fixture has exactly167 cases and the three declared immutable bundle members");
        foreach(var item in members){string file=Safe(bundle,Str(item,"path"));Check(new FileInfo(file).Length==Num(item["bytes"])&&Hash(file)==Str(item,"sha256"),"official fixture member length and SHA are intact");}
        byte[] raw;
        using(var input=File.OpenRead(Path.Combine(bundle,"oracle.json.gz")))using(var gzip=new GZipStream(input,CompressionMode.Decompress))using(var output=new MemoryStream()){
            byte[] buffer=new byte[8192];int read;
            while((read=gzip.Read(buffer,0,buffer.Length))>0){phase.ThrowIfCancellationRequested();Check(output.Length<=2*1024*1024-read,"bounded independent oracle decompression");output.Write(buffer,0,read);}raw=output.ToArray();
        }
        Check(raw.Length==Num(pinned["uncompressed_json_bytes"]),"official JSON has its exact pinned uncompressed size");
        var payload=Json.Deserialize<Dictionary<string,object>>(new UTF8Encoding(false,true).GetString(raw));var cases=List(payload["cases"]);
        Check(Num(payload["schema"])==1&&Str(payload,"commit")==Commit&&cases.Count==167&&cases.Select(item=>Str(item,"name")).Distinct().Count()==167&&cases.Select(item=>Str(item,"constructor")).Distinct().Count()==19,"all independent official profiles and controls are present without replacement or repetition");
        oracle=cases.ToDictionary(item=>Str(item,"name"),StringComparer.Ordinal);
        foreach(var item in cases){byte[] blob=Convert.FromBase64String(Str(item,"blob_base64"));long tl=Num(item["tl_bytes"]);Check(blob.Length==Num(item["bytes"])&&tl>0&&tl<=blob.Length&&HashBytes(blob,blob.Length)==Str(item,"blob_sha256")&&HashBytes(blob,(int)tl)==Str(item,"tl_body_sha256"),"every official serialized BLOB and TL prefix matches its independent exact hash");}
        var current=List(manifest["cases"]);Check(current.Count==167&&new HashSet<string>(current.Select(item=>Str(item,"name"))).SetEquals(oracle.Keys),"all167 current cases are mandatory");
        foreach(var item in current)BindCase(item,"current","current",Str(item,"name"),Str(item,"name"));
        var snapshots=List(manifest["snapshot_cases"]);Check(snapshots.Count==2&&new HashSet<string>(snapshots.Select(item=>Str(item,"name"))).SetEquals(new[]{"history","residual"}),"both independent WAL cases are mandatory");
        foreach(var item in snapshots)BindCase(item,"snapshots",Str(item,"name"),Str(item,"name"),"layer118-flags3");
        var controls=List(manifest["controls"]);Check(controls.Count==4&&new HashSet<string>(controls.Select(item=>Str(item,"name"))).SetEquals(new[]{"bad-mid","bad-date","bad-uid","photo-only-cache"}),"all SQL-mismatch and unchanged photo-cache allowlist controls are mandatory");
        foreach(var item in controls)BindCase(item,"controls",Str(item,"name")=="photo-only-cache"?"media-cache":"current",Str(item,"name"),"layer118-flags3");
        var version=(Dictionary<string,object>)manifest["version_case"];Check(Str(version,"database")=="versions/cache4.db"&&((IEnumerable)version["oracle_names"]).Cast<string>().SequenceEqual(new[]{"id0","id1"}),"same-account WAL control uses the exact preselected zero and negative official references");
        var inventory=(Dictionary<string,object>)manifest["files"];var actual=Binding(fixtures);actual.Remove("manifest.json");
        Check(actual.Count==inventory.Count&&inventory.All(item=>actual.ContainsKey(item.Key.Replace('/',Path.DirectorySeparatorChar))),"the complete generated payload fileset is exact");
        foreach(var item in inventory){var receipt=(Dictionary<string,object>)item.Value;string file=Safe(fixtures,item.Key);Check(receipt.Count==2&&Hash(file)==Str(receipt,"sha256")&&new FileInfo(file).Length==Num(receipt["bytes"]),"every payload file has its exact recorded size and hash");}
    }
    static HelperResult Analyze(string source,string output)
    {
        var result=Guard(token=>TelegramAnalysisService.AnalyzeSelected(output,source,"",false,token,message=>{}));
        Check((result.Status=="complete"||result.Status=="partial")&&File.Exists(Path.Combine(output,"messages.jsonl"))&&!File.Exists(Path.Combine(output,"job.incomplete"))&&!Directory.Exists(output+".work"),"public analysis publishes a controlled archive and cleans scratch");return result;
    }
    static ArchiveSearchResult Search(string archive,string query,long offset=0,bool regex=false,string evidence="")
    {
        var result=Guard(token=>ArchiveSearchService.Search(archive,"Telegram",query,evidence,offset,token,regex));
        Check((result.status=="complete"||result.status=="partial")&&result.records!=null,"actual packaged helper returns a controlled search page");return result;
    }
    static List<ArchiveMessage> All(string archive,string query="")
    {
        var rows=new List<ArchiveMessage>();long total=-1;
        do{var page=Search(archive,query,rows.Count);if(total<0)total=page.total;Check(page.total==total&&page.offset==rows.Count&&(page.records.Count>0||total==0),"pagination retains the exact total and makes progress");rows.AddRange(page.records);}while(rows.Count<total);
        Check(rows.Count==total,"every matched row was read exactly once");return rows;
    }
    static bool Native(ArchiveMessage row){return new[]{"tl_message","tl_message_caption","sqlite_deleted_record","sqlite_deleted_caption"}.Contains(row.record_kind)&&row.application_confirmed==true&&row.evidence_kind!="fragment"&&row.provenance_verification!="provided_archive_metadata";}
    static string Key(ArchiveMessage row){return row.identity_scope+"|"+row.native_tl_body_sha256+"|"+row.text_field;}
    static void Scope(ArchiveMessage row,string originalDatabase)
    {
        // Match Windows os.path.normcase(os.path.abspath(originalDBPath));
        // hash the supplied original path, never the copied scratch database.
        string normalized=Path.GetFullPath(originalDatabase).Replace('/','\\').ToLowerInvariant();
        byte[] bytes=Encoding.UTF8.GetBytes(normalized);string expected="telegram-db:"+HashBytes(bytes,bytes.Length);
        Check(!String.IsNullOrEmpty(row.identity_scope)&&row.identity_scope==expected,"exact nonempty native account scope binds the normalized absolute original database path");
    }
    static void Fragments(IEnumerable<ArchiveMessage> rows)
    {
        foreach(var row in rows){bool memory=row.record_kind=="memory_fragment";
            Check(row.evidence_kind=="fragment"&&(memory||new[]{"typed_tl_fragment","sqlite_residual_fragment","sqlite_wal_residual"}.Contains(row.record_kind)),"every nonnative result is classified as an explicitly weak fragment");
            Check(row.application_confirmed==(memory?false:true)&&row.chat_id==null&&row.chat_name==null&&row.message_id==null&&row.sender_id==null&&row.sender_name==null&&row.timestamp==null&&row.timestamp_raw==null,"recognized application fragments do not invent SQL chat, author, message or date links");
            Check(row.deleted==null&&(row.recovery_status==null||row.recovery_status=="unattributed_structured_fragment")&&(row.residual_sources==null||row.residual_sources.Length==0)&&row.wal_proof==null&&row.wal_snapshot_sha256==null&&row.sqlite_record_sha256==null&&row.sqlite_payload_sha256==null&&row.sqlite_overflow_chain_verified!=true&&row.rollback_content_authenticity_verified!=true&&row.rollback_proof!="all_pages_from_validated_rollback_journal","weak fragments cannot acquire strong native/deletion proof");
        }
    }
    static void Counts(HelperResult summary,List<ArchiveMessage> all,List<ArchiveMessage> native,int expected,int deleted)
    {
        context="rows="+all.Count+",native="+native.Count+",fragments="+(all.Count-native.Count);
        Check(native.Count==expected&&summary.Messages==all.Count&&summary.NativeRecords==expected&&summary.HistoryMessages==expected&&summary.FragmentRecords==all.Count-native.Count&&summary.DeletedSupportedRecords==deleted&&summary.Media==0,"summary agrees with the exact native set and separately classified fragments, with no invented media");
        Fragments(all.Where(row=>!native.Contains(row)));
    }
    static void Source(Dictionary<string,object> item)
    {
        string folder=Path.GetDirectoryName(Safe(fixtures,Str(item,"database")));
        foreach(var member in (Dictionary<string,object>)item["source_files"]){Check(new[]{"cache4.db","cache4.db-wal","cache4.db-shm"}.Contains(member.Key),"input inventory contains only native SQLite DB/WAL/SHM");Check(Hash(Safe(folder,member.Key))==(string)member.Value,"native source bytes match their fixture receipt");}
    }
    static void Part(ArchiveMessage row,Dictionary<string,object> item,bool historical,bool imported=false)
    {
        var known=oracle[Str(item,"oracle_name")];var part=Parts(known).Single(value=>Str(value,"text_field")==row.text_field);var sql=(Dictionary<string,object>)known["exact_sql"];var expected=(Dictionary<string,object>)known["expected"];
        Check(row.text==Str(part,"text")&&Num(row.chat_id)==Num(sql["uid"])&&Num(row.message_id)==Num(expected["id"])&&Num(row.native_layer)==Num(known["layer"])&&row.native_constructor==Str(known,"constructor")&&row.native_tl_body_sha256==Str(known,"tl_body_sha256"),"exact Unicode slot, SQL identity, official Message constructor and body hash survive helper/search/DTO");
        var sender=Get(expected,"from_peer") as Dictionary<string,object>;string wanted=sender==null?null:Str(sender,"kind")+":"+Num(sender["id"]).ToString(CultureInfo.InvariantCulture);
        Check((wanted==null?row.sender_id==null:row.sender_id is string&&(string)row.sender_id==wanted)&&row.sender_name==null,"independent sender and unknown name are preserved");
        long date=Num(expected["date"]);DateTimeOffset observed;
        Check(date==0?row.timestamp==null:DateTimeOffset.TryParse(row.timestamp as string,CultureInfo.InvariantCulture,DateTimeStyles.None,out observed)&&observed.ToUniversalTime()==new DateTimeOffset(1970,1,1,0,0,0,TimeSpan.Zero).AddSeconds(date),"independent date is preserved and zero does not become an invented timestamp");
        Check(row.record_kind==((bool)part["supplemental"]?"tl_message_caption":"tl_message")&&row.application_confirmed==true&&row.evidence_kind==(historical?"previous":"backup")&&row.deleted==null,"primary/supplemental fields retain their verified structure, snapshot category and unknown user deletion");
        string id=Get(known,"document_id")==null?null:Num(known["document_id"]).ToString(CultureInfo.InvariantCulture);bool photo=Str(known,"name")=="photo-control";
        Check(row.media_kind==(photo?"photo":"document")&&row.media_status==(photo?"photo_reference_only":"document_reference_only")&&row.media_id==id&&row.thumbnail_count!=null&&Num(row.thumbnail_count)==0&&(row.attachments==null||row.attachments.Length==0),"metadata-only document/photo preserves absent versus exact signed ID without creating attachment bytes");
        Check(!String.IsNullOrEmpty(row.archive_record_key)&&(!imported||row.provenance_verification=="provided_archive_metadata"),"field has a full-text locator and reimport never claims independent metadata verification");
    }
    static void Full(string archive,ArchiveMessage row)
    {
        var page=Guard(token=>ArchiveSearchService.ReadPage(archive,row.archive_record_key,0,token));
        Check(page.status=="complete"&&page.eof&&page.text==row.text,"full-text locator returns the exact chosen field, including astral Unicode and newlines");
    }
    static void Residual(Dictionary<string,object> origin,Dictionary<string,object> item,ArchiveMessage row,string suppliedDatabase=null)
    {
        string database=suppliedDatabase??Safe(fixtures,Str(item,"database"));Check(Str(origin,"text_field")==row.text_field&&String.Equals(Path.GetFullPath(Str(origin,"source_file")),database,StringComparison.OrdinalIgnoreCase)&&Str(origin,"physical_source")=="wal","physical residual binds the same text slot and original WAL");
        string file=database+"-wal";long at=Num(origin["physical_byte_offset"]),length=Num(origin["sqlite_record_length"]);
        Check(at>=0&&length>0&&length<=4*1024*1024&&at<=new FileInfo(file).Length-length,"reported record range lies entirely inside the native WAL");
        byte[] raw=new byte[(int)length];using(var input=File.OpenRead(file)){input.Position=at;int read=0;while(read<raw.Length){phase.ThrowIfCancellationRequested();int count=input.Read(raw,read,raw.Length-read);if(count==0)throw new EndOfStreamException();read+=count;}}
        Check(HashBytes(raw,raw.Length)==Str(origin,"sqlite_record_sha256"),"reported record bytes replay to their physical SHA; this is replay consistency, not an independent record-boundary oracle");
        byte[] blob=Convert.FromBase64String(Str(oracle[Str(item,"oracle_name")],"blob_base64"));int occurrences=0;
        for(int offset=0;offset<=raw.Length-blob.Length;offset++){bool equal=true;for(int index=0;index<blob.Length;index++)if(raw[offset+index]!=blob[index]){equal=false;break;}if(equal)occurrences++;}
        Check(occurrences==1,"replayed record contains the exact complete independent official BLOB once");
    }
    static List<ArchiveMessage> Current(Dictionary<string,object> manifest)
    {
        var cases=List(manifest["cases"]);foreach(var item in cases)Source(item);
        string archive=Path.Combine(work,"current");var summary=Analyze(Path.Combine(fixtures,"current"),archive);var all=All(archive);var rows=all.Where(Native).ToList();int expected=cases.Sum(item=>Parts(oracle[Str(item,"name")]).Count);
        Counts(summary,all,rows,expected,0);var expectedKeys=new HashSet<string>(cases.SelectMany(item=>Parts(oracle[Str(item,"name")]).Select(part=>Str(item,"name")+"|"+Str(part,"text_field"))));var actualKeys=new HashSet<string>();
        foreach(var row in rows){string name=Path.GetFileName(Path.GetDirectoryName(row.source_file));var item=cases.Single(value=>Str(value,"name")==name);Part(row,item,false);Scope(row,Safe(fixtures,Str(item,"database")));Check(actualKeys.Add(name+"|"+row.text_field),"every independently expected case/slot occurs once");Check(String.Equals(Path.GetFullPath(row.source_file),Safe(fixtures,Str(item,"database")),StringComparison.OrdinalIgnoreCase)&&row.source_sha256==(string)((Dictionary<string,object>)item["source_files"])["cache4.db"],"result names the immutable original native database and its exact hash");}
        Check(actualKeys.SetEquals(expectedKeys)&&rows.Select(Key).Distinct().Count()==expected,"all exact independent identities/roles appear, including absent IDs and empty/equal text controls");
        Check(!rows.Any(row=>Path.GetFileName(Path.GetDirectoryName(row.source_file))=="mode4"),"empty document metadata is not manufactured into a text message");
        foreach(string name in new[]{"id0","id1","id2","id3","layer118-flags2"}){var selected=rows.Where(row=>Path.GetFileName(Path.GetDirectoryName(row.source_file))==name).ToList();Check(selected.Count==Parts(oracle[name]).Count,"explicit zero, signed endpoints and absent document IDs are covered by actual results");}
        int captions=cases.Sum(item=>Parts(oracle[Str(item,"name")]).Count(part=>Str(part,"text_field")=="media.legacy_caption"));var regexAll=AllRegex(archive,"caption[\\s\\S]*第二行");var regex=regexAll.Where(Native).ToList();Fragments(regexAll.Where(row=>!regex.Contains(row)));Check(regex.Count==captions&&regex.All(row=>row.text_field=="media.legacy_caption"),"Regex searches every independent caption without replacing outer text");
        var keywordAll=All(archive,"second");var keyword=keywordAll.Where(Native).ToList();Fragments(keywordAll.Where(row=>!keyword.Contains(row)));Check(keyword.Count==rows.Count(row=>row.text.IndexOf("second",StringComparison.OrdinalIgnoreCase)>=0)&&keyword.All(row=>row.text_field=="message"),"literal keyword search finds the complete independent outer-text set");
        Check(Search(archive,"",0,false,"deleted").total==0,"current surviving records are excluded from supported deletion");
        foreach(var row in rows.Where(value=>value.text_field=="media.legacy_caption").Take(3).Concat(rows.Where(value=>value.text_field=="message").Take(3)))Full(archive,row);
        string html=File.ReadAllText(Path.Combine(archive,"Переписки.html"),Encoding.UTF8);Check(html.Contains("подпись к вложению")&&html.Contains("Сохранилась запись о вложении.")&&html.Contains("connect-src 'none'")&&!html.Contains("<script src="),"offline HTML labels document captions generically, explains missing bytes and prohibits remote script/fetch");
        string imported=Path.Combine(work,"current-reimport");Analyze(Path.Combine(archive,"messages.jsonl"),imported);var copied=All(imported).Where(row=>row.provenance_verification=="provided_archive_metadata"&&new[]{"tl_message","tl_message_caption"}.Contains(row.record_kind)).ToList();var original=rows.ToDictionary(Key);
        Check(copied.Count==expected&&copied.Select(Key).Distinct().Count()==expected&&new HashSet<string>(copied.Select(Key)).SetEquals(original.Keys),"canonical import preserves the complete exact independent field set");
        foreach(var row in copied){var previous=original[Key(row)];string name=Path.GetFileName(Path.GetDirectoryName(previous.source_file));Part(row,cases.Single(item=>Str(item,"name")==name),false,true);Scope(row,previous.source_file);Check(row.text==previous.text&&row.media_id==previous.media_id&&row.media_kind==previous.media_kind,"canonical import preserves exact text and signed decimal metadata without trusted reattribution");}
        Check(Search(imported,"",0,false,"deleted").total==0,"canonical current imports do not invent deletion");return rows;
    }
    static List<ArchiveMessage> AllRegex(string archive,string query)
    {
        var rows=new List<ArchiveMessage>();long total=-1;do{var page=Search(archive,query,rows.Count,true);if(total<0)total=page.total;Check(page.total==total&&page.offset==rows.Count&&(page.records.Count>0||total==0),"Regex pagination retains total and advances");rows.AddRange(page.records);}while(rows.Count<total);Check(rows.Count==total,"all Regex matches are read once");return rows;
    }
    static void Snapshots(Dictionary<string,object> manifest)
    {
        foreach(var item in List(manifest["snapshot_cases"])){Source(item);string name=Str(item,"name"),archive=Path.Combine(work,name);var summary=Analyze(Safe(fixtures,Str(item,"database")),archive);var all=All(archive);var rows=all.Where(Native).ToList();int count=Parts(oracle[Str(item,"oracle_name")]).Count;Counts(summary,all,rows,count,name=="residual"?count:0);
            Check(rows.Select(Key).Distinct().Count()==count&&new HashSet<string>(rows.Select(row=>row.text_field)).SetEquals(Parts(oracle[Str(item,"oracle_name")]).Select(part=>Str(part,"text_field"))),"each historical field is present exactly once");
            foreach(var row in rows){Part(row,item,true);Scope(row,Safe(fixtures,Str(item,"database")));Full(archive,row);Check(row.wal_proof=="all_pages_from_validated_wal"&&!String.IsNullOrEmpty(row.wal_snapshot_sha256),"historical fields retain the validated whole-page WAL snapshot");if(name=="residual"){Check(row.recovery_status=="deleted_supported_by_evidence"&&row.residual_sources!=null&&row.residual_sources.Length>0,"native residual evidence remains attached to both exact fields");foreach(var origin in row.residual_sources)Residual(origin,item,row);}else Check(row.recovery_status!="deleted_supported_by_evidence","ordinary historical observation is not evidence of deletion");}
            Check(Search(archive,"",0,false,"deleted").total==(name=="residual"?count:0),"supported-deletion filter agrees with physical residual evidence only");
            if(name=="residual"){string imported=Path.Combine(work,"residual-reimport");Analyze(Path.Combine(archive,"messages.jsonl"),imported);var copied=All(imported).Where(row=>row.provenance_verification=="provided_archive_metadata"&&new[]{"tl_message","tl_message_caption"}.Contains(row.record_kind)).ToList();Check(copied.Count==count&&new HashSet<string>(copied.Select(Key)).SetEquals(rows.Select(Key))&&copied.All(row=>row.recovery_status=="imported_recovery_claim"&&row.deleted==null),"provided archive keeps exact residual text identities but downgrades its deletion claim");foreach(var row in copied){Part(row,item,true,true);Scope(row,Safe(fixtures,Str(item,"database")));}Check(Search(imported,"",0,false,"deleted").total==0,"unverified residual reimport never enters the supported-deletion filter");}
        }
    }
    static void Controls(Dictionary<string,object> manifest)
    {
        foreach(var item in List(manifest["controls"])){Source(item);string archive=Path.Combine(work,"control-"+Str(item,"name"));var summary=Analyze(Safe(fixtures,Str(item,"database")),archive);var all=All(archive);Counts(summary,all,all.Where(Native).ToList(),0,0);Check(Search(archive,"",0,false,"deleted").total==0,"SQL mismatch or document in photo-only media cache cannot create trusted history/deletion");}
    }
    static void WalVersions(Dictionary<string,object> manifest)
    {
        var item=(Dictionary<string,object>)manifest["version_case"];Source(item);string source=Safe(fixtures,Str(item,"database")),archive=Path.Combine(work,"wal-versions");var summary=Analyze(source,archive);var all=All(archive);var rows=all.Where(Native).ToList();Counts(summary,all,rows,4,0);
        Check(rows.Select(row=>row.identity_scope).Distinct().Count()==1&&rows.Select(row=>Num(row.chat_id)).Distinct().Count()==1&&rows.Select(row=>Num(row.message_id)).Distinct().Count()==1&&rows.Select(Key).Distinct().Count()==4,"same-account SQL IDs retain both distinct complete document bodies and both original text slots");
        foreach(string name in new[]{"id0","id1"}){
            bool historical=name=="id0";var known=oracle[name];var selected=rows.Where(row=>row.native_tl_body_sha256==Str(known,"tl_body_sha256")).ToList();Check(selected.Count==2&&new HashSet<string>(selected.Select(row=>row.text_field)).SetEquals(Parts(known).Select(part=>Str(part,"text_field"))),"each exact independent document version appears once per field");
            foreach(var row in selected){Part(row,new Dictionary<string,object>{{"oracle_name",name}},historical);Scope(row,source);Check(String.Equals(Path.GetFullPath(row.source_file),source,StringComparison.OrdinalIgnoreCase)&&row.recovery_status!="deleted_supported_by_evidence","changed document reference preserves the same physical source without claiming deletion");if(historical)Check(row.wal_proof=="all_pages_from_validated_wal"&&!String.IsNullOrEmpty(row.wal_snapshot_sha256),"earlier document reference is tied to its validated WAL commit");Full(archive,row);}
        }
        Check(Search(archive,"",0,false,"deleted").total==0,"changed document ID alone is never classified as a deleted message");
    }
    static void ForgedResidual(Dictionary<string,object> manifest)
    {
        var item=List(manifest["snapshot_cases"]).Single(value=>Str(value,"name")=="residual");string source=Safe(fixtures,Str(item,"database")),input=Path.Combine(work,"forged-source"),native=Path.Combine(input,"native");Directory.CreateDirectory(native);
        foreach(var member in (Dictionary<string,object>)item["source_files"]){Check(new[]{"cache4.db","cache4.db-wal","cache4.db-shm"}.Contains(member.Key),"forged-input setup copies only its owned native SQLite files");File.Copy(Safe(Path.GetDirectoryName(source),member.Key),Safe(native,member.Key),false);Check(Hash(Safe(native,member.Key))==(string)member.Value,"forged regression starts from exact independent native bytes");}
        string database=Path.Combine(native,"cache4.db"),baselineArchive=Path.Combine(work,"forged-baseline");var initial=Binding(input);var baselineSummary=Analyze(input,baselineArchive);var baselineAll=All(baselineArchive);var baseline=baselineAll.Where(Native).ToList();Counts(baselineSummary,baselineAll,baseline,2,2);
        foreach(var row in baseline){Part(row,item,true);Scope(row,database);Check(row.residual_sources!=null&&row.residual_sources.Length>0,"baseline has physical support for each real document text field");foreach(var origin in row.residual_sources)Residual(origin,item,row,database);}
        Check(Same(initial,Binding(input)),"baseline analysis leaves the copied native DB/WAL/SHM unchanged");
        var selected=baseline.Single(row=>row.text_field=="message");var observed=Json.Deserialize<Dictionary<string,object>>(Json.Serialize(selected));var claim=new Dictionary<string,object>();
        foreach(string field in new[]{"app","record_kind","identity_scope","chat_id","message_id","native_tl_body_sha256","text_field","native_constructor","native_layer","sender_id","sender_name","timestamp","application_confirmed","media_kind","media_id","media_status","thumbnail_count"})claim[field]=observed[field];
        const string fakeText="Forged supplied document recipe: this text is absent from the authentic TL body.";
        claim["text"]=fakeText;claim["evidence_kind"]="backup";claim["attachments"]=new string[0];claim["deleted"]=true;claim["recovery_status"]="deleted_supported_by_evidence";claim["deletion_interpretation"]="provided_claim";claim["provenance_verification"]="internally_verified";
        // The provided root JSONL is visited before its native child directory.
        File.WriteAllText(Path.Combine(input,"messages.jsonl"),Json.Serialize(claim)+"\n",new UTF8Encoding(false));var before=Binding(input);string archive=Path.Combine(work,"forged-after");var summary=Analyze(input,archive);var all=All(archive);var real=all.Where(Native).ToList();var provided=all.Where(row=>row.text==fakeText).ToList();
        Check(provided.Count==1&&real.Count==2&&new HashSet<string>(real.Select(Key)).SetEquals(baseline.Select(Key)),"supplied text cannot replace either checked document field or disappear during result classification");var forged=provided[0];var fragments=all.Where(row=>!real.Contains(row)&&!Object.ReferenceEquals(row,forged)).ToList();Fragments(fragments);
        Check(summary.Messages==all.Count&&summary.HistoryMessages==3&&summary.NativeRecords==3&&summary.FragmentRecords==fragments.Count&&summary.DeletedSupportedRecords==2,"summary counts real fields, one separately imported claim and every weak fragment without promoting the claim");
        Check(Key(forged)==Key(selected)&&forged.provenance_verification=="provided_archive_metadata"&&forged.recovery_status=="imported_recovery_claim"&&forged.deleted==null&&forged.deletion_interpretation=="unknown"&&(forged.residual_sources==null||forged.residual_sources.Length==0),"claimed same-body/same-role metadata cannot borrow checked SQLite residual proof");
        Scope(forged,database);
        foreach(var row in real){Part(row,item,true);Scope(row,database);Check(row.recovery_status=="deleted_supported_by_evidence"&&row.residual_sources!=null&&row.residual_sources.Length>0,"real document fields retain their structural residual evidence");foreach(var origin in row.residual_sources)Residual(origin,item,row,database);Full(archive,row);}
        Full(archive,forged);var deleted=Search(archive,"",0,false,"deleted");Check(deleted.total==2&&deleted.records.All(row=>row.text!=fakeText)&&Same(before,Binding(input)),"only authentic fields enter supported deletion, while all native/provided input bytes remain unchanged");
    }
    static void SameTextVersions(List<ArchiveMessage> current)
    {
        string inputFolder=Path.Combine(work,"same-text-versions-source");Directory.CreateDirectory(inputFolder);string input=Path.Combine(inputFolder,"messages.jsonl");var selected=new[]{"id0","id1"}.Select(name=>current.Single(row=>Path.GetFileName(Path.GetDirectoryName(row.source_file))==name&&row.text_field=="message")).ToList();
        Check(selected[0].text==selected[1].text&&selected[0].native_tl_body_sha256!=selected[1].native_tl_body_sha256,"independent inputs contain equal text and different complete document bodies");
        using(var output=new StreamWriter(input,false,new UTF8Encoding(false)))foreach(var row in selected){var value=Json.Deserialize<Dictionary<string,object>>(Json.Serialize(row));value["identity_scope"]="owned-same-account-scope";output.WriteLine(Json.Serialize(value));}
        string archive=Path.Combine(work,"same-text-versions");Analyze(input,archive);var all=All(archive);var rows=all.Where(row=>row.provenance_verification=="provided_archive_metadata"&&row.record_kind=="tl_message").ToList();
        Check(rows.Count==2&&rows.Select(row=>row.native_tl_body_sha256).Distinct().Count()==2&&new HashSet<string>(rows.Select(row=>row.media_id)).SetEquals(new[]{"0","-1"})&&rows.All(row=>row.text==selected[0].text&&row.deleted==null&&row.identity_scope=="owned-same-account-scope"),"same account/IDs/text does not merge different document bodies or zero/negative references and preserves the supplied literal account scope");
        Fragments(all.Where(row=>!rows.Contains(row)));Check(Search(archive,"",0,false,"deleted").total==0,"same-text provided versions remain unverified observations");
    }
    public static int Main(string[] args)
    {
        try{
            if(args.Length!=1)throw new ArgumentException("Expected project directory");string project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","telegram-document-fixtures-current");work=Path.Combine(project,".build","telegram-document-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            using(var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(20))){phase=timeout.Token;clock=Stopwatch.StartNew();var before=Binding(fixtures);var manifest=Read(Path.Combine(fixtures,"manifest.json"));BindOracle(project,manifest);Check(File.Exists(HelperClient.Executable),"actual packaged helper exists");string helper=Hash(HelperClient.Executable),app=Hash(typeof(RecoveryCore).Assembly.Location);var rows=Current(manifest);Snapshots(manifest);Controls(manifest);WalVersions(manifest);ForgedResidual(manifest);SameTextVersions(rows);Check(Same(before,Binding(fixtures))&&Hash(HelperClient.Executable)==helper&&Hash(typeof(RecoveryCore).Assembly.Location)==app,"all source DB/WAL/SHM/oracle fixture bytes and tested app/helper remain unchanged");phase.ThrowIfCancellationRequested();}
            Console.WriteLine("PASS TelegramDocumentEmptyPortable: "+checks+" checks;167 pinned official-Java cases, exact document text slots and signed IDs, actual helper/search/Regex/fulltext/reimport, checked WAL/residual replay and SQL/cache rejection. No device, document-byte recovery or paid-tool claim.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
