using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using UsbRecovery;

// Actual helper/public-service test. Compilation alone is NOT a portable PASS.
public static class TelegramMediaCachePortableTests
{
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    // Independent fixture writer: literal official TL prefix is 112 bytes;
    // the following 40-byte readAttachPath local tail is not part of Message.
    const string CaptionBody="10ed84da5328e2151d3614ab6a931a649a9f4d7b1e098abfd4ceb222133e7345";
    const string CaptionBlob="63e376b8b34ed2ddfd37a7bacf91f8e048259a057c40b7bdd895eb16d6bc5293";
    const string OtherBody="44724b688c8d860c7d1e0310baa21db0a4c060f8f75051ccb05ce9fc3203974d";
    static readonly string[] BaseCases={"current","history","missing-preimage","corrupt-wal",
        "wrong-schema","wrong-type","mid-mismatch","uid-mismatch","date-mismatch",
        "unknown-flags","missing-media","secret-uid","primary-current",
        "primary-historical","primary-different","repeated-history","metadata-only-edit"};
    static readonly string[] NegativeCases={"missing-preimage","corrupt-wal","wrong-schema",
        "wrong-type","mid-mismatch","uid-mismatch","date-mismatch","unknown-flags",
        "missing-media","secret-uid"};
    static int checks,analyzed;
    static string fixtures,work;
    static CancellationToken phase;

    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static void Require(bool value,string why){if(!value)throw new Exception(why);}
    static string Hash(string file){using(var input=File.OpenRead(file))using(var hash=SHA256.Create())return Hex(hash.ComputeHash(input));}
    static string Hex(byte[] value){return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();}
    static Dictionary<string,object> Read(string file){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file,Encoding.UTF8));}
    static object Get(Dictionary<string,object> row,string key){object value;return row.TryGetValue(key,out value)?value:null;}
    static string Str(Dictionary<string,object> row,string key){return Get(row,key) as string;}
    static long Number(object value){return Convert.ToInt64(value,System.Globalization.CultureInfo.InvariantCulture);}
    static bool Digest(string value){return value!=null&&Regex.IsMatch(value,"\\A[a-f0-9]{64}\\z");}
    static long CodePoints(string value){long count=0;for(int i=0;i<value.Length;i++,count++)if(Char.IsHighSurrogate(value[i])&&i+1<value.Length&&Char.IsLowSurrogate(value[i+1]))i++;return count;}
    static string Safe(string root,string relative){return RecoveryCatalog.SafeFile(root,relative);}
    static Dictionary<string,string> Binding(string folder)
    {
        return Directory.GetFiles(folder,"*",SearchOption.AllDirectories)
            .ToDictionary(path=>path.Substring(folder.TrimEnd('\\','/').Length+1),Hash,StringComparer.OrdinalIgnoreCase);
    }
    static bool Same(Dictionary<string,string> one,Dictionary<string,string> two)
    {return one.Count==two.Count&&one.All(x=>two.ContainsKey(x.Key)&&two[x.Key]==x.Value);}
    static T Guard<T>(Func<CancellationToken,T> action)
    {
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(phase)){
            stop.CancelAfter(TimeSpan.FromMinutes(5));
            var task=Task.Run(()=>action(stop.Token));
            if(Task.WaitAny(new Task[]{task},TimeSpan.FromMinutes(5)+TimeSpan.FromSeconds(15))<0){
                stop.Cancel();throw new Exception("Portable hard watchdog; worker completion/cleanup is unconfirmed.");
            }
            try{return task.GetAwaiter().GetResult();}
            catch(OperationCanceledException){throw new Exception("Portable worker watchdog/cancellation; no success inferred.");}
        }
    }
    static HelperResult AnalyzeAsync(string source,string output)
    {
        // Same public background path used by RecoveryHub, no invented coordinator.
        var result=Guard(token=>Task.Run(()=>TelegramAnalysisService.AnalyzeSelected(
            output,source,"",false,token,message=>{})).GetAwaiter().GetResult());
        Check((result.Status=="complete"||result.Status=="partial")&&File.Exists(Path.Combine(output,"messages.jsonl")),
            "actual packaged helper and public analysis service publish an archive");
        Check(!File.Exists(Path.Combine(output,"job.incomplete"))&&!Directory.Exists(output+".work"),
            "actual analysis completes publication and removes scratch");
        analyzed++;return result;
    }
    static List<Dictionary<string,object>> Raw(string archive)
    {return File.ReadLines(Path.Combine(archive,"messages.jsonl"),Encoding.UTF8).Select(line=>Json.Deserialize<Dictionary<string,object>>(line)).ToList();}
    static List<Dictionary<string,object>> TypedRaw(string archive)
    {return Raw(archive).Where(row=>Str(row,"record_kind")=="telegram_media_cache"||Str(row,"record_kind")=="tl_message"||Str(row,"record_kind")=="sqlite_deleted_record").ToList();}
    static ArchiveSearchResult Search(string archive,string query,bool regex=false,string evidence="")
    {
        var result=Guard(token=>ArchiveSearchService.Search(archive,"Telegram",query,evidence,0,token,regex));
        Check((result.status=="complete"||result.status=="partial")&&result.records!=null,
            "actual search publishes a controlled non-error DTO result");return result;
    }
    static ArchiveTextPage Page(string archive,string key,long offset=0)
    {return Guard(token=>ArchiveSearchService.ReadPage(archive,key,offset,token));}
    static List<Dictionary<string,object>> Origins(Dictionary<string,object> row)
    {
        object value=Get(row,"additional_sources")??Get(row,"sources");
        return value is IEnumerable?((IEnumerable)value).Cast<object>().OfType<Dictionary<string,object>>().ToList():new List<Dictionary<string,object>>();
    }
    static List<Dictionary<string,object>> CacheOrigins(IEnumerable<Dictionary<string,object>> origins)
    {return origins.Where(row=>Str(row,"record_kind")=="telegram_media_cache"&&(Str(row,"source_record")??"").StartsWith("media_v4(",StringComparison.Ordinal)).ToList();}
    static string CacheRecord(string status,object frame)
    {
        string key="media_v4(uid=77,mid=41,type=0)";
        return status=="historical_cache_record"||status=="committed_wal_prefix_snapshot"?
            key+"@wal_commit:"+Number(frame).ToString(System.Globalization.CultureInfo.InvariantCulture):key;
    }
    static void UnknownDeletion(ArchiveMessage message,string why)
    {Check(message.deleted==null&&message.recovery_status!="deleted_supported_by_evidence",why);}
    static void CheckedOrigin(Dictionary<string,object> origin,string body,bool requireWal,string fixture)
    {
        Check(Str(origin,"record_kind")=="telegram_media_cache"&&
            new[]{"current_cache_record","historical_cache_record","cache_base_snapshot_record","committed_wal_prefix_snapshot"}.Contains(Str(origin,"recovery_status"))&&
            Str(origin,"deletion_interpretation")=="unknown"&&Get(origin,"deleted")==null,
            "canonical/search cache origin retains kind/status and unknown user deletion");
        Check(Str(origin,"native_tl_body_sha256")==body&&
            Str(origin,"source_sha256")==Hash(Path.Combine(fixture,"cache4.db"))&&
            Str(origin,"source_record")==CacheRecord(Str(origin,"recovery_status"),Get(origin,"wal_commit_frame")),
            "cache origin retains complete TL body hash, source hash and SQL composite key");
        if(requireWal)Check(Str(origin,"wal_proof")=="all_pages_from_validated_wal"&&
            Number(Get(origin,"wal_commit_frame"))>0&&Digest(Str(origin,"wal_sha256"))&&
            Digest(Str(origin,"wal_db_sha256"))&&Digest(Str(origin,"wal_snapshot_sha256")),
            "historical cache origin retains verified WAL/source/snapshot bindings");
        if(!String.IsNullOrEmpty(Str(origin,"wal_proof")))Check(
            Str(origin,"wal_db_sha256")==Hash(Path.Combine(fixture,"cache4.db"))&&
            Str(origin,"wal_sha256")==Hash(Path.Combine(fixture,"cache4.db-wal")),
            "cache origin WAL proof is bound to exact independently supplied DB/WAL bytes");
    }
    static ArchiveMessage SearchAndFull(string archive,string expected,string recordKind)
    {
        var literal=Search(archive,"Рецепт");
        var regex=Search(archive,"Рецепт[\\s\\S]*第二行",true);
        var matches=literal.records.Where(row=>row.text==expected&&row.record_kind==recordKind).ToList();
        Check(matches.Count==1&&regex.records.Any(row=>row.text==expected&&row.record_kind==recordKind),
            "actual keyword and Regex services return the exact multilingual multiline caption");
        var message=matches[0];UnknownDeletion(message,"DTO does not promote cached/history text to user-deleted chat");
        Check(message.application_confirmed==true&&Number(message.chat_id)==77&&Number(message.message_id)==41&&
            Number(message.native_layer)==232&&message.native_constructor=="0x7600b9d3"&&
            message.native_tl_body_sha256==CaptionBody&&Digest(message.source_sha256),
            "actual helper/search/DTO keep confirmed SQL/TL identity, layer and source/body hashes");
        DateTimeOffset date;
        Check(Convert.ToString(message.sender_id)=="user:77"&&
            DateTimeOffset.TryParse(Convert.ToString(message.timestamp),System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None,out date)&&
            (date.ToUniversalTime()-new DateTimeOffset(1970,1,1,0,0,0,TimeSpan.Zero)).TotalSeconds==1790000000,
            "DTO preserves independently known sender and UTC date without borrowing adjacent identity");
        Check(message.attachments==null||message.attachments.Length==0,"photo metadata never invents a recovered image attachment");
        Check(!String.IsNullOrEmpty(message.archive_record_key),"full Unicode text has an actual source fingerprint locator");
        var full=Page(archive,message.archive_record_key);
        Check(full.status=="complete"&&full.eof&&full.text==expected&&
            full.next_offset==CodePoints(expected)&&full.text_length==CodePoints(expected),
            "actual full-text service returns exact Unicode code points including astral emoji");
        int next=expected.IndexOf('\n')+1;
        Require(next>0,"independent fixture really contains a line boundary");
        var suffix=Page(archive,message.archive_record_key,CodePoints(expected.Substring(0,next)));
        Check(suffix.status=="complete"&&suffix.eof&&suffix.text==expected.Substring(next),
            "full-text offsets preserve complete Unicode suffix after emoji/newline");
        Check(Search(archive,"Рецепт",false,"deleted").records.All(row=>row.archive_record_key!=message.archive_record_key),
            "cache disappearance is never offered as supported deletion");
        return message;
    }
    static string Positive(string name)
    {
        string folder=Safe(fixtures,name),source=Path.Combine(folder,"cache4.db"),archive=Path.Combine(work,name);
        var golden=Read(Path.Combine(folder,"golden.json"));var before=Binding(folder);
        Check(Number(golden["secure_delete"])==1&&Str(golden,"message_constructor")=="0x7600b9d3",
            "independent SQLite/TL232 fixture records real secure-delete policy");
        Check(Str(golden,"blob_sha256")==CaptionBlob,"independent full SQL BLOB oracle includes the separate local attachment tail");
        var result=AnalyzeAsync(source,archive);var rows=TypedRaw(archive);
        Check(rows.Count==1&&Str(rows[0],"record_kind")=="telegram_media_cache",
            "one actual typed cache caption survives current/history/repeated snapshots");
        string expected=Str(golden,"text");var message=SearchAndFull(archive,expected,"telegram_media_cache");
        Check(message.media_kind=="photo"&&message.media_status=="photo_reference_only"&&
            message.media_id=="987654321"&&Number(message.thumbnail_count)==0&&result.Media==0&&
            result.NativeRecords==1&&result.DeletedSupportedRecords==0&&
            message.source_record==CacheRecord(message.recovery_status,message.wal_commit_frame)&&message.source_sha256==Hash(source),
            "missing full photo remains reference-only through actual helper/DTO");
        Check(message.recovery_status==(name=="history"?"historical_cache_record":"current_cache_record")&&
            message.deletion_interpretation=="unknown","cache-specific current/history status remains explicit");
        if(name=="history"){
            Check(Number(golden["current_cache_rows"])==0&&message.evidence_kind=="previous"&&
                message.wal_proof=="all_pages_from_validated_wal"&&Number(message.wal_commit_frame)>0&&
                message.wal_db_sha256==Hash(source)&&message.wal_sha256==Hash(source+"-wal")&&
                Digest(message.wal_snapshot_sha256),"actual deleted cache row comes only from a checked committed before-image");
        }
        if(name=="repeated-history")Check(message.sources!=null&&message.sources.Length>0&&message.sources.Length<=10&&
            result.Warnings!=null&&result.Warnings.Contains("TELEGRAM_MEDIA_CACHE_PROVENANCE_LIMIT"),
            "repeated cache provenance stays bounded and emits the explicit limit warning");
        Check(Same(before,Binding(folder)),"positive supplied DB/WAL/SHM/golden files remain byte-identical");
        return archive;
    }
    static void StrongPrimary(string name)
    {
        string folder=Safe(fixtures,name),archive=Path.Combine(work,name);
        var before=Binding(folder);var golden=Read(Path.Combine(folder,"golden.json"));
        AnalyzeAsync(Path.Combine(folder,"cache4.db"),archive);var raw=TypedRaw(archive);
        Check(raw.Count==1&&Str(raw[0],"record_kind")=="tl_message"&&
            !(Str(raw[0],"source_record")??"").StartsWith("media_v4(",StringComparison.Ordinal),
            "stronger primary survives cache dedup in either current/historical processing order");
        string expected=Str(golden,"text");var message=SearchAndFull(archive,expected,"tl_message");
        Check(message.evidence_kind==(name=="primary-historical"?"previous":"backup")&&
            String.IsNullOrEmpty(message.recovery_status),
            "cache origin never replaces primary recovery/evidence status");
        var canonical=CacheOrigins(Origins(raw[0]));
        var dto=CacheOrigins(message.sources??new Dictionary<string,object>[0]);
        Check(canonical.Count>0&&dto.Count==canonical.Count,
            "all bounded canonical cache origins survive actual search DTO");
        foreach(var origin in dto)CheckedOrigin(origin,message.native_tl_body_sha256,
            Str(origin,"recovery_status")=="historical_cache_record",folder);
        Check(Same(before,Binding(folder)),"both ordering cases leave source copies unchanged");
    }
    static void DifferentContent()
    {
        string folder=Safe(fixtures,"primary-different"),archive=Path.Combine(work,"primary-different");
        var before=Binding(folder);AnalyzeAsync(Path.Combine(folder,"cache4.db"),archive);
        var rows=TypedRaw(archive);
        Check(rows.Count==2&&rows.Select(row=>Str(row,"native_tl_body_sha256")).Distinct().Count()==2&&
            rows.Select(row=>Str(row,"text")).Distinct().Count()==2&&
            new HashSet<string>(rows.Select(row=>Str(row,"native_tl_body_sha256"))).SetEquals(new[]{CaptionBody,OtherBody}),
            "same IDs never collapse different full message content or replace primary text");
        Check(rows.All(row=>Number(Get(row,"chat_id"))==77&&Number(Get(row,"message_id"))==41),
            "different versions retain independently checked shared IDs");
        Check(Same(before,Binding(folder)),"different-content inputs remain unchanged");
    }
    static void MetadataOnly(string name)
    {
        string folder=Safe(fixtures,name),archive=Path.Combine(work,name);var before=Binding(folder);
        var golden=Read(Path.Combine(folder,"golden.json"));
        var expected=new HashSet<string>(((IEnumerable)golden["body_versions_sha256"]).Cast<string>());
        Check(expected.Count==2&&expected.All(Digest)&&expected.Contains(Str(golden,"current_tl_body_sha256"))&&
            expected.Contains(Str(golden,"tl_body_sha256")),"metadata-only fixture supplies two independent exact TL-prefix before-image hashes");
        AnalyzeAsync(Path.Combine(folder,"cache4.db"),archive);var rows=TypedRaw(archive);
        Check(rows.Count==2&&rows.Select(row=>Str(row,"text")).Distinct().Count()==1&&
            expected.SetEquals(rows.Select(row=>Str(row,"native_tl_body_sha256")))&&
            rows.All(row=>Str(row,"record_kind")=="telegram_media_cache"&&Str(row,"text")==Str(golden,"text"))&&
            rows.Count(row=>Str(row,"recovery_status")=="current_cache_record"&&
                Str(row,"native_tl_body_sha256")==Str(golden,"current_tl_body_sha256"))==1&&
            rows.Count(row=>Str(row,"recovery_status")=="historical_cache_record")==1,
            "metadata-only TL changes preserve distinct body versions despite identical visible text");
        foreach(var row in rows)CheckedOrigin(row,Str(row,"native_tl_body_sha256"),
            Str(row,"recovery_status")=="historical_cache_record",folder);
        var found=Search(archive,"Рецепт").records.Where(row=>row.application_confirmed==true&&
            (row.record_kind=="telegram_media_cache"||row.record_kind=="tl_message")).ToList();
        Check(found.Count==2&&expected.SetEquals(found.Select(row=>row.native_tl_body_sha256))&&
            found.Select(row=>row.archive_record_key).Distinct().Count()==2,
            "actual keyword DTO retains metadata-only body identity");
        foreach(var row in found){
            UnknownDeletion(row,"metadata edit is not evidence of user deletion");
            var page=Page(archive,row.archive_record_key);
            Check(page.status=="complete"&&page.eof&&page.text==Str(golden,"text"),
                "both metadata-only versions resolve their own fingerprint to exact independent Unicode text");
        }
        Check(Same(before,Binding(folder)),"metadata-only version inputs remain unchanged");
    }
    static void Negative(string name)
    {
        string folder=Safe(fixtures,name),archive=Path.Combine(work,name);var before=Binding(folder);
        var result=AnalyzeAsync(Path.Combine(folder,"cache4.db"),archive);
        Check(TypedRaw(archive).Count==0,"invalid/missing/corrupt/type/schema/secret source never authorizes a typed cache row: "+name);
        Check(result.NativeRecords==0&&result.DeletedSupportedRecords==0&&result.Warnings!=null&&
            (name=="missing-preimage"?result.Warnings.Contains("TELEGRAM_WAL_HISTORY_INCOMPLETE"):
             name=="corrupt-wal"?result.Warnings.Any(warning=>warning.Contains("WAL")):
             result.Warnings.Contains("TELEGRAM_SQLITE_SCHEMA_UNSUPPORTED")),
            "actual helper exposes the explicit incomplete/corrupt/schema warning without typed/deleted promotion: "+name);
        var found=Search(archive,"Рецепт");
        Check(found.records.All(row=>row.record_kind!="telegram_media_cache"&&
            (row.evidence_kind!="fragment"||row.chat_id==null&&row.message_id==null&&row.sender_id==null&&row.timestamp==null)),
            "any retained fragment stays unattributed; rejected cache context cannot promote IDs: "+name);
        Check(Same(before,Binding(folder)),"negative source DB/WAL/SHM files remain unchanged: "+name);
    }
    static void Reimport(string archive,string label,bool primary)
    {
        var before=Binding(archive);var original=Search(archive,"Рецепт").records.Single(row=>
            row.record_kind==(primary?"tl_message":"telegram_media_cache"));
        string target=Path.Combine(work,"reimport-"+label);
        AnalyzeAsync(Path.Combine(archive,"messages.jsonl"),target);
        var transfer=SearchAndFull(target,original.text,original.record_kind);
        Check(transfer.native_tl_body_sha256==original.native_tl_body_sha256&&
            transfer.recovery_status==original.recovery_status&&transfer.evidence_kind==original.evidence_kind&&
            transfer.deleted==null,"canonical reimport retains body identity/status and unknown deletion");
        if(primary){
            var origins=CacheOrigins(transfer.sources??new Dictionary<string,object>[0]);
            Check(origins.Count>0,"canonical reimport retains explicit cache-origin kind");
            foreach(var origin in origins)CheckedOrigin(origin,original.native_tl_body_sha256,
                Str(origin,"recovery_status")=="historical_cache_record",Safe(fixtures,label));
        }else if(original.evidence_kind=="previous")Check(
            transfer.wal_sha256==original.wal_sha256&&transfer.wal_db_sha256==original.wal_db_sha256&&
            transfer.wal_snapshot_sha256==original.wal_snapshot_sha256&&
            Number(transfer.wal_commit_frame)==Number(original.wal_commit_frame),
            "canonical history reimport keeps original WAL commit/source/snapshot proof");
        Check(Same(before,Binding(archive)),"search/full text/reimport never change original published archive");
    }
    static void CopyTree(string source,string destination)
    {
        Require(!Directory.Exists(destination)&&!File.Exists(destination),"stale-test copy destination is fresh");
        Directory.CreateDirectory(destination);
        foreach(string directory in Directory.GetDirectories(source,"*",SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(destination,directory.Substring(source.Length+1)));
        foreach(string file in Directory.GetFiles(source,"*",SearchOption.AllDirectories))
            File.Copy(file,Path.Combine(destination,file.Substring(source.Length+1)));
    }
    static void ImportedClaims(string archive)
    {
        var originalBefore=Binding(archive);
        string input=Path.Combine(work,"provided-claim"),target=Path.Combine(work,"claim-result");
        Directory.CreateDirectory(input);
        var claimed=Raw(archive).Single(row=>Str(row,"record_kind")=="telegram_media_cache");
        claimed["deleted"]=true;claimed["recovery_status"]="deleted_supported_by_evidence";
        claimed["deletion_interpretation"]=String.Concat(Enumerable.Repeat(Char.ConvertFromUtf32(0x1f967),4096));
        claimed["provenance_verification"]="internally_verified";
        claimed["archive_claims"]=new Dictionary<string,object>{{"secret_key","owned-not-a-secret-sentinel"},{"deleted",new Dictionary<string,object>{{"nested",true}}}};
        File.WriteAllText(Path.Combine(input,"messages.jsonl"),Json.Serialize(claimed)+"\n",new UTF8Encoding(false));
        var inputBefore=Binding(input);var analyzedClaim=AnalyzeAsync(input,target);
        Check(analyzedClaim.DeletedSupportedRecords==0,"actual helper does not count a supplied deletion claim as a newly checked deleted record");
        var found=Search(target,"Рецепт");
        Check(found.records.Count==1&&found.records[0].text==Str(claimed,"text"),"actual archive import preserves claimed text");
        var message=found.records[0];
        Check(message.deleted==null&&message.recovery_status=="imported_recovery_claim"&&
            message.provenance_verification=="provided_archive_metadata"&&message.archive_claims!=null&&
            message.archive_claims.Count==3&&Str(message.archive_claims,"recovery_status")=="deleted_supported_by_evidence"&&
            Str(message.archive_claims,"deletion_interpretation")==Str(claimed,"deletion_interpretation")&&
            Get(message.archive_claims,"deleted") is bool&&(bool)message.archive_claims["deleted"],
            "actual helper/DTO preserve allowlisted original claim while rejecting supplied verification and nested/secret fields");
        Check(Search(target,"",false,"deleted").total==0,"claimed deletion cannot enter the actual deleted search category");
        var full=Page(target,message.archive_record_key);
        Check(full.status=="complete"&&full.eof&&full.text==message.text,"unverified archive claim retains full Unicode reader access");
        string copied=Path.Combine(work,"claim-reimport");var copiedResult=AnalyzeAsync(Path.Combine(target,"messages.jsonl"),copied);
        var copiedMessage=Search(copied,"Рецепт").records.Single();
        Check(copiedResult.DeletedSupportedRecords==0&&copiedMessage.recovery_status=="imported_recovery_claim"&&
            copiedMessage.deleted==null&&Json.Serialize(copiedMessage.archive_claims)==Json.Serialize(message.archive_claims)&&
            Search(copied,"",false,"deleted").total==0,"repeated actual import preserves original claim without escalating its trust");
        Check(!File.ReadAllText(Path.Combine(copied,"messages.jsonl"),Encoding.UTF8).Contains("owned-not-a-secret-sentinel")&&
            Same(inputBefore,Binding(input))&&Same(originalBefore,Binding(archive)),"claim import excludes unrelated metadata and leaves both original archives unchanged");
    }
    static void StaleSource(string archive)
    {
        var before=Binding(archive);var message=Search(archive,"Рецепт").records.Single(row=>row.record_kind=="telegram_media_cache");
        string stale=Path.Combine(work,"stale-archive-copy");CopyTree(archive,stale);
        // Change only a disposable copy, preserving SQLite framing and UTF8 length.
        string file=Path.Combine(stale,"chat-index.sqlite");byte[] raw=File.ReadAllBytes(file);
        byte[] old=new UTF8Encoding(false).GetBytes("Рецепт"),replacement=new UTF8Encoding(false).GetBytes("Сецепт");
        Require(old.Length==replacement.Length,"stale-source mutation preserves byte count");
        int changed=0;for(int at=0;at<=raw.Length-old.Length;at++){
            bool match=true;for(int i=0;i<old.Length;i++)if(raw[at+i]!=old[i]){match=false;break;}
            if(match){Buffer.BlockCopy(replacement,0,raw,at,replacement.Length);changed++;at+=old.Length-1;}
        }
        Check(changed>0,"stale test changes actual copied archived row bytes");
        File.WriteAllBytes(file,raw);
        var page=Page(stale,message.archive_record_key);
        Check(page.status=="error"&&page.code=="RECORD_CHANGED",
            "old fingerprint cannot return text from a changed archived source record");
        var bad=Page(archive,"../not-an-archive-key");
        Check(bad.status=="error","malformed full-text locator cannot become a path");
        Check(Same(before,Binding(archive)),"original archive stays untouched by stale-copy negative");
    }
    public static int Main(string[] args)
    {
        try{
            Require(args.Length==1,"Usage: TelegramMediaCachePortableTests.exe <project>");
            string project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","telegram-media-cache-fixtures-current");
            work=Path.Combine(project,".build","telegram-media-cache-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            var rootBefore=Binding(fixtures);var manifest=Read(Path.Combine(fixtures,"manifest.json"));
            var cases=((IEnumerable)manifest["cases"]).Cast<Dictionary<string,object>>().ToDictionary(row=>Str(row,"variant"));
            Check(Number(manifest["schema"])==1&&Get(manifest,"independent_sqlite_writer") is bool&&
                (bool)manifest["independent_sqlite_writer"]&&Str(manifest,"source_commit")=="4de548e79fed27f1a66fbdff84223321838fe925",
                "independent owned SQLite/official-wire fixture contract exists");
            Check(cases.Count==17&&BaseCases.All(cases.ContainsKey)&&cases.Keys.All(BaseCases.Contains),
                "all seventeen declared controls including metadata-only edit exist and unknown cases are not silently skipped");
            foreach(var item in cases.Values){
                string source=Safe(fixtures,Str(item,"database")),folder=Path.GetDirectoryName(source);
                var declared=(Dictionary<string,object>)item["source_files"];
                Check(declared.All(pair=>Hash(Safe(folder,pair.Key))==(string)pair.Value),
                    "supplied DB/WAL/SHM bytes match independent manifest: "+Str(item,"variant"));
            }
            Check(File.Exists(HelperClient.Executable),"actual packaged helper exists");
            string helperBefore=Hash(HelperClient.Executable),appBefore=Hash(typeof(RecoveryCore).Assembly.Location);
            using(var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(20))){
                phase=timeout.Token;
                string current=Positive("current"),history=Positive("history");
                Positive("repeated-history");
                StrongPrimary("primary-current");StrongPrimary("primary-historical");DifferentContent();
                foreach(string name in NegativeCases)Negative(name);
                MetadataOnly("metadata-only-edit");
                Reimport(current,"current",false);Reimport(history,"history",false);
                Reimport(Path.Combine(work,"primary-current"),"primary-current",true);
                Reimport(Path.Combine(work,"primary-historical"),"primary-historical",true);
                ImportedClaims(current);
                StaleSource(current);
            }
            Check(Same(rootBefore,Binding(fixtures))&&Hash(HelperClient.Executable)==helperBefore&&
                Hash(typeof(RecoveryCore).Assembly.Location)==appBefore,
                "entire fixture corpus and actual helper/app remain byte-identical");
            Console.WriteLine("PASS TelegramMediaCachePortable: "+checks+" checks; "+analyzed+
                " actual helper/public-service analyses, strict current/WAL photo captions, keyword/Regex/full Unicode DTO, canonical cache/body/WAL origins, primary dedup, missing media, stale archive/corruption negatives and immutable owned inputs. Cache disappearance is not user-deleted chat; no devices or broad recovery claim.");
            return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
