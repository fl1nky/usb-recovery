using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class TelegramRollbackPortableTests
{
    static int checks;
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static void Require(bool value,string why){if(!value)throw new Exception(why);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var hash=SHA256.Create())return Hex(hash.ComputeHash(input));}
    static string Hash(byte[] bytes){using(var hash=SHA256.Create())return Hex(hash.ComputeHash(bytes));}
    static string Hex(byte[] value){return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();}
    static Dictionary<string,object> Read(string path){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path,Encoding.UTF8));}
    static long Number(object value){return Convert.ToInt64(value,System.Globalization.CultureInfo.InvariantCulture);}
    static string Safe(string root,string relative)
    {
        Require(!String.IsNullOrEmpty(relative)&&!Path.IsPathRooted(relative)&&!relative.Contains(":"),"owned fixture relative path");
        string parent=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
        string result=Path.GetFullPath(Path.Combine(parent,relative.Replace('/',Path.DirectorySeparatorChar)));
        Require(result.StartsWith(parent,StringComparison.OrdinalIgnoreCase),"owned fixture path boundary");return result;
    }
    static Dictionary<string,string> Binding(string folder)
    {return Directory.GetFiles(folder,"*",SearchOption.AllDirectories).ToDictionary(path=>path.Substring(folder.Length+1),Hash,StringComparer.OrdinalIgnoreCase);}
    static bool Same(Dictionary<string,string> one,Dictionary<string,string> two)
    {return one.Count==two.Count&&one.All(pair=>two.ContainsKey(pair.Key)&&two[pair.Key]==pair.Value);}
    static Dictionary<string,Dictionary<string,object>> Cases(string folder)
    {return ((IEnumerable)Read(Path.Combine(folder,"manifest.json"))["cases"]).Cast<Dictionary<string,object>>().ToDictionary(item=>(string)item["name"]);}
    static HelperResult Analyze(string source,string output)
    {
        var result=TelegramAnalysisService.Analyze(output,new[]{source},CancellationToken.None,null);
        Check(result.Status!="error"&&File.Exists(Path.Combine(output,"messages.jsonl"))&&!File.Exists(Path.Combine(output,"job.incomplete"))&&!Directory.Exists(output+".work"),"actual child publishes archive and removes scratch");return result;
    }
    static List<ArchiveMessage> Rows(string archive)
    {return File.ReadLines(Path.Combine(archive,"messages.jsonl"),Encoding.UTF8).Select(line=>Json.Deserialize<ArchiveMessage>(line)).ToList();}
    static byte[] Bytes(string path,long offset,int length)
    {
        using(var input=File.OpenRead(path)){
            Require(offset>=0&&length>=0&&offset<=input.Length-length,"physical map source bounds");input.Position=offset;var bytes=new byte[length];int done=0;
            while(done<bytes.Length){int read=input.Read(bytes,done,bytes.Length-done);Require(read>0,"physical map complete read");done+=read;}return bytes;
        }
    }
    static uint Big(byte[] value){Require(value.Length==4,"32-bit native journal field");return ((uint)value[0]<<24)|((uint)value[1]<<16)|((uint)value[2]<<8)|value[3];}
    static void Map(string archive,string journal,string before,ArchiveMessage message,bool complete)
    {
        string relative="provenance/rollback/"+Hash(journal)+".json",path=Safe(archive,relative);
        var map=Read(path);int page=checked((int)Number(map["page_size"])),initial=checked((int)Number(map["initial_pages"]));
        Check(message.rollback_page_map==relative&&Hash(path)==message.rollback_page_map_sha256&&(string)map["journal_sha256"]==Hash(journal)&&
              (string)map["format"]=="sqlite_rollback_page_map"&&(string)map["checksum_kind"]=="sqlite_sparse_32bit"&&map["content_authenticity_verified"] is bool&&!(bool)map["content_authenticity_verified"],"published page-map hash/source and sparse-checksum limits are exact");
        var records=((IEnumerable)map["records"]).Cast<Dictionary<string,object>>().ToList();var pages=new SortedDictionary<int,byte[]>();
        foreach(var record in records){
            int number=checked((int)Number(record["page"]));long offset=Number(record["data_offset"]),header=Number(record["header_offset"]),checksumOffset=Number(record["checksum_offset"]);
            Require(number>=1&&number<=initial&&!pages.ContainsKey(number)&&offset==Number(record["record_offset"])+4&&checksumOffset==offset+page,"page-map unique native record bounds");
            byte[] data=Bytes(journal,offset,page),expected=Bytes(before,(long)(number-1)*page,page);
            Require(data.SequenceEqual(expected)&&Hash(data)==(string)record["page_sha256"],"every mapped page equals independently preserved before-image");
            uint nonce=Big(Bytes(journal,header+12,4)),checksum=nonce;unchecked{for(int index=page-200;index>0;index-=200)checksum+=data[index];}
            Require(checksum==Big(Bytes(journal,checksumOffset,4))&&Number(record["nonce"])==nonce,"every mapped page sparse checksum replays from original journal bytes");pages.Add(number,data);
        }
        Check(records.Count>0&&Number(message.rollback_initial_pages)==initial&&(complete?records.Count==initial:records.Count<initial),"native page map independently replays all expected before-images with correct complete/partial coverage");
        if(complete){
            using(var stream=new MemoryStream()){for(int number=1;number<=initial;number++)stream.Write(pages[number],0,page);Check(Hash(stream.ToArray())==message.rollback_snapshot_sha256&&message.rollback_snapshot_sha256==Hash(before),"complete journal snapshot equals independent original database SHA256");}
        }
        if(message.rollback_payload_chain_verified==true){
            long logical=0;using(var stream=new MemoryStream()){
                foreach(var range in message.rollback_payload_ranges){
                    int size=checked((int)Number(range["bytes"]));Require(Number(range["logical_offset"])==logical&&(string)range["physical_source"]=="rollback_journal","overflow ranges remain ordered journal bytes");
                    byte[] part=Bytes(journal,Number(range["physical_byte_offset"]),size);stream.Write(part,0,part.Length);logical+=size;
                }
                Check(message.rollback_payload_ranges.Length>1&&logical==Number(message.rollback_payload_length)&&Hash(stream.ToArray())==message.rollback_payload_sha256,"overflow payload hash replays from original physical journal ranges");
            }
        }
    }
    static string Positive(string corpus,Dictionary<string,object> fixture,string output)
    {
        string name=(string)fixture["name"],source=Safe(corpus,name),journal=Path.Combine(source,"cache4.db-journal"),before=Path.Combine(corpus,"references",name+"-before.sqlite");
        var binding=Binding(source);var expectedFiles=(Dictionary<string,object>)fixture["source_files"];
        Check(expectedFiles.All(pair=>binding.ContainsKey(pair.Key)&&binding[pair.Key]==(string)pair.Value)&&Hash(before)==(string)fixture["before_sha256"],"native owned source bytes match independent manifest: "+name);
        string archive=Path.Combine(output,name);Analyze(source,archive);string expected=(string)fixture["expected_text"],journalHash=Hash(journal);
        var canonical=Rows(archive).Where(row=>row.text==expected&&row.rollback_journal_sha256==journalHash).ToList();
        Check(canonical.Count==1,"one canonical exact old-text journal record: "+name);
        var literal=ArchiveSearchService.Search(archive,"Telegram","прабабушка","",0,CancellationToken.None);
        var regex=ArchiveSearchService.Search(archive,"Telegram","рецепт[\\s\\S]*прабабушка","",0,CancellationToken.None,true);
        var message=literal.records.Single(row=>row.text==expected&&row.rollback_journal_sha256==journalHash);
        Check(regex.records.Any(row=>row.text==expected&&row.rollback_journal_sha256==journalHash)&&!String.IsNullOrEmpty(message.archive_record_key),"actual literal/regex search finds exact old text with fingerprint locator: "+name);
        bool complete=(bool)fixture["expected_full_snapshot"],overflow=name.StartsWith("partial-overflow-",StringComparison.Ordinal);
        Check(message.rollback_hot_state=="unknown"&&message.rollback_current_state_confirmed==false&&message.rollback_content_authenticity_verified==false&&message.rollback_checksum_kind=="sqlite_sparse_32bit"&&message.deleted==null,"actual DTO preserves unknown state and sparse-checksum limitations: "+name);
        if(complete)Check(message.evidence_kind=="backup"&&message.rollback_proof=="all_pages_from_validated_rollback_journal"&&Number(message.chat_id)==77&&Number(message.message_id)==21,"full snapshot alone provides verified in-snapshot IDs: "+name);
        else Check(message.evidence_kind=="fragment"&&message.rollback_snapshot_sha256==null&&message.chat_id==null&&message.sender_id==null&&message.timestamp==null&&message.message_id==null&&
            message.rollback_proof==(overflow?"validated_rollback_payload_chain":"validated_rollback_page_fragment"),"partial text remains unattributed including unrelated current account: "+name);
        Map(archive,journal,before,message,complete);
        var full=ArchiveSearchService.ReadPage(archive,message.archive_record_key,0,CancellationToken.None);
        Check(full.status=="complete"&&full.eof&&full.text==expected,"actual full-text page preserves complete Unicode old text: "+name);
        Check(ArchiveSearchService.Search(archive,"Telegram","прабабушка","deleted",0,CancellationToken.None).total==0,"journal target is never offered as proven deleted: "+name);
        Check(Same(binding,Binding(source)),"DB/journal source files remain byte-identical: "+name);
        return archive;
    }
    static void Negative(string corpus,Dictionary<string,object> fixture,string output)
    {
        string name=(string)fixture["name"],source=Safe(corpus,name);var binding=Binding(source);string archive=Path.Combine(output,name);Analyze(source,archive);
        var found=ArchiveSearchService.Search(archive,"Telegram","прабабушка","",0,CancellationToken.None);
        Check(found.records.All(row=>row.rollback_snapshot_sha256==null&&row.rollback_proof!="all_pages_from_validated_rollback_journal"&&
              (row.rollback_journal_sha256==null||row.evidence_kind=="fragment"&&row.chat_id==null&&row.message_id==null&&row.timestamp==null&&row.sender_id==null)),"invalid/unsupported journal cannot produce a full attributed history: "+name);
        Check(Same(binding,Binding(source)),"invalid/unsupported source bytes remain unchanged: "+name);
    }
    static void ReimportAndKeys(string archive,string output)
    {
        var source=Binding(archive);var message=ArchiveSearchService.Search(archive,"Telegram","прабабушка","",0,CancellationToken.None).records.Single();
        string key=message.archive_record_key,changed=key.Substring(0,key.Length-1)+(key.EndsWith("0",StringComparison.Ordinal)?"1":"0");
        var stale=ArchiveSearchService.ReadPage(archive,changed,0,CancellationToken.None);
        Check(stale.status=="error"&&stale.code=="RECORD_CHANGED","altered record fingerprint returns controlled stale-record error");
        var malformed=ArchiveSearchService.ReadPage(archive,"../not-an-archive-key",0,CancellationToken.None);
        Check(malformed.status=="error","malformed full-text locator cannot become a file path");
        string imported=Path.Combine(output,"canonical-reimport");var result=TelegramAnalysisService.AnalyzeSelected(imported,Path.Combine(archive,"messages.jsonl"),"",false,CancellationToken.None,null);
        var transfer=ArchiveSearchService.Search(imported,"Telegram","прабабушка","",0,CancellationToken.None).records.Single();
        Check(result.Status!="error"&&transfer.rollback_journal_sha256==message.rollback_journal_sha256&&transfer.rollback_snapshot_sha256==message.rollback_snapshot_sha256&&
              Hash(Safe(imported,transfer.rollback_page_map))==transfer.rollback_page_map_sha256,"actual canonical reimport preserves journal snapshot and bound map");
        Check(Same(source,Binding(archive)),"search, rejected keys and reimport leave original archive unchanged");
    }
    static void Contexts(string project,string output)
    {
        string corpus=Path.Combine(project,".build","telegram-rollback-context-fixtures-current"),manifestPath=Path.Combine(corpus,"manifest.json"),manifestBefore=Hash(manifestPath);
        foreach(var pair in Cases(corpus)){
            var fixture=pair.Value;string name=pair.Key,expected=(string)fixture["expected_text"],source=Safe(corpus,(string)fixture["source_path"]),archive=Path.Combine(output,"context-"+name);
            var declared=(Dictionary<string,object>)fixture["source_files"];
            Check(declared.All(file=>Hash(Safe(corpus,file.Key))==(string)file.Value),"context input bytes match independent fixture manifest: "+name);
            HelperResult result;
            if((string)fixture["operation"]=="scan")result=HelperClient.Scan(source,archive,new Dictionary<string,string>(),true,CancellationToken.None,null);
            else result=TelegramAnalysisService.AnalyzeSelected(archive,source,"",false,CancellationToken.None,null);
            Check(result.Status!="error"&&File.Exists(Path.Combine(archive,"messages.jsonl"))&&!Directory.Exists(archive+".work")&&!File.Exists(Path.Combine(archive,"job.incomplete")),"actual copied-phone/ZIP/generic context publishes a complete archive: "+name);
            var literal=ArchiveSearchService.Search(archive,"Telegram",expected,"",0,CancellationToken.None);
            var message=literal.records.Single(row=>row.text==expected&&row.rollback_proof==(string)fixture["expected_proof"]);
            var canonical=Rows(archive).Single(row=>row.text==expected&&row.rollback_proof==(string)fixture["expected_proof"]);
            Check(message.source_file==(string)fixture["expected_origin_path"]&&message.source_id==(string)fixture["expected_source_id"]&&
                  message.original_relative_path==(string)fixture["expected_relative_path"]&&message.source_sha256==(string)fixture["expected_source_sha256"]&&
                  canonical.source_file==message.source_file&&canonical.source_id==message.source_id&&canonical.original_relative_path==message.original_relative_path&&canonical.source_sha256==message.source_sha256,
                  "canonical archive and actual C# DTO preserve original URI/ID/relative path/member SHA: "+name);
            Check(!message.source_file.Contains(".work")&&!message.source_file.Contains("validated-input")&&message.rollback_journal_sha256==(string)fixture["expected_journal_sha256"],"published context never exposes removed working-copy origin: "+name);
            Check(Hash(Safe(archive,message.rollback_page_map))==message.rollback_page_map_sha256,"context page-map copy remains bound to its actual bytes: "+name);
            bool native=(bool)fixture["native_confirmed"];
            if(native)Check(message.application_confirmed==true&&message.record_kind=="tl_message"&&message.evidence_kind=="backup"&&message.rollback_proof=="all_pages_from_validated_rollback_journal"&&Number(message.chat_id)==77&&Number(message.message_id)==21,"only native SQL/TL context qualifies attributed full snapshot: "+name);
            else{
                Check(message.application_confirmed==false&&message.record_kind=="sqlite_rollback_archive_text"&&message.evidence_kind=="fragment"&&message.rollback_proof=="archive_text_from_rollback_snapshot"&&
                      message.rollback_snapshot_sha256!=null&&message.rollback_snapshot_sha256.Length==64&&message.chat_id==null&&message.chat_name==null&&message.message_id==null&&message.sender_id==null&&message.sender_name==null&&message.timestamp==null&&message.deleted==null&&message.native_constructor==null,
                      "generic JSON-derived text keeps physical snapshot but loses all unsupported Telegram identity: "+name);
                Check(ArchiveSearchService.Search(archive,"Telegram",expected,"backup",0,CancellationToken.None).total==0&&ArchiveSearchService.Search(archive,"Telegram",expected,"deleted",0,CancellationToken.None).total==0,"generic archived JSON cannot become native backup or proven deletion");
            }
            if(name=="zip"){
                string container=(string)fixture["container_source_id"],member=(string)fixture["member_path"];
                Check(message.container_sha256==(string)fixture["container_sha256"]&&message.container_source_id==container&&message.container_source_file==(string)fixture["container_origin_path"]&&
                      canonical.container_sha256==message.container_sha256&&canonical.container_source_id==message.container_source_id&&canonical.container_source_file==message.container_source_file,
                      "ZIP container proof survives canonical archive and actual C# DTO");
                Check(message.source_file.EndsWith("!/"+member,StringComparison.Ordinal)&&message.source_id==Hash(new UTF8Encoding(false).GetBytes(container+"!/"+member))&&message.source_sha256!=message.container_sha256,
                      "ZIP journal identity/hash belong to actual member and preserve the container separately");
            }
            var regex=ArchiveSearchService.Search(archive,"Telegram",Regex.Escape(expected),"",0,CancellationToken.None,true);
            var full=ArchiveSearchService.ReadPage(archive,message.archive_record_key,0,CancellationToken.None);
            Check(regex.records.Any(row=>row.text==expected&&row.source_file==message.source_file)&&full.status=="complete"&&full.eof&&full.text==expected,"context keyword/Regex/full-text paths retain exact useful text: "+name);
            Check(declared.All(file=>Hash(Safe(corpus,file.Key))==(string)file.Value),"copied phone/ZIP/generic context source files remain unchanged: "+name);
        }
        Check(Hash(manifestPath)==manifestBefore,"independent context manifest remains unchanged");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),normal=Path.Combine(project,".build","telegram-rollback-fixtures-current"),overflow=Path.Combine(project,".build","telegram-rollback-overflow-fixtures-current");
            string output=Path.Combine(project,".build","telegram-rollback-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(output);
            string normalManifest=Hash(Path.Combine(normal,"manifest.json")),overflowManifest=Hash(Path.Combine(overflow,"manifest.json"));var cases=Cases(normal);var longCases=Cases(overflow);string full=null;
            foreach(string name in new[]{"full-delete","full-standalone","partial-delete","partial-update","partial-wide","foreign-paired"}){
                string archive=Positive(normal,cases[name],output);if(name=="full-delete")full=archive;
            }
            foreach(string name in new[]{"partial-overflow-delete","partial-overflow-update"})Positive(overflow,longCases[name],output);
            foreach(string name in new[]{"bad-magic","bad-checksum","torn-record","zero-count","sentinel-count","super-journal","persist-zero"})Negative(normal,cases[name],output);
            ReimportAndKeys(full,output);
            Contexts(project,output);
            Check(Hash(Path.Combine(normal,"manifest.json"))==normalManifest&&Hash(Path.Combine(overflow,"manifest.json"))==overflowManifest,"both independent manifests remain unchanged");
            Console.WriteLine("PASS TelegramRollbackPortable: "+checks+" checks; actual packaged helper/C# protocol, native full/partial/overflow journals, physical provenance replay, literal/regex/full text, invalid journals/keys, canonical reimport, copied-phone/ZIP origins, conservative generic archive text and immutable owned sources. No real devices or paid-tool claim.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
