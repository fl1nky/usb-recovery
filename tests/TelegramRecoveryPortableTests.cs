using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class TelegramRecoveryPortableTests
{
    static int checks;
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string TextHash(string value){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(new System.Text.UTF8Encoding(false).GetBytes(value))).Replace("-","").ToLowerInvariant();}
    static Dictionary<string,object> Manifest(string folder){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(folder,"manifest.json")));}
    static string Analyze(string source,string output)
    {
        var result=TelegramAnalysisService.AnalyzeSelected(output,source,"",false,CancellationToken.None,null);
        Check(result.Status!="error","actual frozen-helper analysis completes");
        Check(!Directory.Exists(output+".work")&&!File.Exists(Path.Combine(output,"job.incomplete")),"archive published with scratch cleaned");
        return output;
    }
    static void Wal(string project,string output)
    {
        string folder=Path.Combine(project,".build","telegram-wal-tail-fixtures-current");
        foreach(Dictionary<string,object> item in (IEnumerable)Manifest(folder)["cases"]){
            string name=(string)item["name"],source=RecoveryCatalog.SafeFile(folder,(string)item["path"]),wal=source+"-wal";
            string dbHash=Hash(source),walHash=Hash(wal);Check(dbHash==(string)item["source_sha256"]&&walHash==(string)item["wal_sha256"],"independent fixture bytes match manifest");
            string archive=Analyze(source,Path.Combine(output,"wal-"+name));
            var found=ArchiveSearchService.Search(archive,"Telegram",(string)item["latest_text"],"backup",0,CancellationToken.None);
            var records=found.records.Where(r=>r.recovery_status=="committed_wal_prefix_snapshot").ToList();
            Check(records.Count==Convert.ToInt32(item["expected_prefix_records"]),"latest validated prefix expectation: "+name);
            foreach(var message in records){
                Check(message.wal_proof=="all_pages_from_validated_wal"&&message.wal_current_state_confirmed==false&&message.wal_snapshot_latest_known_commit==true,"full WAL proof and uncertainty survive actual worker/search/DTO");
                Check(message.deleted==null&&message.evidence_kind=="backup"&&message.text==(string)item["latest_text"],"exact latest text remains backup with unknown deletion");
                Check(message.wal_tail_reason==(string)item["tail_reason"]&&Convert.ToInt64(message.wal_validated_prefix_bytes)>32,"tail reason and validated byte extent survive DTO");
                Check(message.wal_sha256==walHash&&message.wal_db_sha256==dbHash,"actual source hashes bind snapshot");
            }
            Check(ArchiveSearchService.Search(archive,"Telegram",(string)item["latest_text"],"deleted",0,CancellationToken.None).total==0,"prefix snapshot is never counted as proven deletion");
            Check(Hash(source)==dbHash&&Hash(wal)==walHash,"source DB and WAL remain unchanged");
        }
    }
    static void Overflow(string project,string output)
    {
        string folder=Path.Combine(project,".build","telegram-overflow-fixtures-current");
        foreach(Dictionary<string,object> item in (IEnumerable)Manifest(folder)["cases"]){
            string name=(string)item["name"],source=RecoveryCatalog.SafeFile(folder,(string)item["image"]),before=Hash(source);
            Check(before==(string)item["source_sha256"],"overflow fixture bytes match independent manifest");
            string archive=Analyze(source,Path.Combine(output,"overflow-"+name));
            var found=ArchiveSearchService.Search(archive,"Telegram","recipe 3 яблоки","deleted",0,CancellationToken.None);
            Check(found.total==1&&found.records.Count==1,"long deleted record is searchable through actual frozen helper");
            var message=found.records[0];
            var full=File.ReadLines(Path.Combine(archive,"messages.jsonl")).Select(line=>Json.Deserialize<ArchiveMessage>(line)).Single(row=>Convert.ToInt64(row.message_id)==3&&row.recovery_status=="deleted_supported_by_evidence");
            Check(TextHash(full.text)==(string)item["expected_text_sha256"]&&message.deleted==null,"full archived text is exact and manual deletion is unknown");
            Check(message.text==full.text.Substring(0,Math.Min(full.text.Length,65536))&&message.text_truncated==(full.text.Length>65536),"bounded search view faithfully identifies any truncation");
            if(message.text_truncated)Check(message.text_length==full.text.Length,"original full text length survives bounded DTO");
            Check(message.sqlite_overflow_chain_verified==true&&message.sqlite_payload_ranges.Length>1&&message.sqlite_payload_ranges.Length<=4096,"complete bounded physical map survives DTO");
            long logical=0;using(var digest=SHA256.Create()){
                foreach(var part in message.sqlite_payload_ranges){
                    long length=Convert.ToInt64(part["bytes"]),position=Convert.ToInt64(part["physical_byte_offset"]);
                    Check(Convert.ToInt64(part["logical_offset"])==logical&&(string)part["physical_source"]=="db","ordered ranges point to real source DB");
                    byte[] bytes=new byte[checked((int)length)];using(var input=File.OpenRead(source)){input.Position=position;int count=0;while(count<bytes.Length){int read=input.Read(bytes,count,bytes.Length-count);if(read<=0)throw new EndOfStreamException();count+=read;}}
                    digest.TransformBlock(bytes,0,bytes.Length,bytes,0);logical+=length;
                }
                digest.TransformFinalBlock(new byte[0],0,0);Check(BitConverter.ToString(digest.Hash).Replace("-","").ToLowerInvariant()==message.sqlite_payload_sha256,"replaying physical source ranges matches payload hash");
            }
            Check(logical==Convert.ToInt64(message.sqlite_payload_length)&&Hash(source)==before,"complete map length and immutable source");
        }
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),output=Path.Combine(project,".build","telegram-recovery-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(output);
            if(args.Length<2||args[1]!="overflow")Wal(project,output);Overflow(project,output);
            Console.WriteLine("PASS TelegramRecoveryPortable: "+checks+" checks; actual frozen helper, "+(args.Length>1&&args[1]=="overflow"?"overflow-only preflight":"committed WAL prefixes and real deleted overflow records")+", keyword/DTO/provenance and immutable source hashes. Owned fixtures only, no phones.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
