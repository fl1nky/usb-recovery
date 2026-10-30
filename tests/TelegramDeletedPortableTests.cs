using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class TelegramDeletedPortableTests
{
    public sealed class Fixture {public string Name,Path,Sha256,WalSha256;public int ExpectedResiduals;}
    public sealed class Manifest {public int Schema;public List<Fixture> Cases;}
    static int checks;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    public static int Main(string[] args)
    {
        try{
            string fixtures=Path.GetFullPath(args[0]);var json=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};
            var manifest=json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));
            Check(manifest.Schema==1&&manifest.Cases.Count==4,"Wrong deleted fixture manifest");
            foreach(var fixture in manifest.Cases){
                string source=RecoveryCatalog.SafeFile(fixtures,fixture.Path),before=RecoveryCore.HashFile(source,CancellationToken.None,(a,b)=>{});
                Check(before==fixture.Sha256,"Fixture source changed");
                if(fixture.WalSha256!=null)Check(RecoveryCore.HashFile(source+"-wal",CancellationToken.None,(a,b)=>{})==fixture.WalSha256,"Fixture WAL changed");
                string output=Path.Combine(Path.GetTempPath(),"TelegramDeletedPortable-"+Guid.NewGuid().ToString("N"));
                var result=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="telegram_analyze",destination=output,options=new{roots=new[]{source},scan_fragments=fixture.Name=="typed-dump",fragment_query="recipe",query_mode="literal"}},CancellationToken.None,s=>{});
                Check(result.Status!="error"&&Directory.Exists(output)&&!File.Exists(Path.Combine(output,"job.incomplete")),"Frozen worker did not publish a complete archive");
                Check(result.DeletedSupportedRecords==fixture.ExpectedResiduals,"Frozen worker residual counter incorrect");
                var filtered=ArchiveSearchService.Search(output,"Telegram","recipe","deleted",0,CancellationToken.None);
                Check(filtered.total==fixture.ExpectedResiduals,"Deleted filter differs from actual recovered records");
                foreach(var record in filtered.records){
                    Check(record.recovery_status=="deleted_supported_by_evidence"&&record.deleted==null,"Manual deletion claimed");
                    Check(record.sqlite_page!=null&&record.sqlite_record_page_offset!=null&&record.physical_byte_offset!=null,"SQLite source offsets lost through C# search DTO");
                    Check(record.native_tl_body_sha256!=null&&record.native_tl_body_sha256.Length==64,"TL body hash lost");
                    Check(record.chat_id!=null&&record.message_id!=null&&record.sender_id!=null,"Confirmed SQL/TL identity lost");
                    if(fixture.Name=="current-residual-with-history")Check(record.evidence_kind=="backup","Current residual borrowed historical snapshot attribution");
                }
                if(fixture.Name=="secure-on")Check(filtered.records.Count==0,"Secure deletion manufactured records");
                if(fixture.Name=="typed-dump"){
                    var fragments=ArchiveSearchService.Search(output,"Telegram","recipe","fragment",0,CancellationToken.None);
                    var typed=fragments.records.Where(x=>x.record_kind=="typed_tl_fragment").ToArray();Check(typed.Length==1,"Typed dump fragment missing");
                    Check(typed[0].chat_id==null&&typed[0].sender_id==null&&typed[0].timestamp==null&&typed[0].message_id==null,"Unattributed dump bytes became a confirmed chat");
                    Check(Convert.ToInt64(typed[0].candidate_message_id)==321,"Tentative dump fields lost");
                }
                Check(before==RecoveryCore.HashFile(source,CancellationToken.None,(a,b)=>{}),"Input DB or dump changed");
                if(fixture.WalSha256!=null)Check(RecoveryCore.HashFile(source+"-wal",CancellationToken.None,(a,b)=>{})==fixture.WalSha256,"Input WAL changed");
            }
            Console.WriteLine("PASS TelegramDeletedPortable: "+checks+" checks; frozen helper, real SQLite DELETE, secure-delete negative, typed dump attribution and archive search DTO; synthetic only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
