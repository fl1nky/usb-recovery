using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class TelegramNativePortableTests
{
    sealed class FileProof { public string path {get;set;} public string sha256 {get;set;} public long size {get;set;} }
    sealed class FixtureManifest { public bool synthetic {get;set;} public List<FileProof> files {get;set;} }
    static int checks;
    static string root,fixtures;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static void Verify(FixtureManifest manifest){foreach(var proof in manifest.files){string path=RecoveryCatalog.SafeFile(fixtures,proof.path);Check(new FileInfo(path).Length==proof.size&&Hash(path)==proof.sha256,"source bytes match fixture manifest: "+proof.path);}}
    static string Analyze(string name)
    {
        string output=Path.Combine(root,name);
        var result=TelegramAnalysisService.AnalyzeSelected(output,RecoveryCatalog.SafeFile(fixtures,name),"",false,CancellationToken.None,null);
        Check(result.Status!="error","frozen native analysis completes: "+name);
        Check(!Directory.Exists(output+".work")&&!File.Exists(Path.Combine(output,"job.incomplete")),"complete archive and scratch cleanup: "+name);
        return output;
    }
    static ArchiveSearchResult Search(string output,string query,string category)
    {
        var result=ArchiveSearchService.Search(output,"Telegram",query,category,0,CancellationToken.None);
        Check(result.status=="complete","packaged search: "+category+" "+query);return result;
    }
    public static int Main(string[] args)
    {
        fixtures=Path.GetFullPath(args[0]);root=Path.Combine(Path.GetTempPath(),"TelegramNativePortable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try{
            var manifest=new JavaScriptSerializer().Deserialize<FixtureManifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));
            Check(manifest.synthetic&&manifest.files.Count==8,"independent synthetic fixture inventory");Verify(manifest);
            string output=Analyze("valid");var current=Search(output,"Current recipe","backup");
            Check(current.total==1&&current.records.Single().record_kind=="tl_message","current typed record decoded through frozen worker");
            Check(current.records[0].native_constructor!=null&&current.records[0].source_sha256!=null&&current.records[0].identity_scope!=null,"native source and protocol provenance retained");
            var previous=Search(output,"recipe","previous");Check(previous.total==2,"edited and removed prior records retained separately");
            Check(previous.records.All(x=>x.wal_proof=="all_pages_from_validated_wal"&&x.wal_commit_frame!=null&&x.wal_sha256!=null&&x.wal_snapshot_sha256!=null),"strict historical proof reaches native search");
            Check(previous.records.Any(x=>x.text=="Old recipe before edit")&&previous.records.Any(x=>x.text=="Deleted recipe before removal"),"expected prior text exact");
            Check(previous.records.All(x=>!x.source_file.Contains(".work")&&!x.source_file.Contains("wal-history-")),"removed scratch paths never published as origins");
            Check(Search(Analyze("missing-preimage"),"","previous").total==0,"missing historical pages never filled with current base bytes");
            var accounts=Search(Analyze("cross-account"),"Same IDs independent account","backup");
            Check(accounts.total==2&&accounts.records.Select(x=>x.identity_scope).Distinct().Count()==2,"independent account IDs never merged");
            Check(Search(Analyze("corrupt-wal"),"Current recipe","backup").total==0,"corrupt WAL cannot publish successful current text");
            Verify(manifest);Console.WriteLine("PASS TelegramNativePortable: "+checks+" checks; frozen helper, typed Android records, strict WAL history, missing preimages, account identity, corrupt WAL, original hashes unchanged; synthetic files only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
        finally{if(Path.GetFullPath(root).StartsWith(Path.GetFullPath(Path.GetTempPath()),StringComparison.OrdinalIgnoreCase))try{Directory.Delete(root,true);}catch{}}
    }
}
