using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Actual packaged helper/app API. Fixtures are native Qt/Java/SQLite artifacts;
// no Python/Qt/Java installation, device, personal profile or network is used.
public static class TelegramPlatformPortableTests
{
    const string ManifestHash="f802063b5b9de84f314fa3c700478174b63f01e5171850c601e2ff63f612074e";
    const string TestPasscode="synthetic-known-passcode";
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=4*1024*1024};
    static readonly List<object> Runs=new List<object>();
    static string work,inputs;
    static int checks,analyses;
    static CancellationToken token;
    static void Check(bool value,string name){checks++;if(!value)throw new Exception(name);}
    static string Hash(string path){using(var sha=SHA256.Create())using(var f=File.OpenRead(path))return BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
    static Dictionary<string,string> Binding(string root){return Directory.GetFiles(root,"*",SearchOption.AllDirectories).ToDictionary(p=>p.Substring(root.Length),Hash,StringComparer.Ordinal);}
    static bool Same(Dictionary<string,string>a,Dictionary<string,string>b){return a.Count==b.Count&&a.All(r=>b.ContainsKey(r.Key)&&b[r.Key]==r.Value);}
    static IEnumerable<Dictionary<string,object>> Rows(object value){foreach(var row in (IEnumerable)value)yield return(Dictionary<string,object>)row;}
    static List<Dictionary<string,object>> Records(string archive){return File.ReadAllLines(Path.Combine(archive,"messages.jsonl"),Encoding.UTF8).Where(s=>s.Length>0).Select(s=>Json.Deserialize<Dictionary<string,object>>(s)).ToList();}
    static string Str(Dictionary<string,object>row,string name){object value;return row.TryGetValue(name,out value)?Convert.ToString(value,CultureInfo.InvariantCulture):"";}
    static bool Unknown(Dictionary<string,object>row,string name){object value;return!row.TryGetValue(name,out value)||value==null;}
    static void Extract(string project)
    {
        string fixture=Path.Combine(project,"tests","fixtures","telegram-platforms");
        string manifest=Path.Combine(fixture,"manifest.json");Check(Hash(manifest)==ManifestHash,"fixed independent native platform manifest");
        var data=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(manifest,Encoding.UTF8));
        var expected=Rows(data["sources"]).ToDictionary(r=>Str(r,"path"),StringComparer.Ordinal);
        string zip=Path.Combine(fixture,"native-cases.zip");Check(Hash(zip)==Str(data,"archive_sha256")&&expected.Count==63,"fixed native corpus ZIP and inventory");
        Directory.CreateDirectory(inputs);long total=0;var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using(var archive=new ZipArchive(File.OpenRead(zip),ZipArchiveMode.Read)){
            Check(archive.Entries.Count==63,"exact native corpus members");
            foreach(var entry in archive.Entries){
                token.ThrowIfCancellationRequested();string name=entry.FullName;Check(expected.ContainsKey(name)&&seen.Add(name),"unique declared native member");
                Check(!name.Contains("\\")&&!name.Contains(":")&&!name.StartsWith("/")&&!name.Split('/').Contains("..")&&
                    ((entry.ExternalAttributes>>16)&0xf000)!=0xa000&&entry.Length>=0&&entry.Length<=4*1024*1024,"bounded regular source member");
                total+=entry.Length;Check(total<=4*1024*1024,"bounded total corpus bytes");
                string target=Path.GetFullPath(Path.Combine(inputs,name.Replace('/',Path.DirectorySeparatorChar)));
                Check(target.StartsWith(inputs+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),"source path containment");
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                using(var source=entry.Open())using(var output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None))source.CopyTo(output);
                Check(new FileInfo(target).Length==Convert.ToInt64(expected[name]["bytes"])&&Hash(target)==Str(expected[name],"sha256"),"native input raw byte/SHA binding");
                File.SetAttributes(target,FileAttributes.ReadOnly);
            }
        }
        Check(seen.Count==expected.Count,"complete extracted native corpus");
    }
    static string Analyze(string source,string passcode,long messages,long history,long drafts,long scheduled)
    {
        var before=Binding(inputs);string output=Path.Combine(work,"archive-"+(++analyses).ToString(CultureInfo.InvariantCulture));
        var secrets=new Dictionary<string,string>();if(passcode!=null)secrets["telegram_desktop_passcode"]=passcode;
        HelperResult result;
        try{result=TelegramAnalysisService.AnalyzeSelected(output,source,"",false,secrets,token,m=>{});}
        finally{secrets.Clear();}
        Check(result.Status!="error"&&result.Messages==messages&&result.HistoryMessages==history&&result.DraftRecords==drafts&&result.ScheduledRecords==scheduled,"actual helper counts keep native roles distinct");
        Check(File.Exists(Path.Combine(output,"messages.jsonl"))&&!File.Exists(Path.Combine(output,"job.incomplete"))&&!Directory.Exists(output+".work"),"completed native archive and scratch cleanup");
        Check(Same(before,Binding(inputs)),"source DB/WAL/SHM/TDF/key-data bytes unchanged");
        if(drafts+scheduled>0&&history==0)Check(result.Code=="LOCAL_DRAFTS_OR_SCHEDULED_AVAILABLE","nonhistory records are a usable success");
        foreach(string file in Directory.GetFiles(output,"*",SearchOption.AllDirectories)){
            byte[] raw=File.ReadAllBytes(file);Check(Encoding.UTF8.GetString(raw).IndexOf(TestPasscode,StringComparison.Ordinal)<0,"provided known passcode not published");
        }
        Runs.Add(new{source=source,archive=output,messages=result.Messages,history=result.HistoryMessages,drafts=result.DraftRecords,scheduled=result.ScheduledRecords,code=result.Code});
        return output;
    }
    static string Run(string relative,string passcode,long messages,long history,long drafts,long scheduled){return Analyze(Path.Combine(inputs,relative.Replace('/',Path.DirectorySeparatorChar)),passcode,messages,history,drafts,scheduled);}
    static void SearchAndFull(string archive,int count)
    {
        var list=ArchiveSearchService.Search(archive,"Telegram","","",0,token);Check(list.total==count&&list.records.Count==count,"native rows enter public archive search");
        foreach(var row in list.records){var page=ArchiveSearchService.ReadPage(archive,row.archive_record_key,0,token);Check(page.eof&&page.text==row.text,"native Unicode/empty text reaches fulltext without metadata replacement");}
        Check(ArchiveSearchService.Search(archive,"Telegram","NEVER_FETCH|FILENAME|TAGS_NEVER","",0,token,true).total==0,"paths URL and formatting are not original message text");
    }
    public static int Main(string[] args)
    {
        CancellationTokenSource stop=null;
        try{
            if(args.Length!=1)throw new ArgumentException("Expected project directory");string project=Path.GetFullPath(args[0]);
            work=Path.Combine(project,".build","telegram-platform-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);inputs=Path.Combine(work,"inputs");
            stop=new CancellationTokenSource(TimeSpan.FromMinutes(5));token=stop.Token;Extract(project);
            string android=Run("positive/android",null,3,0,0,3);SearchAndFull(android,3);
            var androidRows=Records(android);Check(androidRows.Single(r=>Str(r,"message_id")=="5101")["text"].Equals("Scheduled native \u043f\u0438\u0440\u043e\u0433 \ud83e\udd67\n\u7b2c\u4e8c\u884c"),"native Java UTF8 original is exact");
            Check(androidRows.Count(r=>Str(r,"text")=="")==1&&androidRows.All(r=>Str(r,"record_kind")=="telegram_android_scheduled"&&Unknown(r,"deleted")),"media-only scheduled record retained without deletion claim");
            string ios=Run("positive/ios",null,2,2,0,0);SearchAndFull(ios,2);
            foreach(int tag in new[]{3,5,6}){
                string draft=Run("positive/desktop-tag"+tag,TestPasscode,2,0,2,0);SearchAndFull(draft,2);
                foreach(var row in Records(draft)){Check(Str(row,"record_kind")=="telegram_desktop_draft"&&Unknown(row,"sender_id")&&Unknown(row,"message_id")&&Unknown(row,"timestamp")&&Unknown(row,"deleted"),"native draft is unsent with unknown sender/message/date/deletion");Check(Str(row,"source_record").Contains("0xffffffffffffff0"+tag),"actual native draft profile tag retained");}
            }
            Run("positive/desktop-tag6","incorrect-synthetic-passcode",0,0,0,0);
            Run("positive/desktop-tag6",null,0,0,0,0);
            Run("positive/desktop-empty-passcode","",2,0,2,0);
            string negative=Run("controls",TestPasscode,2,2,0,0);
            Check(Records(negative).All(r=>Str(r,"record_kind")=="telegram_ios29_message"&&Unknown(r,"sender_id")),"all unsupported/corrupt controls stay unattributed; only two original missing-author iOS rows survive");
            foreach(string platform in new[]{"android","ios"}){
                string previous=Run("wal/"+platform,null,1,platform=="ios"?1:0,0,platform=="android"?1:0);
                var row=Records(previous).Single();Check(Str(row,"evidence_kind")=="previous"&&Str(row,"wal_proof")=="all_pages_from_validated_wal"&&Unknown(row,"deleted"),"actual WAL DELETE yields previous checked snapshot, not invented user deletion");
            }
            string imported=Analyze(android,null,3,0,0,3);SearchAndFull(imported,3);
            File.WriteAllText(Path.Combine(work,"receipt.json"),Json.Serialize(new{status="PASS",checks=checks,analyses=analyses,manifest_sha256=ManifestHash,
                helper_sha256=Hash(HelperClient.Executable),app_sha256=Hash(typeof(RecoveryCore).Assembly.Location),harness_sha256=Hash(typeof(TelegramPlatformPortableTests).Assembly.Location),runs=Runs}),new UTF8Encoding(false));
            Console.WriteLine("PASS TelegramPlatformPortable: "+checks+" checks; "+analyses+" actual helper analyses. Native Qt/Java/SQLite corpus, no real profiles/devices.");return 0;
        }catch(Exception error){Console.WriteLine("FAIL TelegramPlatformPortable: "+error.Message);return 1;}
        finally{if(stop!=null)stop.Dispose();}
    }
}
