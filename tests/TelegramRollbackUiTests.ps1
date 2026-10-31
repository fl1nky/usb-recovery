# Controlled source WinForms/protocol test. Uses owned fake helper/archives only.
# No screenshots, personal profiles, device access, production build or network.
[CmdletBinding()]
param([string]$TestDirectory='')
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
if(-not$TestDirectory){$TestDirectory=Join-Path $taskRoot ('.build\telegram-rollback-ui-'+[Guid]::NewGuid().ToString('N'))}
$taskOut=[IO.Path]::GetFullPath($TestDirectory)
if(Test-Path -LiteralPath $taskOut){throw 'Test output already exists; choose a fresh directory.'}
for($taskParent=[IO.DirectoryInfo]$taskOut;$null-ne$taskParent;$taskParent=$taskParent.Parent){
    if($taskParent.Exists-and($taskParent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Linked test output is not allowed.'}
}
$taskWorker=Join-Path $taskOut 'tools\recovery-helper'
$null=New-Item -ItemType Directory -Force -Path $taskWorker
$taskUtf8=[Text.UTF8Encoding]::new($true)
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskRelative=@('src\Recovery\UI\ArchiveSearchPanel.cs','src\Recovery\UI\ArchiveMessageTextForm.cs','src\Recovery\Infrastructure\HelperClient.cs','src\Recovery\Infrastructure\ApplicationPaths.cs','src\Recovery\UI\Controls\UiTheme.cs','src\Recovery\UI\Controls\ModernControls.cs','src\Recovery\UI\Controls\RecoveryMotion.cs')
function Get-SourceBinding{
    $taskEntries=[ordered]@{}
    foreach($taskRelativeName in $taskRelative){$taskFile=Join-Path $taskRoot $taskRelativeName;$taskEntries[$taskRelativeName]=(Get-FileHash -LiteralPath $taskFile -Algorithm SHA256).Hash.ToLowerInvariant()}
    return $taskEntries
}
$taskBefore=Get-SourceBinding
$taskFixtureSource=@'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;
public static class OwnedRollbackFixture
{
    public static int Main()
    {
        Console.InputEncoding=Encoding.UTF8;Console.OutputEncoding=new UTF8Encoding(false);
        var json=new JavaScriptSerializer{MaxJsonLength=4*1024*1024};
        var request=json.Deserialize<Dictionary<string,object>>(Console.ReadLine());
        string root=Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"..","..","fixtures"))+Path.DirectorySeparatorChar;
        string archive=Path.GetFullPath(Convert.ToString(request["archive"]));
        if(!archive.StartsWith(root,StringComparison.OrdinalIgnoreCase)||Convert.ToString(request["operation"])!="search"||Convert.ToString(request["app"])!="Telegram")return 2;
        var response=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(archive,"response.json"),Encoding.UTF8));
        response["offset"]=request["offset"];response["archive"]=archive;
        Console.WriteLine(json.Serialize(response));return 0;
    }
}
'@
[IO.File]::WriteAllText((Join-Path $taskOut 'OwnedRollbackFixture.cs'),$taskFixtureSource,$taskUtf8)
$taskTestSource=@'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using UsbRecovery;
public static class TelegramRollbackUiTests
{
    static readonly List<string> passed=new List<string>(),failed=new List<string>();
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=4*1024*1024};
    static readonly string JournalHash=new string('a',64),SnapshotHash=new string('b',64),MapHash=new string('c',64);
    static string Root{get{return AppDomain.CurrentDomain.BaseDirectory;}}
    static void Check(bool ok,string label){(ok?passed:failed).Add(label);Console.WriteLine((ok?"PASS: ":"FAIL: ")+label);}
    static T Field<T>(object owner,string name) where T:class{return (T)owner.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(owner);}
    static void Pump(){for(int index=0;index<4;index++){Application.DoEvents();Thread.Sleep(5);}}
    sealed class Host:Form{protected override bool ShowWithoutActivation{get{return true;}}}
    static Dictionary<string,object> Record(bool full,bool overflow)
    {
        var value=new Dictionary<string,object>{
            {"app","Telegram"},{"text","Owned recipe \ud83e\udd67\nДве ложки масла"},{"evidence_kind",full?"backup":"fragment"},
            {"record_kind",full?"tl_message":"typed_tl_fragment"},{"application_confirmed",true},
            {"chat_id",full?(object)77:null},{"message_id",full?(object)21:null},{"sender_id",full?"user:77":null},
            {"timestamp",full?"2026-01-01T00:00:00+00:00":null},{"deleted",null},
            {"snapshot_id","rollback:"+JournalHash},{"source_file","owned-copy/cache4.db-journal"},
            {"source_record","rollback-journal:page=21;record=512"},{"source_sha256",JournalHash},
            {"rollback_journal_sha256",JournalHash},{"rollback_snapshot_sha256",full?SnapshotHash:null},
            {"rollback_proof",full?"all_pages_from_validated_rollback_journal":overflow?"validated_rollback_payload_chain":"validated_rollback_page_fragment"},
            {"rollback_page_map","provenance/rollback/"+JournalHash+".json"},{"rollback_page_map_sha256",MapHash},
            {"rollback_hot_state","unknown"},{"rollback_current_state_confirmed",false},
            {"rollback_checksum_kind","sqlite_sparse_32bit"},{"rollback_content_authenticity_verified",false},
            {"rollback_parse_status","complete"},{"rollback_tail_reason",null},{"rollback_initial_pages",full?4:93},
            {"rollback_validated_prefix_bytes",3600},{"rollback_header_offset",0},{"rollback_record_offset",512},{"rollback_page",full?3:21},
            {"rollback_payload_chain_verified",overflow?(object)true:null},{"rollback_payload_length",overflow?(object)9268:null},
            {"rollback_payload_sha256",overflow?new string('d',64):null},
            {"rollback_payload_ranges",overflow?Ranges():null},
            {"candidate_message_id",21},{"candidate_peer",77},{"candidate_sender","user:77"},{"candidate_date",1767225600},
            {"sqlite_page",21},{"physical_byte_offset",516},{"physical_source","rollback_journal"},{"proof","Validated owned before-image pages"}
        };
        return value;
    }
    static Dictionary<string,object>[] Ranges()
    {
        var ranges=new List<Dictionary<string,object>>();int logical=0;
        for(int index=0;index<19;index++){
            int amount=index==0?124:508;
            ranges.Add(new Dictionary<string,object>{{"logical_offset",logical},{"bytes",amount},{"sqlite_page",index==0?21:index+2},{"physical_source","rollback_journal"},{"physical_byte_offset",1000+index*1024}});logical+=amount;
        }
        return ranges.ToArray();
    }
    static string Archive(string name,Dictionary<string,object> record)
    {
        string folder=Path.Combine(Root,"fixtures",name);Directory.CreateDirectory(folder);
        var reply=new Dictionary<string,object>{{"protocol",1},{"type","result"},{"status","complete"},{"code","OK"},
            {"total",1},{"offset",0},{"limit",100},{"warnings",new string[0]},{"records",new[]{record}}};
        File.WriteAllText(Path.Combine(folder,"response.json"),Json.Serialize(reply),new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(folder,"messages.jsonl"),Json.Serialize(record)+"\n",new UTF8Encoding(false));
        return folder;
    }
    static ArchiveSearchResult Search(string folder){return ArchiveSearchService.Search(folder,"Telegram","recipe","",0,CancellationToken.None);}
    static void Reject(string name,Dictionary<string,object> record)
    {
        bool rejected=false;try{Search(Archive("invalid-"+name,record));}catch(IOException){rejected=true;}
        Check(rejected,"inconsistent rollback protocol rejected: "+name);
    }
    static string Display(ArchiveSearchPanel panel,ArchiveSearchResult response)
    {
        typeof(ArchiveSearchPanel).GetMethod("CompleteSearch",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(panel,new object[]{response,0});
        Pump();return Field<TextBox>(panel,"provenance").Text;
    }
    static void Common(ArchiveMessage row,string label)
    {
        Check(row.rollback_journal_sha256==JournalHash&&row.rollback_page_map_sha256==MapHash,label+" journal/map hashes survive protocol");
        Check(row.rollback_hot_state=="unknown"&&row.rollback_current_state_confirmed==false&&row.rollback_content_authenticity_verified==false,label+" unknown hot state and false authenticity/current flags survive protocol");
        Check(row.deleted==null,label+" does not acquire a deleted flag");
    }
    static void Conservative(string details,string label)
    {
        Check(details.Contains("не подтверждает удаление")&&details.Contains("не удостоверяет подлинность"),label+" sparse-checksum and deletion limitations are visible");
        Check(!details.Contains("коммит WAL")&&!details.Contains("WAL frame")&&!details.Contains("горячий журнал"),label+" rollback is not described as committed WAL or known-hot journal");
    }
    [STAThread] public static int Main()
    {
        Console.OutputEncoding=new UTF8Encoding(false);
        try{
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            var partial=Search(Archive("partial",Record(false,false)));
            Check(partial.records.Count==1,"owned child search returns one partial record");Common(partial.records[0],"partial");
            Check(partial.records[0].chat_id==null&&partial.records[0].message_id==null&&partial.records[0].sender_id==null&&partial.records[0].timestamp==null,"partial IDs/author/date remain null despite candidate fields");
            var full=Search(Archive("full",Record(true,false)));Common(full.records[0],"full");
            Check(full.records[0].rollback_snapshot_sha256==SnapshotHash&&Convert.ToInt64(full.records[0].rollback_initial_pages)==4,"full snapshot hash/page count survive protocol");
            var overflow=Search(Archive("overflow",Record(false,true)));Common(overflow.records[0],"overflow");
            Check(overflow.records[0].rollback_payload_chain_verified==true&&Convert.ToInt64(overflow.records[0].rollback_payload_length)==9268&&overflow.records[0].rollback_payload_ranges.Length==19,"overflow proof, length and physical ranges survive protocol");
            using(var host=new Host{ClientSize=new Size(1000,800),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000)})
            using(var panel=new ArchiveSearchPanel()){
                host.Controls.Add(panel);host.Show();Pump();
                var grid=Field<DataGridView>(panel,"grid");string details=Display(panel,partial);
                Check(Convert.ToString(grid.Rows[0].Cells["chat"].Value)=="Чат неизвестен"&&Convert.ToString(grid.Rows[0].Cells["author"].Value)=="Автор неизвестен"&&Convert.ToString(grid.Rows[0].Cells["date"].Value)=="Дата неизвестна","partial grid retains explicit unknown labels");
                Check(Convert.ToString(grid.Rows[0].Cells["category"].Value)=="Текстовый фрагмент","partial remains in fragment category");
                Check(details.Contains("ID чата: неизвестен")&&details.Contains("ID автора: неизвестен")&&details.Contains("ID сообщения: неизвестен")&&details.Contains("Дата записи: неизвестна"),"partial details do not promote candidate IDs/date");
                Check(details.Contains("Чат, автор и дата не установлены")&&!details.Contains("все исходные страницы присутствуют"),"partial wording does not claim a complete snapshot");
                Check(details.Contains("SHA256 журнала: "+JournalHash)&&details.Contains("Карта исходных байтов: provenance/rollback/"),"partial source hash and relative map location are visible");
                Check(Field<TextBox>(panel,"body").Text=="Owned recipe \ud83e\udd67\r\nДве ложки масла","owned Unicode message remains readable with Windows newlines");Conservative(details,"partial");
                details=Display(panel,full);
                Check(Convert.ToString(grid.Rows[0].Cells["category"].Value)=="Из резервной копии","full snapshot uses backup category rather than deleted label");
                Check(details.Contains("все исходные страницы присутствуют")&&details.Contains("связи записи проверены внутри снимка")&&details.Contains("SHA256 снимка: "+SnapshotHash),"full snapshot clearly describes scope and snapshot hash");Conservative(details,"full");
                details=Display(panel,overflow);
                Check(details.Contains("Текст собран из цепочки сохранившихся страниц журнала")&&details.Contains("не подставлялись из текущей базы"),"overflow explains preserved-chain construction without current DB fill");
                Check(!details.Contains("все исходные страницы присутствуют")&&Convert.ToString(grid.Rows[0].Cells["category"].Value)=="Текстовый фрагмент","overflow proof remains an unattributed partial fragment");Conservative(details,"overflow");
                var tail=Record(false,false);tail["rollback_parse_status"]="validated_prefix";tail["rollback_tail_reason"]="torn_record";
                details=Display(panel,Search(Archive("partial-tail",tail)));
                Check(details.Contains("Журнал прочитан частично: torn_record"),"validated-prefix tail limitation is visible");
                foreach(string field in new[]{"rollback_page_map","source_file","rollback_journal_sha256"}){
                    var huge=Record(false,false);huge[field]=new string('x',250000);bool rejected=false;ArchiveSearchResult response=null;
                    try{response=Search(Archive("oversized-"+field,huge));}catch(IOException){rejected=true;}
                    if(rejected)Check(true,"oversized metadata rejected: "+field);
                    else{details=Display(panel,response);Check(details.Length<=32768,"oversized metadata display bounded: "+field+" (rendered "+details.Length+" chars)");}
                }
                host.Close();
            }
            foreach(string field in new[]{"chat_id","message_id","sender_id","timestamp"}){
                var forged=Record(false,false);forged[field]=field=="timestamp"?(object)"2026-01-01T00:00:00+00:00":77;Reject("partial-promotes-"+field,forged);
            }
            foreach(string field in new[]{"rollback_content_authenticity_verified","rollback_current_state_confirmed"}){
                var forged=Record(false,false);forged[field]=true;Reject("false-confidence-"+field,forged);
            }
            var hot=Record(false,false);hot["rollback_hot_state"]="hot";Reject("known-hot-state",hot);
            var proof=Record(false,false);proof["rollback_proof"]="all_pages_from_validated_rollback_journal";Reject("partial-as-complete-snapshot",proof);
            var overlap=Record(false,true);((Dictionary<string,object>[])overlap["rollback_payload_ranges"])[1]["physical_byte_offset"]=1000;Reject("overlapping-physical-ranges",overlap);
            var length=Record(false,true);length["rollback_payload_length"]=9269;Reject("chain-length-mismatch",length);
        }catch(Exception error){failed.Add("Unhandled controlled UI test failure: "+error);Console.WriteLine(error);}
        var receipt=new{schema=1,status=failed.Count==0?"passed":"failed",scope="Controlled source C# WinForms/protocol/display with owned fake helper and synthetic archives; not portable helper/device acceptance",
            assertions=passed.Count+failed.Count,passed=passed.Count,failures=failed.Count,passed_checks=passed.ToArray(),failed_checks=failed.ToArray(),screenshots_used=false,personal_data_used=false};
        File.WriteAllText(Path.Combine(Root,"ui-receipt.json"),Json.Serialize(receipt),new UTF8Encoding(false));
        Console.WriteLine("Telegram rollback UI: "+receipt.assertions+" checks, "+failed.Count+" failures; controlled source UI only.");return failed.Count==0?0:1;
    }
}
'@
[IO.File]::WriteAllText((Join-Path $taskOut 'TelegramRollbackUiTests.cs'),$taskTestSource,$taskUtf8)
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $taskWorker 'recovery-helper.exe')) (Join-Path $taskOut 'OwnedRollbackFixture.cs')
if($LASTEXITCODE-ne0){throw 'Owned rollback fixture worker build failed.'}
$taskSources=@((Join-Path $taskOut 'TelegramRollbackUiTests.cs'))+@($taskRelative|ForEach-Object{Join-Path $taskRoot $_})
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $taskOut 'TelegramRollbackUiTests.exe')) @taskSources
if($LASTEXITCODE-ne0){throw 'Rollback source UI test build failed.'}
$taskOutput=& (Join-Path $taskOut 'TelegramRollbackUiTests.exe')
$taskExit=$LASTEXITCODE
[IO.File]::WriteAllText((Join-Path $taskOut 'ui-output.log'),($taskOutput-join"`n")+"`n",[Text.UTF8Encoding]::new($false))
$taskAfter=Get-SourceBinding
$taskUnchanged=($taskBefore|ConvertTo-Json -Compress)-ceq($taskAfter|ConvertTo-Json -Compress)
$taskMetadata=[ordered]@{schema=1;scope='Controlled source UI only; no production helper/device acceptance';checked_utc=[DateTime]::UtcNow.ToString('o');output=$taskOut;exit_code=$taskExit;source_unchanged_during_run=$taskUnchanged;source_before=$taskBefore;source_after=$taskAfter;test_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();test_exe_sha256=(Get-FileHash -LiteralPath (Join-Path $taskOut 'TelegramRollbackUiTests.exe') -Algorithm SHA256).Hash.ToLowerInvariant();fake_helper_sha256=(Get-FileHash -LiteralPath (Join-Path $taskWorker 'recovery-helper.exe') -Algorithm SHA256).Hash.ToLowerInvariant();compiler_sha256=(Get-FileHash -LiteralPath $taskCompiler -Algorithm SHA256).Hash.ToLowerInvariant()}
[IO.File]::WriteAllText((Join-Path $taskOut 'run-metadata.json'),($taskMetadata|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
$taskOutput
if(-not$taskUnchanged){throw 'Production source changed during controlled UI check; rerun after freeze.'}
if($taskExit-ne0){throw 'Telegram rollback controlled source UI checks failed; inspect ui-receipt.json.'}
