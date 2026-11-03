using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Own ordinary files only. This tests managed mapping/catalog code, not a helper
// recovery algorithm, physical device, source originality or paid-tool result.
public static class PhotoSourceAliasTests
{
    static int checks;
    static string work;
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static readonly MethodInfo Verify=typeof(FragmentedPhotoRecovery).GetMethod("VerifyMapping",BindingFlags.Static|BindingFlags.NonPublic);
    static readonly MethodInfo Account=typeof(FragmentedPhotoRecovery).GetMethod("AccountAlternates",BindingFlags.Static|BindingFlags.NonPublic);
    sealed class Owned
    {
        public string Root,Image,File;
        public byte[] Bytes;
        public FragmentedPhotoRecovery.Candidate Candidate;
    }
    sealed class CancelOnAliasRead:FileStream
    {
        readonly CancellationTokenSource stop;
        readonly long trigger;
        public CancelOnAliasRead(string path,CancellationTokenSource cancellation,long at):base(path,FileMode.Open,FileAccess.Read,FileShare.Read){stop=cancellation;trigger=at;}
        public override int Read(byte[] buffer,int offset,int count){int result=base.Read(buffer,offset,count);if(Position>=trigger)stop.Cancel();return result;}
    }
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static object Call(MethodInfo method,object[] arguments){try{return method.Invoke(null,arguments);}catch(TargetInvocationException error){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}}
    static string Hash(string file){using(var input=File.OpenRead(file))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string HashBytes(byte[] bytes){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
    static string Fresh(string name){string root=Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);return root;}
    static FragmentedPhotoRecovery.Extent E(long source,long logical,long length){return new FragmentedPhotoRecovery.Extent{ImageOffset=source,LogicalOffset=logical,Length=length};}
    static List<FragmentedPhotoRecovery.Extent> Map(params FragmentedPhotoRecovery.Extent[] ranges){return ranges.ToList();}
    static FragmentedPhotoRecovery.Candidate Clone(FragmentedPhotoRecovery.Candidate candidate){return Json.Deserialize<FragmentedPhotoRecovery.Candidate>(Json.Serialize(candidate));}
    static byte[] ImageBytes(bool jpeg)
    {
        using(var bitmap=new Bitmap(8,4))using(var output=new MemoryStream()){
            for(int y=0;y<bitmap.Height;y++)for(int x=0;x<bitmap.Width;x++)bitmap.SetPixel(x,y,Color.FromArgb(255,x*29,y*53,(x+y)*19));
            bitmap.Save(output,jpeg?ImageFormat.Jpeg:ImageFormat.Png);return output.ToArray();
        }
    }
    static Owned Fixture(string name,bool jpeg=false)
    {
        string folder=Fresh(name),root=Path.Combine(folder,"result");Directory.CreateDirectory(Path.Combine(root,"fragmented-photos"));byte[] png=ImageBytes(jpeg),image=new byte[65536];
        var candidate=new FragmentedPhotoRecovery.Candidate{Bytes=png.Length,Sha256=HashBytes(png),Status="png_crc_zlib_reassembled_candidate",Note="Owned synthetic physical aliases",Extents=Map(E(512,0,32),E(8192,32,png.Length-32)),AlternateExtents=new List<List<FragmentedPhotoRecovery.Extent>>{Map(E(16384,0,png.Length)),Map(E(24576,0,17),E(32768,17,png.Length-17))}};
        candidate.Path="fragmented-photos/"+(jpeg?"jpeg-":"png-")+candidate.Sha256+(jpeg?".jpg":".png");
        foreach(var map in new[]{candidate.Extents}.Concat(candidate.AlternateExtents))foreach(var extent in map)Buffer.BlockCopy(png,(int)extent.LogicalOffset,image,(int)extent.ImageOffset,(int)extent.Length);
        string source=Path.Combine(folder,"source.dd"),file=RecoveryCatalog.SafeFile(root,candidate.Path);File.WriteAllBytes(source,image);File.WriteAllBytes(file,png);
        RecoveryCore.SaveJson(Path.Combine(root,RecoverySession.FileName),new{Schema=1,SourcePath=source,SourceBytes=image.Length,SourceSha256=Hash(source)});
        return new Owned{Root=root,Image=source,File=file,Bytes=png,Candidate=candidate};
    }
    static void Replay(Owned fixture,FragmentedPhotoRecovery.Candidate candidate=null,CancellationToken? token=null)
    {
        using(var source=new FileStream(fixture.Image,FileMode.Open,FileAccess.Read,FileShare.Read))Call(Verify,new object[]{source,fixture.File,candidate??fixture.Candidate,token??CancellationToken.None});
    }
    static bool Rejected(Action action,string message=null)
    {
        try{action();return false;}catch(IOException error){return message==null||error.Message.Contains(message);}
    }
    static void InvalidMappings()
    {
        var fixture=Fixture("mapping");string before=Hash(fixture.Image),output=Hash(fixture.File);Replay(fixture);Check(Hash(fixture.Image)==before&&Hash(fixture.File)==output,"all three maps replay unchanged source and output bytes");
        var legacyRow=Json.Deserialize<Dictionary<string,object>>(Json.Serialize(fixture.Candidate));legacyRow.Remove("AlternateExtents");var legacy=Json.Deserialize<FragmentedPhotoRecovery.Candidate>(Json.Serialize(legacyRow));Replay(fixture,legacy);Check(legacy.AlternateExtents!=null&&legacy.AlternateExtents.Count==0,"genuinely absent optional JSON field retains the initialized empty list and legacy primary map");
        var nullAliases=Clone(fixture.Candidate);nullAliases.AlternateExtents=null;Check(Rejected(()=>Replay(fixture,nullAliases)),"explicit null aliases are invalid rather than silently treated as an absent optional field");
        var modes=new Dictionary<string,Action<FragmentedPhotoRecovery.Candidate>>{
            {"exact primary duplicate",candidate=>candidate.AlternateExtents= new List<List<FragmentedPhotoRecovery.Extent>>{candidate.Extents}},
            {"partitioned primary duplicate",candidate=>candidate.AlternateExtents=new List<List<FragmentedPhotoRecovery.Extent>>{Map(E(512,0,16),E(528,16,16),E(8192,32,candidate.Bytes-32))}},
            {"partitioned alternate duplicate",candidate=>candidate.AlternateExtents.Add(Map(E(16384,0,31),E(16415,31,candidate.Bytes-31)))},
            {"empty alternate",candidate=>candidate.AlternateExtents.Add(new List<FragmentedPhotoRecovery.Extent>())},
            {"null alternate",candidate=>candidate.AlternateExtents.Add(null)},
            {"logical gap",candidate=>candidate.AlternateExtents[0][0].LogicalOffset=1},
            {"omitted suffix",candidate=>candidate.AlternateExtents[0][0].Length--},
            {"negative physical offset",candidate=>candidate.AlternateExtents[0][0].ImageOffset=-1},
            {"outside image",candidate=>candidate.AlternateExtents[0][0].ImageOffset=new FileInfo(fixture.Image).Length-1},
            {"physical overlap",candidate=>candidate.AlternateExtents[1][1].ImageOffset=24584},
            {"zero extent",candidate=>candidate.AlternateExtents[0][0].Length=0},
            {"oversize extent",candidate=>candidate.AlternateExtents[0][0].Length=Int64.MaxValue},
            {"wrong file SHA",candidate=>candidate.Sha256=new string('0',64)}
        };
        foreach(var mode in modes){var changed=Clone(fixture.Candidate);mode.Value(changed);Check(Rejected(()=>Replay(fixture,changed)),mode.Key+" cannot verify as a valid physical placement");}
        var tampered=Fixture("tampered-alias");byte[] bytes=File.ReadAllBytes(tampered.Image);bytes[16384+10]^=64;File.WriteAllBytes(tampered.Image,bytes);Check(Rejected(()=>Replay(tampered)),"an alias with correct geometry but wrong source bytes is replayed and rejected");
        tampered=Fixture("tampered-output");bytes=File.ReadAllBytes(tampered.File);bytes[20]^=1;File.WriteAllBytes(tampered.File,bytes);Check(Rejected(()=>Replay(tampered)),"changed output bytes fail SHA instead of inheriting source-map proof");
        Check(Hash(fixture.Image)==before&&Hash(fixture.File)==output,"all invalid report controls preserve the original tested files");
    }
    static void Limits()
    {
        var fixture=Fixture("limits");var tooMany=Clone(fixture.Candidate);tooMany.AlternateExtents=Enumerable.Range(0,512).Select(index=>Map(E(16384,0,tooMany.Bytes))).ToList();Check(Rejected(()=>Replay(fixture,tooMany),"лимит дополнительных"),"more than511 alternate maps fail the explicit report bound");
        var tooManyExtents=Clone(fixture.Candidate);tooManyExtents.AlternateExtents=new List<List<FragmentedPhotoRecovery.Extent>>{Enumerable.Repeat(E(16384,0,1),100001).ToList()};Check(Rejected(()=>Replay(fixture,tooManyExtents),"лимит участков"),"more than100000 alias extents fail before replay");
        var budget=new FragmentedPhotoRecovery.Candidate{Bytes=64L*1024*1024,AlternateExtents=Enumerable.Range(0,8).Select(index=>Map(E(index,0,1))).ToList()};object[] counters={budget,0L,0};Call(Account,counters);Check((long)counters[1]==512L*1024*1024&&(int)counters[2]==8,"alias replay accounting accepts exactly512MiB across candidates");
        var next=new FragmentedPhotoRecovery.Candidate{Bytes=1,AlternateExtents=new List<List<FragmentedPhotoRecovery.Extent>>{Map(E(0,0,1))}};object[] extra={next,counters[1],counters[2]};Check(Rejected(()=>Call(Account,extra),"лимит дополнительных"),"global replay budget cannot reset for the next file");
        budget=new FragmentedPhotoRecovery.Candidate{Bytes=1,AlternateExtents=new List<List<FragmentedPhotoRecovery.Extent>>{Enumerable.Repeat(E(0,0,1),100000).ToList()}};counters=new object[]{budget,0L,0};Call(Account,counters);extra=new object[]{next,counters[1],counters[2]};Check((int)counters[2]==100000&&Rejected(()=>Call(Account,extra),"лимит участков"),"global extent budget cannot reset for the next file");
        string root=Fresh("max-map-count");byte[] plain=new byte[128],image=new byte[131072];string source=Path.Combine(root,"source.dd"),file=Path.Combine(root,"candidate.bin");File.WriteAllBytes(source,image);File.WriteAllBytes(file,plain);
        var candidate=new FragmentedPhotoRecovery.Candidate{Bytes=plain.Length,Sha256=HashBytes(plain),Extents=Map(E(0,0,64),E(128,64,64)),AlternateExtents=Enumerable.Range(0,511).Select(index=>Map(E(512+index*128,0,128))).ToList()};
        using(var stream=File.OpenRead(source))Call(Verify,new object[]{stream,file,candidate,CancellationToken.None});Check(candidate.AlternateExtents.Count==511,"all511 genuinely distinct physical aliases are replayed without pruning");
    }
    static void Cancellation()
    {
        var fixture=Fixture("cancel");var stop=new CancellationTokenSource();stop.Cancel();bool cancelled=false;
        try{Replay(fixture,null,stop.Token);}catch(OperationCanceledException){cancelled=true;}Check(cancelled,"pre-cancellation is observed before candidate validation");
        stop=new CancellationTokenSource();var candidate=Clone(fixture.Candidate);candidate.AlternateExtents.RemoveAt(1);cancelled=false;
        using(var source=new CancelOnAliasRead(fixture.Image,stop,16384))try{Call(Verify,new object[]{source,fixture.File,candidate,stop.Token});}catch(OperationCanceledException){cancelled=true;}
        Check(cancelled&&stop.IsCancellationRequested,"cancellation during the final alternate read cannot return successful verification");
    }
    static void Manifest(Owned fixture)
    {
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"fragmented-photo-search.json"),new FragmentedPhotoRecovery.Report{Schema=1,Candidates=1,Files=new List<FragmentedPhotoRecovery.Candidate>{fixture.Candidate},Status="complete",SourceSha256=Hash(fixture.Image),SourceUnchanged=true,OutputBytes=fixture.Candidate.Bytes});
    }
    static long Physical(List<FragmentedPhotoRecovery.Extent> map,long logical)
    {
        var extent=map.Single(value=>value.LogicalOffset<=logical&&logical<value.LogicalOffset+value.Length);return extent.ImageOffset+logical-extent.LogicalOffset;
    }
    static void Errors(Owned fixture,params long[] offsets)
    {
        var ranges=offsets.Distinct().Select(offset=>new FileExtent{Offset=offset,Length=1}).ToArray();
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"source-read-errors.json"),new{status="complete_with_read_errors",size=new FileInfo(fixture.Image).Length,copied=new FileInfo(fixture.Image).Length,unreadBytes=ranges.Length,ranges=ranges});
    }
    static RecoveredItem Item(Owned fixture,string quality="unverified")
    {return new RecoveredItem{Path=fixture.Candidate.Path,Sha256=fixture.Candidate.Sha256,Bytes=fixture.Candidate.Bytes,Quality=quality,QualityLabel="existing specific finding",IntegrityDetail="Independent content finding.",Note="",Status=""};}
    static IEnumerable<Dictionary<string,object>> Rows(object value){return ((IEnumerable)value).Cast<Dictionary<string,object>>();}
    static void CatalogAndExport()
    {
        var fixture=Fixture("catalog");Manifest(fixture);Replay(fixture);string sourceBefore=Hash(fixture.Image),outputBefore=Hash(fixture.File);var index=RecoveryCatalog.Build(fixture.Root,CancellationToken.None,null);var item=index.Items.Single();
        Check(item.SourceOffset==null&&item.SourceRanges.Count==2&&item.SourceRangeAlternatives.Count==2&&item.Quality=="structural_candidate"&&item.Status!="Неоднозначная сборка","byte-identical aliases preserve the primary witness and both alternatives without claiming a different image variant");
        Check(item.IntegrityDetail.Contains("карт размещения одинаковых байтов: 3")&&item.IntegrityDetail.Contains("Исходное размещение неизвестно"),"Russian provenance explains the count and unknown original placement");
        var loaded=RecoveryCatalog.Load(fixture.Root).Items.Single();Check(loaded.SourceRangeAlternatives.Count==2&&loaded.SourceRangeAlternatives[0].Single().Offset==16384,"saved catalog retains all alternate ranges");
        string exported=RecoveryCatalog.Export(fixture.Root,Fresh("export"),new[]{loaded},CancellationToken.None);var report=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(exported,"export-manifest.json")));var row=Rows(report["files"]).Single();
        Check(row["sourceOffset"]==null&&((IEnumerable)row["sourceRangeAlternatives"]).Cast<object>().Count()==2&&Rows(row["sourceMapGroups"]).Count()==1,"export manifest includes alternatives/source groups and never invents one source offset");
        Check(Hash(fixture.Image)==sourceBefore&&Hash(fixture.File)==outputBefore,"catalog, reload and export leave source and recovered candidate unchanged");
        var evidence=FileEvidence.Load(fixture.Root);evidence.Apply(loaded);evidence.Apply(loaded);Check(loaded.SourceRangeAlternatives.Count==2&&loaded.SourceMapGroups.Count==1,"repeated evidence application does not accumulate alternate maps/groups");loaded.Sha256=new string('0',64);evidence.Apply(loaded);Check(loaded.SourceRanges.Count==0&&loaded.SourceRangeAlternatives.Count==0&&loaded.SourceMapGroups.Count==0&&loaded.SourceOffset==null&&loaded.UnreadBytes==null&&loaded.SourceCandidatePath==null,"changed file identity clears every old alias/group claim");
        File.AppendAllText(fixture.File,"changed after extraction");var changed=RecoveryCatalog.Build(fixture.Root,CancellationToken.None,null).Items.Single();Check(changed.Quality=="changed"&&changed.SourceRanges.Count==0&&changed.SourceRangeAlternatives.Count==0&&changed.SourceOffset==null,"actual changed output cannot inherit alias provenance through catalog rebuild");
    }
    static void ReadErrorAgreement()
    {
        foreach(string mode in new[]{"all-clean","all-same","different-counts","different-logical-positions"}){
            var fixture=Fixture(mode);Check(fixture.Bytes[8]==0&&fixture.Bytes[9]==0,"synthetic unread-map controls select actual zero-valued PNG bytes");Manifest(fixture);var maps=new[]{fixture.Candidate.Extents}.Concat(fixture.Candidate.AlternateExtents).ToList();
            if(mode=="all-clean")Errors(fixture,0);
            else if(mode=="all-same")Errors(fixture,maps.Select(map=>Physical(map,8)).ToArray());
            else if(mode=="different-counts")Errors(fixture,Physical(maps[0],8));
            else Errors(fixture,Physical(maps[0],8),Physical(maps[1],9),Physical(maps[2],9));
            var evidence=FileEvidence.Load(fixture.Root);var item=Item(fixture);evidence.Apply(item);
            if(mode=="all-clean")Check(item.UnreadBytes==0&&item.SourceOffset==null,"every alias agrees on zero mapped unread bytes without choosing a source placement");
            else if(mode=="all-same"){
                Check(item.UnreadBytes==1&&item.Quality=="read_errors","all aliases agree on the same logical unread interval");
                foreach(string quality in new[]{"partial","damaged","changed","read_errors","encrypted","mapping_unknown"}){item=Item(fixture,quality);evidence.Apply(item);Check(item.Quality==quality&&item.QualityLabel=="existing specific finding"&&item.UnreadBytes==1,"alias error agreement preserves existing "+quality+" findings");}
            }else Check(item.UnreadBytes==null&&item.SourceOffset==null&&item.IntegrityDetail.Contains("по-разному пересекают карту ошибок")&&item.Quality!="read_errors","disagreement keeps unknown unread bytes, including equal counts at different logical positions");
        }
    }
    static void ReaderValidationAndDuplicates()
    {
        var fixture=Fixture("reader-invalid");fixture.Candidate.AlternateExtents.Add(Map(E(512,0,16),E(528,16,16),E(8192,32,fixture.Candidate.Bytes-32)));Manifest(fixture);var proof=FileEvidence.Load(fixture.Root).For(fixture.Candidate.Path);
        Check(proof!=null&&!proof.MappingComplete&&proof.Ranges.Count==0&&proof.SourceRangeAlternatives.Count==0&&proof.Offset==null,"catalog reader rejects a canonically duplicated map instead of publishing incomplete alternatives");
        fixture=Fixture("reader-bounds");fixture.Candidate.AlternateExtents[0][0].ImageOffset=65536;Manifest(fixture);proof=FileEvidence.Load(fixture.Root).For(fixture.Candidate.Path);Check(proof!=null&&!proof.MappingComplete&&proof.SourceRangeAlternatives.Count==0,"catalog reader also checks aliases against bound session source length");
        fixture=Fixture("dedup-provenance");Manifest(fixture);string copy="filesystem/files/same.png",path=RecoveryCatalog.SafeFile(fixture.Root,copy);Directory.CreateDirectory(Path.GetDirectoryName(path));File.Copy(fixture.File,path);
        File.WriteAllText(Path.Combine(fixture.Root,"filesystem/file-extents.jsonl"),Json.Serialize(new{path=copy,sha256=fixture.Candidate.Sha256,bytes=fixture.Candidate.Bytes,mappingComplete=true,status="owned",ranges=new[]{new FileExtent{Offset=16384,Length=fixture.Candidate.Bytes}}})+Environment.NewLine);
        var item=RecoveryCatalog.Build(fixture.Root,CancellationToken.None,null).Items.Single();Check(item.Copies.Count==1&&item.SourceRangeAlternatives.Count==2&&item.SourceMapGroups.Count==2&&item.SourceOffset==null&&item.SourceMapGroups.Any(group=>group.SourceCandidatePath==fixture.Candidate.Path),"content dedup cannot hide alternate maps behind a different preferred clean witness");
        fixture=Fixture("reader-null");fixture.Candidate.AlternateExtents=null;Manifest(fixture);proof=FileEvidence.Load(fixture.Root).For(fixture.Candidate.Path);Check(proof!=null&&!proof.MappingComplete&&proof.Ranges.Count==0&&proof.SourceRangeAlternatives.Count==0&&proof.Offset==null,"explicit null catalog aliases invalidate every map claim");
        fixture=Fixture("reader-legacy-absent");Manifest(fixture);string manifestPath=Path.Combine(fixture.Root,"fragmented-photo-search.json");var legacyReport=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(manifestPath));Rows(legacyReport["Files"]).Single().Remove("AlternateExtents");RecoveryCore.SaveJson(manifestPath,legacyReport);proof=FileEvidence.Load(fixture.Root).For(fixture.Candidate.Path);Check(proof!=null&&proof.MappingComplete&&proof.Ranges.Count==2&&proof.SourceRangeAlternatives.Count==0&&proof.Offset==512,"actual missing catalog field preserves the legacy primary map");
        fixture=Fixture("legacy-jpeg",true);fixture.Candidate.Status="jpeg_gap_ambiguous_candidate";fixture.Candidate.AlternateExtents=new List<List<FragmentedPhotoRecovery.Extent>>();Manifest(fixture);item=Item(fixture);FileEvidence.Load(fixture.Root).Apply(item);Check(item.Quality=="ambiguous_candidate"&&item.Status=="Неоднозначная сборка"&&item.SourceRangeAlternatives.Count==0&&item.SourceOffset==512,"legacy JPEG ambiguity metadata and basic source map semantics remain unchanged");
    }
    static Owned History(Owned current,bool foreign=false,bool unknown=false)
    {
        var candidate=Clone(current.Candidate);candidate.Extents=Map(E(40960,0,47),E(49152,47,candidate.Bytes-47));candidate.AlternateExtents=new List<List<FragmentedPhotoRecovery.Extent>>{Map(E(57344,0,candidate.Bytes))};
        byte[] image=File.ReadAllBytes(current.Image);foreach(var map in new[]{candidate.Extents}.Concat(candidate.AlternateExtents))foreach(var extent in map)Buffer.BlockCopy(current.Bytes,(int)extent.LogicalOffset,image,(int)extent.ImageOffset,(int)extent.Length);
        File.WriteAllBytes(current.Image,image);RecoveryCore.SaveJson(Path.Combine(current.Root,RecoverySession.FileName),new{Schema=1,SourcePath=current.Image,SourceSha256=Hash(current.Image),SourceBytes=image.Length});Manifest(current);
        string root=Path.Combine(current.Root,"attempt-history","prior"),source=current.Image;
        if(foreign){source=Path.Combine(Fresh("foreign-image"),"source.dd");image[65535]^=1;File.WriteAllBytes(source,image);}
        string file=RecoveryCatalog.SafeFile(root,candidate.Path);Directory.CreateDirectory(Path.GetDirectoryName(file));File.WriteAllBytes(file,current.Bytes);
        if(!unknown)RecoveryCore.SaveJson(Path.Combine(root,RecoverySession.FileName),new{Schema=1,SourcePath=source,SourceSha256=Hash(source),SourceBytes=image.Length});
        var history=new Owned{Root=root,Image=source,File=file,Bytes=current.Bytes,Candidate=candidate};Manifest(history);Replay(history);return history;
    }
    static void SourceScopedGroups()
    {
        var current=Fixture("same-source-history");var history=History(current);Replay(current);var item=RecoveryCatalog.Build(current.Root,CancellationToken.None,null).Items.Single();
        Check(item.SourceMapGroups.Count==2&&item.SourceMapGroups.All(group=>group.SourceScopeVerified&&group.MappingComplete&&group.SourceSha256==Hash(current.Image)&&group.SourceBytes==65536),"both current and history carriers retain their verified equal source-image scope");
        Check(item.SourceRangeAlternatives.Count==4&&item.SourceOffset==null&&item.SourceMapGroups.SelectMany(group=>group.Maps).Count()==5,"same-source canonical union retains all five distinct maps from both alias-bearing origins");
        Check(item.SourceMapGroups.Any(group=>group.SourceCandidatePath.StartsWith("attempt-history/prior/",StringComparison.Ordinal)),"history group keeps its explicit relative origin path");
        var maps=new[]{current.Candidate.Extents}.Concat(current.Candidate.AlternateExtents).Concat(new[]{history.Candidate.Extents}).Concat(history.Candidate.AlternateExtents);Errors(current,maps.Select(map=>Physical(map,8)).ToArray());var evidence=FileEvidence.Load(current.Root);evidence.Apply(item);Check(item.UnreadBytes==1,"read errors are compared across every current/history map in the same source scope");
        string exported=RecoveryCatalog.Export(current.Root,Fresh("group-export"),new[]{item},CancellationToken.None);var report=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(exported,"export-manifest.json")));var groups=Rows(Rows(report["files"]).Single()["sourceMapGroups"]).ToList();Check(groups.Count==2&&groups.All(group=>(bool)group["SourceScopeVerified"]&&Convert.ToString(group["SourceSha256"])==Hash(current.Image)),"export preserves every origin group and verified source identity");
        current=Fixture("different-source-history");history=History(current,true);Errors(current,Physical(current.Candidate.Extents,8));item=RecoveryCatalog.Build(current.Root,CancellationToken.None,null).Items.Single();Check(item.SourceMapGroups.Count==2&&item.SourceMapGroups.All(group=>group.SourceScopeVerified)&&item.SourceMapGroups.Select(group=>group.SourceSha256).Distinct().Count()==2,"different image hashes remain separate known source groups despite identical file bytes");Check(item.SourceRangeAlternatives.Count+1==item.SourceMapGroups.Single(group=>group.SourceCandidatePath==item.SourceCandidatePath).Maps.Count&&item.SourceOffset==null&&item.UnreadBytes==null,"foreign offsets are not merged and current read errors are not applied to another image");
        current=Fixture("unknown-source-history");history=History(current,false,true);Errors(current,Physical(current.Candidate.Extents,8));item=RecoveryCatalog.Build(current.Root,CancellationToken.None,null).Items.Single();Check(item.SourceMapGroups.Count==2&&item.SourceMapGroups.Count(group=>group.SourceScopeVerified)==1&&item.SourceMapGroups.Single(group=>!group.SourceScopeVerified).SourceBytes==null,"missing history source binding remains unknown instead of borrowing the current session");Check(item.SourceRangeAlternatives.Count+1==item.SourceMapGroups.Single(group=>group.SourceCandidatePath==item.SourceCandidatePath).Maps.Count&&item.UnreadBytes==null&&item.SourceOffset==null,"unknown source groups retain their own maps without cross-source merging or read-error attribution");
        current=Fixture("ambiguous-and-aliases",true);current.Candidate.Status="jpeg_restart_structural_candidate";history=History(current);history.Candidate.Status="jpeg_gap_ambiguous_candidate";Manifest(history);item=RecoveryCatalog.Build(current.Root,CancellationToken.None,null).Items.Single();Check(item.Quality=="ambiguous_candidate"&&item.Status=="Неоднозначная сборка"&&item.SourceMapGroups.Count==2&&item.SourceRangeAlternatives.Count==4,"weaker JPEG ambiguity survives independently while all maps from both alias carriers remain available");
        current=Fixture("scope-mismatch");Manifest(current);var session=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(current.Root,RecoverySession.FileName)));session["SourceSha256"]=current.Candidate.Sha256;RecoveryCore.SaveJson(Path.Combine(current.Root,RecoverySession.FileName),session);Errors(current,Physical(current.Candidate.Extents,8));item=RecoveryCatalog.Build(current.Root,CancellationToken.None,null).Items.Single();Check(item.SourceMapGroups.Count==1&&!item.SourceMapGroups[0].SourceScopeVerified&&item.UnreadBytes==null,"a file-content hash cannot invent an image scope when report and session hashes disagree");
        foreach(string bad in new[]{"schema-bool","source-bytes-string","unchanged-string"}){
            current=Fixture(bad);Manifest(current);string path=Path.Combine(current.Root,bad=="unchanged-string"?"fragmented-photo-search.json":RecoverySession.FileName);var raw=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path));raw[bad=="schema-bool"?"Schema":bad=="source-bytes-string"?"SourceBytes":"SourceUnchanged"]=bad=="schema-bool"?(object)true:bad=="source-bytes-string"?"65536":"True";RecoveryCore.SaveJson(path,raw);Errors(current,Physical(current.Candidate.Extents,8));item=RecoveryCatalog.Build(current.Root,CancellationToken.None,null).Items.Single();Check(!item.SourceMapGroups.Single().SourceScopeVerified&&item.UnreadBytes==null,"malformed source binding primitive is not promoted to a verified scope: "+bad);
        }
    }
    static void AggregateGroupBudget()
    {
        // Metadata-only resource boundary: no large files or recovery outcome
        // are inferred from these deliberately constructed capacity claims.
        var evidence=FileEvidence.Load(Fresh("aggregate-budget"));long size=64L*1024*1024;var origins=Enumerable.Range(0,9).Select(index=>new EvidenceEntry{Path="owned-"+index,Kind="reassembled_media_candidate",VerifiedBytes=size,VerifiedSha256=new string('b',64),MappingComplete=true,SourceScopeVerified=true,SourceSha256=new string('a',64),SourceBytes=1024L*1024*1024,Ranges=new List<FileExtent>{new FileExtent{Offset=index*size,Length=size}}}).ToList();
        var item=new RecoveredItem{Bytes=size,Sha256=new string('b',64),Quality="partial",QualityLabel="existing problem",IntegrityDetail="",SourceRanges=new List<FileExtent>{new FileExtent{Offset=0,Length=size}}};var apply=typeof(FileEvidence).GetMethod("ApplyMapGroups",BindingFlags.Instance|BindingFlags.NonPublic);
        try{apply.Invoke(evidence,new object[]{item,origins[0],origins});}catch(TargetInvocationException error){ExceptionDispatchInfo.Capture(error.InnerException).Throw();}
        Check(item.SourceMapGroupsLimited&&item.SourceMapGroupsOmitted==1&&item.SourceMapGroups.Count==8,"aggregate budget charges every additional origin's primary map, not just AlternateExtents");
        Check(item.SourceRanges.Count==0&&item.SourceRangeAlternatives.Count==0&&item.SourceOffset==null&&item.UnreadBytes==null&&item.IntegrityDetail.Contains("Перечень карт ограничен")&&item.Quality=="partial","overflow explicitly rejects aggregate flat claims without choosing one map or erasing a known content problem");
    }
    static void LegacySingleOriginReadErrors()
    {
        var fixture=Fixture("legacy-single-origin");File.Delete(Path.Combine(fixture.Root,RecoverySession.FileName));
        string metadata=Path.Combine(fixture.Root,"filesystem");Directory.CreateDirectory(metadata);
        var ranges=new[]{new FileExtent{Offset=512,Length=32},new FileExtent{Offset=8192,Length=fixture.Bytes.Length-32}};
        string manifest=Path.Combine(metadata,"file-extents.jsonl");
        File.WriteAllText(manifest,Json.Serialize(new{path=fixture.Candidate.Path,sha256=fixture.Candidate.Sha256,bytes=fixture.Bytes.Length,mappingComplete=true,status="complete",ranges=ranges}));
        string imageBefore=Hash(fixture.Image),fileBefore=Hash(fixture.File);var item=Item(fixture);
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"source-read-errors.json"),new{unreadBytes=1,ranges=new[]{new FileExtent{Offset=8192+8,Length=1}}});
        FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.SourceMapGroups.Count==1&&item.SourceMapGroups[0].Maps.Count==1&&!item.SourceMapGroups[0].SourceScopeVerified&&item.SourceRangeAlternatives.Count==0,"single local legacy physical map remains unbound without inventing image identity");
        Check(item.UnreadBytes==1&&item.Quality=="read_errors"&&item.IntegrityDetail.Contains("Подтверждено пересечение"),"legacy one-origin metadata retains its exact logical overlap verdict without requiring a new session schema");
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"source-read-errors.json"),new{unreadBytes=1,ranges=new[]{new FileExtent{Offset=8192+fixture.Bytes.Length,Length=1}}});item=Item(fixture);FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.UnreadBytes==0&&item.Quality!="read_errors","legacy single-origin sector slack beyond the file length is excluded");
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"source-read-errors.json"),new{unreadBytes=2,ranges=new[]{new FileExtent{Offset=8192+8,Length=1}}});item=Item(fixture);FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.UnreadBytes==null,"inconsistent legacy error totals still cannot produce an exact mapped verdict");
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"source-read-errors.json"),new{unreadBytes=1,ranges=new[]{new FileExtent{Offset=8192+8,Length=1}}});item=Item(fixture);item.Sha256=new string('f',64);FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.Quality=="changed"&&item.SourceMapGroups.Count==0&&item.SourceRanges.Count==0&&item.UnreadBytes==null,"changed legacy content loses stale maps and never receives a read-error overlap verdict");
        string duplicate=fixture.Candidate.Path.Replace("png-","copy-");File.Copy(fixture.File,RecoveryCatalog.SafeFile(fixture.Root,duplicate));
        File.AppendAllText(manifest,"\n"+Json.Serialize(new{path=duplicate,sha256=fixture.Candidate.Sha256,bytes=fixture.Bytes.Length,mappingComplete=true,status="complete",ranges=ranges}));item=Item(fixture);item.Copies.Add(duplicate);FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.SourceMapGroups.Count==2&&item.SourceOffset==null&&item.UnreadBytes==null,"two unbound legacy origins do not inherit the single-local-map exception");
        string historyRoot=Fresh("legacy-history"),prior=Path.Combine(historyRoot,"attempt-history","prior");Directory.CreateDirectory(Path.Combine(prior,"filesystem"));
        File.Copy(manifest,Path.Combine(prior,"filesystem","file-extents.jsonl"));RecoveryCore.SaveJson(Path.Combine(historyRoot,"source-read-errors.json"),new{unreadBytes=1,ranges=new[]{new FileExtent{Offset=8192+8,Length=1}}});item=Item(fixture);item.Path="attempt-history/prior/"+item.Path;FileEvidence.Load(historyRoot).Apply(item);
        Check(item.SourceMapGroups.Count==1&&!item.SourceMapGroups[0].SourceScopeVerified&&item.UnreadBytes==null,"a single unknown history origin cannot borrow the current error map through the legacy exception");
        Check(Hash(fixture.Image)==imageBefore&&Hash(fixture.File)==fileBefore,"legacy provenance and read-error analysis preserves all source and candidate bytes");
        foreach(bool missing in new[]{false,true}){
            var photo=Fixture(missing?"single-unknown-photo":"single-foreign-photo");photo.Candidate.AlternateExtents.Clear();Manifest(photo);Errors(photo,Physical(photo.Candidate.Extents,8));
            if(missing)File.Delete(Path.Combine(photo.Root,RecoverySession.FileName));else RecoveryCore.SaveJson(Path.Combine(photo.Root,RecoverySession.FileName),new{Schema=1,SourceSha256=new string('f',64),SourceBytes=65536});
            item=Item(photo);FileEvidence.Load(photo.Root).Apply(item);Check(item.SourceMapGroups.Count==1&&item.SourceMapGroups[0].Maps.Count==1&&!item.SourceMapGroups[0].SourceScopeVerified&&item.UnreadBytes==null,"a single explicitly declared photo scope remains strict when "+(missing?"unknown":"foreign"));
        }
    }
    static void QualifiedLegacyLocations()
    {
        // Own metadata qualification controls. Encoded record spans are not
        // plaintext-byte maps; the existing real ZIP suite tests actual recovery.
        var fixture=Fixture("encoded-local-location");File.Delete(Path.Combine(fixture.Root,RecoverySession.FileName));
        var entry=new{Path=fixture.Candidate.Path,HeaderOffset=123,DataOffset=154,CompressedBytes=17,Bytes=fixture.Bytes.Length,Sha256=fixture.Candidate.Sha256,Status="member_crc"};
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"archive-salvage.json"),new{files=new[]{entry}});var item=Item(fixture);FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.SourceOffset==123&&item.SourceRanges.Count==1&&item.SourceRanges[0].Length==48,"one local legacy encoded record retains its qualified header offset and compressed physical span");
        Check(item.SourceMapGroups.Count==1&&!item.SourceMapGroups[0].MappingComplete&&item.SourceRangeAlternatives.Count==0&&item.IntegrityDetail.Contains("закодированной ZIP")&&item.IntegrityDetail.Contains("полная логическая карта содержимого не установлена"),"qualified encoded offset never promotes its compressed span into a complete plaintext map");
        RecoveryCore.SaveJson(Path.Combine(fixture.Root,"source-read-errors.json"),new{unreadBytes=2,ranges=new[]{new FileExtent{Offset=133,Length=2}}});item=Item(fixture);FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.SourceOffset==123&&item.UnreadBytes==2&&item.Quality=="read_errors"&&!item.SourceMapGroups[0].MappingComplete,"known unread header bytes retain the old encoded-record overlap semantics without claiming a complete logical map");
        string history=Fresh("encoded-history-location"),prior=Path.Combine(history,"attempt-history","prior");Directory.CreateDirectory(prior);File.Copy(Path.Combine(fixture.Root,"archive-salvage.json"),Path.Combine(prior,"archive-salvage.json"));RecoveryCore.SaveJson(Path.Combine(history,"source-read-errors.json"),new{unreadBytes=2,ranges=new[]{new FileExtent{Offset=133,Length=2}}});item=Item(fixture);item.Path="attempt-history/prior/"+item.Path;FileEvidence.Load(history).Apply(item);
        Check(item.SourceMapGroups.Count==1&&!item.SourceMapGroups[0].MappingComplete&&item.SourceOffset==null&&item.UnreadBytes==null,"an unknown history encoded span cannot receive the current-local qualified offset or error-map exception");
        string duplicate=fixture.Candidate.Path.Replace("png-","copy-");var other=new{Path=duplicate,HeaderOffset=4096,DataOffset=4127,CompressedBytes=17,Bytes=fixture.Bytes.Length,Sha256=fixture.Candidate.Sha256,Status="member_crc"};RecoveryCore.SaveJson(Path.Combine(fixture.Root,"archive-salvage.json"),new{files=new[]{entry,other}});item=Item(fixture);item.Copies.Add(duplicate);FileEvidence.Load(fixture.Root).Apply(item);
        Check(item.SourceMapGroups.Count==2&&item.SourceOffset==null&&item.UnreadBytes==null,"multiple encoded origins retain separate incomplete groups and do not choose a header as original placement");
    }
    static void MissingMapCarrier()
    {
        foreach(bool photo in new[]{true,false}){
            var fixture=Fixture(photo?"verified-and-unmapped":"legacy-and-unmapped");fixture.Candidate.AlternateExtents.Clear();
            if(photo)Manifest(fixture);else {
                File.Delete(Path.Combine(fixture.Root,RecoverySession.FileName));Directory.CreateDirectory(Path.Combine(fixture.Root,"filesystem"));
                File.WriteAllText(Path.Combine(fixture.Root,"filesystem","file-extents.jsonl"),Json.Serialize(new{path=fixture.Candidate.Path,sha256=fixture.Candidate.Sha256,bytes=fixture.Bytes.Length,mappingComplete=true,ranges=fixture.Candidate.Extents.Select(range=>new FileExtent{Offset=range.ImageOffset,Length=range.Length}).ToArray()}));
            }
            string duplicate="metadata-rescue/files/same-content.bin";Directory.CreateDirectory(Path.GetDirectoryName(RecoveryCatalog.SafeFile(fixture.Root,duplicate)));File.Copy(fixture.File,RecoveryCatalog.SafeFile(fixture.Root,duplicate));
            RecoveryCore.SaveJson(Path.Combine(fixture.Root,"metadata-rescue","report.json"),new{Entries=new[]{new{Output="files/same-content.bin",RecordOffset=49152,RecoveredBytes=fixture.Bytes.Length,Sha256=fixture.Candidate.Sha256,Status="resident_candidate",UsaFixupsRestored=true}}});Errors(fixture,Physical(fixture.Candidate.Extents,8));var item=Item(fixture,"partial");item.Copies.Add(duplicate);FileEvidence.Load(fixture.Root).Apply(item);
            Check(item.Copies.Contains(duplicate)&&item.SourceMapGroups.Count==1&&item.SourceMapGroups[0].Maps.Count==1&&item.SourceOffset==null&&item.UnreadBytes==null,"one mapped carrier plus a confirmed matching no-map copy cannot assert original placement or whole-file error agreement: "+photo);
            Check(item.Quality=="partial"&&item.QualityLabel=="existing specific finding"&&!item.SourceMapGroupsLimited&&item.SourceMapGroupsOmitted==0&&item.IntegrityDetail.Contains("Источников без физической карты: 1"),"missing map is explicitly explained without being invented, classified as budget truncation or erasing known damage: "+photo);
        }
    }
    static void EqualLengthEncodedZipWitness()
    {
        // Standard raw DEFLATE for37 zero bytes (stdlib zlib, default settings):
        // 63 60 20 02 00 00, CRC32=24d17f64. Header31 + compressed6 == plain37.
        // Geometry equality cannot turn ZIP header/compressed bytes into plaintext.
        byte[] payload=new byte[37],packed={0x63,0x60,0x20,0x02,0x00,0x00};
        using(var input=new MemoryStream(packed))using(var deflate=new DeflateStream(input,CompressionMode.Decompress))using(var decoded=new MemoryStream()){
            deflate.CopyTo(decoded);Check(decoded.ToArray().SequenceEqual(payload),"equal-length ZIP witness independently inflates six raw DEFLATE bytes to the exact37 zero bytes");
        }
        uint crc=0xffffffff;foreach(byte value in payload){crc^=value;for(int bit=0;bit<8;bit++)crc=(crc>>1)^((crc&1)!=0?0xedb88320U:0);}crc^=0xffffffff;
        Check(crc==0x24d17f64U,"equal-length ZIP witness has the independently pinned standard CRC32");
        byte[] zip;using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)){
            Action<ushort> u16=writer.Write;Action<uint> u32=writer.Write;
            u32(0x04034b50);u16(20);u16(0);u16(8);u16(0);u16(0x21);u32(crc);u32(6);u32(37);u16(1);u16(0);writer.Write((byte)'a');writer.Write(packed);
            long central=stream.Position;u32(0x02014b50);u16(20);u16(20);u16(0);u16(8);u16(0);u16(0x21);u32(crc);u32(6);u32(37);u16(1);u16(0);u16(0);u16(0);u16(0);u32(0);u32(0);writer.Write((byte)'a');
            uint centralBytes=(uint)(stream.Position-central);u32(0x06054b50);u16(0);u16(0);u16(1);u16(1);u32(centralBytes);u32((uint)central);u16(0);writer.Flush();zip=stream.ToArray();
        }
        Check(zip.Length==106&&31+packed.Length==payload.Length&&!zip.Take(payload.Length).SequenceEqual(payload),"valid complete ZIP has equal encoded/plain lengths with demonstrably different byte contents");
        string folder=Fresh("equal-length-valid-zip"),image=Path.Combine(folder,"source.zip"),run=Path.Combine(folder,"result");File.WriteAllBytes(image,zip);Directory.CreateDirectory(run);string before=Hash(image);
        Check(ArchiveSalvage.Recover(image,run,CancellationToken.None,null)==1,"actual managed ZIP salvage verifies and extracts the equal-length witness member");var item=RecoveryCatalog.Build(run,CancellationToken.None,null).Items.Single();
        Check(item.Bytes==37&&File.ReadAllBytes(RecoveryCatalog.SafeFile(run,item.Path)).SequenceEqual(payload)&&item.SourceOffset==0&&item.SourceRanges.Count==1&&item.SourceRanges[0].Length==37,"actual catalog retains the qualified zero header offset and encoded37-byte span for the exact37-byte extracted member");
        Check(item.SourceMapGroups.Count==1&&!item.SourceMapGroups[0].MappingComplete&&item.IntegrityDetail.Contains("полная логическая карта содержимого не установлена"),"equal physical/plaintext lengths never make an encoded ZIP SourceMapGroup a complete plaintext map");
        RecoveryCore.SaveJson(Path.Combine(run,"source-read-errors.json"),new{unreadBytes=2,ranges=new[]{new FileExtent{Offset=10,Length=2}}});item=RecoveryCatalog.Build(run,CancellationToken.None,null).Items.Single();
        Check(item.SourceOffset==0&&item.UnreadBytes==2&&item.Quality=="read_errors"&&!item.SourceMapGroups[0].MappingComplete&&Hash(image)==before,"equal-length encoded witness preserves qualified legacy header-hole intersections and unchanged source without claiming logical mapping");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args.Length==0?Directory.GetCurrentDirectory():args[0]);work=Path.Combine(project,".build","photo-source-alias-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            Check(Verify!=null&&Account!=null,"actual managed source-map verification and global accounting methods are present");InvalidMappings();Limits();Cancellation();CatalogAndExport();ReadErrorAgreement();ReaderValidationAndDuplicates();SourceScopedGroups();AggregateGroupBudget();LegacySingleOriginReadErrors();QualifiedLegacyLocations();MissingMapCarrier();EqualLengthEncodedZipWitness();
            Console.WriteLine("PASS PhotoSourceAlias: "+checks+" checks; every physical alias replayed, canonical duplicates/tamper/bounds/budgets/cancel rejected, catalog/export/source changes and logical unread agreement preserved. Own regular files only; no helper/device/paid-tool claim.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
