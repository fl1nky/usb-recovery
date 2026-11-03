using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class Fmp4RecoveryTests
{
    const string OriginalSha="9b977c560afa2b120d4b85373494ce9bcdd13328ce299dd5b726eda9c31dcbd8";
    const string ImageSha="a270ed13657d4e346814fa40ec1de01d60380ac6f026f52dd206bde905610d1f";
    const string WitnessSha="a412e3c6c957dfab92027d22eb9e3e6cacee8cf8cda63a38e25433bbcb4b4207";
    const string ManifestSha="9fdcdec5ecb03380ebf35a7628aafba02c655a1042ae11e266b660b22bad6b45";
    const string PreparerSha="94358ba428cffef5c2796e6208acc1218fbe4f31dd5a9ff0a9b40d1c6ca230c2";
    const string FrameSha="cde0c6f13cb74aa5adbbe3258c5bf314eb850922aefe3b06f22f77b71e1e1c6e";
    static int checks,calls;static string project,fixtures,corpus,work;static byte[] native,original;
    static Dictionary<string,object> witness;static Dictionary<string,string> inputs,publicInputs,sources;
    static string runtimeHash;
    static readonly List<object> records=new List<object>();
    sealed class Run {public string Image,Folder;public FragmentedMediaRecovery.Report Report;}
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=32*1024*1024};}
    static void Check(bool value,string reason){checks++;if(!value)throw new Exception(reason);}
    static string Hash(string p){using(var f=File.OpenRead(p))using(var h=SHA256.Create())return Hex(h.ComputeHash(f));}
    static string HashBytes(byte[] b){using(var h=SHA256.Create())return Hex(h.ComputeHash(b));}
    static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
    static Dictionary<string,object> Read(string p){return Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(p));}
    static Dictionary<string,object>[] Rows(object rows){return ((IEnumerable)rows).Cast<object>().Select(x=>(Dictionary<string,object>)x).ToArray();}
    static long Num(Dictionary<string,object> row,string key){return Convert.ToInt64(row[key]);}
    static Dictionary<string,string> Bind(string folder){return Directory.GetFiles(folder,"*",SearchOption.AllDirectories).ToDictionary(p=>p.Substring(folder.Length).Replace('\\','/'),Hash,StringComparer.Ordinal);}
    static void Unchanged(string folder,Dictionary<string,string> before,string label){var after=Bind(folder);Check(before.Count==after.Count&&before.All(p=>after.ContainsKey(p.Key)&&after[p.Key]==p.Value),label);}
    static string Fresh(string name){return Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N").Substring(0,8));}
    static byte[] Copy(){return (byte[])native.Clone();}
    static int Physical(int fragment){return fragment==1?1572864:fragment==2?262144:786432;}
    static int PairBytes(int fragment){return fragment==1?6520:fragment==2?6252:6156;}
    static int Header(byte[] image,int at,int bytes,string type){var found=new List<int>();for(int p=at;p<=at+bytes-8;p++)if(Encoding.ASCII.GetString(image,p+4,4)==type)found.Add(p+8);Check(found.Count==1,"Independent native box field locator: "+type);return found[0];}
    static void Put32(byte[] image,int p,uint n){image[p]=(byte)(n>>24);image[p+1]=(byte)(n>>16);image[p+2]=(byte)(n>>8);image[p+3]=(byte)n;}
    static void Put64(byte[] image,int p,long n){Put32(image,p,(uint)((ulong)n>>32));Put32(image,p+4,(uint)n);}
    static byte[] Box(string type,byte[] data){var raw=new byte[data.Length+8];Put32(raw,0,(uint)raw.Length);Buffer.BlockCopy(Encoding.ASCII.GetBytes(type),0,raw,4,4);Buffer.BlockCopy(data,0,raw,8,data.Length);return raw;}
    static byte[] Words(params uint[] words){var b=new byte[4*words.Length];for(int i=0;i<words.Length;i++)Put32(b,4*i,words[i]);return b;}
    static byte[] SampleClaimPair(int sequence,int count)
    {
        byte[] tfdt=Words(0x01000000,0,0);Put64(tfdt,4,(sequence-1L)*count);
        byte[] tfhd=Box("tfhd",Words(0x020038,1,1,5,0)),trun=Box("trun",Words(1,(uint)count,0));
        byte[] moof=Box("moof",Box("mfhd",Words(0,(uint)sequence)).Concat(Box("traf",tfhd.Concat(Box("tfdt",tfdt)).Concat(trun).ToArray())).ToArray());
        // Independent synthetic framing-only sample table, not a native decode.
        int trunData=Header(moof,0,moof.Length,"trun");Put32(moof,trunData+8,(uint)(moof.Length+8));
        byte[] data=new byte[count*5];for(int i=0;i<count;i++){data[i*5+3]=1;data[i*5+4]=0x65;}
        return moof.Concat(Box("mdat",data)).ToArray();
    }
    static byte[] LargeIndex(int count)
    {
        var rows=new byte[count*19];for(int n=0;n<count;n++){Put64(rows,n*19,n*8192L);Put64(rows,n*19+8,741+n*6520L);rows[n*19+16]=rows[n*19+17]=rows[n*19+18]=1;}
        var tfra=Box("tfra",Words(0x01000000,1,0,(uint)count).Concat(rows).ToArray());return Box("mfra",tfra.Concat(Box("mfro",Words(0,(uint)(8+tfra.Length+16)))).ToArray());
    }
    static void Erase(byte[] image,int p,int bytes){for(int i=0;i<bytes;i++)image[p+i]=0xa7;}
    static void Duplicate(byte[] image,int source,int bytes,int target){Check(image.Skip(target).Take(bytes).All(b=>b==0xa7),"Synthetic alias goes only in independently known filler");Buffer.BlockCopy(image,source,image,target,bytes);}
    static string Output(Run run){return Path.Combine(run.Folder,run.Report.Files.Single().Path.Replace('/',Path.DirectorySeparatorChar));}
    static void Replay(string image,string output,List<FragmentedMediaRecovery.Extent> map,string reason)
    {
        long logical=0;using(var input=File.OpenRead(image))using(var result=File.OpenRead(output))foreach(var e in map.OrderBy(e=>e.LogicalOffset)){
            Check(e.LogicalOffset==logical&&e.Length>0&&e.ImageOffset>=0&&e.ImageOffset<=input.Length-e.Length,reason+": exact bounded coverage");
            var a=new byte[(int)e.Length];var b=new byte[a.Length];input.Position=e.ImageOffset;result.Position=e.LogicalOffset;
            Check(input.Read(a,0,a.Length)==a.Length&&result.Read(b,0,b.Length)==b.Length&&a.SequenceEqual(b),reason+": every mapped source byte replays output");logical+=e.Length;
        }
        Check(logical==new FileInfo(output).Length,reason+": no absent or fabricated bytes");
    }
    static Run Execute(string label,byte[] bytes,int expected,string status,string skipped=null,FragmentedMediaRecovery.Limits limits=null)
    {
        string image=Fresh(label)+".dd",folder=Fresh("run-"+label);File.WriteAllBytes(image,bytes);string before=Hash(image);int count=-1;bool io=false;
        try{calls++;count=FragmentedMediaRecovery.Recover(image,folder,CancellationToken.None,null,limits??new FragmentedMediaRecovery.Limits());}catch(IOException){io=true;}
        var report=Json().Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Path.Combine(folder,"fragmented-media.json")));
        Check((status=="partial"||status=="limited")==io,label+": incomplete/limit signalled through public IOException contract");
        Check(report.Status==status&&report.Files.Count==expected&&(io||count==expected),label+": actual public engine count/status");
        Check(Hash(image)==before,label+": source bytes unchanged");Check(!Directory.GetFiles(folder,"*.partial",SearchOption.AllDirectories).Any(),label+": no partial file published");
        if(skipped!=null)Check(report.Skipped.ContainsKey(skipped),label+": precise rejection reason");
        if(expected==0)Check(Directory.GetFiles(Path.Combine(folder,"fragmented-media")).Length==0,label+": no arbitrary candidate emitted");
        else foreach(var item in report.Files){Check(item.Status=="iso_bmff_structural_candidate"&&!item.PayloadAuthenticated&&!item.DeletionConfirmed,label+": no ownership/deletion/decoded guarantee");Check(Hash(Path.Combine(folder,item.Path.Replace('/',Path.DirectorySeparatorChar)))==item.Sha256,label+": actual output hash");}
        records.Add(new{label=label,source_sha256=before,status=report.Status,count=report.Files.Count,folder=folder});return new Run{Image=image,Folder=folder,Report=report};
    }
    static void ReportControl(Run run,string name,Action<Dictionary<string,object>> mutate,bool mapping,bool scope)
    {
        string path=Path.Combine(run.Folder,"fragmented-media.json"),valid=File.ReadAllText(path);var raw=Read(path);mutate(raw);
        string control=Json().Serialize(raw);File.WriteAllText(Path.Combine(work,"report-control-"+name+".json"),control);
        try{
            File.WriteAllText(path,control);var entry=FileEvidence.Load(run.Folder).For(run.Report.Files[0].Path);
            Check(entry!=null&&entry.MappingComplete==mapping&&entry.SourceScopeVerified==scope,name+": load honors explicit report/session scope and byte bounds");
            var item=RecoveryCatalog.Build(run.Folder,CancellationToken.None,null).Items.Single();
            if(!mapping||!scope)Check(!item.SourceOffset.HasValue,name+": public catalog does not invent verified original placement");
            if(!mapping)Check(item.SourceRanges.Count==0&&item.SourceRangeAlternatives.Count==0,name+": public flat source claims cleared");
        }finally{File.WriteAllText(path,valid);}
    }
    static void NativeOracle()
    {
        Check(Hash(Path.Combine(corpus,"manifest.json"))==ManifestSha&&Hash(Path.Combine(fixtures,"manifest.json"))==ManifestSha,"Public/expanded native manifest is independently pinned");
        Check(Hash(Path.Combine(project,"tests","prepare_fmp4_media_fixtures.py"))==PreparerSha,"Exact preparer source bound");
        Check(Hash(Path.Combine(fixtures,"witness.json"))==WitnessSha,"Original pre-implementation witness preserved byte-exact");witness=Read(Path.Combine(fixtures,"witness.json"));
        native=File.ReadAllBytes(Path.Combine(fixtures,"image.dd"));original=File.ReadAllBytes(Path.Combine(fixtures,"original.mp4"));
        Check(native.Length==2097152&&HashBytes(native)==ImageSha&&original.Length==19774&&HashBytes(original)==OriginalSha,"Same native source image and independent native original");
        string frameRows=String.Join("\n",File.ReadAllLines(Path.Combine(fixtures,"original.framemd5")).Where(s=>s.Length>0&&!s.StartsWith("#",StringComparison.Ordinal)));
        Check(frameRows.Split('\n').Length==12&&HashBytes(Encoding.UTF8.GetBytes(frameRows))==FrameSha,"Pinned independent FFmpeg12-frame canonical oracle; no decoder called by this suite");
        var expected=Rows(witness["physical_extents"]);Check(expected.Length==6,"Independent six complete source runs");
        var run=Execute("native",native,1,"complete");var item=run.Report.Files.Single();
        Check(item.Bytes==19774&&item.Sha256==OriginalSha&&File.ReadAllBytes(Output(run)).SequenceEqual(original),"Actual new native recovery is all exact original bytes");
        Check(item.Tracks==1&&item.Chunks==3&&item.Extents.Count==6&&item.AlternateExtents.Count==0,"One track/three intact pairs and full six-run map");
        for(int i=0;i<expected.Length;i++){var e=item.Extents[i];Check(e.ImageOffset==Num(expected[i],"source_offset")&&e.LogicalOffset==Num(expected[i],"logical_offset")&&e.Length==Num(expected[i],"bytes"),"Native extent matches frozen independent physical/logical oracle");Check(HashBytes(native.Skip((int)e.ImageOffset).Take((int)e.Length).ToArray())==(string)expected[i]["sha256"],"Native source range matches its independent piece SHA");}
        Replay(run.Image,Output(run),item.Extents,"native");var raw=Read(Path.Combine(run.Folder,"fragmented-media.json"));
        Check((string)raw["SourceSha256"]==ImageSha&&(bool)raw["SourceUnchanged"],"Actual report binds complete locked source bytes, not only output identity");
        var marker=Read(Path.Combine(fixtures,".prepared.json"));Check((string)marker["manifest_sha256"]==ManifestSha&&(string)marker["preparer_sha256"]==PreparerSha,"Cache retains source/producer binding");
    }
    static void SourcesAndAmbiguity()
    {
        byte[] image=Copy();Duplicate(image,Physical(1),PairBytes(1),65536);var identical=Execute("identical",image,1,"complete");
        Check(identical.Report.Files[0].Sha256==OriginalSha&&identical.Report.Files[0].AlternateExtents.Count==1,"Identical pair creates two full source maps, one byte result");
        foreach(var map in new[]{identical.Report.Files[0].Extents}.Concat(identical.Report.Files[0].AlternateExtents))Replay(identical.Image,Output(identical),map,"identical alias");
        image=Copy();Duplicate(image,Physical(1),PairBytes(1),65536);int tfhd=Header(image,65536,120,"tfhd");Put32(image,tfhd+4,2);
        var foreign=Execute("foreign-track",image,1,"complete","fmp4_foreign_track");Check(foreign.Report.Files[0].Sha256==OriginalSha&&foreign.Report.Files[0].AlternateExtents.Count==0,"Different track is excluded without inventing ambiguity");
        image=Copy();Duplicate(image,Physical(1),PairBytes(1),65536);image[65536+128+17]^=1;
        Execute("competing-compatible",image,0,"complete","fmp4_payload_ambiguous");
        image=Copy();image[Physical(1)+128+17]^=1;var replacement=Execute("opaque-compatible-replacement",image,1,"complete");
        Check(replacement.Report.Files[0].Sha256!=OriginalSha&&!replacement.Report.Files[0].PayloadAuthenticated,"Opaque bytes can differ while NAL framing/tables agree; never claimed original/authentic");
        image=Copy();Duplicate(image,Physical(1),PairBytes(1),65536);Duplicate(image,32768,28,131072);Duplicate(image,1048576,713,1310720);Duplicate(image,1966080,105,1900000);
        var aliases=Execute("metadata-aliases",image,1,"complete");var result=aliases.Report.Files.Single();
        Check(result.Sha256==OriginalSha&&result.AlternateExtents.Count==15&&aliases.Report.Skipped.ContainsKey("duplicate_fmp4_init"),"All sixteen complete same-byte placements retained, duplicate init not reassembled arbitrarily");
        foreach(var map in new[]{result.Extents}.Concat(result.AlternateExtents))Replay(aliases.Image,Output(aliases),map,"metadata alias");
        var catalog=RecoveryCatalog.Build(aliases.Folder,CancellationToken.None,null);var item=catalog.Items.Single();
        Check(item.Quality=="structural_candidate"&&!item.SourceOffset.HasValue&&item.SourceRangeAlternatives.Count==15,"Public catalog keeps mapping uncertainty and structural quality");
        Check(item.SourceMapGroups.Count==1&&item.SourceMapGroups[0].SourceScopeVerified&&item.SourceMapGroups[0].SourceSha256==Hash(aliases.Image)&&item.SourceMapGroups[0].Maps.Count==16,"Source hash/full maps propagate to public catalog group");
        string export=Fresh("export");Directory.CreateDirectory(export);export=RecoveryCatalog.Export(aliases.Folder,export,new[]{item},CancellationToken.None);string exported=File.ReadAllText(Path.Combine(export,"export-manifest.json"));
        Check(exported.Contains("sourceRangeAlternatives")&&exported.Contains("sourceMapGroups")&&exported.Contains(Hash(aliases.Image)),"Export retains complete aliases and exact source scope");
        var loaded=RecoveryCatalog.Load(aliases.Folder).Items.Single();Check(loaded.SourceRangeAlternatives.Count==15&&loaded.SourceMapGroups[0].Maps.Count==16&&!loaded.SourceOffset.HasValue,"Saved catalog roundtrip retains aliases, no invented original placement");
        string copyDir=Path.Combine(aliases.Folder,"containers");Directory.CreateDirectory(copyDir);File.Copy(Output(aliases),Path.Combine(copyDir,"same.mp4"));
        item=RecoveryCatalog.Build(aliases.Folder,CancellationToken.None,null).Items.Single();Check(item.Copies.Count==1&&item.SourceMapGroups.Count==1&&item.SourceMapGroups[0].Maps.Count==16&&!item.SourceOffset.HasValue,"Content dedup keeps mapped witness when a second copy has unknown map");
        string reportFile=Path.Combine(aliases.Folder,"fragmented-media.json"),valid=File.ReadAllText(reportFile);var altered=Read(reportFile);var row=Rows(altered["Files"])[0];row["AlternateExtents"]=null;File.WriteAllText(reportFile,Json().Serialize(altered));
        var evidence=FileEvidence.Load(aliases.Folder).For(result.Path);Check(evidence!=null&&!evidence.MappingComplete&&evidence.Ranges.Count==0&&evidence.SourceRangeAlternatives.Count==0,"Explicit null alternative maps invalidate all map claims");File.WriteAllText(reportFile,valid);
        altered=Read(reportFile);row=Rows(altered["Files"])[0];Rows(row["Extents"])[0]["ImageOffset"]=new FileInfo(aliases.Image).Length;File.WriteAllText(reportFile,Json().Serialize(altered));
        evidence=FileEvidence.Load(aliases.Folder).For(result.Path);Check(evidence!=null&&!evidence.MappingComplete&&evidence.Ranges.Count==0,"Standalone native report source-byte bound rejects out-of-source mapping");File.WriteAllText(reportFile,valid);
        long sourceBytes=new FileInfo(aliases.Image).Length;
        ReportControl(aliases,"primary-EOF",raw=>Rows(Rows(raw["Files"])[0]["Extents"])[0]["ImageOffset"]=sourceBytes,false,true);
        ReportControl(aliases,"alias-EOF",raw=>Rows(((IEnumerable)Rows(raw["Files"])[0]["AlternateExtents"]).Cast<object>().First())[0]["ImageOffset"]=sourceBytes,false,true);
        ReportControl(aliases,"primary-overflow",raw=>Rows(Rows(raw["Files"])[0]["Extents"])[0]["ImageOffset"]=Int64.MaxValue,false,true);
        ReportControl(aliases,"alias-overflow",raw=>Rows(((IEnumerable)Rows(raw["Files"])[0]["AlternateExtents"]).Cast<object>().First())[0]["ImageOffset"]=Int64.MaxValue,false,true);
        foreach(object corrupt in new object[]{0,-1,"not-a-size",null})ReportControl(aliases,"bad-input-size-"+checks,raw=>raw["InputBytes"]=corrupt,true,false);
        ReportControl(aliases,"unknown-input-size",raw=>raw.Remove("InputBytes"),true,false);
        ReportControl(aliases,"forged-verified-flag",raw=>{raw["SourceUnchanged"]=false;raw["SourceScopeVerified"]=true;},true,false);
        string session=Path.Combine(aliases.Folder,RecoverySession.FileName);
        File.WriteAllText(session,Json().Serialize(new{Schema=1,SourceSha256=Hash(aliases.Image),SourceBytes=sourceBytes}));
        ReportControl(aliases,"session-precedes-report-size",raw=>raw["InputBytes"]=sourceBytes+1,true,false);
        ReportControl(aliases,"session-different-source-SHA",raw=>raw["SourceSha256"]=new string('0',64),true,false);
        ReportControl(aliases,"session-explicit-null-SHA",raw=>{raw["SourceSha256"]=null;raw["SourceScopeVerified"]=true;},true,false);
        ReportControl(aliases,"session-legacy-absent-SHA",raw=>{raw.Remove("SourceSha256");raw.Remove("SourceUnchanged");},true,true);
        ReportControl(aliases,"session-EOF",raw=>{raw["InputBytes"]=sourceBytes+1000;Rows(Rows(raw["Files"])[0]["Extents"])[0]["ImageOffset"]=sourceBytes;},false,false);
        File.Delete(session);
        byte[] changed=File.ReadAllBytes(Output(aliases));changed[changed.Length-1]^=1;File.WriteAllBytes(Output(aliases),changed);File.Delete(Path.Combine(copyDir,"same.mp4"));
        item=RecoveryCatalog.Build(aliases.Folder,CancellationToken.None,null).Items.Single();Check(item.SourceRanges.Count==0&&item.SourceRangeAlternatives.Count==0&&item.SourceMapGroups.Count==0&&!item.SourceOffset.HasValue,"Changed recovered bytes cannot retain any prior alias/source-map claim");
    }
    static void NegativeTables()
    {
        byte[] b=Copy();Erase(b,Physical(2),PairBytes(2));Execute("missing-pair",b,0,"partial","fmp4_indexed_fragment_missing");
        b=Copy();Erase(b,1966080,105);Execute("missing-index",b,0,"partial","fmp4_index_or_init_layout_unavailable");
        b=Copy();Erase(b,32768,28);Execute("missing-ftyp",b,0,"partial");
        b=Copy();Erase(b,1048576,713);Execute("missing-init",b,0,"complete");
        b=Copy();Put32(b,Header(b,Physical(2),120,"tfhd"),0x020078);Execute("unknown-tfhd-flag",b,0,"partial","fmp4_tfhd_flags_unsupported");
        b=Copy();Put32(b,Header(b,Physical(2),120,"trun")+8,0xffffffff);Execute("signed-negative-offset",b,0,"partial","fmp4_relative_data_offset");
        b=Copy();Put32(b,Header(b,Physical(2),120,"trun")+4,0xffffffff);Execute("overflow-sample-count",b,0,"partial","table_count_limit");
        b=Copy();Put64(b,Header(b,Physical(2),120,"tfdt")+4,8193);Execute("decode-gap",b,0,"partial","fmp4_indexed_fragment_missing");
        b=Copy();Put32(b,Header(b,Physical(2),120,"mfhd")+4,1);Execute("repeated-sequence",b,0,"partial","fmp4_indexed_fragment_missing");
        b=Copy();Put32(b,Header(b,Physical(2),120,"tfhd")+8,0);Execute("zero-duration",b,0,"partial","fmp4_sample_geometry_invalid");
        b=Copy();Put32(b,Physical(2)+128,0xffffffff);Execute("invalid-nal-length",b,0,"partial","fmp4_avc_framing_invalid");
        b=Copy();Put64(b,Header(b,1966080,105,"tfra")+16+19+8,7262);Execute("index-logical-offset",b,0,"partial","fmp4_indexed_fragment_missing");
        b=Copy();Put64(b,Header(b,1966080,105,"tfra")+16+19,8193);Execute("index-time-gap",b,0,"partial","fmp4_indexed_fragment_missing");
        b=Copy();Put32(b,Header(b,1966080,105,"mfro")+4,104);Execute("tail-size-tamper",b,0,"partial","fmp4_mfro_size_invalid");
        b=Copy();Put32(b,Header(b,1966080,105,"tfra")+8,64);Execute("index-reserved-bits",b,0,"partial","fmp4_tfra_reserved_bits");
        b=Copy();Put32(b,Physical(2)+120,100);Execute("short-mdat",b,0,"partial","fmp4_sample_geometry_invalid");
        b=Copy();Duplicate(b,1966080,105,65536);Put32(b,Header(b,65536,105,"tfra")+12,257);
        Check(HashBytes(b)=="d90c9292e6bd3ec8b23991336935545bb085a745439f49c53c76153326ed19b9","Malformed-index mutation matches independent peer witness; original six runs untouched");
        var nonPoisoned=Execute("malformed-index-does-not-poison",b,1,"complete","fmp4_index_length_invalid");Check(nonPoisoned.Report.Files[0].Sha256==OriginalSha,"Clearly truncated count is rejected before cap; valid surviving index still yields exact original");
    }
    static void LimitsAndCancellation()
    {
        Execute("limit-headers",native,0,"limited",null,new FragmentedMediaRecovery.Limits{MaxCandidates=1});Execute("limit-verified-bytes",native,0,"limited",null,new FragmentedMediaRecovery.Limits{MaxVerifiedBytes=1});Execute("limit-output-bytes",native,0,"limited",null,new FragmentedMediaRecovery.Limits{MaxOutputBytes=1});
        byte[] many=Enumerable.Repeat((byte)0xa7,7*1024*1024).ToArray();Buffer.BlockCopy(native,0,many,0,native.Length);
        for(int i=0;i<512;i++)Buffer.BlockCopy(native,Physical(1),many,2097152+i*8192,PairBytes(1));Execute("513-source-maps-limit",many,0,"limited");
        many=Enumerable.Repeat((byte)0xa7,4*1024*1024).ToArray();Buffer.BlockCopy(native,0,many,0,native.Length);
        for(int i=0;i<8193;i++)Buffer.BlockCopy(native,Physical(1),many,2097152+i*128,120);Execute("8192-work-states-limit",many,0,"limited");
        many=Enumerable.Repeat((byte)0xa7,4*1024*1024).ToArray();Buffer.BlockCopy(native,0,many,0,native.Length);
        for(int i=0;i<3;i++){var pair=SampleClaimPair(i+1,40000);Buffer.BlockCopy(pair,0,many,2097152+i*262144,pair.Length);}Execute("aggregate-sample-claims-limit",many,0,"limited");
        many=Copy();var completeLargeIndex=LargeIndex(257);Buffer.BlockCopy(completeLargeIndex,0,many,1966080,completeLargeIndex.Length);Execute("complete-257-entry-index-limit",many,0,"limited");
        string image=Path.Combine(fixtures,"image.dd"),before=Hash(image),folder=Fresh("cancel");var cancel=new CancellationTokenSource();bool stopped=false;
        try{calls++;FragmentedMediaRecovery.Recover(image,folder,cancel.Token,(a,b)=>cancel.Cancel());}catch(OperationCanceledException){stopped=true;}
        Check(stopped&&Read(Path.Combine(folder,"fragmented-media.json"))["Status"].ToString()=="cancelled"&&!Directory.GetFiles(folder,"*.partial",SearchOption.AllDirectories).Any(),"Public cancellation leaves no successful file/partial");
        folder=Fresh("pre-cancel");stopped=false;try{calls++;FragmentedMediaRecovery.Recover(image,folder,cancel.Token,null);}catch(OperationCanceledException){stopped=true;}Check(stopped&&!Directory.Exists(folder),"Pre-cancel performs no writes");
        folder=Fresh("read-lock");bool denied=false;calls++;FragmentedMediaRecovery.Recover(image,folder,CancellationToken.None,(a,b)=>{try{using(var f=new FileStream(image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)){} }catch(IOException){denied=true;}});Check(denied&&Hash(image)==before,"Whole native source remains locked against writes");
        string pipeline=Fresh("pipeline");Directory.CreateDirectory(pipeline);string checksum=Path.Combine(pipeline,"fixture.sha256");File.WriteAllText(checksum,ImageSha);
        var options=new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedVideo=true};options.Validate();
        calls++;var first=RecoveryPipeline.Run(image,pipeline,options,CancellationToken.None,s=>{},checksum);Check(first.Candidates==1&&RecoveryCatalog.Load(pipeline).Items.Single().Sha256==OriginalSha,"Actual public pipeline/native checkbox/session/catalog reaches exact file without helper");
        var resumed=RecoveryPipeline.Resume(pipeline,CancellationToken.None,s=>{});Check(resumed.ResumedStages>=1&&RecoveryCatalog.Load(pipeline).Items.Count==1,"Verified native stage resumes without duplicated output");
        byte[] incomplete=Copy();Erase(incomplete,1966080,105);string incompleteImage=Fresh("pipeline-missing-index")+".dd";File.WriteAllBytes(incompleteImage,incomplete);
        pipeline=Fresh("pipeline-partial");Directory.CreateDirectory(pipeline);checksum=Path.Combine(pipeline,"fixture.sha256");File.WriteAllText(checksum,Hash(incompleteImage));bool failed=false;
        try{calls++;RecoveryPipeline.Run(incompleteImage,pipeline,options,CancellationToken.None,s=>{},checksum);}catch(IOException){failed=true;}
        string stages=File.ReadAllText(Path.Combine(pipeline,"scan-stages.json"));Check(failed&&stages.Contains("incomplete")&&stages.Contains("mfra/tfra"),"Public workflow/session uses existing incomplete stage and meaningful reason, not successful reconstruction");
    }
    public static int Main(string[] args)
    {
        try{
            project=Path.GetFullPath(args[0]);fixtures=Path.GetFullPath(args.Length>1?args[1]:Path.Combine(project,".build/fmp4-fixtures-current"));corpus=Path.Combine(project,"tests/fixtures/video-fmp4");work=Path.Combine(project,".build/fmp4-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            inputs=Bind(fixtures);publicInputs=Bind(corpus);sources=new Dictionary<string,string>();foreach(string name in new[]{"src/Recovery/Recovery/Engines/Fmp4Recovery.cs","src/Recovery/Recovery/Engines/FragmentedMediaRecovery.cs","src/Recovery/Recovery/Results/FileEvidence.cs","tests/build_fmp4_media_fixtures.py","tests/prepare_fmp4_media_fixtures.py","tests/Fmp4RecoveryTests.cs"})sources[name]=Hash(Path.Combine(project,name));runtimeHash=Hash(typeof(FragmentedMediaRecovery).Assembly.Location);
            NativeOracle();SourcesAndAmbiguity();NegativeTables();LimitsAndCancellation();Unchanged(fixtures,inputs,"Prepared native corpus unchanged");Unchanged(corpus,publicInputs,"Public native/oracle bytes unchanged");Check(sources.All(p=>Hash(Path.Combine(project,p.Key))==p.Value)&&Hash(typeof(FragmentedMediaRecovery).Assembly.Location)==runtimeHash,"Runtime and all engine/test/producer sources unchanged during actual source checks");
            File.WriteAllText(Path.Combine(work,"verification.json"),Json().Serialize(new{schema=1,status="source-tests-passed",scope="One native FFmpeg witness plus explicitly synthetic mutations; no universal fMP4/ownership/deletion/device/paid claim",checks=checks,recovery_calls=calls,runtime_sha256=runtimeHash,sources=sources,cases=records}),new UTF8Encoding(false));
            Console.WriteLine("PASS Fmp4Recovery: "+checks+" checks; exact native19774bytes/six source extents, full-map aliases/catalog/export/session, foreign vs ambiguous/opaque mutations, indexed timing/bounds, limits/cancel and immutable inputs. "+work);return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
