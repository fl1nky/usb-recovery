using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Actual managed recovery of four independently muxed/decoded own originals.
// Packing/policy reflection controls are explicitly not decoded-video cases.
public static class Stz2MediaRecoveryTests
{
    const string ManifestSha="350c860ece2b28b5b40b8b99b4a079976125574510018057a12a45baa803d865";
    const string CanonicalManifest="98d23d8bd8cc39dd7f4aa7959d59e415b73e0622983565e82519d26a88fef396";
    const string TablesSha="2ed0e22af4bf26b11084116eac5a43d874b15035266fc4830e91ca97f4b1e23a";
    const string PreparerSha="d9589ed011cc7958ac835946f043a2f3730c3a582473e88d864975388b8bba64";
    static readonly string[] Names={"avc-stsz-control","avc-stz2-16","hevc-stsz-control","hevc-stz2-16"};
    static readonly string[] Originals={"5c0cb3048ab0e4e216e15b01d350f9d9b55be0054e49ba6c3e28a8294ea0c89e","70106863682cc8dc20420f60742162f661fcf4f7b0a4a1d00b60cbcede944059","4b7751ddeb9b877953c1614eac6f76c0b92fa0bf08740e86b4c7d337d5a1bec5","685ae0800bc520dab2a66727e9da27453db5d437c254dd77258e8b97ba04cc19"};
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static readonly MethodInfo Boxes=typeof(FragmentedMediaRecovery).GetMethod("Boxes",BindingFlags.Static|BindingFlags.NonPublic);
    static readonly MethodInfo Sizes=typeof(FragmentedMediaRecovery).GetMethod("SampleSizes",BindingFlags.Static|BindingFlags.NonPublic);
    static int checks,nativeRuns,tableControls;
    static string project,fixtures,work,corpus;
    static CancellationToken token;
    static Dictionary<string,string> inputsBefore,corpusBefore;
    static string assemblyBefore,engineBefore,preparerBefore;
    static readonly List<object> results=new List<object>();

    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Hash(string file){using(var stream=File.OpenRead(file))using(var sha=SHA256.Create())return Hex(sha.ComputeHash(stream));}
    static string HashBytes(byte[] bytes){using(var sha=SHA256.Create())return Hex(sha.ComputeHash(bytes));}
    static string Hex(byte[] bytes){return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
    static string Safe(string root,string relative){return RecoveryCatalog.SafeFile(root,relative.Replace('\\','/'));}
    static Dictionary<string,object> ReadJson(string file){return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file,Encoding.UTF8));}
    static object Field(Dictionary<string,object> row,string key){object value;if(row==null||!row.TryGetValue(key,out value))throw new IOException("Missing oracle field: "+key);return value;}
    static string Str(Dictionary<string,object> row,string key){return (string)Field(row,key);}
    static long Num(Dictionary<string,object> row,string key){return Convert.ToInt64(Field(row,key));}
    static Dictionary<string,object> Obj(object value){var row=value as Dictionary<string,object>;if(row==null)throw new IOException("Expected oracle object");return row;}
    static List<Dictionary<string,object>> Rows(object value){var array=value as IEnumerable;if(array==null||value is string||value is IDictionary)throw new IOException("Expected oracle rows");return array.Cast<object>().Select(Obj).ToList();}
    static int[] Ints(object value){return ((IEnumerable)value).Cast<object>().Select(Convert.ToInt32).ToArray();}
    static Dictionary<string,string> Binding(string root)
    {
        root=Path.GetFullPath(root).TrimEnd('\\','/');for(var parent=new DirectoryInfo(root);parent!=null;parent=parent.Parent)if((parent.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked fixture ancestor");
        var answer=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var pending=new Stack<string>();pending.Push(root);
        while(pending.Count>0)foreach(string path in Directory.GetFileSystemEntries(pending.Pop())){
            var attributes=File.GetAttributes(path);if((attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked fixture entry");
            if((attributes&FileAttributes.Directory)!=0)pending.Push(path);else answer.Add(path.Substring(root.Length+1).Replace('\\','/'),Hash(path));
        }return answer;
    }
    static bool Same(Dictionary<string,string> left,Dictionary<string,string> right){return left.Count==right.Count&&left.All(row=>right.ContainsKey(row.Key)&&right[row.Key]==row.Value);}
    static string Fresh(string name){string path=Safe(work,name+"-"+Guid.NewGuid().ToString("N"));if(File.Exists(path)||Directory.Exists(path))throw new IOException("Fresh output required");return path;}
    static uint U32(byte[] data,int at){return (uint)data[at]<<24|(uint)data[at+1]<<16|(uint)data[at+2]<<8|data[at+3];}
    static void Put32(byte[] data,int at,uint value){for(int n=3;n>=0;n--){data[at+n]=(byte)value;value>>=8;}}
    static object Invoke(MethodInfo method,params object[] args){try{return method.Invoke(null,args);}catch(TargetInvocationException error){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}}
    static int[] ParseTables(byte[] raw){var boxes=Invoke(Boxes,raw,0,raw.Length);return (int[])Invoke(Sizes,raw,boxes);}
    static string Rejection(byte[] raw)
    {
        try{ParseTables(raw);return null;}catch(Exception error){var code=error.GetType().GetField("Code");if(code==null)throw;return (string)code.GetValue(error);}
    }
    static byte[] Compact(int bits,uint count,byte[] payload)
    {
        var raw=new byte[20+payload.Length];Put32(raw,0,(uint)raw.Length);Array.Copy(Encoding.ASCII.GetBytes("stz2"),0,raw,4,4);raw[15]=(byte)bits;Put32(raw,16,count);Array.Copy(payload,0,raw,20,payload.Length);return raw;
    }
    static byte[] Standard(uint count,uint fixedSize,params uint[] sizes)
    {
        var raw=new byte[20+sizes.Length*4];Put32(raw,0,(uint)raw.Length);Array.Copy(Encoding.ASCII.GetBytes("stsz"),0,raw,4,4);Put32(raw,12,fixedSize);Put32(raw,16,count);for(int n=0;n<sizes.Length;n++)Put32(raw,20+n*4,sizes[n]);return raw;
    }
    static void TableControls()
    {
        Check(Boxes!=null&&Sizes!=null,"actual new managed sample-size parser and validated box reader are present");
        string path=Safe(fixtures,"table-oracles.json");Check(Hash(path)==TablesSha,"table-only oracle raw bytes are independently pinned");var oracle=ReadJson(path);var controls=Rows(Field(oracle,"controls"));
        Check(Num(oracle,"native_video_cases_added")==0&&Num(oracle,"positive_packing_controls")==7&&Num(oracle,"negative_policy_controls")==12&&controls.Count==19,"packing/policy controls are not counted as native decoded videos");
        int positive=0,negative=0;foreach(var row in controls){
            string name=Str(row,"name"),file=Safe(fixtures,Str(row,"path"));byte[] raw=File.ReadAllBytes(file);Check(raw.Length==Num(row,"bytes")&&HashBytes(raw)==Str(row,"sha256"),name+": unchanged independent table fixture");
            object expected=Field(row,"expected_sizes");if(expected==null){Check(Rejection(raw)!=null,name+": explicit strict recovery policy rejects malformed table");negative++;}
            else{Check(ParseTables(raw).SequenceEqual(Ints(expected)),name+": exact independent compact entries; odd low nibble is ignored");positive++;}tableControls++;
        }Check(positive==7&&negative==12,"all seven packing positives and twelve policy negatives executed");
        Check(ParseTables(Standard(3,7)).SequenceEqual(new[]{7,7,7}),"legacy fixed stsz entries retain their existing behavior");
        Check(ParseTables(Standard(3,0,1,256,65535)).SequenceEqual(new[]{1,256,65535}),"legacy variable stsz entries retain32-bit big-endian values");
        foreach(int count in new[]{8193,FragmentedMediaRecovery.MaximumSamples}){var raw=Compact(8,(uint)count,Enumerable.Repeat((byte)1,count).ToArray());int[] parsed=ParseTables(raw);Check(parsed.Length==count&&parsed.All(size=>size==1),"complete table count"+count+" respects the100000 whole-track bound, separate from the8192 unit fallback");}
        foreach(uint count in new[]{0U,(uint)FragmentedMediaRecovery.MaximumSamples+1,UInt32.MaxValue})Check(Rejection(Compact(8,count,new byte[0]))=="table_count_limit","invalid/oversized compact count rejected before size arithmetic and allocation: "+count);
        Check(Rejection(Standard(1,(uint)FragmentedMediaRecovery.MaximumSampleBytes+1))=="sample_size_limit","legacy maximum sample bytes remains enforced");
        byte[] compact=Compact(8,2,new byte[]{3,4}),standard=Standard(2,0,3,4);
        foreach(byte[] raw in new[]{compact.Concat(compact).ToArray(),standard.Concat(standard).ToArray(),compact.Concat(standard).ToArray(),standard.Concat(compact).ToArray(),new byte[0]})
            Check(Rejection(raw)=="sample_sizes_missing_or_duplicate","duplicate/mixed/missing tables cannot choose one size interpretation");
        byte[] extended=new byte[compact.Length+8];Put32(extended,0,1);Array.Copy(compact,4,extended,4,4);Put32(extended,12,(uint)extended.Length);Array.Copy(compact,8,extended,16,compact.Length-8);Check(ParseTables(extended).SequenceEqual(new[]{3,4}),"extended-size compact box obeys its actual header boundary");
    }
    static List<Dictionary<string,object>> Fixtures()
    {
        Check(Hash(Safe(corpus,"manifest.json"))==ManifestSha&&Hash(Safe(fixtures,"manifest.json"))==ManifestSha,"source and expanded corpus have the frozen native manifest bytes");
        Check(Hash(Safe(project,"tests/prepare_stz2_media_fixtures.py"))==PreparerSha,"fixture preparer source is independently pinned");var manifest=ReadJson(Safe(fixtures,"manifest.json"));var files=Rows(Field(manifest,"files"));
        Check(Num(manifest,"schema")==1&&Str(manifest,"source_commit")=="663246439f39ab612a492bb65ec0d203dcb13b82"&&files.Count==41,"complete four-case pinned native corpus source provenance");
        var sourceNames=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"manifest.json"};var payloadNames=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"manifest.json","prepared.json"};
        foreach(var row in files){string source=Str(row,"source").Replace('\\','/'),payload=Str(row,"path").Replace('\\','/');Check(sourceNames.Add(source)&&payloadNames.Add(payload),"fixture source/payload names are unique");
            string s=Safe(corpus,source),p=Safe(fixtures,payload);Check(new FileInfo(s).Length==Num(row,"source_bytes")&&Hash(s)==Str(row,"source_sha256")&&new FileInfo(p).Length==Num(row,"bytes")&&Hash(p)==Str(row,"sha256"),"every compressed source and expanded payload matches its frozen size/SHA");}
        Check(sourceNames.SetEquals(corpusBefore.Keys)&&payloadNames.SetEquals(inputsBefore.Keys),"fixture fileset has no missing/extra/unrecorded source or payload");var marker=ReadJson(Safe(fixtures,"prepared.json"));
        Check(Str(marker,"preparer_sha256")==PreparerSha&&Str(marker,"manifest_canonical_sha256")==CanonicalManifest&&Str(marker,"kind")=="owned-video-stz2-cache-v1","expanded cache binds its exact preparer and independent canonical source manifest");
        var cases=Rows(Field(manifest,"cases"));Check(cases.Count==4&&cases.Select(row=>Str(row,"name")).SequenceEqual(Names),"all four exact native AVC/HEVC stsz/stz2 cases are mandatory");
        for(int n=0;n<cases.Count;n++){
            var row=cases[n];Check(Str(row,"original_sha256")==Originals[n]&&Num(row,"decoded_frame_count")==12,"native original digest/frame count is independently fixed");string original=Safe(fixtures,Str(row,"original")),image=Safe(fixtures,Str(row,"image"));
            Check(Hash(original)==Originals[n]&&new FileInfo(original).Length==Num(row,"original_bytes")&&Hash(image)==Str(row,"image_sha256")&&new FileInfo(image).Length==Num(row,"image_bytes"),"original/image exact hashes and lengths match the independent native oracle");
            string codec=Str(row,"codec"),suffix=Str(Obj(Field(row,"table")),"box")=="stsz"?"stsz":"stz2-16";var lines=File.ReadAllText(Safe(fixtures,"originals/"+codec+"-"+suffix+".framemd5")).Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Where(line=>!line.StartsWith("#",StringComparison.Ordinal)).ToArray();
            Check(lines.Length==12&&HashBytes(Encoding.UTF8.GetBytes(String.Join("\n",lines)))==Str(row,"decoded_frames_sha256"),"twelve independently decoded-frame oracle rows remain intact; no decoder is launched by this suite");
            var table=Obj(Field(row,"table"));int[] sizes=Ints(Field(table,"sample_sizes"));var packets=Rows(Field(ReadJson(Safe(fixtures,"originals/"+codec+"-packets.json")),"packets"));long at=Num(table,"first_sample");
            Check(packets.Count==12&&sizes.Length==12&&Num(table,"sample_count")==12,"native packet and sample counts agree");for(int j=0;j<12;j++){Check(Convert.ToInt64(Field(packets[j],"size"))==sizes[j]&&Convert.ToInt64(Field(packets[j],"pos"))==at,"independent packet offsets/sizes exactly match the table");at+=sizes[j];}
        }return cases;
    }
    static string Key(IEnumerable<FragmentedMediaRecovery.Extent> extents)
    {return String.Join("|",extents.OrderBy(e=>e.LogicalOffset).Select(e=>e.LogicalOffset+":"+e.ImageOffset+":"+e.Length));}
    static void Replay(string image,string output,FragmentedMediaRecovery.Result result)
    {
        long logical=0;using(var source=File.OpenRead(image))using(var file=File.OpenRead(output)){
            var a=new byte[65536];var b=new byte[65536];foreach(var range in result.Extents.OrderBy(e=>e.LogicalOffset)){
                Check(range.Length>0&&range.LogicalOffset==logical&&range.ImageOffset>=0&&range.ImageOffset<=source.Length-range.Length&&range.Length<=result.Bytes-logical,"recovered extent has exact bounded logical coverage");
                foreach(long location in new[]{range.ImageOffset}.Concat(range.EquivalentOffsets).Distinct()){
                    Check(location>=0&&location<=source.Length-range.Length,"every equivalent physical extent is bounded");source.Position=location;file.Position=logical;long remaining=range.Length;
                    while(remaining>0){token.ThrowIfCancellationRequested();int count=(int)Math.Min(a.Length,remaining);ReadExact(source,a,count);ReadExact(file,b,count);Check(a.Take(count).SequenceEqual(b.Take(count)),"every primary/equivalent extent replays actual output bytes");remaining-=count;}
                }logical+=range.Length;
            }Check(logical==result.Bytes&&file.Length==result.Bytes,"extent coverage equals the complete emitted file");
        }
        long end=-1;foreach(var range in result.Extents.OrderBy(e=>e.ImageOffset)){Check(range.ImageOffset>=end,"physical extents never reuse overlapping source bytes");end=range.ImageOffset+range.Length;}
    }
    static void ReadExact(Stream stream,byte[] bytes,int count){int done=0;while(done<count){int n=stream.Read(bytes,done,count-done);if(n==0)throw new EndOfStreamException();done+=n;}}
    static FragmentedMediaRecovery.Report Report(string run){return Json.Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Safe(run,"fragmented-media.json")));}
    static FragmentedMediaRecovery.Result RecoverExact(Dictionary<string,object> fixture,string image,string label,bool exactMap)
    {
        string before=Hash(image),run=Fresh(label);nativeRuns++;int count=FragmentedMediaRecovery.Recover(image,run,token,null);var report=Report(run);
        Check(count==1&&report.Status=="complete"&&report.Candidates==1&&report.Recovered==1&&report.Files.Count==1&&report.InputBytes==new FileInfo(image).Length,"actual managed recovery produces exactly one complete candidate: "+label);
        var result=report.Files.Single();string output=Safe(run,result.Path);Check(result.Bytes==Num(fixture,"original_bytes")&&result.Sha256==Str(fixture,"original_sha256")&&Hash(output)==result.Sha256&&report.OutputBytes==result.Bytes,"native recovered bytes exactly equal the independent original: "+label);
        Check(result.Status=="iso_bmff_structural_candidate"&&!result.PayloadAuthenticated&&!result.DeletionConfirmed&&result.Tracks==1&&result.Chunks==1&&result.Note.Contains("not a decoded-video"),"structural framing does not authenticate entropy/ownership/deletion");Replay(image,output,result);
        if(exactMap){var planted=Rows(Field(fixture,"physical_extents")).Select(row=>new FragmentedMediaRecovery.Extent{LogicalOffset=Num(row,"logical_offset"),ImageOffset=Num(row,"source_offset"),Length=Num(row,"length")});Check(Key(planted)==Key(result.Extents),"every planted native physical extent is retained in exact logical order");}
        Check(Hash(image)==before&&!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),"source is immutable and no partial candidate is exposed");results.Add(new{name=label,source_sha256=before,output_sha256=result.Sha256,exact_native_original=true,maps_replayed=true});return result;
    }
    static void AvcHeaders(byte[] bytes,int[] sizes)
    {
        int at=0;foreach(int size in sizes){int end=at+size;bool vcl=false;while(at<end){Check(end-at>=5,"independent AVC length/header bounds");uint length=U32(bytes,at);at+=4;Check(length>=1&&length<=end-at&&(bytes[at]&128)==0,"independent AVC NAL framing remains intact");int type=bytes[at]&31;Check(type>=1&&type<=23,"independent AVC NAL type remains structural");vcl|=type==1||type==5;at+=(int)length;}Check(at==end&&vcl,"each independent AVC sample retains VCL and complete NAL coverage");}Check(at==bytes.Length,"whole candidate chunk is framed, not entropy-decoded");
    }
    static void Ambiguity(Dictionary<string,object> fixture)
    {
        byte[] original=File.ReadAllBytes(Safe(fixtures,Str(fixture,"image")));var chunk=Rows(Field(fixture,"physical_extents")).Single(row=>Str(row,"kind")=="sample_chunk");int source=(int)Num(chunk,"source_offset"),length=(int)Num(chunk,"length"),target=524288;int[] sizes=Ints(Field(Obj(Field(fixture,"table")),"sample_sizes"));byte[] payload=original.Skip(source).Take(length).ToArray();AvcHeaders(payload,sizes);
        Check(target>=0&&target+length<=original.Length&&original.Skip(target).Take(length).All(value=>value==0xee)&&Rows(Field(fixture,"physical_extents")).All(range=>target+length<=Num(range,"source_offset")||Num(range,"source_offset")+Num(range,"length")<=target),"own duplicate placement occupies only frozen0xEE padding outside every planted extent in a disposable image");
        byte[] identical=(byte[])original.Clone();Array.Copy(payload,0,identical,target,length);string image=Fresh("identical-source")+".dd";File.WriteAllBytes(image,identical);var result=RecoverExact(fixture,image,"identical-whole-chunk",false);
        Check(result.Extents.Any(range=>range.Kind=="sample_chunk"&&range.EquivalentOffsets.Contains(source)&&range.EquivalentOffsets.Contains(target)),"identical whole chunks retain both verified physical origins without false content ambiguity");
        byte[] different=(byte[])payload.Clone();int at=0,changed=-1;foreach(int size in sizes){int end=at+size;while(at<end){int n=(int)U32(different,at);at+=4;int kind=different[at]&31;if(changed<0&&(kind==1||kind==5)&&n>3)changed=at+2;at+=n;}}
        Check(changed>=0,"own distinct candidate changes an AVC payload interior, never a length/header");different[changed]^=1;AvcHeaders(different,sizes);Check(HashBytes(different)!=HashBytes(payload),"two structurally valid whole chunks have distinct bytes, not an independently decoded foreign-video claim");
        byte[] ambiguous=(byte[])original.Clone();Array.Copy(different,0,ambiguous,target,length);image=Fresh("ambiguous-source")+".dd";File.WriteAllBytes(image,ambiguous);string before=Hash(image),run=Fresh("ambiguous-whole-chunk");nativeRuns++;int count=FragmentedMediaRecovery.Recover(image,run,token,null);var report=Report(run);
        Check(count==0&&report.Status=="complete"&&report.Files.Count==0&&report.Skipped.Keys.Any(key=>key.Contains("ambiguous")),"distinct valid complete AVC-header assignments remain explicitly ambiguous, never first-match unique");Check(!Directory.GetFiles(Safe(run,"fragmented-media")).Any()&&Hash(image)==before,"ambiguous scan publishes no candidate/partial and does not change source");
    }
    static void LimitsAndCancellation(string image)
    {
        string before=Hash(image);foreach(bool verification in new[]{false,true}){
            string run=Fresh(verification?"verification-limit":"output-limit");var limits=new FragmentedMediaRecovery.Limits();if(verification)limits.MaxVerifiedBytes=1;else limits.MaxOutputBytes=1;bool limited=false;
            nativeRuns++;try{FragmentedMediaRecovery.Recover(image,run,token,null,limits);}catch(IOException error){limited=error.Message=="MEDIA_SEARCH_LIMIT_REACHED";}var report=Report(run);
            Check(limited&&report.Status=="limited"&&report.Files.Count==0&&!Directory.GetFiles(Safe(run,"fragmented-media")).Any(),"budget exhaustion is incomplete and publishes no successful candidate");
        }
        using(var stop=new CancellationTokenSource()){string run=Fresh("cancel-before");stop.Cancel();bool cancelled=false;nativeRuns++;try{FragmentedMediaRecovery.Recover(image,run,stop.Token,null);}catch(OperationCanceledException){cancelled=true;}Check(cancelled&&!Directory.Exists(run),"pre-cancellation creates no output directory");}
        using(var stop=new CancellationTokenSource()){string run=Fresh("cancel-during");bool cancelled=false;nativeRuns++;try{FragmentedMediaRecovery.Recover(image,run,stop.Token,(a,b)=>stop.Cancel());}catch(OperationCanceledException){cancelled=true;}Check(cancelled&&Report(run).Status=="cancelled"&&!Directory.GetFiles(Safe(run,"fragmented-media")).Any(),"in-flight cancellation remains cancelled with no published candidate");}
        Check(Hash(image)==before,"all limit/cancel controls preserve the native source");
    }
    public static int Main(string[] args)
    {
        try{
            if(args.Length<1||args.Length>3)throw new ArgumentException("Usage: Stz2MediaRecoveryTests.exe <project> [fixtures] [fresh-output]");project=Path.GetFullPath(args[0]);fixtures=Path.GetFullPath(args.Length>1?args[1]:Safe(project,".build/video-stz2-fixtures-current"));corpus=Safe(project,"tests/fixtures/video-stz2");
            string build=Safe(project,".build").TrimEnd('\\','/');work=Path.GetFullPath(args.Length>2?args[2]:Safe(project,".build/stz2-media-tests-"+Guid.NewGuid().ToString("N")));if(!work.StartsWith(build+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||File.Exists(work)||Directory.Exists(work))throw new IOException("Fresh own .build output required");Directory.CreateDirectory(work);
            using(var deadline=new CancellationTokenSource(TimeSpan.FromMinutes(8))){token=deadline.Token;inputsBefore=Binding(fixtures);corpusBefore=Binding(corpus);assemblyBefore=Hash(typeof(FragmentedMediaRecovery).Assembly.Location);engineBefore=Hash(Safe(project,"src/Recovery/Recovery/Engines/FragmentedMediaRecovery.cs"));preparerBefore=Hash(Safe(project,"tests/prepare_stz2_media_fixtures.py"));var cases=Fixtures();TableControls();foreach(var sample in cases)RecoverExact(sample,Safe(fixtures,Str(sample,"image")),Str(sample,"name"),true);Ambiguity(cases.Single(row=>Str(row,"name")=="avc-stz2-16"));LimitsAndCancellation(Safe(fixtures,Str(cases[1],"image")));
                Check(Same(inputsBefore,Binding(fixtures))&&Same(corpusBefore,Binding(corpus))&&assemblyBefore==Hash(typeof(FragmentedMediaRecovery).Assembly.Location)&&engineBefore==Hash(Safe(project,"src/Recovery/Recovery/Engines/FragmentedMediaRecovery.cs"))&&preparerBefore==Hash(Safe(project,"tests/prepare_stz2_media_fixtures.py")),"all input/source/preparer and actual tested assembly bytes remain unchanged");
                File.WriteAllText(Safe(work,"verification.json"),Json.Serialize(new{schema=0,Scope="Own managed native stz2 fixtures and separate table controls; not device/paid/entropy acceptance",status="passed",checks=checks,native_original_cases=4,native_recovery_calls=nativeRuns,table_oracle_controls=tableControls,table_controls_are_decoded_videos=false,decoder_executed=false,helper_executed=false,assembly_sha256=assemblyBefore,engine_source_sha256=engineBefore,fixture_manifest_sha256=ManifestSha,fixtures_before=inputsBefore,fixtures_after=Binding(fixtures),cases=results}),new UTF8Encoding(false));
            }Console.WriteLine("PASS Stz2MediaRecovery: "+checks+" checks; four exact native AVC/HEVC stsz/stz2 originals and every source extent, nineteen separate table-only controls plus boundaries/duplicates, whole-chunk identity/ambiguity, limits/cancel. No helper/device/network or new decoder/entropy/authenticity claim. "+work);return 0;
        }catch(Exception error){if(work!=null&&Directory.Exists(work))try{File.WriteAllText(Safe(work,"failed-verification.json"),Json.Serialize(new{schema=0,Scope="Own synthetic test failure; not recovery acceptance",status="failed",checks=checks,message=error.Message,assembly_sha256_before=assemblyBefore,inputs_before=inputsBefore,recovery_calls_started=nativeRuns}),new UTF8Encoding(false));}catch(IOException){}Console.Error.WriteLine(error);return 1;}
    }
}
