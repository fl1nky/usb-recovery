using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using UsbRecovery;

// This harness must execute the newly packaged helper. Compilation is not acceptance.
public static class PngTwoGapPortableTests
{
    public sealed class Extent { public long ImageOffset,LogicalOffset,Length; }
    public sealed class KnownMap { public string Sha256;public List<Extent> Extents; }
    public sealed class Oracle { public int Width,Height;public string Mode,PixelsSha256; }
    public sealed class Fixture
    {
        public string Name,Image,Original,Sha256,SourceSha256;
        public long Bytes,SourceBytes;
        public int ExpectedCandidates,IdatIndex;
        public bool AllOriginalBytesPresent,IndependentEncoder,NoRecoveryImports;
        public List<long> LogicalCuts;
        public List<Extent> PhysicalExtents;
        public List<KnownMap> KnownMaps;
        public Oracle Oracle;
    }
    public sealed class Manifest { public int Schema;public string GeneratorSha256;public bool IndependentEncoder;public List<Fixture> Cases; }
    public sealed class Candidate
    {
        public string Path,Sha256,Status,Note;
        public long Bytes;
        public List<Extent> Extents;
        public List<List<Extent>> AlternateExtents=new List<List<Extent>>();
    }
    public sealed class Report
    {
        public int Schema,Candidates,ReusedCandidates;
        public string Status,SourceSha256;
        public bool SourceUnchanged,ResumedFromCheckpoint;
        public long OutputBytes,ResumedIndexBytes;
        public List<Candidate> Files;
        public Dictionary<string,int> Skipped;
    }
    sealed class Decoded { public string RawPixelsSha256,RgbSha256;public int Width,Height;public string Mode; }
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    const string FactorySha="f5fc3a7908708e7bda0e103c3581c8ce6ef33dacc029e49a64fd8dbfd376084b";
    const string NativeFactorySha="e971450b938958133c6d6053cac58f4641607f4b5ed20b751d182677d6da86eb";
    const string ManifestSha="92e8a0bb8f2e4446184b07a41e7a2f7d8e5a966c44793f83ec8a40f9658c4e3b";
    static readonly string[] Names={"two-gap-rgb","two-gap-large","two-gap-ambiguous","two-gap-duplicate-middle",
        "physical-order-012","physical-order-021","physical-order-102","physical-order-120","physical-order-201","physical-order-210",
        "unaligned-head","crc-split-0","crc-split-1","crc-split-2","crc-split-3","multi-idat-middle","ancillary-prefix","ancillary-tail",
        "indexed-palette","mixed-intact-three-run-ambiguous"};
    static readonly Dictionary<string,string> BaselineSha=new Dictionary<string,string>{
        {"two-gap-rgb","29caa93faa24cd91f0b88dab2d81722441a217d5796e9a3d559a7e15ef77bcdc"},
        {"two-gap-large","d5c5b65bc5054878002c8771f7318b502e0c23d68701947d382b4cfe1b5a7766"},
        {"two-gap-ambiguous","09ac1c5e93fc58963f03aae880296f70b30006c263453fe08aa938b4336a3c9d"},
        {"two-gap-duplicate-middle","7a57430fd9dfb8c5aaaa44c8c6b8b5e26d05d0352fce6cb4ea3f003fd5a2122f"}};
    static int checks,analyses;
    static string project,fixtures,work;
    static CancellationToken phase;
    static Stopwatch clock;
    static Dictionary<string,string> inputBindingBefore,sourceBindingBefore;
    static string runtimeAppBefore,runtimeHelperBefore;
    static readonly uint[] CrcTable=BuildCrcTable();

    static void Check(bool value,string why){Interlocked.Increment(ref checks);if(!value)throw new Exception(why);}
    static string Safe(string root,string relative){return RecoveryCatalog.SafeFile(root,relative);}
    static string Hex(byte[] value){return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();}
    static string BytesHash(byte[] value){using(var sha=SHA256.Create())return Hex(sha.ComputeHash(value));}
    static string Hash(string path){return RecoveryCore.HashFile(path,phase,(a,b)=>{});}
    static bool Digest(string value){return value!=null&&value.Length==64&&value.All(c=>c>='0'&&c<='9'||c>='a'&&c<='f');}
    static object Field(Dictionary<string,object> row,string key)
    {object value;if(row==null||!row.TryGetValue(key,out value))throw new IOException("Missing required evidence field: "+key);return value;}
    static List<Dictionary<string,object>> Rows(object raw)
    {
        var sequence=raw as IEnumerable;if(sequence==null||raw is string||raw is IDictionary)throw new IOException("Expected evidence array");
        var rows=new List<Dictionary<string,object>>();foreach(object value in sequence){var row=value as Dictionary<string,object>;if(row==null)throw new IOException("Expected evidence row");rows.Add(row);}return rows;
    }
    static Dictionary<string,object> Data(string file)
    {return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file,Encoding.UTF8));}
    static string Canonical(object value)
    {
        var row=value as Dictionary<string,object>;
        if(row!=null)return "{"+String.Join(",",row.OrderBy(pair=>pair.Key,StringComparer.Ordinal).Select(pair=>Json.Serialize(pair.Key)+":"+Canonical(pair.Value)))+"}";
        var list=value as IEnumerable;
        if(value!=null&&!(value is string)&&list!=null)return "["+String.Join(",",list.Cast<object>().Select(Canonical))+"]";
        return Json.Serialize(value);
    }
    static T Guard<T>(Func<CancellationToken,T> action)
    {
        int remaining=(int)Math.Min(285000,1200000-clock.ElapsedMilliseconds);
        if(remaining<=0)throw new TimeoutException("Hard twenty-minute phase watchdog; no completed recovery inferred.");
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(phase)){
            stop.CancelAfter(Math.Max(1,remaining-1000));var task=Task.Run(()=>action(stop.Token));
            if(Task.WaitAny(new Task[]{task},remaining)<0){stop.Cancel();throw new TimeoutException("Hard 4m45 call watchdog; worker completion is unconfirmed, no success inferred.");}
            return task.GetAwaiter().GetResult();
        }
    }
    static string Output(string name)
    {string path=Path.Combine(work,name);if(Directory.Exists(path)||File.Exists(path))throw new IOException("Fresh output required");Directory.CreateDirectory(path);return path;}
    static Dictionary<string,string> Binding(string root)
    {
        root=Path.GetFullPath(root).TrimEnd('\\','/');
        for(var parent=new DirectoryInfo(root);parent!=null;parent=parent.Parent)if((parent.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked input ancestor");
        var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var pending=new Stack<string>();pending.Push(root);
        while(pending.Count>0){string directory=pending.Pop();foreach(string file in Directory.GetFileSystemEntries(directory)){
            var attributes=File.GetAttributes(file);if((attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked input entry");
            if((attributes&FileAttributes.Directory)!=0)pending.Push(file);else result.Add(file.Substring(root.Length+1).Replace('\\','/'),Hash(file));
        }}return result;
    }
    static bool Same(Dictionary<string,string> left,Dictionary<string,string> right)
    {return left.Count==right.Count&&left.All(row=>right.ContainsKey(row.Key)&&right[row.Key]==row.Value);}
    static Dictionary<string,string> SourceInputs()
    {
        var result=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(string relative in new[]{"tests/build_png_two_gap_fixtures.py","tests/build_png_idat_gap_fixtures.py","tests/PngTwoGapPortableTests.cs",
            "helpers/recovery_engine/png_fragments.py","helpers/recovery_engine/fragmented_photos.py","helpers/recovery_engine/jpeg_fragments.py","helpers/recovery_engine/recovery_checkpoint.py"})
            result.Add(relative,Hash(Safe(project,relative)));
        return result;
    }
    static Report ReadReport(string run,bool publicManifest=true)
    {return Json.Deserialize<Report>(File.ReadAllText(Safe(run,publicManifest?"fragmented-photo-search.json":"fragmented-photos/report.json")));}
    static RecoveryOptions Options()
    {return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};}
    static void ReadExact(Stream source,byte[] buffer,int count)
    {int done=0;while(done<count){phase.ThrowIfCancellationRequested();int read=source.Read(buffer,done,count-done);if(read==0)throw new EndOfStreamException();done+=read;}}
    static string Key(IEnumerable<Extent> source)
    {
        var result=new List<Extent>();long logical=0;
        foreach(var range in source){
            Check(range.LogicalOffset==logical&&range.Length>0,"map canonicalization has exact logical coverage");logical+=range.Length;
            if(result.Count>0&&result[result.Count-1].ImageOffset+result[result.Count-1].Length==range.ImageOffset)result[result.Count-1].Length+=range.Length;
            else result.Add(new Extent{ImageOffset=range.ImageOffset,Length=range.Length});
        }
        return String.Join("|",result.Select(range=>range.ImageOffset.ToString(CultureInfo.InvariantCulture)+":"+range.Length.ToString(CultureInfo.InvariantCulture)));
    }
    static void Replay(string image,string file,List<Extent> ranges,long size,string context)
    {
        Check(ranges!=null&&ranges.Count>0&&ranges.Count<=100000,context+": physical ranges present and bounded");
        long logical=0,previousEnd=-1;
        using(var source=File.OpenRead(image))using(var actual=File.OpenRead(file)){
            var left=new byte[65536];var right=new byte[65536];
            foreach(var range in ranges){
                Check(range!=null&&range.ImageOffset>=0&&range.Length>0&&range.LogicalOffset==logical&&range.Length<=size-logical&&range.ImageOffset<=source.Length-range.Length,context+": exact logical coverage and physical bounds");
                source.Position=range.ImageOffset;long remaining=range.Length;
                while(remaining>0){int count=(int)Math.Min(left.Length,remaining);ReadExact(source,left,count);ReadExact(actual,right,count);Check(left.Take(count).SequenceEqual(right.Take(count)),context+": source bytes replay every emitted byte");remaining-=count;}
                logical+=range.Length;
            }
            Check(logical==size&&actual.Length==size&&actual.Position==actual.Length,context+": complete replay size");
        }
        foreach(var range in ranges.OrderBy(value=>value.ImageOffset)){Check(range.ImageOffset>=previousEnd,context+": physical ranges disjoint in all source orders");previousEnd=range.ImageOffset+range.Length;}
    }
    static List<List<Extent>> Maps(Candidate row)
    {
        Check(row.Extents!=null&&row.Extents.Count>=2&&row.AlternateExtents!=null&&row.AlternateExtents.Count<=511,"actual helper supplies primary and bounded optional aliases");
        var maps=new[]{row.Extents}.Concat(row.AlternateExtents).ToList();Check(maps.Select(Key).Distinct(StringComparer.Ordinal).Count()==maps.Count,"actual source maps are canonically distinct, including primary");return maps;
    }
    static List<Extent> CatalogMap(object raw)
    {
        var result=new List<Extent>();long logical=0;
        foreach(var row in Rows(raw)){long offset=Convert.ToInt64(Field(row,"Offset")),length=Convert.ToInt64(Field(row,"Length"));result.Add(new Extent{ImageOffset=offset,LogicalOffset=logical,Length=length});logical+=length;}return result;
    }
    static List<List<Extent>> CatalogMaps(Dictionary<string,object> row,bool exported)
    {
        string primary=exported?"sourceRanges":"SourceRanges",alternatives=exported?"sourceRangeAlternatives":"SourceRangeAlternatives";
        var result=new List<List<Extent>>{CatalogMap(Field(row,primary))};
        var sequence=Field(row,alternatives) as IEnumerable;if(sequence==null||sequence is string)throw new IOException("Missing catalog aliases");
        foreach(object map in sequence)result.Add(CatalogMap(map));return result;
    }
    static void CatalogEvidence(Dictionary<string,object> row,bool exported,Candidate candidate,string sourceSha,long sourceBytes,string context)
    {
        var expected=Maps(candidate).Select(Key).OrderBy(value=>value,StringComparer.Ordinal).ToArray();
        var actual=CatalogMaps(row,exported).Select(Key).OrderBy(value=>value,StringComparer.Ordinal).ToArray();
        Check(actual.SequenceEqual(expected),context+": catalog/export retains all exact physical maps after DTO serialization");
        string offset=exported?"sourceOffset":"SourceOffset";
        if(expected.Length>1)Check(Field(row,offset)==null,context+": multiple maps make the original source offset unknown");
        var groups=Rows(Field(row,exported?"sourceMapGroups":"SourceMapGroups"));
        Check(groups.Count==1,context+": one bound physical image is represented by exactly one source group");
        var group=groups[0];
        Check(Convert.ToBoolean(Field(group,"SourceScopeVerified"))&&Convert.ToBoolean(Field(group,"MappingComplete"))&&
            (string)Field(group,"SourceSha256")==sourceSha&&Convert.ToInt64(Field(group,"SourceBytes"))==sourceBytes,
            context+": source group is bound to this unchanged image, size and complete mapping");
        var groupRaw=Field(group,"Maps") as IEnumerable;if(groupRaw==null||groupRaw is string)throw new IOException("Missing source group maps");
        var grouped=groupRaw.Cast<object>().Select(CatalogMap).Select(Key).OrderBy(value=>value,StringComparer.Ordinal).ToArray();
        Check(grouped.SequenceEqual(expected),context+": source group retains every physical placement without cross-image invention");
        Check(!Convert.ToBoolean(Field(row,exported?"sourceMapGroupsLimited":"SourceMapGroupsLimited"))&&Convert.ToInt64(Field(row,exported?"sourceMapGroupsOmitted":"SourceMapGroupsOmitted"))==0,
            context+": complete small source group has no hidden omitted maps");
    }
    static uint[] BuildCrcTable()
    {var table=new uint[256];for(uint index=0;index<table.Length;index++){uint value=index;for(int bit=0;bit<8;bit++)value=(value>>1)^((value&1)!=0?0xedb88320U:0);table[index]=value;}return table;}
    static uint Crc(byte[] bytes,int start,int length)
    {uint value=0xffffffffU;for(int at=start;at<start+length;at++)value=CrcTable[(value^bytes[at])&255]^(value>>8);return value^0xffffffffU;}
    static uint Big(byte[] raw,int at){return (uint)raw[at]<<24|(uint)raw[at+1]<<16|(uint)raw[at+2]<<8|raw[at+3];}
    static int Paeth(int a,int b,int c)
    {int p=a+b-c,x=Math.Abs(p-a),y=Math.Abs(p-b),z=Math.Abs(p-c);return x<=y&&x<=z?a:y<=z?b:c;}
    static Decoded NativeOracle(string file,Oracle expected)
    {
        byte[] raw=File.ReadAllBytes(file);Check(raw.Length>33&&raw.Take(8).SequenceEqual(new byte[]{137,80,78,71,13,10,26,10}),"independent oracle: PNG signature");
        int at=8,width=0,height=0,channels=0;bool ended=false;byte[] palette=null;var packed=new MemoryStream();
        while(at<raw.Length){
            phase.ThrowIfCancellationRequested();Check(at<=raw.Length-12,"independent oracle: complete chunk header");long length=Big(raw,at);Check(length<=2*1024*1024&&length<=raw.Length-at-12,"independent oracle: bounded chunk");
            string kind=Encoding.ASCII.GetString(raw,at+4,4);int count=(int)length,end=at+count+12;
            Check(Crc(raw,at+4,count+4)==Big(raw,end-4),"independent oracle: original unchanged chunk CRC");
            if(at==8){Check(kind=="IHDR"&&count==13,"independent oracle: initial IHDR");width=checked((int)Big(raw,at+8));height=checked((int)Big(raw,at+12));
                channels=raw[at+17]==2?3:raw[at+17]==3?1:0;
                Check(width>0&&height>0&&width==expected.Width&&height==expected.Height&&raw[at+16]==8&&channels!=0&&raw[at+18]==0&&raw[at+19]==0&&raw[at+20]==0,"independent oracle: exact noninterlaced RGB8/indexed8 geometry");
            }else Check(kind!="IHDR","independent oracle: no duplicate IHDR");
            if(kind=="PLTE"){Check(count>0&&count<=768&&count%3==0,"independent oracle: palette geometry");palette=raw.Skip(at+8).Take(count).ToArray();}
            if(kind=="IDAT")packed.Write(raw,at+8,count);
            if(kind=="IEND"){Check(count==0&&end==raw.Length,"independent oracle: terminal IEND without extra bytes");ended=true;}
            at=end;
        }
        byte[] zlib=packed.ToArray();Check(ended&&zlib.Length>=6&&(zlib[0]&15)==8&&(zlib[0]>>4)<=7&&((zlib[0]<<8)|zlib[1])%31==0&&(zlib[1]&32)==0,"independent oracle: complete PNG and ordinary zlib wrapper");
        int rowBytes=checked(width*channels),expectedInflated=checked(height*(rowBytes+1));Check(expectedInflated<=32*1024*1024,"independent oracle: bounded inflation");
        var inflated=new MemoryStream();using(var input=new MemoryStream(zlib,2,zlib.Length-6,false))using(var deflate=new DeflateStream(input,CompressionMode.Decompress)){
            var block=new byte[65536];int count;while((count=deflate.Read(block,0,block.Length))>0){phase.ThrowIfCancellationRequested();Check(inflated.Length+count<=expectedInflated,"independent oracle: no oversized inflated tail");inflated.Write(block,0,count);}
        }
        byte[] rows=inflated.ToArray();Check(rows.Length==expectedInflated,"independent oracle: full DEFLATE stream row length");uint s1=1,s2=0;foreach(byte value in rows){s1=(s1+value)%65521;s2=(s2+s1)%65521;}
        Check((s2<<16|s1)==Big(zlib,zlib.Length-4),"independent oracle: full unmodified zlib Adler32");
        var pixels=new byte[checked(height*rowBytes)];var prior=new byte[rowBytes];var expanded=new byte[checked(width*height*3)];int rgb=0;
        for(int y=0;y<height;y++){
            phase.ThrowIfCancellationRequested();int position=y*(rowBytes+1),filter=rows[position];Check(filter<=4,"independent oracle: standard PNG filter");var line=new byte[rowBytes];
            for(int x=0;x<rowBytes;x++){int left=x>=channels?line[x-channels]:0,up=prior[x],upperLeft=x>=channels?prior[x-channels]:0;
                int predictor=filter==0?0:filter==1?left:filter==2?up:filter==3?(left+up)/2:Paeth(left,up,upperLeft);line[x]=unchecked((byte)(rows[position+1+x]+predictor));}
            Array.Copy(line,0,pixels,y*rowBytes,rowBytes);prior=line;
            if(channels==3){Array.Copy(line,0,expanded,rgb,rowBytes);rgb+=rowBytes;}
            else {Check(palette!=null,"independent oracle: indexed palette present");foreach(byte index in line){int color=index*3;Check(color<=palette.Length-3,"independent oracle: every palette index exists");expanded[rgb++]=palette[color];expanded[rgb++]=palette[color+1];expanded[rgb++]=palette[color+2];}}
        }
        string mode=channels==3?"RGB":"P",pixelHash=BytesHash(pixels);Check(expected.Mode==mode&&expected.PixelsSha256==pixelHash,"independent raw filter/palette oracle matches pinned native pixels");
        string rgbHash=BytesHash(expanded);Check(GdiPixels(file,width,height)==rgbHash,"independent GDI+ decoder agrees with PNG reverse-filter RGB pixels");
        return new Decoded{RawPixelsSha256=pixelHash,RgbSha256=rgbHash,Width=width,Height=height,Mode=mode};
    }
    static string GdiPixels(string file,int width,int height)
    {
        using(var bitmap=new Bitmap(file)){
            Check(bitmap.Width==width&&bitmap.Height==height,"GDI+ exact PNG dimensions");var pixels=new byte[checked(width*height*3)];int at=0;
            for(int y=0;y<height;y++){phase.ThrowIfCancellationRequested();for(int x=0;x<width;x++){Color color=bitmap.GetPixel(x,y);pixels[at++]=color.R;pixels[at++]=color.G;pixels[at++]=color.B;}}
            return BytesHash(pixels);
        }
    }
    static void Fixtures(Manifest manifest,Dictionary<string,string> binding)
    {
        Check(Hash(Safe(project,"tests/build_png_two_gap_fixtures.py"))==FactorySha&&Hash(Safe(project,"tests/build_png_idat_gap_fixtures.py"))==NativeFactorySha&&Hash(Safe(fixtures,"manifest.json"))==ManifestSha,
            "fixture/factory/native encoder hashes equal the physically frozen independent corpus");
        Check(manifest.Schema==1&&manifest.GeneratorSha256==FactorySha&&manifest.IndependentEncoder&&manifest.Cases!=null&&manifest.Cases.Count==20&&
            manifest.Cases.Select(row=>row.Name).Distinct(StringComparer.Ordinal).Count()==20&&Names.All(name=>manifest.Cases.Any(row=>row.Name==name))&&manifest.Cases.All(row=>Names.Contains(row.Name)),
            "all twenty mandatory native cases exist without skipped/replaced names");
        var rawCases=Rows(Field(Data(Safe(fixtures,"manifest.json")),"Cases"));var expectedFiles=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"manifest.json"};long bytes=0;
        foreach(var item in manifest.Cases){
            bool ambiguous=item.Name=="two-gap-ambiguous"||item.Name=="mixed-intact-three-run-ambiguous";string folder=Safe(fixtures,item.Name),image=Safe(fixtures,item.Image),original=Safe(folder,item.Original);
            Check(item.Image==item.Name+"/image.dd"&&item.Original=="original.png"&&item.AllOriginalBytesPresent&&item.IndependentEncoder&&item.NoRecoveryImports&&item.ExpectedCandidates==(ambiguous?0:1)&&
                Digest(item.Sha256)&&Digest(item.SourceSha256)&&Hash(image)==item.SourceSha256&&new FileInfo(image).Length==item.SourceBytes&&Hash(original)==item.Sha256&&new FileInfo(original).Length==item.Bytes,
                item.Name+": independent originals and source bytes equal the pinned manifest");
            if(BaselineSha.ContainsKey(item.Name))Check(item.Sha256==BaselineSha[item.Name],item.Name+": independently approved pre-feature original remains exact");
            var row=rawCases.Single(value=>(string)value["Name"]==item.Name);var local=new Dictionary<string,object>(row);local["Image"]="image.dd";
            Check(Canonical(local)==Canonical(Data(Safe(folder,"golden.json"))),item.Name+": individual oracle exactly matches pinned aggregate manifest");
            Check(item.Oracle!=null&&item.LogicalCuts!=null&&item.LogicalCuts.Count==2&&item.LogicalCuts[0]<item.LogicalCuts[1]&&item.PhysicalExtents!=null&&item.PhysicalExtents.Count==3&&
                item.KnownMaps!=null&&item.KnownMaps.Count==(item.Name=="two-gap-duplicate-middle"||ambiguous?2:1),item.Name+": independent cuts and complete three-run placements are present");
            long head=item.PhysicalExtents[0].ImageOffset;Check((head+item.LogicalCuts[0])%512==0&&(head+item.LogicalCuts[1])%512==0,item.Name+": both cuts are absolute allocation-unit boundaries");
            Check(Key(item.PhysicalExtents)==Key(item.KnownMaps[0].Extents),item.Name+": primary independent map matches declared physical allocation");
            NativeOracle(original,item.Oracle);
            foreach(var known in item.KnownMaps){
                string target=known.Sha256==item.Sha256?original:Safe(folder,"alternative.png");Check(Hash(target)==known.Sha256,item.Name+": every planted mapping targets real independent bytes");Replay(image,target,known.Extents,new FileInfo(target).Length,item.Name+" independent known map");
            }
            if(ambiguous){string alternative=Safe(folder,"alternative.png");Check(Hash(alternative)!=item.Sha256&&GdiPixels(alternative,item.Oracle.Width,item.Oracle.Height)!=GdiPixels(original,item.Oracle.Width,item.Oracle.Height),item.Name+": both ambiguous native PNGs decode to distinct pixels");expectedFiles.Add(item.Name+"/alternative.png");}
            expectedFiles.Add(item.Name+"/image.dd");expectedFiles.Add(item.Name+"/original.png");expectedFiles.Add(item.Name+"/golden.json");bytes+=item.SourceBytes+item.Bytes;
        }
        Check(binding.Count==63&&new HashSet<string>(binding.Keys,StringComparer.OrdinalIgnoreCase).SetEquals(expectedFiles)&&bytes<32L*1024*1024,"immutable independent corpus has the exact bounded 63-file payload");
        var large=manifest.Cases.Single(row=>row.Name=="two-gap-large");Check(large.LogicalCuts[0]>=131072&&large.LogicalCuts[1]>=1310720,"mandatory late 128KiB/1.31MiB two-gap case cannot be silently reduced");
        var rgb=manifest.Cases.Single(row=>row.Name=="two-gap-rgb");Check(rgb.LogicalCuts[0]>=32768&&rgb.LogicalCuts[1]>=131072,"mandatory 32KiB/128KiB case cannot be silently reduced");
    }
    static void Exact(string run,string image,Fixture fixture,bool gallery)
    {
        var report=ReadReport(run);Check(report.Schema==1&&report.Status=="complete"&&report.SourceUnchanged&&report.SourceSha256==fixture.SourceSha256&&report.Candidates==1&&report.Files.Count==1&&report.OutputBytes==fixture.Bytes,fixture.Name+": complete public report bound to unchanged source");
        var candidate=report.Files.Single();string file=Safe(run,candidate.Path);
        Check(candidate.Sha256==fixture.Sha256&&candidate.Bytes==fixture.Bytes&&Hash(file)==fixture.Sha256&&candidate.Status=="png_crc_zlib_reassembled_candidate"&&candidate.Note!=null&&candidate.Note.Contains("not authenticated"),fixture.Name+": exact bytes retain structural, unauthenticated provenance");
        var maps=Maps(candidate);foreach(var map in maps)Replay(image,file,map,candidate.Bytes,fixture.Name+" actual map");
        foreach(var known in fixture.KnownMaps.Where(row=>row.Sha256==fixture.Sha256))Check(maps.Any(map=>Key(map)==Key(known.Extents)),fixture.Name+": every independently planted physical placement survives content deduplication");
        if(fixture.Name=="two-gap-duplicate-middle")Check(maps.Count==2,fixture.Name+": both distinct middle placements retained, without duplicate maps");
        NativeOracle(file,fixture.Oracle);
        Check(!File.Exists(Safe(run,"fragmented-photos/job.incomplete"))&&!Directory.GetFiles(Safe(run,"fragmented-photos"),"*.partial").Any(),fixture.Name+": complete publication leaves no incomplete marker or partial candidate");
        var index=RecoveryCatalog.Build(run,phase,null);Check(index.Candidates==1&&index.Items.Count==1&&index.Items[0].Quality=="structural_candidate"&&index.Items[0].OriginalPath==null,fixture.Name+": catalog does not authenticate original content or invent an original name");
        CatalogEvidence(Json.Deserialize<Dictionary<string,object>>(Json.Serialize(index.Items[0])),false,candidate,fixture.SourceSha256,fixture.SourceBytes,fixture.Name+" catalog");
        var loaded=RecoveryCatalog.Load(run).Items.Single();CatalogEvidence(Json.Deserialize<Dictionary<string,object>>(Json.Serialize(loaded)),false,candidate,fixture.SourceSha256,fixture.SourceBytes,fixture.Name+" reloaded catalog");
        if(gallery){
            PhotoCatalog.Build(run,phase,null);var photos=Rows(Field(Data(Safe(run,"photo-catalog.json")),"items"));Check(photos.Count==1&&(string)Field(photos[0],"Status")=="decoded",fixture.Name+": gallery decodes actual reconstructed bytes");
            loaded=RecoveryCatalog.Build(run,phase,null).Items.Single();Check(loaded.Quality=="structural_candidate",fixture.Name+": gallery decoding preserves structural uncertainty");
            CatalogEvidence(Json.Deserialize<Dictionary<string,object>>(Json.Serialize(loaded)),false,candidate,fixture.SourceSha256,fixture.SourceBytes,fixture.Name+" after gallery");
            string exported=RecoveryCatalog.Export(run,Output("export-"+fixture.Name),new[]{loaded},phase);var exportedRow=Rows(Field(Data(Safe(exported,"export-manifest.json")),"files")).Single();
            Check(Hash(Safe(exported,(string)Field(exportedRow,"file")))==fixture.Sha256,fixture.Name+": export preserves exact emitted bytes");CatalogEvidence(exportedRow,true,candidate,fixture.SourceSha256,fixture.SourceBytes,fixture.Name+" export");
        }
    }
    static void Wrapper(Fixture fixture)
    {
        string image=Safe(fixtures,fixture.Image),run=Output("wrapper-"+fixture.Name);int progress=0;var session=RecoverySession.Start(run,image,fixture.SourceSha256,Options(),phase);session.Begin("fragmented-photos");
        int count=Guard(token=>FragmentedPhotoRecovery.Recover(image,run,token,(done,total)=>{Interlocked.Increment(ref progress);Check(done>=0&&done<=total,fixture.Name+": bounded actual helper progress");},null,session.CapturePhotoCheckpoint));analyses++;
        session.Finish("fragmented-photos",count,false,phase);session.Status("finished");var report=ReadReport(run);
        Check(count==fixture.ExpectedCandidates&&report.Candidates==fixture.ExpectedCandidates&&report.Status=="complete"&&report.SourceUnchanged&&report.SourceSha256==fixture.SourceSha256&&progress>0&&Hash(image)==fixture.SourceSha256,fixture.Name+": actual helper/public wrapper matches mandatory independent outcome");
        if(count==1)Exact(run,image,fixture,fixture.Name=="two-gap-duplicate-middle"||fixture.Name=="indexed-palette");
        else {
            Check(report.Files.Count==0&&report.OutputBytes==0&&report.Skipped!=null&&report.Skipped.ContainsKey("png_ambiguous")&&report.Skipped["png_ambiguous"]>0,fixture.Name+": distinct valid PNG contents are explicitly ambiguous, never first-success unique");
            Check(!Directory.GetFiles(Safe(run,"fragmented-photos"),"*.png").Any()&&!Directory.GetFiles(Safe(run,"fragmented-photos"),"*.partial").Any()&&RecoveryCatalog.Build(run,phase,null).Items.Count==0,fixture.Name+": ambiguity publishes no hidden successful candidate");
        }
    }
    static void Pipeline(Fixture fixture)
    {
        string image=Safe(fixtures,fixture.Image),run=Output("pipeline-"+fixture.Name),checksum=Safe(run,"baseline.sha256");File.WriteAllText(checksum,fixture.SourceSha256,new UTF8Encoding(false));var updates=new List<RecoveryStageProgress>();
        var result=Guard(token=>RecoveryPipeline.Run(image,run,Options(),token,message=>{},checksum,updates.Add));analyses++;
        Check(result.Candidates==1&&result.UniqueFiles==1&&updates.Any(row=>row.Key=="fragmented-photos"&&row.State=="complete"),"whole public pipeline publishes exactly one complete photo stage");Exact(run,image,fixture,true);
        var stage=RecoverySession.Read(run).Stages.Single();Check(stage.Key=="fragmented-photos"&&stage.Status=="complete"&&stage.Candidates==1&&stage.Artifacts.Count>=3,"whole pipeline binds complete report, maps, outputs and checkpoint artifacts");
        string before=Hash(Safe(run,"fragmented-photo-search.json"));var resumed=Guard(token=>RecoveryPipeline.Resume(run,token,message=>{}));
        Check(resumed.ResumedStages==1&&Hash(Safe(run,"fragmented-photo-search.json"))==before&&Hash(image)==fixture.SourceSha256,"completed-stage resume reuses exact source-bound artifacts without rerunning recovery");
    }
    static void Copy(string source,string destination)
    {
        var before=Binding(source);if(Directory.Exists(destination))throw new IOException("Fresh copy target required");Directory.CreateDirectory(destination);
        foreach(var row in before){string target=Safe(destination,row.Key);Directory.CreateDirectory(Path.GetDirectoryName(target));File.Copy(Safe(source,row.Key),target);}
        Check(Same(before,Binding(destination)),"checkpoint controls use exact independent disposable copies");
    }
    static Fixture TwoStarts(Fixture original)
    {
        byte[] bytes=File.ReadAllBytes(Safe(Safe(fixtures,original.Name),original.Original)),image=Enumerable.Repeat((byte)0xa5,512*1024).ToArray();var known=new List<KnownMap>();
        foreach(long[] positions in new[]{new long[]{8192,65536,131072},new long[]{196608,262144,327680}}){
            var map=new List<Extent>();long[] edges={0,4096,32768,bytes.Length};
            for(int index=0;index<3;index++){long length=edges[index+1]-edges[index];Array.Copy(bytes,edges[index],image,positions[index],length);map.Add(new Extent{ImageOffset=positions[index],LogicalOffset=edges[index],Length=length});}
            known.Add(new KnownMap{Sha256=original.Sha256,Extents=map});
        }
        string source=Safe(work,"two-starts-owned.dd");File.WriteAllBytes(source,image);string sha=Hash(source);
        foreach(var map in known)Replay(source,Safe(Safe(fixtures,original.Name),original.Original),map.Extents,bytes.Length,"independent two-start known placement");
        File.WriteAllText(Safe(work,"two-starts-oracle.json"),Json.Serialize(new{Image="two-starts-owned.dd",SourceSha256=sha,SourceBytes=image.Length,OriginalSha256=original.Sha256,KnownMaps=known,Oracle=original.Oracle,OriginalBytesNeverPassedToHelper=true}),new UTF8Encoding(false));
        return new Fixture{Name="two-starts",Image=source,Original=original.Original,Sha256=original.Sha256,Bytes=bytes.Length,SourceBytes=image.Length,SourceSha256=sha,KnownMaps=known,Oracle=original.Oracle,ExpectedCandidates=1};
    }
    static void RejectCheckpoint(string run,SessionStage saved,string image,string mode)
    {
        string copy=Safe(work,"checkpoint-"+mode);Copy(run,copy);string point=Safe(copy,saved.CheckpointPath);var state=Data(point);string expected;
        if(mode=="hash") {File.AppendAllText(point," ",new UTF8Encoding(false));expected="PHOTO_CHECKPOINT_HASH_MISMATCH";}
        else if(mode=="code") {var binding=(Dictionary<string,object>)Field(state,"Binding");Check(Digest((string)Field(binding,"CodeSha256")),"actual checkpoint has a code fingerprint");binding["CodeSha256"]=new string((string)binding["CodeSha256"]==new string('0',64)?'f':'0',64);File.WriteAllText(point,Json.Serialize(state),new UTF8Encoding(false));expected="PHOTO_CHECKPOINT_BINDING_MISMATCH";}
        else {
            var record=Rows(Field(state,"Files")).Single();var maps=Field(record,"AlternateExtents") as IEnumerable;Check(maps!=null&&maps.Cast<object>().Any(),"actual first-start checkpoint has aliases for map-tamper regression");
            var map=Rows(maps.Cast<object>().First());map[0]["ImageOffset"]=450560L;File.WriteAllText(point,Json.Serialize(state),new UTF8Encoding(false));expected="PHOTO_CHECKPOINT_OUTPUT_CHANGED";
        }
        var anchor=new PhotoRecoveryCheckpoint{Path=point,Sha256=mode=="hash"?saved.CheckpointSha256:Hash(point),Sequence=saved.CheckpointSequence};var before=Binding(copy);
        var result=Guard(token=>HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="fragmented_photos",source=image,destination=Safe(copy,"fragmented-photos"),options=new{resume_checkpoint=anchor}},token,message=>{}));analyses++;
        Check(result.Status=="error"&&result.Code==expected&&Same(before,Binding(copy)),"actual helper rejects "+mode+" checkpoint tamper with exact error and unchanged copied output");
    }
    static void CancelResume(Fixture original)
    {
        var fixture=TwoStarts(original);string image=fixture.Image,run=Output("cancel-two-starts");var session=RecoverySession.Start(run,image,fixture.SourceSha256,Options(),phase);session.Begin("fragmented-photos");
        bool acknowledged=false;int initialMaps=0;bool cancelled=Guard(token=>{
            using(var stop=CancellationTokenSource.CreateLinkedTokenSource(token)){
                bool stopped=false;try{FragmentedPhotoRecovery.Recover(image,run,stop.Token,(done,total)=>{},null,checkpoint=>{
                    if(stop.IsCancellationRequested)return;session.CapturePhotoCheckpoint(checkpoint);var state=Data(checkpoint.Path);var cursor=(Dictionary<string,object>)Field(state,"Cursor");
                    if((string)Field(state,"Phase")=="candidates"&&Convert.ToInt64(Field(cursor,"Png"))==1){
                        var record=Rows(Field(state,"Files")).Single();Check((string)Field(record,"Sha256")==fixture.Sha256,"acknowledged first-start checkpoint commits the independent exact output");
                        var aliases=Field(record,"AlternateExtents") as IEnumerable;Check(aliases!=null,"first-start checkpoint explicitly retains same-content physical aliases");initialMaps=1+aliases.Cast<object>().Count();acknowledged=true;stop.Cancel();
                    }
                });}catch(OperationCanceledException){stopped=true;}token.ThrowIfCancellationRequested();return stopped;
            }
        });analyses++;
        Check(cancelled&&acknowledged&&initialMaps>=2,"actual cancellation follows an acknowledged first PNG start, before second start is committed");session.Fail("fragmented-photos","cancelled",null);session.Status("cancelled");var saved=RecoverySession.Read(run).Stages.Single();
        Check(saved.CheckpointSequence>0&&saved.Status=="cancelled"&&File.Exists(Safe(run,"fragmented-photos/job.incomplete"))&&!File.Exists(Safe(run,"files-index.json")),"cancelled parent retains incomplete state without publishing successful catalog");
        string candidatePath=Safe(run,"fragmented-photos/png-"+fixture.Sha256+".png");string stored=File.Exists(candidatePath)?candidatePath:candidatePath+".partial";
        Check(File.Exists(stored)&&Hash(stored)==fixture.Sha256,"acknowledged first output exists before resume");long ticks=File.GetLastWriteTimeUtc(stored).Ticks;
        RejectCheckpoint(run,saved,image,"hash");RejectCheckpoint(run,saved,image,"code");RejectCheckpoint(run,saved,image,"map");
        Guard(token=>RecoveryPipeline.Resume(run,token,message=>{}));analyses++;var report=ReadReport(run);
        Check(report.ResumedFromCheckpoint&&report.ResumedIndexBytes==fixture.SourceBytes&&report.ReusedCandidates==1&&report.Candidates==1&&report.OutputBytes==fixture.Bytes,"actual resumed worker reuses first output and the whole verified source index, without recopying duplicate content");
        Check(Hash(candidatePath)==fixture.Sha256&&File.GetLastWriteTimeUtc(candidatePath).Ticks==ticks,"resuming and adding source aliases does not rewrite the previously committed output bytes");
        Check(Maps(report.Files.Single()).Count>initialMaps,"second PNG start adds physical aliases to the previously committed content");Exact(run,image,fixture,true);
        var checkpoints=Directory.GetFiles(Safe(run,"fragmented-photos.state"),"checkpoint-*.json").Select(Data).ToList();
        Check(checkpoints.Any(state=>state.ContainsKey("AliasUpdates")&&Rows(state["AliasUpdates"]).Any(update=>(string)Field(update,"Sha256")==fixture.Sha256&&((IEnumerable)Field(update,"AddedExtents")).Cast<object>().Any())),"cross-start source aliases are durably anchored as append-only checkpoint updates");
        string before=Hash(Safe(run,"fragmented-photo-search.json"));var complete=Guard(token=>RecoveryPipeline.Resume(run,token,message=>{}));Check(complete.ResumedStages==1&&Hash(Safe(run,"fragmented-photo-search.json"))==before&&Hash(image)==fixture.SourceSha256,"completed resumed stage and its alias map chain are reusable without source mutation");
    }
    static void Limits(Fixture fixture)
    {
        string image=Safe(fixtures,fixture.Image),run=Output("limited-three-run");PhotoRecoveryCheckpoint last=null;
        var result=Guard(token=>HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="fragmented_photos",source=image,destination=Safe(run,"fragmented-photos"),options=new{max_states=1}},token,message=>{},update=>{
            if(update.Phase=="photo_checkpoint")last=new PhotoRecoveryCheckpoint{Path=update.CheckpointPath,Sha256=update.CheckpointSha256,Sequence=update.CheckpointSequence};
        }));analyses++;
        var report=ReadReport(run,false);Check(result.Status=="partial"&&result.Files==0&&report.Status=="limited"&&report.Candidates==0&&report.Files.Count==0&&report.SourceUnchanged&&report.SourceSha256==fixture.SourceSha256,"one-state three-run search is explicitly incomplete, never recovered or unique");
        Check(report.Skipped!=null&&report.Skipped.Keys.Any(key=>key.EndsWith("_incomplete",StringComparison.Ordinal))&&last!=null&&File.Exists(Safe(run,"fragmented-photos/job.incomplete")),"bounded incomplete join has explicit reason, marker and acknowledged checkpoint");
        Check(Convert.ToInt64(Field((Dictionary<string,object>)Field(Data(last.Path),"Cursor"),"Png"))==0&&Hash(image)==fixture.SourceSha256&&!File.Exists(Safe(run,"fragmented-photo-search.json"))&&!File.Exists(Safe(run,"files-index.json")),"incomplete direct worker keeps PNG cursor before unsearched alternatives and publishes no public success catalog");
    }
    static void FailedEvidence(Exception error)
    {
        if(work==null)return;
        try{
            var inputsAfter=fixtures!=null&&Directory.Exists(fixtures)?Binding(fixtures):null;
            var sourceAfter=project!=null?SourceInputs():null;
            string appAfter=runtimeAppBefore==null?null:Hash(typeof(RecoveryCore).Assembly.Location),helperAfter=runtimeHelperBefore==null?null:Hash(HelperClient.Executable);
            File.WriteAllText(Safe(work,"failed-acceptance.json"),Json.Serialize(new{Schema=1,Status="FAIL",Error=error.GetType().Name,Message=error.Message,Checks=checks,CompletedAnalyses=analyses,
                AfterChecks="COMPLETED",FilesBefore=inputBindingBefore,FilesAfter=inputsAfter,SourceInputsBefore=sourceBindingBefore,SourceInputsAfter=sourceAfter,
                AppSha256Before=runtimeAppBefore,AppSha256After=appAfter,HelperSha256Before=runtimeHelperBefore,HelperSha256After=helperAfter,
                InputsUnchanged=inputBindingBefore!=null&&inputsAfter!=null&&Same(inputBindingBefore,inputsAfter),SourceInputsUnchanged=sourceBindingBefore!=null&&sourceAfter!=null&&Same(sourceBindingBefore,sourceAfter),
                RuntimeUnchanged=runtimeAppBefore!=null&&runtimeHelperBefore!=null&&runtimeAppBefore==appAfter&&runtimeHelperBefore==helperAfter,WorkerOutputsPreserved=true,NoSuccessfulAcceptanceInferred=true}),new UTF8Encoding(false));
        }catch(Exception afterError){
            File.WriteAllText(Safe(work,"failed-acceptance.json"),Json.Serialize(new{Schema=1,Status="FAIL",Error=error.GetType().Name,Message=error.Message,Checks=checks,CompletedAnalyses=analyses,
                AfterChecks="NOT_COMPLETED",AfterError=afterError.GetType().Name,AfterMessage=afterError.Message,FilesBefore=inputBindingBefore,SourceInputsBefore=sourceBindingBefore,
                AppSha256Before=runtimeAppBefore,HelperSha256Before=runtimeHelperBefore,WorkerOutputsPreserved=true,NoSuccessfulAcceptanceInferred=true}),new UTF8Encoding(false));
        }
    }
    public static int Main(string[] args)
    {
        try{
            if(args.Length!=1)throw new ArgumentException("Usage: PngTwoGapPortableTests.exe <project>");
            using(var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(20))){
                phase=timeout.Token;clock=Stopwatch.StartNew();project=Path.GetFullPath(args[0]);fixtures=Safe(project,".build/png-two-gap-fixtures-current");work=Safe(project,".build/png-two-gap-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
                var inputsBefore=Binding(fixtures);inputBindingBefore=inputsBefore;var sourceBefore=SourceInputs();sourceBindingBefore=sourceBefore;var manifest=Json.Deserialize<Manifest>(File.ReadAllText(Safe(fixtures,"manifest.json")));Fixtures(manifest,inputsBefore);
                Check(File.Exists(HelperClient.Executable),"actual packaged helper is present");string helperBefore=Hash(HelperClient.Executable),appBefore=Hash(typeof(RecoveryCore).Assembly.Location);runtimeAppBefore=appBefore;runtimeHelperBefore=helperBefore;
                File.WriteAllText(Safe(work,"inputs-before.json"),Json.Serialize(new{Schema=1,FixtureManifestSha256=ManifestSha,FactorySha256=FactorySha,NativeFactorySha256=NativeFactorySha,SourceInputs=sourceBefore,Files=inputsBefore,App=typeof(RecoveryCore).Assembly.Location,AppSha256=appBefore,Helper=HelperClient.Executable,HelperSha256=helperBefore}),new UTF8Encoding(false));
                foreach(var fixture in manifest.Cases)Wrapper(fixture);
                Pipeline(manifest.Cases.Single(row=>row.Name=="two-gap-rgb"));CancelResume(manifest.Cases.Single(row=>row.Name=="physical-order-012"));Limits(manifest.Cases.Single(row=>row.Name=="two-gap-rgb"));
                var inputsAfter=Binding(fixtures);var sourceAfter=SourceInputs();string helperAfter=Hash(HelperClient.Executable),appAfter=Hash(typeof(RecoveryCore).Assembly.Location);
                Check(Same(inputsBefore,inputsAfter)&&Same(sourceBefore,sourceAfter)&&helperAfter==helperBefore&&appAfter==appBefore,"all original source fixtures, tested source inputs and actual app/helper remain byte-identical");
                File.WriteAllText(Safe(work,"acceptance.json"),Json.Serialize(new{Schema=1,Status="PASS",RuntimeExecuted=true,ActualHelperExecuted=true,Checks=checks,Analyses=analyses,FixtureManifestSha256=ManifestSha,FactorySha256=FactorySha,NativeFactorySha256=NativeFactorySha,
                    Cases=manifest.Cases.Select(row=>new{row.Name,row.ExpectedCandidates,row.Sha256,row.SourceSha256}).ToArray(),SourceInputsBefore=sourceBefore,SourceInputsAfter=sourceAfter,FilesBefore=inputsBefore,FilesAfter=inputsAfter,
                    AppSha256Before=appBefore,AppSha256After=appAfter,HelperSha256Before=helperBefore,HelperSha256After=helperAfter,RealDevicesTested=false,NewPaidComparisonRun=false,AuthenticatesOriginalOwnership=false}),new UTF8Encoding(false));
                Console.WriteLine("PASS PngTwoGapPortable: "+checks+" checks; "+analyses+" actual helper/public analyses, all20 mandatory native cases/18 exact outputs/both ambiguities, original CRC/Adler/filter/palette plus independent GDI pixels, every physical map replayed, source aliases/catalog/export/groups, two-start checkpoint cancellation/tamper/code binding/reuse and incomplete limits. Own regular images only; no devices, vendor comparison or authenticated original claim.");
            }return 0;
        }catch(Exception error){FailedEvidence(error);Console.Error.WriteLine(error);return 1;}
    }
}
