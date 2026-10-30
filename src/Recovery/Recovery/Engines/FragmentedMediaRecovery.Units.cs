using System;
using System.Collections.Generic;
using System.Linq;

namespace UsbRecovery
{
    public static partial class FragmentedMediaRecovery
    {
        // Allocation-unit search is a narrower, explicit hypothesis than a
        // general byte permutation. Every unit needs a container/sample anchor.
        // Sample tables declare offsets and lengths, not hashes or ownership.
        const int UnitCellLimit=4096,UnitStateLimit=8192;
        const int UnitMetadataLimit=65536,UnitMetadataParts=8,UnitMemoryLimit=32*1024*1024;
        sealed class UnitHead {public long At;public byte[] Raw;}
        sealed class UnitIndex
        {
            public Dictionary<string,List<long>> Audio=new Dictionary<string,List<long>>(StringComparer.Ordinal);
            public int States,MetadataProbes,AudioMatches;
            public long MetadataCacheBytes;
        }
        sealed class UnitAudioQuery {public int Residue;public UnitSample Sample;public List<long> Positions=new List<long>();}
        sealed class UnitSample {public long Logical;public int Bytes;public Chunk Chunk;}
        sealed class UnitCopy {public long At;public int Length,ContentId;public string Sha;public List<long> Copies=new List<long>(),Choices=new List<long>();}
        sealed class UnitLocation {public int Cell;public long At,End;public string Key;}
        sealed class UnitOption {public UnitCopy Copy;public long At;}
        sealed class UnitFixed {public long Logical;public byte[] Raw;}
        sealed class UnitPlan {public Movie Movie;public List<Extent> Extents;public string Hash;}
        static bool UnitFallbackCode(string code){return code=="chunk_missing_or_invalid"||code=="aac_chunk_missing_or_invalid"||code=="aac_boundary_invalid"||code=="audio_geometry_overlap_or_bounds";}
        static IEnumerable<Extent> MetadataExtents(long logical,Atom atom)
        {
            if(atom.Parts==null)return new[]{Ext(logical,atom,"moov")};
            return atom.Parts.Select(e=>new Extent{LogicalOffset=logical+e.LogicalOffset,ImageOffset=e.ImageOffset,Length=e.Length,Kind="moov",EquivalentOffsets=new List<long>{e.ImageOffset}});
        }
        static int Mod(long value,int n){int r=(int)(value%n);return r<0?r+n:r;}
        static void UnitIndexAt(Context c)
        {
            if(c.Units==null)c.Units=new UnitIndex();
        }
        static IEnumerable<UnitHead> UnitHeads(Context c,int phase)
        {
            for(long at=0;at<c.Input.Length;at+=BlockBytes){
                c.Cancel.ThrowIfCancellationRequested();int count=(int)Math.Min(BlockBytes,c.Input.Length-at);
                byte[] raw=c.Read(at,(int)Math.Min(count+64L,c.Input.Length-at));
                for(int p=Mod(phase-at,512);p<count;p+=512){
                    c.Cancel.ThrowIfCancellationRequested();if(p+8>raw.Length)continue;int n=Math.Min(64,raw.Length-p);var head=new byte[n];Buffer.BlockCopy(raw,p,head,0,n);yield return new UnitHead{At=at+p,Raw=head};
                }
            }
        }
        static List<UnitSample> UnitSamples(Movie movie)
        {
            var result=new List<UnitSample>();foreach(var chunk in movie.Chunks){long logical=chunk.Logical;foreach(int bytes in chunk.Samples){result.Add(new UnitSample{Logical=logical,Bytes=bytes,Chunk=chunk});logical+=bytes;}}
            if(result.Count>8192)throw new Reject("unit_sample_limit");return result;
        }
        static bool UnitSampleValid(byte[] raw,Chunk chunk)
        {
            string code;if(chunk.Codec=="mp4a")return AacLcValidator.TryValidate(raw,chunk.Channels,chunk.AudioFrequency,out code);
            if(chunk.Codec=="jpeg"||chunk.Codec=="mjpg")return JpegValid(raw,chunk.Width,chunk.Height);
            if(chunk.Hevc!=null){HevcSampleValidator.SampleInfo info;return HevcSampleValidator.TryValidateSample(raw,chunk.Hevc,out info,out code);}
            return AvcValid(raw);
        }
        static string UnitAudioKey(UnitSample sample,int phase)
        {
            return Mod(sample.Logical+phase,512)+":"+sample.Bytes+":"+sample.Chunk.Channels+":"+sample.Chunk.AudioFrequency;
        }
        static bool UnitAudioEnd(byte[] raw,int at,int length)
        {
            if(length<2)return false;int last=raw[at+length-1];if(last==0)return false;int zero=0;while((last&(1<<zero))==0)zero++;
            int tail=(raw[at+length-2]<<8)|last;return ((tail>>zero)&7)==7;
        }
        static void UnitAudioIndex(Context c,List<UnitSample> samples,int phase)
        {
            var queries=new Dictionary<string,UnitAudioQuery>(StringComparer.Ordinal);
            foreach(var sample in samples.Where(x=>x.Chunk.Codec=="mp4a"&&x.Bytes<=AacLcValidator.MaximumSampleBytes)){
                string key=UnitAudioKey(sample,phase);if(!c.Units.Audio.ContainsKey(key)&&!queries.ContainsKey(key)){if(c.Units.Audio.Count+queries.Count>=c.Limits.MaxCandidates)throw new Budget();queries.Add(key,new UnitAudioQuery{Residue=Mod(sample.Logical+phase,512),Sample=sample});}
            }
            if(queries.Count==0)return;int extra=queries.Values.Max(x=>x.Sample.Bytes);
            for(long at=0;at<c.Input.Length;at+=BlockBytes){
                c.Cancel.ThrowIfCancellationRequested();int count=(int)Math.Min(BlockBytes,c.Input.Length-at);byte[] raw=c.Read(at,(int)Math.Min(count+(long)extra,c.Input.Length-at));
                foreach(var query in queries.Values){
                    c.Cancel.ThrowIfCancellationRequested();var sample=query.Sample;
                    for(int p=Mod(query.Residue-at,512);p<count&&p<=raw.Length-sample.Bytes;p+=512){
                        if((p&65535)==query.Residue)c.Cancel.ThrowIfCancellationRequested();if(!AacLcValidator.IsPossibleStart(raw,p)||!UnitAudioEnd(raw,p,sample.Bytes))continue;
                        if(sample.Bytes>c.Limits.MaxVerifiedBytes-c.Report.VerifiedBytes)throw new Budget();c.Report.VerifiedBytes+=sample.Bytes;
                        byte[] bytes=new byte[sample.Bytes];Buffer.BlockCopy(raw,p,bytes,0,bytes.Length);if(!UnitSampleValid(bytes,sample.Chunk))continue;
                        if(++c.Units.AudioMatches>c.Limits.MaxCandidates)throw new Budget();query.Positions.Add(at+p);
                    }
                }
            }
            foreach(var query in queries)c.Units.Audio.Add(query.Key,query.Value.Positions);
        }
        static bool UnitVideoHeader(Context c,long at,UnitSample sample)
        {
            if(at>c.Input.Length-8)return false;var chunk=sample.Chunk;
            if(chunk.Codec=="jpeg"||chunk.Codec=="mjpg"){byte[] b=c.Read(at,3);return b[0]==255&&b[1]==216&&b[2]==255;}
            int prefix=chunk.Hevc==null?4:chunk.Hevc.NalLengthBytes;byte[] raw=c.Read(at,prefix+3);long size=0;for(int n=0;n<prefix;n++)size=(size<<8)|raw[n];
            if(size<1||size>sample.Bytes-prefix)return false;
            if(chunk.Hevc!=null)return HevcSampleValidator.IsPossibleSampleStart(raw,0,raw.Length,prefix);
            int kind=raw[4]&31;return (raw[4]&128)==0&&(kind==1||kind==5||kind==6||kind==7||kind==8||kind==9);
        }
        static bool UnitCellValid(byte[] raw,long logical,List<UnitFixed> known,List<UnitSample> samples)
        {
            long end=logical+raw.Length;
            foreach(var fixedBytes in known){long left=Math.Max(logical,fixedBytes.Logical),right=Math.Min(end,fixedBytes.Logical+fixedBytes.Raw.Length);for(long p=left;p<right;p++)if(raw[(int)(p-logical)]!=fixedBytes.Raw[(int)(p-fixedBytes.Logical)])return false;}
            foreach(var sample in samples){if(sample.Logical<logical||sample.Logical+sample.Bytes>end)continue;byte[] bytes=new byte[sample.Bytes];Buffer.BlockCopy(raw,(int)(sample.Logical-logical),bytes,0,bytes.Length);if(!UnitSampleValid(bytes,sample.Chunk))return false;}
            return true;
        }
        static void UnitSeed(Context c,HashSet<long>[] cells,int unit,int length,int phase,long logical,long physical)
        {
            if(logical<0||logical>=length)return;int cell=(int)(logical/unit);long origin=physical-logical%unit;int count=Math.Min(unit,length-cell*unit);
            if(origin<0||origin>c.Input.Length-count||Mod(origin,512)!=phase)return;
            cells[cell].Add(origin);if(cells[cell].Count>256)throw new Budget();
        }
        static List<Extent> UnitSolve(Context c,int unit,int length,List<UnitFixed> known,List<UnitSample> samples,List<Extent> metadata,int phase,out string digest)
        {
            digest=null;int count=(length+unit-1)/unit;if(count>UnitCellLimit)return null;
            bool ranged=length>16*1024*1024;
            var seeds=Enumerable.Range(0,count).Select(x=>new HashSet<long>()).ToArray();
            if(ranged){seeds=RangeUnitSeeds(c,unit,length,known,samples,metadata,phase);if(seeds==null)return null;}
            else {
            foreach(var e in metadata){for(long p=e.LogicalOffset;p<e.LogicalOffset+e.Length;p=(p/unit+1)*unit)UnitSeed(c,seeds,unit,length,phase,p,e.ImageOffset+p-e.LogicalOffset);}
            foreach(var sample in samples){
                c.Cancel.ThrowIfCancellationRequested();int within=(int)(sample.Logical%unit);
                if(sample.Chunk.Codec=="mp4a"){
                    if(sample.Bytes>unit-within)continue;
                    List<long> positions;if(c.Units.Audio.TryGetValue(UnitAudioKey(sample,phase),out positions))foreach(long at in positions)UnitSeed(c,seeds,unit,length,phase,sample.Logical,at);
                }else{
                    int header=sample.Chunk.Hevc==null?5:sample.Chunk.Hevc.NalLengthBytes+2;if(header>unit-within)continue;
                    var positions=sample.Chunk.Codec=="jpeg"||sample.Chunk.Codec=="mjpg"?c.Jpeg:sample.Chunk.Hevc!=null?c.Hevc:c.Avc;
                    foreach(long at in positions){c.Cancel.ThrowIfCancellationRequested();if(Mod(at-sample.Logical,512)==phase&&UnitVideoHeader(c,at,sample))UnitSeed(c,seeds,unit,length,phase,sample.Logical,at);}
                }
            }
            if(seeds.Any(x=>x.Count==0))return null;
            }
            var candidates=new List<UnitCopy>[count];long retained=0;
            for(int cell=0;cell<count;cell++){
                int bytes=Math.Min(unit,length-cell*unit);var groups=new Dictionary<string,UnitCopy>(StringComparer.Ordinal);
                foreach(long at in seeds[cell].OrderBy(x=>x)){
                    if(ranged){if(!UnitCellRangeValid(c,at,(long)cell*unit,bytes,known,samples))continue;}
                    else {byte[] raw=c.Read(at,bytes,true);if(!UnitCellValid(raw,(long)cell*unit,known,samples))continue;}
                    string hash=HashRange(c,at,bytes);UnitCopy copy;
                    if((retained+=512)>UnitMemoryLimit)throw new Budget();if(groups.TryGetValue(hash,out copy)){copy.Copies.Add(at);continue;}
                    if((retained+=1024)>UnitMemoryLimit)throw new Budget();copy=new UnitCopy{At=at,Length=bytes,Sha=hash,ContentId=groups.Count};copy.Copies.Add(at);groups.Add(hash,copy);
                }
                candidates[cell]=groups.Values.ToList();if(candidates[cell].Count==0)return null;
            }
            // Equal-byte copies are interchangeable only if every other cell
            // sees exactly the same overlap constraints. Greedy copy selection
            // otherwise can hide a second, distinct valid file assignment.
            var locations=new List<UnitLocation>();for(int cell=0;cell<count;cell++)for(int item=0;item<candidates[cell].Count;item++)foreach(long at in candidates[cell][item].Copies)locations.Add(new UnitLocation{Cell=cell,At=at,End=at+candidates[cell][item].Length,Key=cell+":"+item+":"+at});
            locations=locations.OrderBy(x=>x.At).ThenBy(x=>x.Cell).ToList();int comparisons=0;
            for(int cell=0;cell<count;cell++)foreach(var item in candidates[cell]){
                c.Cancel.ThrowIfCancellationRequested();var seen=new HashSet<string>(StringComparer.Ordinal);
                foreach(long at in item.Copies){int low=0,high=locations.Count;while(low<high){int middle=low+(high-low)/2;if(locations[middle].At<at-unit+1)low=middle+1;else high=middle;}var key=new System.Text.StringBuilder();
                    for(int n=low;n<locations.Count&&locations[n].At<at+item.Length;n++){if((++comparisons&255)==0)c.Cancel.ThrowIfCancellationRequested();if(comparisons>1000000)throw new Budget();var other=locations[n];if(other.Cell!=cell&&other.End>at)key.Append(other.Key).Append('|');}
                    if(seen.Add(key.ToString()))item.Choices.Add(at);
                }
            }
            int[] order=Enumerable.Range(0,count).OrderBy(x=>candidates[x].Sum(item=>item.Choices.Count)).ThenBy(x=>x).ToArray();var assigned=new UnitCopy[count];var positionsChosen=new long[count];var mapped=new bool[count];List<Extent> result=null;string firstHash=null,firstContent=null;
            var options=order.Select(cell=>candidates[cell].SelectMany(item=>item.Choices.Select(at=>new UnitOption{Copy=item,At=at})).ToArray()).ToArray();var next=new int[count];int depth=0;
            // Iterative DFS: the cell limit is a resource bound, not a CLR
            // recursion-depth assumption. A long uniquely anchored movie must
            // not be able to cause an uncatchable stack overflow.
            while(depth>=0){
                c.Cancel.ThrowIfCancellationRequested();
                if(depth==count){string key=String.Join(",",assigned.Select(x=>x.ContentId));string hash=key==firstContent?firstHash:HashUnitMap(c,assigned,positionsChosen);if(firstHash!=null&&hash!=firstHash)throw new Reject("unit_mapping_ambiguous");if(firstHash==null){firstHash=hash;firstContent=key;result=Enumerable.Range(0,count).Select(x=>new Extent{ImageOffset=positionsChosen[x],LogicalOffset=(long)x*unit,Length=assigned[x].Length,Kind="allocation_unit",EquivalentOffsets=new List<long>(assigned[x].Copies)}).ToList();}depth--;if(depth>=0)mapped[order[depth]]=false;continue;}
                int cell=order[depth];if(next[depth]>=options[depth].Length){next[depth]=0;assigned[cell]=null;mapped[cell]=false;depth--;if(depth>=0)mapped[order[depth]]=false;continue;}
                var option=options[depth][next[depth]++];var item=option.Copy;long at=option.At;if(++c.Units.States>UnitStateLimit)throw new Budget();
                    bool overlap=false;for(int x=0;x<count;x++)if(mapped[x]&&at<positionsChosen[x]+assigned[x].Length&&positionsChosen[x]<at+item.Length){overlap=true;break;}
                    if(overlap)continue;assigned[cell]=item;positionsChosen[cell]=at;mapped[cell]=true;bool valid=true;
                    foreach(var sample in samples){int first=(int)(sample.Logical/unit),last=(int)((sample.Logical+sample.Bytes-1)/unit);if(cell<first||cell>last)continue;bool complete=true;for(int x=first;x<=last;x++)if(!mapped[x]){complete=false;break;}if(!complete)continue;if(!UnitRangeSampleValid(sample,(logical,bytes)=>ReadUnitMap(c,assigned,positionsChosen,unit,length,logical,bytes))){valid=false;break;}}
                    if(valid){depth++;if(depth<count)next[depth]=0;}else{mapped[cell]=false;assigned[cell]=null;}
            }
            digest=firstHash;return result;
        }
        static UnitPlan PlanUnits(Context c,Movie movie)
        {
            var metadata=Layout(c,movie);long end=Math.Max(metadata.Max(x=>x.LogicalOffset+x.Length),movie.Chunks.Max(x=>x.Logical+x.Bytes));
            if(end>MaximumFileBytes||end>UnitCellLimit*65536L)throw new Reject("unit_file_limit");int length=(int)end;var samples=UnitSamples(movie);if(!samples.Any(x=>x.Chunk.Codec!="mp4a"))throw new Reject("video_anchor_missing");UnitIndexAt(c);
            var known=metadata.Select(x=>new UnitFixed{Logical=x.LogicalOffset,Raw=c.Read(x.ImageOffset,(int)x.Length,true)}).ToList();int phase=Mod(metadata.Single(x=>x.Kind=="ftyp").ImageOffset,512);if(length<=16*1024*1024)UnitAudioIndex(c,samples,phase);List<Extent> chosen=null;string expected=null;
            for(int unit=512;unit<=65536;unit*=2){string hash;var extents=UnitSolve(c,unit,length,known,samples,metadata,phase,out hash);if(extents==null)continue;if(expected!=null&&hash!=expected)throw new Reject("unit_mapping_ambiguous");if(chosen==null){chosen=extents;expected=hash;}}
            if(chosen==null)throw new Reject("unit_mapping_missing");return new UnitPlan{Movie=movie,Extents=chosen,Hash=expected};
        }
        static Result WriteUnits(Context c,UnitPlan plan,string folder)
        {
            var result=WriteCandidate(c,plan.Movie,folder,plan.Extents,true,plan.Hash);
            result.AudioSearch=result.AudioChunks==0?null:"allocation_unit_syntax";result.Note="A unique byte result was found within bounded 512..65536-byte allocation-unit hypotheses. Every unit had a container or sample anchor; complete AAC-LC syntax and supported video/container structure were checked across joins. Opaque AVC/HEVC entropy and reference pictures were not decoded or authenticated. Unanchored interiors, arbitrary byte permutations and missing bytes are unsupported. Original name, ownership and deletion state are unknown.";return result;
        }
        static Result AssembleUnits(Context c,Movie movie,string folder){return WriteUnits(c,PlanUnits(c,movie),folder);}
        static Result AssembleRepairedUnits(Context c,Atom atom,string folder)
        {
            UnitPlan selected=null;foreach(var movie in RepairMovies(c,atom)){
                UnitPlan plan;try{plan=PlanUnits(c,movie);}catch(Reject error){if(error.Code=="unit_mapping_missing"||error.Code=="surviving_box_layout_missing")continue;throw;}
                if(selected!=null&&plan.Hash!=selected.Hash)throw new Reject("moov_unit_ambiguous");if(selected==null)selected=plan;
            }
            if(selected==null)throw new Reject("unit_mapping_missing");return WriteUnits(c,selected,folder);
        }
        static bool MetadataPrefix(Context c,byte[] raw,int available,int total)
        {
            int boxes=0;Func<int,int,int,bool> walk=null;walk=(start,end,depth)=>{
                if(depth>16)return false;for(int p=start;p<end;){
                    if((++boxes&255)==0)c.Cancel.ThrowIfCancellationRequested();if(boxes>10000)return false;int have=Math.Min(available-p,end-p);if(have<=0)return true;
                    for(int n=4;n<Math.Min(have,8);n++)if(raw[p+n]<32||raw[p+n]>126)return false;
                    if(have<4)return true;uint size=U32(raw,p);int header=size==1?16:8;if(size!=1&&(size<header||size>end-p))return false;if(have<header)return true;
                    long bytes=size==1?U64(raw,p+8):size;if(bytes<header||bytes>end-p)return false;string type=Type(raw,p+4);if(!MetadataLeafPrefix(raw,p,header,(int)bytes,available,type))return false;
                    if(type=="moov"||type=="trak"||type=="mdia"||type=="minf"||type=="stbl"||type=="dinf"||type=="edts"||type=="udta"||type=="ilst")if(!walk(p+header,p+(int)bytes,depth+1))return false;
                    if(type=="meta"){
                        if(bytes<header+4)return false;if(available>=p+header+4&&U32(raw,p+header)!=0)return false;
                        if(!walk(p+header+4,p+(int)bytes,depth+1))return false;
                    }
                    if(p+bytes>available)return true;p+=(int)bytes;
                }return true;
            };try{return walk(0,total,0);}catch(Reject){return false;}
        }
        static List<Movie> RepairMovies(Context c,Atom atom)
        {
            if(atom.Bytes>UnitMetadataLimit)throw new Reject("moov_unit_limit");UnitIndexAt(c);var logicals=new HashSet<long>();foreach(var ftyp in c.Ftyp){if(++c.LayoutAttempts>4096)throw new Budget();logicals.Add(ftyp.Bytes);foreach(var mdat in c.Mdat){if(++c.LayoutAttempts>4096)throw new Budget();logicals.Add(ftyp.Bytes+mdat.Bytes);foreach(var free in c.Free){c.Cancel.ThrowIfCancellationRequested();if(++c.LayoutAttempts>4096)throw new Budget();logicals.Add(ftyp.Bytes+free.Bytes+mdat.Bytes);}}}
            var selected=new List<Movie>();var hashes=new HashSet<string>(StringComparer.Ordinal);
            foreach(long logical in logicals){foreach(int unit in new[]{512,1024,2048,4096,8192,16384,32768,65536}){
                if(++c.LayoutAttempts>4096)throw new Budget();int first=(int)Math.Min(atom.Bytes,unit-logical%unit);int parts=1+(int)((atom.Bytes-first+unit-1)/unit);if(parts<2||parts>UnitMetadataParts)continue;
                int phase=Mod(atom.Offset-logical%unit,512);if(!c.Ftyp.Any(x=>Mod(x.Offset,512)==phase))continue;
                byte[] raw=new byte[(int)atom.Bytes];Buffer.BlockCopy(c.Read(atom.Offset,first,true),0,raw,0,first);if(!MetadataPrefix(c,raw,first,raw.Length))continue;
                var extents=new List<Extent>{new Extent{ImageOffset=atom.Offset,LogicalOffset=0,Length=first,Kind="moov"}};
                Action<int> join=null;join=filled=>{
                    c.Cancel.ThrowIfCancellationRequested();if(filled==raw.Length){
                        var candidate=new Atom{Offset=atom.Offset,Bytes=atom.Bytes,Header=atom.Header,Type="moov",Raw=(byte[])raw.Clone(),Parts=extents.Select(x=>new Extent{ImageOffset=x.ImageOffset,LogicalOffset=x.LogicalOffset,Length=x.Length,Kind="moov"}).ToList()};Movie movie;try{movie=ParseMovie(candidate);}catch(Reject){return;}
                        // Equal metadata bytes at different source maps can
                        // block different payload choices. Retain those maps;
                        // coalesce only the same contiguous physical runs.
                        var runs=new List<Extent>();foreach(var part in candidate.Parts){var last=runs.LastOrDefault();if(last!=null&&last.LogicalOffset+last.Length==part.LogicalOffset&&last.ImageOffset+last.Length==part.ImageOffset)last.Length+=part.Length;else runs.Add(new Extent{LogicalOffset=part.LogicalOffset,ImageOffset=part.ImageOffset,Length=part.Length});}
                        string hash=Sha(raw)+"|"+String.Join(";",runs.Select(x=>x.LogicalOffset+":"+x.ImageOffset+":"+x.Length));if(hashes.Add(hash)){if(selected.Count>=64)throw new Budget();selected.Add(movie);}return;
                    }
                    int bytes=Math.Min(unit,raw.Length-filled);var rejectedHeads=new HashSet<string>(StringComparer.Ordinal);long cachedBytes=0;bool rejectedZero=false;try{foreach(var head in UnitHeads(c,phase)){
                        if(head.At>c.Input.Length-bytes||extents.Any(x=>head.At<x.ImageOffset+x.Length&&x.ImageOffset<head.At+bytes))continue;
                        int prefix=Math.Min(bytes,head.Raw.Length);bool uniform=true;for(int n=1;n<prefix;n++)if(head.Raw[n]!=head.Raw[0]){uniform=false;break;}string headKey=uniform?prefix+":"+head.Raw[0]:null;if(headKey!=null&&rejectedHeads.Contains(headKey))continue;
                        if(++c.Units.MetadataProbes>1000000)throw new Budget();Buffer.BlockCopy(head.Raw,0,raw,filled,prefix);if(!MetadataPrefix(c,raw,filled+prefix,raw.Length)){
                            // Cache repeated padding prefixes, not every unique
                            // entropy fragment. A full optimization cache must
                            // never consume the budget needed to test mappings.
                            if(headKey!=null&&c.Units.MetadataCacheBytes+256<=UnitMemoryLimit){rejectedHeads.Add(headKey);cachedBytes+=256;c.Units.MetadataCacheBytes+=256;}continue;
                        }
                        bool zero=SourceZeroRange(c,head.At,bytes);if(zero&&rejectedZero)continue;byte[] body;
                        if(zero){if(bytes>c.Limits.MaxVerifiedBytes-c.Report.VerifiedBytes)throw new Budget();c.Report.VerifiedBytes+=bytes;body=new byte[bytes];}else body=c.Read(head.At,bytes,true);
                        Buffer.BlockCopy(body,0,raw,filled,bytes);if(!MetadataPrefix(c,raw,filled+bytes,raw.Length)){if(zero)rejectedZero=true;continue;}
                        extents.Add(new Extent{ImageOffset=head.At,LogicalOffset=filled,Length=bytes,Kind="moov"});join(filled+bytes);extents.RemoveAt(extents.Count-1);
                    }}finally{c.Units.MetadataCacheBytes-=cachedBytes;}
                };join(first);
            }}
            if(selected.Count==0)throw new Reject("moov_unit_missing");return selected;
        }
    }
}
