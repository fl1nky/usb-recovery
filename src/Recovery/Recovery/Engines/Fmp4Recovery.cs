using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace UsbRecovery
{
    public static partial class FragmentedMediaRecovery
    {
        // Narrow indexed native fMP4 profile; no remuxing or invented bytes.
        // https://www.w3.org/TR/2024/NOTE-mse-byte-stream-format-isobmff-20240723/#media-segments
        const int Fmp4MaximumFragments=256,Fmp4MaximumStates=8192,Fmp4MaximumMaps=512;
        const int Fmp4MaximumMapExtents=100000;
        const long Fmp4MaximumReplayBytes=512L*1024*1024;
        sealed class Fmp4IncompleteException:IOException
        {
            public Fmp4IncompleteException():base("Для фрагментированного MP4 не найдены проверяемый индекс mfra/tfra или все указанные в нём части. Полный файл не собран; другие способы поиска продолжатся."){}
        }
        sealed class FragmentInit
        {
            public Atom Moov;public uint Track,Duration,Size,Flags;public int Timescale;
        }
        sealed class FragmentUnit
        {
            public Atom Moof;public long Bytes,Time,End;public uint Sequence;public int[] Sizes;
        }
        sealed class FragmentIndex
        {
            public Atom Mfra;public long[] Times,Offsets;
        }
        static bool IsFmp4Init(Atom atom)
        {
            try{return Boxes(atom.Raw,atom.Header,atom.Raw.Length).Any(b=>b.Type=="mvex");}
            catch(Reject){return false;} // Keep classic metadata-repair behavior.
        }
        static void ScanFragmentAtoms(Context c)
        {
            // Only a surviving native init enables this pass. Classic files keep
            // their original header whitelist, budgets and metadata retention.
            byte[] block=new byte[BlockBytes+7];int carry=0;long position=0;var seen=new HashSet<long>();
            while(position<c.Input.Length){
                c.Cancel.ThrowIfCancellationRequested();int count=(int)Math.Min(BlockBytes,c.Input.Length-position);byte[] next=c.Read(position,count);Buffer.BlockCopy(next,0,block,carry,count);int total=carry+count;long start=position-carry;
                for(int p=0;p+8<=total;p++){
                    bool moof=block[p+4]==109&&block[p+5]==111&&block[p+6]==111&&block[p+7]==102;
                    bool mfra=block[p+4]==109&&block[p+5]==102&&block[p+6]==114&&block[p+7]==97;
                    long at=start+p;if((!moof&&!mfra)||!seen.Add(at))continue;
                    if(++c.Report.Headers>c.Limits.MaxCandidates)throw new Budget();
                    try{var atom=AtomAt(c,at);if(moof)c.Moof.Add(atom);else c.Mfra.Add(atom);}catch(Reject error){Skip(c.Report,error.Code);}
                }
                carry=Math.Min(7,total);Buffer.BlockCopy(block,total-carry,block,0,carry);position+=count;
            }
        }
        static uint Fragment32(byte[] raw,ref int at,int end)
        {
            if(at<0||at>end-4)throw new Reject("fmp4_table_truncated");uint n=U32(raw,at);at+=4;return n;
        }
        static long Fragment64(byte[] raw,ref int at,int end)
        {
            if(at<0||at>end-8)throw new Reject("fmp4_table_truncated");long n=U64(raw,at);at+=8;return n;
        }
        static uint FragmentHeader(byte[] raw,Box box,out int version)
        {
            int p=box.Data;uint flags=Fragment32(raw,ref p,box.End);version=(int)(flags>>24);return flags&0xffffff;
        }
        static void FragmentZeroTable(byte[] raw,List<Box> boxes,string type,int length)
        {
            Box box=One(boxes,type);FullBox(raw,box,length-4);Exact(box,length);
            for(int p=box.Data+4;p<box.End;p+=4)if(U32(raw,p)!=0)throw new Reject("fmp4_init_samples_unsupported");
        }
        static FragmentInit ParseFragmentInit(Atom atom)
        {
            byte[] raw=atom.Raw;var top=Boxes(raw,atom.Header,raw.Length);Box mvhd=One(top,"mvhd");
            FullBox(raw,mvhd,20);if(U32(raw,mvhd.Data+12)==0||U32(raw,mvhd.Data+16)!=0)throw new Reject("fmp4_init_duration_unsupported");
            Box trak=One(top,"trak"),mvex=One(top,"mvex");var track=Children(raw,trak);Box tkhd=One(track,"tkhd");int version;
            uint flags=FragmentHeader(raw,tkhd,out version);
            if(version!=0||(flags&~7U)!=0||tkhd.End-tkhd.Data<84||track.Any(b=>b.Type=="edts"))throw new Reject("fmp4_track_profile_unsupported");
            uint id=U32(raw,tkhd.Data+12);if(id==0||U32(raw,tkhd.Data+20)!=0)throw new Reject("fmp4_track_identity_invalid");
            var mdia=Children(raw,One(track,"mdia"));Box mdhd=One(mdia,"mdhd");FullBox(raw,mdhd,20);
            uint scale=U32(raw,mdhd.Data+12);if(scale==0||scale>Int32.MaxValue||U32(raw,mdhd.Data+16)!=0)throw new Reject("fmp4_media_duration_unsupported");
            Box hdlr=One(mdia,"hdlr");FullBox(raw,hdlr,8);if(Type(raw,hdlr.Data+8)!="vide")throw new Reject("fmp4_codec_unsupported");
            var minf=Children(raw,One(mdia,"minf"));var dinf=Children(raw,One(minf,"dinf"));Box dref=One(dinf,"dref");FullBox(raw,dref,4);
            var references=Boxes(raw,dref.Data+8,dref.End);Box reference=One(references,"url ");
            if(U32(raw,dref.Data+4)!=1||references.Count!=1||reference.End-reference.Data!=4||U32(raw,reference.Data)!=1)throw new Reject("fmp4_external_media_unsupported");
            var stbl=Children(raw,One(minf,"stbl"));FragmentZeroTable(raw,stbl,"stts",8);FragmentZeroTable(raw,stbl,"stsc",8);FragmentZeroTable(raw,stbl,"stco",8);FragmentZeroTable(raw,stbl,"stsz",12);
            if(stbl.Any(b=>b.Type=="co64"||b.Type=="stz2"||b.Type=="ctts"||b.Type=="senc"))throw new Reject("fmp4_init_tables_unsupported");
            Box stsd=One(stbl,"stsd");FullBox(raw,stsd,4);if(U32(raw,stsd.Data+4)!=1)throw new Reject("fmp4_description_unsupported");
            var descriptions=Boxes(raw,stsd.Data+8,stsd.End);if(descriptions.Count!=1)throw new Reject("fmp4_description_unsupported");Box description=descriptions[0];
            if(description.Type!="avc1"||description.End-description.Data<78||raw[description.Data+6]!=0||raw[description.Data+7]!=1)throw new Reject("fmp4_codec_unsupported");
            var extensions=Boxes(raw,description.Data+78,description.End);Box avcc=One(extensions,"avcC");
            if(extensions.Any(b=>b.Type=="sinf")||avcc.End-avcc.Data<7||raw[avcc.Data]!=1||(raw[avcc.Data+4]&3)!=3)throw new Reject("fmp4_avc_configuration_unsupported");ValidateAvcc(raw,avcc);
            var defaults=Children(raw,mvex);Box trex=One(defaults,"trex");FullBox(raw,trex,20);Exact(trex,24);
            if(defaults.Count!=1||U32(raw,trex.Data+4)!=id||U32(raw,trex.Data+8)!=1)throw new Reject("fmp4_defaults_unsupported");
            return new FragmentInit{Moov=atom,Track=id,Timescale=(int)scale,Duration=U32(raw,trex.Data+12),Size=U32(raw,trex.Data+16),Flags=U32(raw,trex.Data+20)};
        }
        static FragmentUnit ParseFragmentUnit(Context c,Atom atom,FragmentInit init)
        {
            byte[] raw=atom.Raw;var top=Boxes(raw,atom.Header,raw.Length);Box mfhd=One(top,"mfhd"),traf=One(top,"traf");FullBox(raw,mfhd,4);Exact(mfhd,8);
            if(top.Count!=2)throw new Reject("fmp4_moof_boxes_unsupported");uint sequence=U32(raw,mfhd.Data+4);if(sequence==0)throw new Reject("fmp4_sequence_invalid");
            var children=Children(raw,traf);Box tfhd=One(children,"tfhd"),tfdt=One(children,"tfdt"),trun=One(children,"trun");
            if(children.Count!=3)throw new Reject("fmp4_traf_boxes_unsupported");int version;uint flags=FragmentHeader(raw,tfhd,out version);
            if(version!=0||(flags&0x020000)==0||(flags&~0x02003aU)!=0)throw new Reject("fmp4_tfhd_flags_unsupported");
            int p=tfhd.Data+4;uint track=Fragment32(raw,ref p,tfhd.End);if(track!=init.Track)throw new Reject("fmp4_foreign_track");
            uint description=1,duration=init.Duration,size=init.Size,sampleFlags=init.Flags;
            if((flags&2)!=0)description=Fragment32(raw,ref p,tfhd.End);if((flags&8)!=0)duration=Fragment32(raw,ref p,tfhd.End);if((flags&16)!=0)size=Fragment32(raw,ref p,tfhd.End);if((flags&32)!=0)sampleFlags=Fragment32(raw,ref p,tfhd.End);
            if(p!=tfhd.End||description!=1)throw new Reject("fmp4_tfhd_length_or_description");
            if(FragmentHeader(raw,tfdt,out version)!=0||version>1)throw new Reject("fmp4_tfdt_version_unsupported");p=tfdt.Data+4;
            long time=version==1?Fragment64(raw,ref p,tfdt.End):Fragment32(raw,ref p,tfdt.End);if(p!=tfdt.End)throw new Reject("fmp4_tfdt_length");
            flags=FragmentHeader(raw,trun,out version);if(version>1||(flags&1)==0||(flags&~0xf05U)!=0||(flags&0x404)==0x404)throw new Reject("fmp4_trun_flags_unsupported");
            p=trun.Data+4;int count=Count(Fragment32(raw,ref p,trun.End),MaximumSamples);int offset=unchecked((int)Fragment32(raw,ref p,trun.End));
            uint firstFlags=sampleFlags;if((flags&4)!=0)firstFlags=Fragment32(raw,ref p,trun.End);
            int columns=((flags&0x100)!=0?1:0)+((flags&0x200)!=0?1:0)+((flags&0x400)!=0?1:0)+((flags&0x800)!=0?1:0);
            if(trun.End-p!=(long)count*columns*4)throw new Reject("fmp4_trun_table_length");
            if(atom.Bytes>c.Input.Length-atom.Offset-8)throw new Reject("fmp4_pair_truncated");Atom mdat=AtomAt(c,atom.Offset+atom.Bytes);
            if(mdat.Type!="mdat"||mdat.Bytes>c.Input.Length-mdat.Offset||offset!=atom.Bytes+mdat.Header)throw new Reject("fmp4_relative_data_offset");
            if(count>MaximumSamples-c.Fmp4SampleClaims)throw new Budget();c.Fmp4SampleClaims+=count;
            var sizes=new int[count];long cursor=mdat.Offset+mdat.Header,end=time;
            for(int n=0;n<count;n++){
                c.Cancel.ThrowIfCancellationRequested();uint d=duration,s=size,f=n==0?firstFlags:sampleFlags,cts=0;
                if((flags&0x100)!=0)d=Fragment32(raw,ref p,trun.End);if((flags&0x200)!=0)s=Fragment32(raw,ref p,trun.End);if((flags&0x400)!=0)f=Fragment32(raw,ref p,trun.End);if((flags&0x800)!=0)cts=Fragment32(raw,ref p,trun.End);
                if(d==0||s==0||s>MaximumSampleBytes||cts!=0||(f&0xf0000000)!=0||n==0&&(f&0x10000)!=0||s>mdat.Offset+mdat.Bytes-cursor||end>Int64.MaxValue-d)throw new Reject("fmp4_sample_geometry_invalid");
                sizes[n]=(int)s;if(!AvcPhysicalValid(c,cursor,sizes[n]))throw new Reject("fmp4_avc_framing_invalid");cursor+=s;end+=d;
            }
            if(p!=trun.End||cursor!=mdat.Offset+mdat.Bytes)throw new Reject("fmp4_mdat_coverage_invalid");
            return new FragmentUnit{Moof=atom,Bytes=atom.Bytes+mdat.Bytes,Time=time,End=end,Sequence=sequence,Sizes=sizes};
        }
        static FragmentIndex ParseFragmentIndex(Atom atom,uint track)
        {
            byte[] raw=atom.Raw;var children=Boxes(raw,atom.Header,raw.Length);Box tfra=One(children,"tfra"),mfro=One(children,"mfro");
            if(children.Count!=2||children.Last()!=mfro)throw new Reject("fmp4_index_boxes_unsupported");FullBox(raw,mfro,4);Exact(mfro,8);if(U32(raw,mfro.Data+4)!=atom.Bytes)throw new Reject("fmp4_mfro_size_invalid");
            int version;if(FragmentHeader(raw,tfra,out version)!=0||version>1)throw new Reject("fmp4_tfra_version_unsupported");int p=tfra.Data+4;
            if(Fragment32(raw,ref p,tfra.End)!=track)throw new Reject("fmp4_foreign_index");uint lengths=Fragment32(raw,ref p,tfra.End);
            if((lengths&~63U)!=0)throw new Reject("fmp4_tfra_reserved_bits");uint declared=Fragment32(raw,ref p,tfra.End);
            if(declared<1)throw new Reject("fmp4_index_empty");
            int stride=(version==1?16:8)+(int)(lengths>>4&3)+(int)(lengths>>2&3)+(int)(lengths&3)+3;
            if(tfra.End-p!=(long)declared*stride)throw new Reject("fmp4_index_length_invalid");
            if(declared>Fmp4MaximumFragments)throw new Budget();int count=(int)declared;
            var result=new FragmentIndex{Mfra=atom,Times=new long[count],Offsets=new long[count]};
            for(int n=0;n<count;n++){
                result.Times[n]=version==1?Fragment64(raw,ref p,tfra.End):Fragment32(raw,ref p,tfra.End);result.Offsets[n]=version==1?Fragment64(raw,ref p,tfra.End):Fragment32(raw,ref p,tfra.End);
                foreach(int shift in new[]{4,2,0}){int bytes=(int)(lengths>>shift&3)+1;if(p>tfra.End-bytes)throw new Reject("fmp4_tfra_truncated");uint value=0;for(int i=0;i<bytes;i++)value=value<<8|raw[p++];if(value!=1)throw new Reject("fmp4_index_subsample_unsupported");}
                if(result.Offsets[n]<1||result.Offsets[n]>MaximumFileBytes||n==0&&result.Times[n]!=0||n>0&&(result.Times[n]<=result.Times[n-1]||result.Offsets[n]<=result.Offsets[n-1]))throw new Reject("fmp4_index_order_invalid");
            }
            if(p!=tfra.End)throw new Reject("fmp4_index_length_invalid");return result;
        }
        static void FragmentWork(Context c){c.Cancel.ThrowIfCancellationRequested();if(++c.Fmp4States>Fmp4MaximumStates)throw new Budget();}
        static string FragmentMapKey(List<Extent> map)
        {
            long physical=-1,logical=-1,length=0;var pieces=new List<string>();
            foreach(var e in map.OrderBy(e=>e.LogicalOffset)){
                if(length>0&&physical+length==e.ImageOffset&&logical+length==e.LogicalOffset){length+=e.Length;continue;}
                if(length>0)pieces.Add(logical+":"+physical+":"+length);physical=e.ImageOffset;logical=e.LogicalOffset;length=e.Length;
            }
            if(length>0)pieces.Add(logical+":"+physical+":"+length);return String.Join("|",pieces);
        }
        static string FragmentMapHash(Context c,List<Extent> map)
        {
            using(var hash=SHA256.Create()){
                foreach(var e in map.OrderBy(e=>e.LogicalOffset)){long at=e.ImageOffset,left=e.Length;while(left>0){int n=(int)Math.Min(65536,left);byte[] raw=c.Read(at,n,true);hash.TransformBlock(raw,0,n,null,0);at+=n;left-=n;}}
                hash.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        static string FragmentSourceHash(Context c)
        {
            using(var hash=SHA256.Create()){
                for(long at=0;at<c.Input.Length;){int n=(int)Math.Min(BlockBytes,c.Input.Length-at);byte[] raw=c.Read(at,n);hash.TransformBlock(raw,0,n,null,0);at+=n;}
                hash.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        static Result AssembleFmp4(Context c,Atom moov,string folder)
        {
            FragmentInit init=ParseFragmentInit(moov);var units=new List<FragmentUnit>();
            foreach(var atom in c.Moof){FragmentWork(c);try{units.Add(ParseFragmentUnit(c,atom,init));}catch(Reject error){Skip(c.Report,error.Code);}}
            if(c.Mfra.Count==0){c.Report.Fmp4Incomplete=true;throw new Reject("fmp4_index_or_init_layout_unavailable");}
            var unitIndex=new Dictionary<Tuple<uint,long>,List<FragmentUnit>>();
            foreach(var unit in units){FragmentWork(c);var key=Tuple.Create(unit.Sequence,unit.Time);List<FragmentUnit> values;if(!unitIndex.TryGetValue(key,out values)){values=new List<FragmentUnit>();unitIndex.Add(key,values);}values.Add(unit);}
            var ftypIndex=new Dictionary<long,List<Atom>>();
            foreach(var atom in c.Ftyp){FragmentWork(c);List<Atom> values;if(!ftypIndex.TryGetValue(atom.Bytes,out values)){values=new List<Atom>();ftypIndex.Add(atom.Bytes,values);}values.Add(atom);}
            var initSources=new List<Atom>();foreach(var atom in c.Moov){FragmentWork(c);if(atom.Raw.Length==moov.Raw.Length&&atom.Raw.SequenceEqual(moov.Raw))initSources.Add(atom);}
            var maps=new List<List<Extent>>();var mapKeys=new HashSet<string>(StringComparer.Ordinal);string identity=null;bool missing=false;List<FragmentUnit> firstUnits=null;
            foreach(var atom in c.Mfra){
                FragmentWork(c);FragmentIndex index;try{index=ParseFragmentIndex(atom,init.Track);}catch(Reject error){Skip(c.Report,error.Code);continue;}
                // Unit matching depends only on this index, never on the number
                // of ftyp/init physical aliases. Account every actual match.
                var options=new List<FragmentUnit>[index.Times.Length];bool absent=false;
                for(int n=0;n<options.Length;n++){
                    FragmentWork(c);options[n]=new List<FragmentUnit>();List<FragmentUnit> values;
                    if(unitIndex.TryGetValue(Tuple.Create((uint)(n+1),index.Times[n]),out values))foreach(var unit in values){FragmentWork(c);if(n+1==options.Length||unit.End==index.Times[n+1]&&unit.Bytes==index.Offsets[n+1]-index.Offsets[n])options[n].Add(unit);}
                    if(options[n].Count==0){absent=true;break;}
                }
                if(absent){missing=true;continue;}List<Atom> ftypSources;if(!ftypIndex.TryGetValue(index.Offsets[0]-moov.Bytes,out ftypSources))continue;
                foreach(var ftyp in ftypSources)foreach(var initSource in initSources){
                    FragmentWork(c);var metadata=new List<Extent>{Ext(0,ftyp,"ftyp"),Ext(ftyp.Bytes,initSource,"init_moov")};
                    if(metadata.Any(a=>metadata.Any(b=>!Object.ReferenceEquals(a,b)&&Overlaps(a,b))))continue;
                    var chosen=new List<FragmentUnit>();var selected=new List<Extent>(metadata);Action<int> visit=null;
                    visit=delegate(int depth){
                        FragmentWork(c);
                        if(depth==options.Length){
                            long end=index.Offsets[depth-1]+chosen[depth-1].Bytes;
                            if(end>MaximumFileBytes-atom.Bytes)return;var tail=Ext(end,atom,"mfra");if(selected.Any(e=>Overlaps(e,tail)))return;
                            var map=new List<Extent>(selected){tail};string key=FragmentMapKey(map);if(!mapKeys.Add(key))return;
                            long bytes=end+atom.Bytes;if(maps.Count>=Fmp4MaximumMaps||map.Count>Fmp4MaximumMapExtents-c.Fmp4MapExtents||bytes>Fmp4MaximumReplayBytes-c.Fmp4ReplayBytes)throw new Budget();
                            c.Fmp4MapExtents+=map.Count;c.Fmp4ReplayBytes+=bytes;string digest=FragmentMapHash(c,map);
                            if(identity!=null&&identity!=digest)throw new Reject("fmp4_payload_ambiguous");identity=digest;maps.Add(map);if(firstUnits==null)firstUnits=new List<FragmentUnit>(chosen);return;
                        }
                        foreach(var unit in options[depth]){
                            if(depth>0&&chosen[depth-1].End!=unit.Time)continue;
                            var extent=new Extent{ImageOffset=unit.Moof.Offset,LogicalOffset=index.Offsets[depth],Length=unit.Bytes,Kind="fmp4_moof_mdat",EquivalentOffsets=new List<long>{unit.Moof.Offset}};
                            if(selected.Any(e=>Overlaps(e,extent)))continue;chosen.Add(unit);selected.Add(extent);visit(depth+1);selected.RemoveAt(selected.Count-1);chosen.RemoveAt(chosen.Count-1);
                        }
                    };visit(0);
                }
            }
            if(maps.Count==0){c.Report.Fmp4Incomplete=true;throw new Reject(missing?"fmp4_indexed_fragment_missing":"fmp4_index_or_init_layout_unavailable");}
            var primary=maps[0];
            foreach(var extent in primary)extent.EquivalentOffsets=maps.SelectMany(map=>map.Where(e=>e.LogicalOffset==extent.LogicalOffset&&e.Length==extent.Length).Select(e=>e.ImageOffset)).Distinct().OrderBy(p=>p).ToList();
            var movie=new Movie{Moov=moov,Tracks=1};for(int i=0;i<firstUnits.Count;i++)movie.Chunks.Add(new Chunk{Codec="avc1",Samples=firstUnits[i].Sizes,Bytes=firstUnits[i].Sizes.Sum(n=>(long)n)});
            var result=WriteCandidate(c,movie,folder,primary,false,identity);result.AlternateExtents=maps.Skip(1).ToList();
            result.Note="Кандидат сборки фрагментированного MP4: сохранившиеся заголовки, таблицы фрагментов, время и индекс mfra/tfra согласуются с исходными байтами. Проверена структура AVC, декодирование видео не выполнялось. Все проверенные полные варианты дают одинаковые байты. Индекс и идентификаторы не подтверждают владельца, наличие потерянного окончания или факт удаления. Исходное имя неизвестно; проверь содержимое файла.";
            if(maps.Count>1)result.Note+=" Для одинаковых байтов сохранено полных карт размещения: "+maps.Count+". Исходное размещение неизвестно.";
            return result;
        }
    }
}
