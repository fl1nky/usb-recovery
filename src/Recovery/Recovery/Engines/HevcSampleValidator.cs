using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    // Independent bounded syntax reader: H.265 (2023), clauses 7.3/7.4;
    // ISO/IEC 14496-15 HEVCDecoderConfigurationRecord, cross-checked against
    // official FFmpeg n8.0 libavformat/hevc.c and cbs_h265_syntax_template.c.
    // https://www.itu.int/rec/T-REC-H.265-202309-S/en
    // https://github.com/FFmpeg/FFmpeg/tree/n8.0/libavcodec
    // No CABAC decoding is performed. Syntax/parameter identities reduce
    // false joins but cannot authenticate foreign streams with identical sets.
    public static class HevcSampleValidator
    {
        public const int MaximumConfigurationBytes=1024*1024,MaximumSampleBytes=8*1024*1024,MaximumNalUnits=4096;
        public const string Scope="Single-layer Main/Main10, 4:2:0 8/10-bit, complete supplied VPS/SPS/PPS, uniform-slice pictures, bounded full slice headers, reference-set identities and entry-point bounds. No CABAC decode, reference-picture reconstruction, payload authentication or ownership/deletion confirmation. Identical parameter identities across unrelated streams remain indistinguishable by syntax alone.";
        public sealed class Configuration
        {
            public int NalLengthBytes{get;internal set;}public int Width{get;internal set;}public int Height{get;internal set;}
            public int BitDepth{get;internal set;}public int TemporalLayers{get;internal set;}public string Fingerprint{get;internal set;}
            public string SampleEntry{get;internal set;}public bool SinglePictureOnly{get;internal set;}
            internal readonly Dictionary<int,Vps> Vps=new Dictionary<int,Vps>();
            internal readonly Dictionary<int,Sps> Sps=new Dictionary<int,Sps>();
            internal readonly Dictionary<int,Pps> Pps=new Dictionary<int,Pps>();
            internal readonly HashSet<string> ParameterHashes=new HashSet<string>(StringComparer.Ordinal);
            internal Configuration(){}
        }
        public sealed class SampleInfo
        {
            public int NalUnits,VclNalUnits,ParameterSetId,SpsId,VpsId,NalUnitType,TemporalId,PictureOrderCountLsb,MaxPictureOrderCountLsb,Width,Height;
            public bool RandomAccess,EndOfSequence,Decoded=false,PayloadAuthenticated=false,OwnershipConfirmed=false;
            public string ConfigurationFingerprint,Status="hevc_structural_sample_candidate";
            public int[] UsedShortTermReferenceDeltas=new int[0];
        }
        sealed class Invalid:Exception{public readonly string Code;public Invalid(string code){Code=code;}}
        internal sealed class Profile{public int Id,Tier,Level;public uint Compatible;public ulong Constraints;}
        internal sealed class Vps{public int Id,SubLayers;public bool Nested;public Profile Profile;public int[] Dpb;}
        internal sealed class RefSet{public readonly List<int> Deltas=new List<int>();public readonly List<bool> Used=new List<bool>();}
        internal sealed class Sps
        {
            public int Id,Vps,SubLayers,Width,Height,CodedWidth,CodedHeight,Depth,PocBits,MinCbLog2,CtbLog2,CtbWidth,CtbHeight,MaxDpb;
            public bool Nested,Sao,TemporalMvp,LongTerm;public Profile Profile;public int[] Dpb;
            public readonly List<RefSet> RefSets=new List<RefSet>();public bool[] LongTermUsed=new bool[0];
        }
        internal sealed class Pps
        {
            public int Id,Sps,ExtraBits,RefL0,RefL1,InitQp,CbOffset,CrOffset,TileColumns=1,TileRows=1;
            public bool Dependent,Output,CabacInit,ChromaOffsets,WeightedP,WeightedB,Tiles,EntropySync,LoopAcrossSlices,DeblockOverride,DeblockDisabled,ListModification,HeaderExtension;
        }
        sealed class Bits
        {
            public readonly byte[] Data;public int Position;
            public Bits(byte[] data){Data=data;}
            public int Remaining{get{return Data.Length*8-Position;}}
            public uint Read(int count){if(count<0||count>32||count>Remaining)throw new Invalid("hevc_bit_bounds");uint value=0;for(int n=0;n<count;n++,Position++)value=(value<<1)|(uint)((Data[Position/8]>>(7-Position%8))&1);return value;}
            public bool Flag(){return Read(1)!=0;}
            public void Fixed(int bits,uint value){if(Read(bits)!=value)throw new Invalid("hevc_reserved_or_alignment_bits");}
            public int Ue(int maximum){int zeros=0;while(!Flag()){if(++zeros>30)throw new Invalid("hevc_golomb_bounds");}long value=(1L<<zeros)-1+Read(zeros);if(value>maximum)throw new Invalid("hevc_golomb_bounds");return (int)value;}
            public int Se(int minimum,int maximum){int code=Ue(Int32.MaxValue-1);long value=(code&1)!=0?(code+1L)/2:-(long)code/2;if(value<minimum||value>maximum)throw new Invalid("hevc_signed_golomb_bounds");return (int)value;}
            public void Align(){Fixed(1,1);while(Position%8!=0)Fixed(1,0);}
            public void Trailing(){Align();if(Remaining!=0)throw new Invalid("hevc_parameter_trailing_data");}
        }
        sealed class Nal
        {
            public byte[] Bytes,Rbsp;public int Type,Temporal;
            public int PhysicalByte(int index)
            {
                if(index<0||index>=Rbsp.Length)throw new Invalid("hevc_bit_bounds");int zeros=0,seen=0;
                for(int i=2;i<Bytes.Length;i++){int value=Bytes[i];if(zeros>=2&&value==3){zeros=0;continue;}if(seen++==index)return i;zeros=value==0?zeros+1:0;}throw new Invalid("hevc_bit_bounds");
            }
        }
        static string Sha(byte[] data){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(data)).Replace("-","").ToLowerInvariant();}
        static int Log2Ceil(int value){if(value<=1)return 0;int bits=0;for(int n=value-1;n>0;n>>=1)bits++;return bits;}
        static bool Vcl(int kind){return kind>=0&&kind<=9||kind>=16&&kind<=21;}
        static int Length(byte[] data,int at,int bytes){uint value=0;for(int i=0;i<bytes;i++)value=(value<<8)|data[at+i];if(value>MaximumSampleBytes)throw new Invalid("hevc_nal_length_bounds");return (int)value;}
        static Nal ReadNal(byte[] data,int start,int size)
        {
            if(size<3||start<0||start>data.Length-size)throw new Invalid("hevc_nal_bounds");int first=data[start],second=data[start+1];
            if((first&128)!=0||((first&1)<<5|(second>>3))!=0||(second&7)==0)throw new Invalid("hevc_nal_header");
            var raw=new byte[size];Buffer.BlockCopy(data,start,raw,0,size);var rbsp=new List<byte>(size-2);int zeros=0;
            for(int i=2;i<size;i++){
                int value=raw[i];if(zeros>=2){if(value<3)throw new Invalid("hevc_unescaped_start_code");if(value==3){if(i+1>=size||raw[i+1]>3)throw new Invalid("hevc_emulation_prevention");zeros=0;continue;}}
                rbsp.Add((byte)value);zeros=value==0?zeros+1:0;
            }
            return new Nal{Bytes=raw,Rbsp=rbsp.ToArray(),Type=(first>>1)&63,Temporal=(second&7)-1};
        }
        static void ParameterHeader(Nal nal,int expected){if(nal.Type!=expected||nal.Temporal!=0||nal.Bytes.Length>65535)throw new Invalid("hevc_parameter_header");}
        static Profile ProfileAt(Bits bits)
        {
            bits.Fixed(2,0);int tier=(int)bits.Read(1),id=(int)bits.Read(5);uint compatible=bits.Read(32);ulong constraint=(ulong)bits.Read(16)<<32|bits.Read(32);int level=(int)bits.Read(8);
            if(id!=1&&id!=2)throw new Invalid("hevc_profile_unsupported");
            ulong allowed=1UL;if(id==2||(compatible&(1U<<29))!=0)allowed|=1UL<<36;
            if((constraint&(((1UL<<44)-1)&~allowed))!=0)throw new Invalid("hevc_profile_reserved_bits");
            if(!new[]{30,60,63,90,93,120,123,150,153,156,180,183,186}.Contains(level))throw new Invalid("hevc_level_unsupported");
            return new Profile{Id=id,Tier=tier,Compatible=compatible,Level=level,Constraints=constraint};
        }
        static Profile ProfileTier(Bits bits,int subLayers)
        {
            var profile=ProfileAt(bits);var present=new bool[subLayers];var levels=new bool[subLayers];for(int i=0;i<subLayers;i++){present[i]=bits.Flag();levels[i]=bits.Flag();}
            if(subLayers>0)for(int i=subLayers;i<8;i++)bits.Fixed(2,0);
            for(int i=0;i<subLayers;i++){
                // A sub-layer profile has 88 bits, followed by its optional
                // separate level. Reuse the same bounds by supplying one byte.
                if(present[i]){var encoded=new byte[12];for(int j=0;j<11;j++)encoded[j]=(byte)bits.Read(8);encoded[11]=(byte)profile.Level;ProfileAt(new Bits(encoded));}
                if(levels[i]){int level=(int)bits.Read(8);if(level>profile.Level)throw new Invalid("hevc_sub_layer_level");}
            }return profile;
        }
        static int[] Ordering(Bits bits,int subLayers)
        {
            bool all=bits.Flag();int previousDpb=-1,previousReorder=-1;var result=new int[subLayers+1];
            for(int i=all?0:subLayers;i<=subLayers;i++){int dpb=bits.Ue(15),reorder=bits.Ue(dpb);bits.Ue(Int32.MaxValue-1);if(dpb<previousDpb||reorder<previousReorder)throw new Invalid("hevc_sub_layer_ordering");previousDpb=dpb;previousReorder=reorder;result[i]=dpb+1;}if(!all)for(int i=0;i<subLayers;i++)result[i]=result[subLayers];return result;
        }
        static void Hrd(Bits bits,int subLayers)
        {
            bool nal=bits.Flag(),vcl=bits.Flag(),subPic=false;if(nal||vcl){subPic=bits.Flag();if(subPic){bits.Read(8);bits.Read(5);bits.Read(1);bits.Read(5);}bits.Read(4);bits.Read(4);if(subPic)bits.Read(4);bits.Read(5);bits.Read(5);bits.Read(5);}
            for(int layer=0;layer<=subLayers;layer++){bool fixedRate=bits.Flag(),within=fixedRate||bits.Flag(),lowDelay=false;if(within)bits.Ue(Int32.MaxValue-1);else lowDelay=bits.Flag();int cpb=lowDelay?0:bits.Ue(31);for(int kind=0;kind<2;kind++)if(kind==0?nal:vcl)for(int i=0;i<=cpb;i++){bits.Ue(Int32.MaxValue-1);bits.Ue(Int32.MaxValue-1);if(subPic){bits.Ue(Int32.MaxValue-1);bits.Ue(Int32.MaxValue-1);}bits.Read(1);}}
        }
        static void Timing(Bits bits){if(bits.Read(32)==0||bits.Read(32)==0)throw new Invalid("hevc_timing_zero");if(bits.Flag())bits.Ue(Int32.MaxValue-1);}
        static Vps ParseVps(Nal nal)
        {
            ParameterHeader(nal,32);var bits=new Bits(nal.Rbsp);var vps=new Vps{Id=(int)bits.Read(4)};bits.Fixed(1,1);bits.Fixed(1,1);if(bits.Read(6)!=0)throw new Invalid("hevc_multilayer_unsupported");vps.SubLayers=(int)bits.Read(3);if(vps.SubLayers>6)throw new Invalid("hevc_temporal_layers");vps.Nested=bits.Flag();if(vps.SubLayers==0&&!vps.Nested)throw new Invalid("hevc_temporal_nesting");bits.Fixed(16,65535);vps.Profile=ProfileTier(bits,vps.SubLayers);vps.Dpb=Ordering(bits,vps.SubLayers);
            if(bits.Read(6)!=0||bits.Ue(1023)!=0)throw new Invalid("hevc_multilayer_unsupported");if(bits.Flag()){Timing(bits);int hrd=bits.Ue(1);for(int i=0;i<hrd;i++){bits.Ue(0);Hrd(bits,vps.SubLayers);}}
            if(bits.Flag())throw new Invalid("hevc_vps_extension_unsupported");bits.Trailing();return vps;
        }
        static void Scaling(Bits bits)
        {
            for(int size=0;size<4;size++)for(int matrix=0;matrix<6;matrix+=size==3?3:1){if(!bits.Flag()){bits.Ue(size==3?matrix/3:matrix);continue;}if(size>1)bits.Se(-7,247);int count=Math.Min(64,1<<(4+2*size));for(int i=0;i<count;i++)bits.Se(-128,127);}
        }
        static RefSet References(Bits bits,List<RefSet> sets,int index,int spsCount)
        {
            var result=new RefSet();if(index>0&&bits.Flag()){
                int back=index==spsCount?bits.Ue(index-1):0,reference=index-back-1;if(reference<0||reference>=sets.Count)throw new Invalid("hevc_reference_set_identity");bool negative=bits.Flag();int delta=(bits.Ue(32767)+1)*(negative?-1:1);var prior=sets[reference];var entries=new List<KeyValuePair<int,bool>>();
                int included=0;for(int i=0;i<=prior.Deltas.Count;i++){bool used=bits.Flag(),include=used||bits.Flag();if(include){if(++included>15)throw new Invalid("hevc_reference_set_bounds");int poc=checked((i==prior.Deltas.Count?0:prior.Deltas[i])+delta);if(poc!=0)entries.Add(new KeyValuePair<int,bool>(poc,used));}}
                if(entries.Count>15||entries.Select(x=>x.Key).Distinct().Count()!=entries.Count)throw new Invalid("hevc_reference_set_bounds");foreach(var entry in entries.Where(e=>e.Key<0).OrderByDescending(e=>e.Key).Concat(entries.Where(e=>e.Key>0).OrderBy(e=>e.Key))){result.Deltas.Add(entry.Key);result.Used.Add(entry.Value);}
            }else{
                int negative=bits.Ue(15),positive=bits.Ue(15-negative),delta=0;for(int i=0;i<negative;i++){delta=checked(delta-bits.Ue(32767)-1);result.Deltas.Add(delta);result.Used.Add(bits.Flag());}delta=0;for(int i=0;i<positive;i++){delta=checked(delta+bits.Ue(32767)+1);result.Deltas.Add(delta);result.Used.Add(bits.Flag());}
            }return result;
        }
        static void Vui(Bits bits,Sps sps)
        {
            if(bits.Flag()){int aspect=(int)bits.Read(8);if(aspect==255){if(bits.Read(16)==0||bits.Read(16)==0)throw new Invalid("hevc_aspect_ratio");}else if(aspect>16)throw new Invalid("hevc_aspect_ratio");}
            if(bits.Flag())bits.Read(1);if(bits.Flag()){if(bits.Read(3)>5)throw new Invalid("hevc_video_format");bits.Read(1);if(bits.Flag()){bits.Read(8);bits.Read(8);bits.Read(8);}}
            if(bits.Flag()){bits.Ue(5);bits.Ue(5);}bits.Read(1);if(bits.Flag())throw new Invalid("hevc_interlaced_unsupported");bits.Read(1);
            if(bits.Flag()){int left=bits.Ue(sps.CodedWidth),right=bits.Ue(sps.CodedWidth),top=bits.Ue(sps.CodedHeight),bottom=bits.Ue(sps.CodedHeight);if((long)(left+right)*2>=sps.CodedWidth||(long)(top+bottom)*2>=sps.CodedHeight)throw new Invalid("hevc_display_window");}
            if(bits.Flag()){Timing(bits);if(bits.Flag())Hrd(bits,sps.SubLayers);}
            if(bits.Flag()){bits.Read(3);bits.Ue(4095);bits.Ue(16);bits.Ue(16);bits.Ue(15);bits.Ue(15);}
        }
        static Sps ParseSps(Nal nal,Configuration config)
        {
            ParameterHeader(nal,33);var bits=new Bits(nal.Rbsp);var sps=new Sps{Vps=(int)bits.Read(4)};Vps vps;if(!config.Vps.TryGetValue(sps.Vps,out vps))throw new Invalid("hevc_missing_vps");sps.SubLayers=(int)bits.Read(3);if(sps.SubLayers>vps.SubLayers)throw new Invalid("hevc_temporal_layers");sps.Nested=bits.Flag();if((vps.Nested||sps.SubLayers==0)&&!sps.Nested)throw new Invalid("hevc_temporal_nesting");sps.Profile=ProfileTier(bits,sps.SubLayers);sps.Id=bits.Ue(15);if(bits.Ue(3)!=1)throw new Invalid("hevc_chroma_unsupported");
            sps.CodedWidth=bits.Ue(16384);sps.CodedHeight=bits.Ue(16384);if(sps.CodedWidth<1||sps.CodedHeight<1||(long)sps.CodedWidth*sps.CodedHeight>64000000)throw new Invalid("hevc_dimensions_bounds");int left=0,right=0,top=0,bottom=0;if(bits.Flag()){left=bits.Ue(sps.CodedWidth);right=bits.Ue(sps.CodedWidth);top=bits.Ue(sps.CodedHeight);bottom=bits.Ue(sps.CodedHeight);}sps.Width=sps.CodedWidth-2*(left+right);sps.Height=sps.CodedHeight-2*(top+bottom);if(sps.Width!=config.Width||sps.Height!=config.Height)throw new Invalid("hevc_dimension_mismatch");
            int depth=bits.Ue(8),chroma=bits.Ue(8);if((depth!=0&&depth!=2)||chroma!=depth)throw new Invalid("hevc_bit_depth_unsupported");sps.Depth=8+depth;if(sps.Depth!=config.BitDepth||sps.Profile.Id==1&&sps.Depth!=8)throw new Invalid("hevc_bit_depth_mismatch");sps.PocBits=bits.Ue(12)+4;sps.Dpb=Ordering(bits,sps.SubLayers);sps.MaxDpb=sps.Dpb[sps.SubLayers];for(int i=0;i<sps.Dpb.Length;i++)if(sps.Dpb[i]>vps.Dpb[i])throw new Invalid("hevc_dpb_configuration_mismatch");
            sps.MinCbLog2=bits.Ue(3)+3;sps.CtbLog2=sps.MinCbLog2+bits.Ue(3);if(sps.CtbLog2<4||sps.CtbLog2>6||sps.CodedWidth%(1<<sps.MinCbLog2)!=0||sps.CodedHeight%(1<<sps.MinCbLog2)!=0)throw new Invalid("hevc_coding_block_geometry");int minTransform=bits.Ue(sps.MinCbLog2-3)+2;bits.Ue(Math.Min(sps.CtbLog2,5)-minTransform);bits.Ue(sps.CtbLog2-minTransform);bits.Ue(sps.CtbLog2-minTransform);int ctb=1<<sps.CtbLog2;sps.CtbWidth=(sps.CodedWidth+ctb-1)/ctb;sps.CtbHeight=(sps.CodedHeight+ctb-1)/ctb;
            if(bits.Flag()&&bits.Flag())Scaling(bits);bits.Read(1);sps.Sao=bits.Flag();if(bits.Flag()){if(bits.Read(4)>=sps.Depth||bits.Read(4)>=sps.Depth)throw new Invalid("hevc_pcm_depth");int minPcm=bits.Ue(Math.Min(sps.CtbLog2,5)-3)+3;if(minPcm<Math.Min(sps.MinCbLog2,5))throw new Invalid("hevc_pcm_geometry");bits.Ue(Math.Min(sps.CtbLog2,5)-minPcm);bits.Read(1);}
            int count=bits.Ue(64);for(int i=0;i<count;i++){var refs=References(bits,sps.RefSets,i,count);if(refs.Deltas.Count>=sps.MaxDpb)throw new Invalid("hevc_reference_dpb_bounds");sps.RefSets.Add(refs);}sps.LongTerm=bits.Flag();if(sps.LongTerm){int total=bits.Ue(32);sps.LongTermUsed=new bool[total];for(int i=0;i<total;i++){bits.Read(sps.PocBits);sps.LongTermUsed[i]=bits.Flag();}}
            sps.TemporalMvp=bits.Flag();bits.Read(1);if(bits.Flag())Vui(bits,sps);if(bits.Flag()&&bits.Read(8)!=0)throw new Invalid("hevc_sps_extension_unsupported");bits.Trailing();return sps;
        }
        static Pps ParsePps(Nal nal,Configuration config)
        {
            ParameterHeader(nal,34);var bits=new Bits(nal.Rbsp);var pps=new Pps{Id=bits.Ue(63),Sps=bits.Ue(15)};Sps sps;if(!config.Sps.TryGetValue(pps.Sps,out sps))throw new Invalid("hevc_missing_sps");pps.Dependent=bits.Flag();pps.Output=bits.Flag();pps.ExtraBits=(int)bits.Read(3);bits.Read(1);pps.CabacInit=bits.Flag();pps.RefL0=bits.Ue(14)+1;pps.RefL1=bits.Ue(14)+1;pps.InitQp=bits.Se(-26-6*(sps.Depth-8),25);bits.Read(1);bits.Read(1);if(bits.Flag())bits.Ue(sps.CtbLog2-sps.MinCbLog2);pps.CbOffset=bits.Se(-12,12);pps.CrOffset=bits.Se(-12,12);pps.ChromaOffsets=bits.Flag();pps.WeightedP=bits.Flag();pps.WeightedB=bits.Flag();bits.Read(1);pps.Tiles=bits.Flag();pps.EntropySync=bits.Flag();
            if(pps.Tiles){pps.TileColumns=bits.Ue(Math.Min(63,sps.CtbWidth-1))+1;pps.TileRows=bits.Ue(Math.Min(63,sps.CtbHeight-1))+1;if(!bits.Flag()){int width=0,height=0;for(int i=1;i<pps.TileColumns;i++)width+=bits.Ue(sps.CtbWidth-1)+1;for(int i=1;i<pps.TileRows;i++)height+=bits.Ue(sps.CtbHeight-1)+1;if(width>=sps.CtbWidth||height>=sps.CtbHeight)throw new Invalid("hevc_tile_geometry");}bits.Read(1);}
            pps.LoopAcrossSlices=bits.Flag();if(bits.Flag()){pps.DeblockOverride=bits.Flag();pps.DeblockDisabled=bits.Flag();if(!pps.DeblockDisabled){bits.Se(-6,6);bits.Se(-6,6);}}
            if(bits.Flag())Scaling(bits);pps.ListModification=bits.Flag();bits.Ue(sps.CtbLog2-2);pps.HeaderExtension=bits.Flag();if(bits.Flag()&&bits.Read(8)!=0)throw new Invalid("hevc_pps_extension_unsupported");bits.Trailing();return pps;
        }
        static void ConsistentProfile(Profile general,Profile parameter)
        {
            if(general.Id!=parameter.Id&&(parameter.Compatible&(1U<<(31-general.Id)))==0||general.Tier<parameter.Tier||general.Level<parameter.Level||(general.Compatible&~parameter.Compatible)!=0||(general.Constraints&~parameter.Constraints)!=0)throw new Invalid("hevc_profile_configuration_mismatch");
        }
        static void Sei(Nal nal)
        {
            var bits=new Bits(nal.Rbsp);int messages=0;while(bits.Remaining>8){if(++messages>1024)throw new Invalid("hevc_sei_limit");int type=0,value;do{value=(int)bits.Read(8);type=checked(type+value);if(type>65535)throw new Invalid("hevc_sei_type_bounds");}while(value==255);int size=0;do{value=(int)bits.Read(8);size=checked(size+value);if(size>MaximumConfigurationBytes)throw new Invalid("hevc_sei_size_bounds");}while(value==255);if(size>bits.Remaining/8)throw new Invalid("hevc_sei_size_bounds");bits.Position+=size*8;}bits.Trailing();
        }
        static Configuration ParseConfiguration(byte[] data,string sampleEntry,int width,int height)
        {
            if(data==null||data.Length<23||data.Length>MaximumConfigurationBytes||sampleEntry!="hvc1"&&sampleEntry!="hev1"||width<1||height<1||(long)width*height>64000000)throw new Invalid("hevc_configuration_bounds");
            if(data[0]!=1||(data[13]&240)!=240||(data[15]&252)!=252||(data[16]&252)!=252||(data[17]&248)!=248||(data[18]&248)!=248)throw new Invalid("hevc_configuration_reserved_bits");
            int length=(data[21]&3)+1,depth=8+(data[17]&7);if(length==3)throw new Invalid("hevc_nal_length_size_unsupported");if((data[16]&3)!=1||(depth!=8&&depth!=10)||(data[18]&7)!=(data[17]&7))throw new Invalid("hevc_configuration_profile_unsupported");
            var profile=ProfileAt(new Bits(data.Skip(1).Take(12).ToArray()));int layers=(data[21]>>3)&7;if(layers<1||(data[21]>>6)==3||layers==1&&(data[21]&4)==0)throw new Invalid("hevc_configuration_temporal_layers");
            var config=new Configuration{SampleEntry=sampleEntry,NalLengthBytes=length,Width=width,Height=height,BitDepth=depth,TemporalLayers=layers,Fingerprint=Sha(Encoding.ASCII.GetBytes(sampleEntry+":"+width+":"+height+":").Concat(data).ToArray())};
            int arrays=data[22],at=23,total=0;if(arrays<3||arrays>5)throw new Invalid("hevc_configuration_arrays");var seen=new HashSet<int>();var nals=new List<Nal>();
            for(int i=0;i<arrays;i++){
                if(data.Length-at<3)throw new Invalid("hevc_configuration_array_bounds");int flags=data[at++],kind=flags&63,count=data[at]<<8|data[at+1];at+=2;if((flags&64)!=0||!seen.Add(kind)||kind!=32&&kind!=33&&kind!=34&&kind!=39&&kind!=40||count<1||count>64||total+count>128)throw new Invalid("hevc_configuration_array_bounds");total+=count;
                if(sampleEntry=="hvc1"&&kind>=32&&kind<=34&&(flags&128)==0)throw new Invalid("hevc_incomplete_hvc1_configuration");
                for(int j=0;j<count;j++){if(data.Length-at<2)throw new Invalid("hevc_configuration_nal_bounds");int bytes=data[at]<<8|data[at+1];at+=2;if(bytes<3||bytes>data.Length-at)throw new Invalid("hevc_configuration_nal_bounds");var nal=ReadNal(data,at,bytes);at+=bytes;if(nal.Type!=kind)throw new Invalid("hevc_configuration_nal_type");nals.Add(nal);}
            }
            if(at!=data.Length||!seen.Contains(32)||!seen.Contains(33)||!seen.Contains(34))throw new Invalid("hevc_missing_configuration_sets");
            foreach(var nal in nals.Where(n=>n.Type==32)){var value=ParseVps(nal);if(config.Vps.ContainsKey(value.Id))throw new Invalid("hevc_duplicate_parameter_id");config.Vps.Add(value.Id,value);config.ParameterHashes.Add(Sha(nal.Bytes));ConsistentProfile(profile,value.Profile);}
            foreach(var nal in nals.Where(n=>n.Type==33)){var value=ParseSps(nal,config);if(config.Sps.ContainsKey(value.Id))throw new Invalid("hevc_duplicate_parameter_id");config.Sps.Add(value.Id,value);config.ParameterHashes.Add(Sha(nal.Bytes));ConsistentProfile(profile,value.Profile);}
            foreach(var nal in nals.Where(n=>n.Type==34)){var value=ParsePps(nal,config);if(config.Pps.ContainsKey(value.Id))throw new Invalid("hevc_duplicate_parameter_id");config.Pps.Add(value.Id,value);config.ParameterHashes.Add(Sha(nal.Bytes));int mode=value.Tiles?(value.EntropySync?0:2):value.EntropySync?3:1;if((data[15]&3)!=0&&(data[15]&3)!=mode)throw new Invalid("hevc_parallelism_configuration_mismatch");}
            foreach(var nal in nals.Where(n=>n.Type==39||n.Type==40)){if(nal.Temporal>=layers)throw new Invalid("hevc_configuration_temporal_layers");Sei(nal);}
            if(config.Vps.Values.Max(v=>v.SubLayers)+1!=layers||config.Sps.Values.Any(s=>s.SubLayers+1>layers))throw new Invalid("hevc_configuration_temporal_layers");config.SinglePictureOnly=config.Vps.Values.Any(v=>(v.Profile.Constraints&(1UL<<36))!=0)||config.Sps.Values.Any(s=>(s.Profile.Constraints&(1UL<<36))!=0);return config;
        }
        static void Weights(Bits bits,Sps sps,int l0,int l1,bool bidirectional)
        {
            int luma=bits.Ue(7),chroma=luma+bits.Se(-7,7);if(chroma<0||chroma>7)throw new Invalid("hevc_weight_denominator");int totalFlags=0;
            for(int list=0;list<(bidirectional?2:1);list++){int count=list==0?l0:l1;var hasLuma=new bool[count];var hasChroma=new bool[count];for(int i=0;i<count;i++){hasLuma[i]=bits.Flag();if(hasLuma[i])totalFlags++;}for(int i=0;i<count;i++){hasChroma[i]=bits.Flag();if(hasChroma[i])totalFlags+=2;}if(totalFlags>24)throw new Invalid("hevc_weight_flag_limit");for(int i=0;i<count;i++){if(hasLuma[i]){bits.Se(-128,127);bits.Se(-(1<<(sps.Depth-1)),(1<<(sps.Depth-1))-1);}if(hasChroma[i])for(int j=0;j<2;j++){bits.Se(-128,127);bits.Se(-(4<<(sps.Depth-1)),(4<<(sps.Depth-1))-1);}}}
        }
        sealed class Slice{public int Pps,Type,Poc,Address,HeaderBytes;public bool First,Dependent;public int[] UsedDeltas;}
        static Slice SliceHeader(Nal nal,Configuration config,Slice previous)
        {
            var bits=new Bits(nal.Rbsp);var slice=new Slice{First=bits.Flag()};bool irap=nal.Type>=16&&nal.Type<=21,idr=nal.Type==19||nal.Type==20;if(irap){if(nal.Temporal!=0)throw new Invalid("hevc_irap_temporal_id");bits.Read(1);}if(nal.Type>=2&&nal.Type<=5&&nal.Temporal==0)throw new Invalid("hevc_tsa_stsa_temporal_id");slice.Pps=bits.Ue(63);Pps pps;if(!config.Pps.TryGetValue(slice.Pps,out pps))throw new Invalid("hevc_unknown_slice_pps");Sps sps=config.Sps[pps.Sps];if(nal.Temporal>sps.SubLayers)throw new Invalid("hevc_slice_temporal_id");int ctbs=sps.CtbWidth*sps.CtbHeight;
            if(!slice.First){if(pps.Dependent)slice.Dependent=bits.Flag();slice.Address=(int)bits.Read(Log2Ceil(ctbs));if(slice.Address<1||slice.Address>=ctbs)throw new Invalid("hevc_slice_address");}
            if(slice.Dependent){if(previous==null||previous.Pps!=slice.Pps)throw new Invalid("hevc_dependent_slice_identity");slice.Type=previous.Type;slice.Poc=previous.Poc;slice.UsedDeltas=previous.UsedDeltas;}
            else{
                for(int i=0;i<pps.ExtraBits;i++)bits.Fixed(1,0);slice.Type=bits.Ue(2);if(irap&&slice.Type!=2)throw new Invalid("hevc_irap_slice_type");if(pps.Output)bits.Read(1);int totalCurrent=0;bool temporalMvp=false;var used=new List<int>();
                if(!idr){slice.Poc=(int)bits.Read(sps.PocBits);RefSet refs;if(!bits.Flag())refs=References(bits,sps.RefSets,sps.RefSets.Count,sps.RefSets.Count);else{if(sps.RefSets.Count==0)throw new Invalid("hevc_missing_slice_reference_set");int index=sps.RefSets.Count>1?(int)bits.Read(Log2Ceil(sps.RefSets.Count)):0;if(index>=sps.RefSets.Count)throw new Invalid("hevc_slice_reference_set_index");refs=sps.RefSets[index];}for(int i=0;i<refs.Deltas.Count;i++)if(refs.Used[i]){totalCurrent++;used.Add(refs.Deltas[i]);}
                    int remaining=sps.Dpb[nal.Temporal]-1-refs.Deltas.Count;if(remaining<0)throw new Invalid("hevc_reference_dpb_bounds");if(sps.LongTerm){int fromSps=sps.LongTermUsed.Length>0?bits.Ue(Math.Min(sps.LongTermUsed.Length,remaining)):0,other=bits.Ue(remaining-fromSps);for(int i=0;i<fromSps+other;i++){if(i<fromSps){int index=sps.LongTermUsed.Length>1?(int)bits.Read(Log2Ceil(sps.LongTermUsed.Length)):0;if(index>=sps.LongTermUsed.Length)throw new Invalid("hevc_long_term_index");if(sps.LongTermUsed[index])totalCurrent++;}else{bits.Read(sps.PocBits);if(bits.Flag())totalCurrent++;}if(bits.Flag())bits.Ue(Int32.MaxValue-1);}}
                    if(sps.TemporalMvp)temporalMvp=bits.Flag();
                }
                slice.UsedDeltas=used.ToArray();bool saoLuma=false,saoChroma=false;if(sps.Sao){saoLuma=bits.Flag();saoChroma=bits.Flag();}
                if(slice.Type!=2){if(totalCurrent<1)throw new Invalid("hevc_inter_slice_without_references");int l0=pps.RefL0,l1=pps.RefL1;if(bits.Flag()){l0=bits.Ue(14)+1;if(slice.Type==0)l1=bits.Ue(14)+1;}
                    if(pps.ListModification&&totalCurrent>1){int width=Log2Ceil(totalCurrent);if(bits.Flag())for(int i=0;i<l0;i++)if(bits.Read(width)>=totalCurrent)throw new Invalid("hevc_reference_list_index");if(slice.Type==0&&bits.Flag())for(int i=0;i<l1;i++)if(bits.Read(width)>=totalCurrent)throw new Invalid("hevc_reference_list_index");}
                    if(slice.Type==0)bits.Read(1);if(pps.CabacInit)bits.Read(1);if(temporalMvp){bool collocatedL0=slice.Type!=0||bits.Flag();int count=collocatedL0?l0:l1;if(count>1)bits.Ue(count-1);}if(pps.WeightedP&&slice.Type==1||pps.WeightedB&&slice.Type==0)Weights(bits,sps,l0,l1,slice.Type==0);bits.Ue(4);
                }
                bits.Se(-6*(sps.Depth-8)-(pps.InitQp+26),51-(pps.InitQp+26));if(pps.ChromaOffsets){int cb=bits.Se(-12,12),cr=bits.Se(-12,12);if(cb+pps.CbOffset<-12||cb+pps.CbOffset>12||cr+pps.CrOffset<-12||cr+pps.CrOffset>12)throw new Invalid("hevc_slice_chroma_qp");}
                bool disabled=pps.DeblockDisabled;if(pps.DeblockOverride&&bits.Flag()){disabled=bits.Flag();if(!disabled){bits.Se(-6,6);bits.Se(-6,6);}}if(pps.LoopAcrossSlices&&(saoLuma||saoChroma||!disabled))bits.Read(1);
            }
            long entryBytes=0;if(pps.Tiles||pps.EntropySync){int max=pps.Tiles?(pps.EntropySync?pps.TileColumns*sps.CtbHeight-1:pps.TileColumns*pps.TileRows):sps.CtbHeight-1;int entries=bits.Ue(Math.Min(max,65535));if(entries>0){int width=bits.Ue(31)+1;for(int i=0;i<entries;i++)entryBytes+=1L+bits.Read(width);}}
            if(pps.HeaderExtension){int bytes=bits.Ue(256);for(int i=0;i<bytes;i++)bits.Read(8);}bits.Align();slice.HeaderBytes=bits.Position/8;if(bits.Remaining<8)throw new Invalid("hevc_missing_slice_data");int physicalStart=nal.PhysicalByte(slice.HeaderBytes);if(entryBytes>=nal.Bytes.Length-physicalStart)throw new Invalid("hevc_entry_point_bounds");return slice;
        }
        static SampleInfo ValidateSample(byte[] sample,Configuration config)
        {
            if(sample==null||config==null||sample.Length<config.NalLengthBytes+3||sample.Length>MaximumSampleBytes)throw new Invalid("hevc_sample_bounds");var result=new SampleInfo{ConfigurationFingerprint=config.Fingerprint,Width=config.Width,Height=config.Height};int at=0,lastAddress=-1,aud=-1,endKind=0;bool suffix=false,ended=false;Slice previous=null;
            while(at<sample.Length){if(++result.NalUnits>MaximumNalUnits||sample.Length-at<config.NalLengthBytes)throw new Invalid("hevc_sample_nal_bounds");int bytes=Length(sample,at,config.NalLengthBytes);at+=config.NalLengthBytes;if(bytes>sample.Length-at)throw new Invalid("hevc_sample_nal_bounds");var nal=ReadNal(sample,at,bytes);at+=bytes;
                if(nal.Temporal>=config.TemporalLayers||ended&&!(endKind==36&&nal.Type==37))throw new Invalid("hevc_access_unit_order_or_temporal_id");
                if(Vcl(nal.Type)){
                    if(suffix||ended)throw new Invalid("hevc_access_unit_order");var slice=SliceHeader(nal,config,previous);if(result.VclNalUnits==0){if(!slice.First)throw new Invalid("hevc_missing_first_slice");result.ParameterSetId=slice.Pps;var pps=config.Pps[slice.Pps];var sps=config.Sps[pps.Sps];result.SpsId=sps.Id;result.VpsId=sps.Vps;result.NalUnitType=nal.Type;result.TemporalId=nal.Temporal;result.PictureOrderCountLsb=slice.Poc;result.MaxPictureOrderCountLsb=1<<sps.PocBits;result.RandomAccess=nal.Type>=16;result.UsedShortTermReferenceDeltas=slice.UsedDeltas;}
                    else if(slice.First||slice.Pps!=result.ParameterSetId||slice.Poc!=result.PictureOrderCountLsb||nal.Type!=result.NalUnitType||nal.Temporal!=result.TemporalId||slice.Type!=previous.Type)throw new Invalid("hevc_multiple_picture_or_slice_identity");
                    if(slice.Address<=lastAddress)throw new Invalid("hevc_slice_order");if(aud==0&&slice.Type!=2||aud==1&&slice.Type==0)throw new Invalid("hevc_aud_picture_type");lastAddress=slice.Address;previous=slice;result.VclNalUnits++;
                }else if(nal.Type>=32&&nal.Type<=34){if(config.SampleEntry=="hvc1"||result.VclNalUnits!=0||ended)throw new Invalid("hevc_inband_parameters_unsupported");if(!config.ParameterHashes.Contains(Sha(nal.Bytes)))throw new Invalid("hevc_foreign_parameter_set");}
                else if(nal.Type==35){if(aud>=0||result.VclNalUnits!=0||ended)throw new Invalid("hevc_access_unit_order");var bits=new Bits(nal.Rbsp);aud=(int)bits.Read(3);if(aud>2)throw new Invalid("hevc_aud_type");bits.Trailing();}
                else if(nal.Type==39||nal.Type==40){if(nal.Type==39&&result.VclNalUnits!=0||nal.Type==40&&result.VclNalUnits==0||ended)throw new Invalid("hevc_sei_order");Sei(nal);if(nal.Type==40)suffix=true;}
                else if(nal.Type==36||nal.Type==37){if(result.VclNalUnits==0||nal.Temporal!=0)throw new Invalid("hevc_end_marker_order");new Bits(nal.Rbsp).Trailing();ended=true;endKind=nal.Type;result.EndOfSequence=true;}
                else if(nal.Type==38){int p=0;while(p<nal.Rbsp.Length&&nal.Rbsp[p]==255)p++;if(p!=nal.Rbsp.Length-1||nal.Rbsp[p]!=128)throw new Invalid("hevc_filler_data");}
                else throw new Invalid("hevc_nal_type_unsupported");
            }
            if(result.VclNalUnits==0)throw new Invalid("hevc_no_picture");return result;
        }
        public static bool TryParseConfiguration(byte[] hvcc,string sampleEntry,int width,int height,out Configuration configuration,out string code)
        {
            configuration=null;code=null;try{configuration=ParseConfiguration(hvcc,sampleEntry,width,height);return true;}catch(Invalid error){code=error.Code;return false;}catch(OverflowException){code="hevc_integer_bounds";return false;}
        }
        public static bool TryValidateSample(byte[] sample,Configuration configuration,out SampleInfo info,out string code)
        {
            info=null;code=null;try{info=ValidateSample(sample,configuration);return true;}catch(Invalid error){code=error.Code;return false;}catch(OverflowException){code="hevc_integer_bounds";return false;}
        }
        public static bool IsPossibleSampleStart(byte[] buffer,int at,int available,int nalLengthBytes=4)
        {
            if(buffer==null||at<0||available<0||at>buffer.Length-available||(nalLengthBytes!=1&&nalLengthBytes!=2&&nalLengthBytes!=4)||available<nalLengthBytes+3)return false;
            int first=buffer[at+nalLengthBytes],second=buffer[at+nalLengthBytes+1],kind=(first>>1)&63;if((first&128)!=0||((first&1)<<5|(second>>3))!=0||(second&7)==0)return false;
            uint count=0;for(int i=0;i<nalLengthBytes;i++)count=(count<<8)|buffer[at+i];if(count<3||count>MaximumSampleBytes)return false;
            return Vcl(kind)?(buffer[at+nalLengthBytes+2]&128)!=0:kind>=32&&kind<=35||kind==39;
        }
    }
}
