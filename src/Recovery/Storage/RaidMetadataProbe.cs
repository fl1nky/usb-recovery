using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace UsbRecovery
{
    // Independent read-only Linux MD format reader. Format facts:
    // https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/raid/md_p.h
    // https://github.com/md-raid-utilities/mdadm/tree/c940aae94ac55efadaf741e9dd2a81fb6fbf8794
    // mdadm super0.c/super1.c specify placement and folded additive checksums.
    // Metadata is not authentication of array ownership or payload integrity.
    public static class RaidMetadataProbe
    {
        public const int MaximumImages=128,MaximumSuperblockBytes=4096;
        public sealed class Member
        {
            public string Path,Format,Uuid,Name,MetadataSha256,RoleMapSha256,DeviceUuid,Layout,Status="not_found",Code="MD_NOT_FOUND";
            public long FileBytes,MetadataOffset=-1,DataOffset,DataBytes,ComponentBytes,ChunkBytes;
            public int Level,RaidDisks,DeviceNumber,Role=-1,LayoutCode;
            public ulong Events,CreationTime;
            public uint Features;
            public bool ChecksumValid,Clean,Active,Supported,SourceUnchanged;
            public List<string> Reasons=new List<string>();
        }
        public sealed class Group
        {
            public string Uuid,Format,Name,Status="unsupported",Level,Layout;
            public ulong Events;
            public long ComponentBytes,ChunkBytes,LogicalBytes;
            public int RaidDisks;
            public bool MetadataOnly=true,RequiresReview=true,DataIntegrityEstablished=false;
            public RaidConfiguration Configuration;
            public List<Member> Members=new List<Member>();
            public List<int> MissingRoles=new List<int>();
            public List<string> Reasons=new List<string>();
        }
        public sealed class Report
        {
            public int Schema=1,Images;
            public string Status="complete";
            public long MetadataBytesRead;
            public List<Member> Members=new List<Member>();
            public List<Group> Groups=new List<Group>();
            public string Scope="Linux MD 0.90 / 1.0 / 1.1 / 1.2 at documented offsets in supplied complete RAW component images. No controller/DDF/IMSM, partition inference, stale-event arbitration or reshape. Configuration remains a reviewable metadata candidate; assembly still verifies payload redundancy where available.";
        }
        sealed class Failure:IOException {public string Code;public Failure(string code){Code=code;}}
        [StructLayout(LayoutKind.Sequential)]struct Identity {public uint Attributes,CreatedLow,CreatedHigh,AccessedLow,AccessedHigh,WrittenLow,WrittenHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
        [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle file,out Identity value);
        static uint U32(byte[] b,int at,bool big=false){return big?(uint)b[at]<<24|(uint)b[at+1]<<16|(uint)b[at+2]<<8|b[at+3]:(uint)b[at]|(uint)b[at+1]<<8|(uint)b[at+2]<<16|(uint)b[at+3]<<24;}
        static ushort U16(byte[] b,int at){return (ushort)(b[at]|b[at+1]<<8);}
        static ulong U64(byte[] b,int at){return (ulong)U32(b,at)|((ulong)U32(b,at+4)<<32);}
        static string Hash(byte[] b){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
        static bool Zero(byte[] b,int at,int count){for(int n=at;n<at+count;n++)if(b[n]!=0)return false;return true;}
        static long Bytes(ulong sectors){if(sectors>(ulong)(Int64.MaxValue/512))throw new Failure("MD_SECTOR_OVERFLOW");return (long)sectors*512;}
        static void Reject(Member m,string code){if(!m.Reasons.Contains(code))m.Reasons.Add(code);m.Supported=false;m.Status="unsupported";m.Code=code;}
        static void Invalid(Member m,string code){m.Supported=false;m.Status="invalid";m.Code=code;if(!m.Reasons.Contains(code))m.Reasons.Add(code);}
        static bool Pow2(long n){return n>=512&&n<=RaidImageBuilder.MaximumChunkSize&&(n&(n-1))==0;}
        static string SafePath(string value)
        {
            if(String.IsNullOrWhiteSpace(value)||value.StartsWith("\\\\",StringComparison.Ordinal)||value.IndexOf(':',2)>=0)throw new Failure("MD_LOCAL_RAW_REQUIRED");
            string full=System.IO.Path.GetFullPath(value);if(full.StartsWith("\\\\",StringComparison.Ordinal))throw new Failure("MD_LOCAL_RAW_REQUIRED");
            DriveType drive=new DriveInfo(System.IO.Path.GetPathRoot(full)).DriveType;if(drive!=DriveType.Fixed&&drive!=DriveType.Removable&&drive!=DriveType.Ram)throw new Failure("MD_LOCAL_RAW_REQUIRED");
            if(new[]{".partial",".vhd",".vhdx",".vmdk",".qcow",".qcow2",".e01",".aff4",".gz",".zip"}.Contains(System.IO.Path.GetExtension(full).ToLowerInvariant()))throw new Failure("MD_COMPLETE_RAW_REQUIRED");
            var parents=new List<string>();for(var parent=System.IO.Path.GetDirectoryName(full);!String.IsNullOrEmpty(parent);parent=System.IO.Path.GetDirectoryName(parent))parents.Add(parent);parents.Reverse();
            foreach(string parent in parents)if((File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0)throw new Failure("MD_LINKED_SOURCE");
            FileAttributes attributes=File.GetAttributes(full);if((attributes&(FileAttributes.ReparsePoint|FileAttributes.Directory|FileAttributes.Device))!=0)throw new Failure("MD_REGULAR_IMAGE_REQUIRED");return full;
        }
        static byte[] Read(FileStream input,long at,int size,Report report,CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();if(at<0||size<0||at>input.Length-size)throw new Failure("MD_METADATA_BOUNDS");
            input.Position=at;byte[] b=new byte[size];int count=0,n;while(count<size&&(n=input.Read(b,count,size-count))>0){cancel.ThrowIfCancellationRequested();count+=n;}if(count!=size)throw new Failure("MD_SOURCE_TRUNCATED");report.MetadataBytesRead+=size;return b;
        }
        static uint Checksum(byte[] data,int bytes,int field,bool big)
        {
            ulong sum=0;for(int at=0;at+4<=bytes;at+=4)if(at!=field)sum+=U32(data,at,big);
            if(bytes%4==2)sum+=U16(data,bytes-2);return unchecked((uint)((sum&0xffffffffUL)+(sum>>32)));
        }
        static void Layout(Member m)
        {
            if(m.Level==0){m.Layout="striped";if(m.LayoutCode<0||m.LayoutCode>2)Reject(m,"MD_RAID0_LAYOUT_UNSUPPORTED");}
            else if(m.Level==1){m.Layout="mirror";if(m.LayoutCode!=0)Reject(m,"MD_MIRROR_LAYOUT_UNSUPPORTED");}
            else if(m.Level==10){m.Layout="adjacent-pairs";if(m.LayoutCode!=258||m.RaidDisks<4||m.RaidDisks%2!=0)Reject(m,"MD_RAID10_LAYOUT_UNSUPPORTED");}
            else if(m.Level==5){string[] layouts={"left-asymmetric","right-asymmetric","left-symmetric","right-symmetric","parity-first","parity-last"};if(m.LayoutCode>=0&&m.LayoutCode<layouts.Length)m.Layout=layouts[m.LayoutCode];else Reject(m,"MD_PARITY_LAYOUT_UNSUPPORTED");}
            else if(m.Level==6){if(m.LayoutCode==2)m.Layout="left-symmetric";else if(m.LayoutCode==3)m.Layout="right-symmetric";else if(m.LayoutCode==5)m.Layout="parity-last";else Reject(m,"MD_PARITY_LAYOUT_UNSUPPORTED");}
            else Reject(m,"MD_LEVEL_UNSUPPORTED");
            int minimum=m.Level==5?3:m.Level==6||m.Level==10?4:2;
            if(m.RaidDisks<minimum||m.RaidDisks>RaidImageBuilder.MaximumMembers)Reject(m,"MD_MEMBER_COUNT_UNSUPPORTED");
            if(m.Level!=1&&!Pow2(m.ChunkBytes)||m.Level==1&&m.ChunkBytes!=0&&!Pow2(m.ChunkBytes))Reject(m,"MD_CHUNK_UNSUPPORTED");
            if(m.ComponentBytes<=0||m.Level!=1&&m.ChunkBytes>0&&m.ComponentBytes%m.ChunkBytes!=0)Reject(m,"MD_COMPONENT_ALIGNMENT_UNSUPPORTED");
        }
        static Member VersionOne(byte[] b,string path,long length,long offset,int minor)
        {
            var m=new Member{Path=path,FileBytes=length,MetadataOffset=offset,Format="1."+minor,Supported=true,Status="candidate",Code="MD_METADATA_CANDIDATE"};
            if(b.Length<256){Invalid(m,"MD_SUPERBLOCK_TRUNCATED");return m;}
            uint max=U32(b,220);if(max<1||max>(MaximumSuperblockBytes-256)/2||256L+max*2>b.Length){Invalid(m,"MD_ROLE_TABLE_BOUNDS");return m;}
            int used=256+(int)max*2;byte[] metadata=b.Take(used).ToArray();m.MetadataSha256=Hash(metadata);
            if(Checksum(b,used,216,false)!=U32(b,216)){Invalid(m,"MD_CHECKSUM_INVALID");return m;}m.ChecksumValid=true;
            m.Uuid=new Guid(b.Skip(16).Take(16).ToArray()).ToString();m.DeviceUuid=new Guid(b.Skip(168).Take(16).ToArray()).ToString();m.Name=Encoding.UTF8.GetString(b,32,32).Split('\0')[0];
            m.Level=unchecked((int)U32(b,72));m.LayoutCode=unchecked((int)U32(b,76));m.RaidDisks=unchecked((int)U32(b,92));m.DeviceNumber=unchecked((int)U32(b,160));m.Features=U32(b,8);m.Events=U64(b,200);m.CreationTime=U64(b,64);m.Clean=U64(b,208)==UInt64.MaxValue;
            try{m.ChunkBytes=Bytes(U32(b,88));m.DataOffset=Bytes(U64(b,128));m.DataBytes=Bytes(U64(b,136));m.ComponentBytes=Bytes(U64(b,80));if(m.Level==0)m.ComponentBytes=m.DataBytes;}
            catch(Failure error){Invalid(m,error.Code);return m;}
            // Linux super_1_load requires at least ten sectors of available
            // data. With end metadata (1.0), data_size must also fit before
            // sb_start, independently of the smaller currently used size.
            if(U64(b,144)!=(ulong)(offset/512)||m.DataBytes<10L*512||minor==0&&m.DataBytes>offset||m.DataOffset>length||m.DataBytes>length-m.DataOffset||m.ComponentBytes>m.DataBytes){Invalid(m,"MD_DATA_OR_SUPER_OFFSET_INVALID");return m;}
            if(m.DataOffset<offset+used&&m.DataOffset+m.ComponentBytes>offset){Invalid(m,"MD_METADATA_DATA_OVERLAP");return m;}
            if(m.Uuid==Guid.Empty.ToString()||U32(b,12)!=0||!Zero(b,224,32)){Reject(m,"MD_RESERVED_FIELDS_UNSUPPORTED");}
            // Bitmap presence does not change a clean array's mapping. Recovery,
            // reshape, bad-block remapping, replacements and journal/PPL do.
            if((m.Features&~(1U|4096U))!=0)Reject(m,"MD_FEATURES_UNSUPPORTED");
            if((m.Features&4096U)!=0&&m.Level!=0)Reject(m,"MD_FEATURES_UNSUPPORTED");
            if((b[184]&~3)!=0)Reject(m,"MD_DEVICE_FLAGS_UNSUPPORTED");
            if(m.DeviceNumber<0||m.DeviceNumber>=max){Invalid(m,"MD_DEVICE_NUMBER_INVALID");return m;}
            var roles=new HashSet<int>();bool duplicate=false;for(int i=0;i<max;i++){int role=U16(b,256+i*2);if(role<0xff00){if(role>=m.RaidDisks||!roles.Add(role))duplicate=true;}else if(role!=0xffff&&role!=0xfffe&&role!=0xfffd)duplicate=true;}
            m.RoleMapSha256=Hash(b.Skip(256).Take((int)max*2).ToArray());m.Role=U16(b,256+m.DeviceNumber*2);m.Active=m.Role<0xff00&&m.Role<m.RaidDisks;
            if(duplicate)Reject(m,"MD_ROLE_TABLE_INCONSISTENT");if(!m.Active)Reject(m,"MD_NOT_ACTIVE_MEMBER");if(!m.Clean)Reject(m,"MD_ARRAY_NOT_FULLY_SYNCED");Layout(m);return m;
        }
        static Member VersionZero(byte[] b,string path,long length,long offset,bool big)
        {
            var m=new Member{Path=path,FileBytes=length,MetadataOffset=offset,Format="0.90"+(big?"-be":""),Supported=true,Status="candidate",Code="MD_METADATA_CANDIDATE"};
            if(b.Length!=4096){Invalid(m,"MD_SUPERBLOCK_TRUNCATED");return m;}m.MetadataSha256=Hash(b);
            if(U32(b,8,big)!=90||U32(b,12,big)>3){Reject(m,"MD_LEGACY_VERSION_UNSUPPORTED");return m;}
            if(Checksum(b,4096,152,big)!=U32(b,152,big)){Invalid(m,"MD_CHECKSUM_INVALID");return m;}m.ChecksumValid=true;
            byte[] uuid=new byte[16];int[] words={20,52,56,60};for(int i=0;i<4;i++)Buffer.BlockCopy(BitConverter.GetBytes(U32(b,words[i],big)),0,uuid,i*4,4);m.Uuid=new Guid(uuid).ToString();
            m.Level=unchecked((int)U32(b,28,big));m.LayoutCode=unchecked((int)U32(b,256,big));m.RaidDisks=unchecked((int)U32(b,40,big));m.ChunkBytes=U32(b,260,big);m.ComponentBytes=(long)U32(b,32,big)*1024;m.DataBytes=m.ComponentBytes;m.DataOffset=0;if(m.Level==0)m.ComponentBytes=m.DataBytes=offset;
            m.Events=((ulong)U32(b,big?156:160,big)<<32)|U32(b,big?160:156,big);m.CreationTime=U32(b,24,big);uint state=U32(b,132,big);m.Clean=(state&1)!=0;
            m.DeviceNumber=unchecked((int)U32(b,3968,big));m.Role=unchecked((int)U32(b,3980,big));uint flags=U32(b,3984,big);m.Active=(flags&6)==6&&(flags&9)==0&&m.Role>=0&&m.Role<m.RaidDisks;
            const uint knownDiskFlags=1U|2U|4U|8U|512U|1024U;
            if((flags&~knownDiskFlags)!=0)Reject(m,"MD_LEGACY_DEVICE_FLAGS_UNSUPPORTED");
            if(m.ComponentBytes<=0||m.ComponentBytes>offset||m.RaidDisks>27||m.DeviceNumber<0||m.DeviceNumber>=27){Invalid(m,"MD_LEGACY_GEOMETRY_INVALID");return m;}
            if(m.Uuid==Guid.Empty.ToString()||U32(b,48,big)!=0||(state&~257U)!=0)Reject(m,"MD_LEGACY_STATE_UNSUPPORTED");
            var roles=new HashSet<int>();var map=new List<byte>();bool duplicate=false;int active=0;
            for(int i=0;i<27;i++){int at=512+i*128;uint diskFlags=U32(b,at+16,big);if((diskFlags&~knownDiskFlags)!=0)Reject(m,"MD_LEGACY_DEVICE_FLAGS_UNSUPPORTED");int role=unchecked((int)U32(b,at+12,big));bool online=(diskFlags&6)==6&&(diskFlags&9)==0;if(online){active++;if(U32(b,at,big)!=(uint)i||role<0||role>=m.RaidDisks||!roles.Add(role))duplicate=true;}map.AddRange(BitConverter.GetBytes(online?role:-1));}
            m.RoleMapSha256=Hash(map.ToArray());int descriptor=512+m.DeviceNumber*128;if(U32(b,descriptor,big)!=(uint)m.DeviceNumber||U32(b,descriptor+12,big)!=(uint)m.Role||U32(b,descriptor+16,big)!=flags||active!=U32(b,136,big))duplicate=true;
            if(duplicate)Reject(m,"MD_ROLE_TABLE_INCONSISTENT");if(!m.Active)Reject(m,"MD_NOT_ACTIVE_MEMBER");if(!m.Clean)Reject(m,"MD_ARRAY_NOT_FULLY_SYNCED");Layout(m);return m;
        }
        static void ProbeFile(string value,Report report,Dictionary<string,string> identities,CancellationToken cancel)
        {
            string full=value;int first=report.Members.Count;
            try{
                full=SafePath(value);using(var file=new FileStream(full,FileMode.Open,FileAccess.Read,FileShare.Read,4096)){
                    Identity before;if(!GetFileInformationByHandle(file.SafeFileHandle,out before)||before.Links!=1)throw new Failure("MD_FILE_IDENTITY_INVALID");string id=before.Volume+":"+before.IndexHigh+":"+before.IndexLow;string previous;if(identities.TryGetValue(id,out previous)){foreach(var prior in report.Members.Where(m=>m.Path==previous)){Reject(prior,"MD_DUPLICATE_IMAGE");prior.Status="ambiguous";}throw new Failure("MD_DUPLICATE_IMAGE");}identities.Add(id,full);
                    long length=file.Length;if(length<512||length%512!=0)throw new Failure("MD_RAW_LENGTH_INVALID");var offsets=new Dictionary<long,int>();if(length>=4096)offsets[0]=1;if(length>=8192)offsets[4096]=2;if(length>=8192&&!offsets.ContainsKey(((length/512-16)&~7L)*512))offsets[((length/512-16)&~7L)*512]=0;if(length>=65536&&!offsets.ContainsKey((length/65536-1)*65536))offsets[(length/65536-1)*65536]=-1;
                    var observed=new List<KeyValuePair<long,byte[]>>();foreach(var pair in offsets){
                        byte[] b=Read(file,pair.Key,(int)Math.Min(4096,length-pair.Key),report,cancel);observed.Add(new KeyValuePair<long,byte[]>(pair.Key,b));uint magic=U32(b,0);bool big=magic==0xfc4e2ba9;
                        if(magic!=0xa92b4efc&&!big)continue;Member member;
                        if(!big&&U32(b,4)==1&&pair.Value>=0)member=VersionOne(b,full,length,pair.Key,pair.Value);
                        else if(U32(b,4,big)==0&&length>=65536&&pair.Key==(length/65536-1)*65536)member=VersionZero(b,full,length,pair.Key,big);
                        else member=new Member{Path=full,FileBytes=length,MetadataOffset=pair.Key,Status="unsupported",Code="MD_UNKNOWN_SUPERBLOCK_VERSION",Reasons=new List<string>{"MD_UNKNOWN_SUPERBLOCK_VERSION"}};
                        report.Members.Add(member);
                    }
                    foreach(var pair in observed)if(!pair.Value.SequenceEqual(Read(file,pair.Key,pair.Value.Length,report,cancel)))throw new Failure("MD_SOURCE_CHANGED");Identity after;if(!GetFileInformationByHandle(file.SafeFileHandle,out after)||before.Volume!=after.Volume||before.IndexHigh!=after.IndexHigh||before.IndexLow!=after.IndexLow||before.WrittenHigh!=after.WrittenHigh||before.WrittenLow!=after.WrittenLow||before.SizeHigh!=after.SizeHigh||before.SizeLow!=after.SizeLow)throw new Failure("MD_SOURCE_CHANGED");
                    if(report.Members.Count==first)report.Members.Add(new Member{Path=full,FileBytes=length,SourceUnchanged=true});else{for(int i=first;i<report.Members.Count;i++)report.Members[i].SourceUnchanged=true;if(report.Members.Count-first>1)for(int i=first;i<report.Members.Count;i++){Reject(report.Members[i],"MD_MULTIPLE_SUPERBLOCKS");report.Members[i].Status="ambiguous";}}
                }
            }catch(OperationCanceledException){throw;}catch(Failure error){foreach(var prior in report.Members.Skip(first))Invalid(prior,error.Code);report.Members.Add(new Member{Path=full,Status="invalid",Code=error.Code,Reasons=new List<string>{error.Code}});}catch(IOException){report.Members.Add(new Member{Path=full,Status="invalid",Code="MD_SOURCE_IO_FAILED",Reasons=new List<string>{"MD_SOURCE_IO_FAILED"}});}catch(UnauthorizedAccessException){report.Members.Add(new Member{Path=full,Status="invalid",Code="MD_SOURCE_ACCESS_DENIED",Reasons=new List<string>{"MD_SOURCE_ACCESS_DENIED"}});}catch(ArgumentException){report.Members.Add(new Member{Path=full,Status="invalid",Code="MD_SOURCE_PATH_INVALID",Reasons=new List<string>{"MD_SOURCE_PATH_INVALID"}});}catch(NotSupportedException){report.Members.Add(new Member{Path=full,Status="invalid",Code="MD_SOURCE_PATH_INVALID",Reasons=new List<string>{"MD_SOURCE_PATH_INVALID"}});}
        }
        static void Reason(Group group,string reason){if(!group.Reasons.Contains(reason))group.Reasons.Add(reason);}
        static Group MakeGroup(IEnumerable<Member> members)
        {
            var list=members.ToList();Member first=list[0];var group=new Group{Uuid=first.Uuid,Format=first.Format,Name=first.Name,Level=first.Level.ToString(System.Globalization.CultureInfo.InvariantCulture),Layout=first.Layout,RaidDisks=first.RaidDisks,ComponentBytes=first.ComponentBytes,ChunkBytes=first.ChunkBytes,Events=first.Events,Members=list};
            foreach(var member in list)foreach(string reason in member.Reasons)Reason(group,reason);
            if(list.Any(m=>m.Status=="ambiguous")){group.Status="ambiguous";return group;}
            if(list.Any(m=>m.Format!=first.Format||m.Level!=first.Level||m.LayoutCode!=first.LayoutCode||m.RaidDisks!=first.RaidDisks||m.ComponentBytes!=first.ComponentBytes||m.ChunkBytes!=first.ChunkBytes||m.CreationTime!=first.CreationTime||m.RoleMapSha256!=first.RoleMapSha256||m.Name!=first.Name)){
                group.Status="inconsistent";Reason(group,"MD_ARRAY_GEOMETRY_MISMATCH");return group;
            }
            if(list.Any(m=>m.Events!=first.Events)){group.Status="inconsistent";Reason(group,"MD_EVENT_COUNTER_MISMATCH");return group;}
            if(list.GroupBy(m=>m.DeviceNumber).Any(g=>g.Count()>1)||list.Where(m=>m.Active).GroupBy(m=>m.Role).Any(g=>g.Count()>1)||list.Where(m=>!String.IsNullOrEmpty(m.DeviceUuid)&&m.DeviceUuid!=Guid.Empty.ToString()).GroupBy(m=>m.DeviceUuid).Any(g=>g.Count()>1)){
                group.Status="ambiguous";Reason(group,"MD_DUPLICATE_DEVICE_OR_ROLE");return group;
            }
            if(list.Any(m=>!m.Supported||!m.ChecksumValid||!m.SourceUnchanged)){group.Status="unsupported";return group;}
            var active=list.Where(m=>m.Active).ToDictionary(m=>m.Role);for(int role=0;role<first.RaidDisks;role++)if(!active.ContainsKey(role))group.MissingRoles.Add(role);
            var config=new RaidConfiguration{Level=group.Level,Layout=group.Layout,ChunkSize=group.ChunkBytes==0?512:group.ChunkBytes};
            for(int role=0;role<first.RaidDisks;role++){Member m;config.Members.Add(active.TryGetValue(role,out m)?new RaidMember{Path=m.Path,Offset=m.DataOffset}:new RaidMember{Missing=true});}
            int data=first.Level==0?first.RaidDisks:first.Level==5?first.RaidDisks-1:first.Level==6?first.RaidDisks-2:first.Level==10?first.RaidDisks/2:1;
            try{config.LogicalSize=checked(first.ComponentBytes*data);RaidImageBuilder.Validate(config);}catch(OverflowException){Reason(group,"MD_ARRAY_SIZE_OVERFLOW");return group;}catch(RaidRecoveryException error){Reason(group,error.Code);return group;}
            group.LogicalBytes=config.LogicalSize;group.Configuration=config;group.Status="candidate";Reason(group,"MD_METADATA_ONLY_REVIEW_REQUIRED");return group;
        }
        public static Report Probe(IEnumerable<string> images,CancellationToken cancel,Action<int,int> progress=null)
        {
            if(images==null)throw new ArgumentNullException("images");var paths=new List<string>();foreach(string image in images){cancel.ThrowIfCancellationRequested();if(paths.Count>=MaximumImages)throw new ArgumentException("MD_IMAGE_LIMIT");paths.Add(image);}var report=new Report{Images=paths.Count};var identities=new Dictionary<string,string>(StringComparer.Ordinal);
            for(int i=0;i<paths.Count;i++){cancel.ThrowIfCancellationRequested();ProbeFile(paths[i],report,identities,cancel);if(progress!=null)progress(i+1,paths.Count);}
            foreach(var set in report.Members.Where(m=>m.ChecksumValid&&!String.IsNullOrEmpty(m.Uuid)).GroupBy(m=>m.Uuid,StringComparer.OrdinalIgnoreCase))report.Groups.Add(MakeGroup(set));return report;
        }
    }
}
