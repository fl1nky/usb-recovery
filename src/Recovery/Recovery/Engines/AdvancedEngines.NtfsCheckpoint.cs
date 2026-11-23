// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class AdvancedEngines
    {
        sealed class NtfsVolumePlan
        {
            public int Number, SectorSize;
            public long Offset, Length, BootOffset;
            public string Table;
        }
        sealed class NtfsVolumeResult
        {
            public int Files;
            public bool Complete;
            public RecoveryMethodCheckpoint Anchor;
            internal NtfsVolumeResult Copy() {return (NtfsVolumeResult)MemberwiseClone();}
        }
        sealed class NtfsEngineState
        {
            public int Schema=1, Phase;
            public string Identity, ReportSha256;
            public int ReportBytes;
            public List<NtfsVolumeResult> Volumes;
            internal NtfsEngineState Copy()
            {var copy=(NtfsEngineState)MemberwiseClone();copy.Volumes=Volumes.Select(x=>x.Copy()).ToList();return copy;}
        }
        static byte[] NtfsEncode(object value)
        {return new UTF8Encoding(false,true).GetBytes(new JavaScriptSerializer {MaxJsonLength=1024*1024}.Serialize(value));}
        static string NtfsHash(byte[] data)
        {using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(data)).Replace("-","").ToLowerInvariant();}
        static List<NtfsVolumePlan> NtfsPlans(FileStream source, IList<BootCandidate> discovered, CancellationToken cancel)
        {
            var plans=new List<NtfsVolumePlan>();
            foreach(var partition in FindNtfs(source.Name,cancel))plans.Add(new NtfsVolumePlan {Number=partition.Number,SectorSize=partition.SectorSize,
                Offset=partition.Offset,Length=partition.Length,BootOffset=partition.Offset,Table=partition.Table});
            if(discovered!=null)foreach(var candidate in discovered) {
                if(candidate==null || candidate.Kind!="NTFS" || plans.Any(x=>x.Offset==candidate.Offset))continue;
                plans.Add(new NtfsVolumePlan {Number=1000+plans.Count,SectorSize=candidate.SectorSize,Offset=candidate.Offset,
                    Length=candidate.Length,BootOffset=candidate.BootOffset,Table="discovered_view"});
            }
            if(plans.Count>BootScout.MaximumVolumes)throw new IOException("NTFS_PARTITION_LIMIT");
            foreach(var plan in plans) {
                cancel.ThrowIfCancellationRequested();
                if(plan.Offset<0 || plan.Length<512 || plan.Offset>source.Length-plan.Length || plan.BootOffset<plan.Offset ||
                    plan.SectorSize!=512&&plan.SectorSize!=1024&&plan.SectorSize!=2048&&plan.SectorSize!=4096 ||
                    plan.BootOffset>source.Length-plan.SectorSize)throw new IOException("NTFS_PARTITION_PLAN_INVALID");
                byte[] boot=ReadAt(source,plan.BootOffset,512);
                if(boot==null || Encoding.ASCII.GetString(boot,3,8)!="NTFS    " || boot[510]!=0x55 || boot[511]!=0xaa ||
                    BitConverter.ToUInt16(boot,11)!=plan.SectorSize || boot[13]==0 || (boot[13]&(boot[13]-1))!=0)
                    throw new IOException("NTFS_PARTITION_BOOT_INVALID");
                ulong last=BitConverter.ToUInt64(boot,40);
                if(last==UInt64.MaxValue || last+1>(ulong)(plan.Length/plan.SectorSize))throw new IOException("NTFS_PARTITION_GEOMETRY_INVALID");
                plan.Length=checked((long)(last+1)*plan.SectorSize);
                if(plan.BootOffset!=plan.Offset && plan.BootOffset!=plan.Offset+plan.Length-plan.SectorSize)
                    throw new IOException("NTFS_PARTITION_BACKUP_INVALID");
            }
            return plans.OrderBy(x=>x.Offset).ThenBy(x=>x.BootOffset).ToList();
        }
        static RecoveryCheckpointContext NtfsVolumeContext(RecoveryCheckpointContext parent,int index,RecoveryMethodCheckpoint anchor,
            Action<RecoveryMethodCheckpoint> commit)
        {
            string directory=Path.GetDirectoryName(RecoveryCatalog.SafeFile(parent.Directory,"ntfs.state/volumes/volume-"+index.ToString(CultureInfo.InvariantCulture)+"/guard"));
            RecoveryMethodCheckpoint resume=null;
            if(anchor!=null) {
                if(anchor.Path==null || Path.IsPathRooted(anchor.Path))throw new IOException("NTFS_VOLUME_LINK_INVALID");
                resume=new RecoveryMethodCheckpoint {Path=RecoveryCatalog.SafeFile(parent.Directory,anchor.Path),Sha256=anchor.Sha256,Sequence=anchor.Sequence};
            }
            return new RecoveryCheckpointContext {Directory=directory,Method="ntfs",SourceSha256=parent.SourceSha256,
                Settings=NtfsHash(Encoding.UTF8.GetBytes(parent.Settings))+":volume-"+index.ToString(CultureInfo.InvariantCulture),Resume=resume,
                Commit=value=>{
                    string prefix=Path.GetFullPath(parent.Directory).TrimEnd('\\','/')+Path.DirectorySeparatorChar,path=Path.GetFullPath(value.Path);
                    if(!path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase))throw new IOException("NTFS_VOLUME_COMMIT_INVALID");
                    commit(new RecoveryMethodCheckpoint {Path=path.Substring(prefix.Length).Replace('\\','/'),Sha256=value.Sha256,Sequence=value.Sequence});
                }};
        }
        internal static int RecoverNtfsCheckpointed(string image,string directory,CancellationToken cancel,Action<string> progress,
            IList<BootCandidate> discovered,RecoveryCheckpointContext checkpoint,IList<RecoveryNativeToolFile> nativeTools=null)
        {
            if(checkpoint==null || checkpoint.Method!="ntfs" || checkpoint.Settings==null)throw new IOException("NTFS_ENGINE_CONTEXT_INVALID");
            image=ValidateImage(image);string root=Path.GetFullPath(directory);
            var context=new RecoveryCheckpointContext {Directory=Path.GetFullPath(checkpoint.Directory),Method="ntfs",Settings=checkpoint.Settings,
                SourceSha256=checkpoint.SourceSha256,Resume=checkpoint.Resume,Commit=checkpoint.Commit};
            if(root!=context.Directory)throw new IOException("NTFS_ENGINE_OUTPUT_CONTEXT_INVALID");
            using(var source=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))
            using(var verified=new RecoveryVerifiedImage(source,context.SourceSha256,cancel)) {
                var plans=NtfsPlans(source,discovered,cancel);
                var tools=plans.Count==0?new List<RecoveryNativeToolFile>():nativeTools??RecoveryNativeTools.Ntfs();
                string identity=NtfsHash(NtfsEncode(new {Profile="native-ntfs-checkpoint-v1",Volumes=plans,
                    Tools=tools.Select(t=>new {Name=Path.GetFileName(t.Path),Sha256=t.Sha256}).ToArray()}));
                var journal=new RecoveryMethodJournal<NtfsEngineState>(image,new NtfsEngineState {Identity=identity,
                    Volumes=plans.Select(x=>new NtfsVolumeResult()).ToList()},context,cancel);
                var state=journal.Payload;
                if(state.Schema!=1 || state.Identity!=identity || state.Phase<0 || state.Phase>2 || state.Volumes==null || state.Volumes.Count!=plans.Count ||
                    state.Volumes.Any(x=>x==null || x.Files<0 || x.Files>100000 || x.Complete&&x.Anchor==null) ||
                    state.Phase>0&&state.Volumes.Any(x=>!x.Complete) || state.Phase==0&&(state.ReportSha256!=null||state.ReportBytes!=0))
                    throw new IOException("NTFS_ENGINE_CHECKPOINT_INVALID");
                Action<NtfsEngineState> save=next=>{cancel.ThrowIfCancellationRequested();verified.Validate(source,context.SourceSha256);journal.Save(next);state=next;};
                for(int i=0;i<plans.Count;i++) {
                    int index=i;var plan=plans[i];
                    var child=NtfsVolumeContext(context,index,state.Volumes[index].Anchor,link=>{
                        var next=state.Copy();next.Volumes[index].Anchor=link;save(next);
                    });
                    string output=RecoveryCatalog.SafeFile(root,"ntfs/partition-"+index.ToString(CultureInfo.InvariantCulture)+"/data");
                    if(progress!=null)progress("ntfs: volume "+index.ToString(CultureInfo.InvariantCulture)+" begin");
                    cancel.ThrowIfCancellationRequested();
                    var engine=new RecoveryNativeNtfsVolume(source,verified,child,tools,plan.Offset,plan.Length,plan.SectorSize,
                        root,output,1024L*1024*1024*1024,4L*1024*1024*1024,100000,TimeSpan.FromHours(24),cancel,progress,
                        plan.BootOffset==plan.Offset?(long?)null:plan.BootOffset,
                        RecoveryCatalog.SafeFile(root,"ntfs/partition-"+index.ToString(CultureInfo.InvariantCulture)+"/ntfs-volume.json"));
                    int count=engine.Run();
                    if(state.Volumes[index].Complete && state.Volumes[index].Files!=count)throw new IOException("NTFS_VOLUME_RESULT_CHANGED");
                    if(!state.Volumes[index].Complete){var next=state.Copy();next.Volumes[index].Files=count;next.Volumes[index].Complete=true;save(next);}
                }
                int files=state.Volumes.Sum(x=>x.Files);
                byte[] report=NtfsEncode(new {engine="TestDisk NTFS checkpoint worker",status="complete",detected_partitions=plans.Count,files=files,
                    partitions=plans.Select((plan,index)=>new {partition=index,offset=plan.Offset,length=plan.Length,table=plan.Table,
                        boot_offset=plan.BootOffset,status="complete",files=state.Volumes[index].Files,
                        report="partition-"+index.ToString(CultureInfo.InvariantCulture)+"/ntfs-volume.json"}).ToArray(),
                    note="Source image unchanged. Allocation recoverability does not prove original content integrity."});
                string digest=NtfsHash(report);
                if(state.Phase==0){var next=state.Copy();next.Phase=1;next.ReportSha256=digest;next.ReportBytes=report.Length;save(next);if(progress!=null)progress("ntfs: engine report pending");}
                if(state.ReportSha256!=digest || state.ReportBytes!=report.Length)throw new IOException("NTFS_ENGINE_REPORT_CHANGED");
                string path=RecoveryCatalog.SafeFile(root,"ntfs/report.json");Directory.CreateDirectory(Path.GetDirectoryName(path));
                if(!File.Exists(path)) {
                    string pending=RecoveryCatalog.SafeFile(root,"ntfs/report-"+Guid.NewGuid().ToString("N")+".partial");
                    using(var file=new FileStream(pending,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){file.Write(report,0,report.Length);file.Flush(true);}
                    cancel.ThrowIfCancellationRequested();File.Move(pending,path);
                }
                using(var lease=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                    if(lease.Length!=report.Length || RecoveryCore.HashFile(path,cancel,(n,total)=>{})!=digest)throw new IOException("NTFS_ENGINE_REPORT_CHANGED");
                    if(state.Phase!=2){var next=state.Copy();next.Phase=2;save(next);}
                }
                return files;
            }
        }
    }
}
