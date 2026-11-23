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
    // One logical NTFS volume. Partition discovery and pipeline ownership stay
    // outside this controller; they must supply a distinct anchored context.
    internal sealed class RecoveryNativeNtfsVolume
    {
        const int MaximumPlanBytes = 8 * 1024 * 1024, MaximumReportBytes = 32 * 1024 * 1024;
        sealed class State
        {
            public int Schema = 1, Phase, ClusterBytes, RecordBytes, Files, DoneStreams, Part;
            public long Next, Records;
            public string Binding, Record, Candidate, ReportHash;
            public int ReportBytes;
            public RecoveryMethodCheckpoint Cache, ActiveFile;
            public RecoveryOutputHead Finished, Candidates, Repairs;
            internal State Copy() { return (State)MemberwiseClone(); }
        }
        sealed class Candidate
        { public int Schema = 1; public RecoveryNativeNtfsRecord Record; public RecoveryNativeNtfsStream Stream; }
        sealed class FileFact
        { public int Index, Part; public string Candidate, Sha256; public RecoveryMethodCheckpoint Anchor; }
        sealed class CandidateFact
        { public long Ordinal; public uint Stream; public string Candidate, Status; public int FirstFile, Files; }
        sealed class RepairFact { public int Index; public RecoveryMethodCheckpoint Anchor; }

        readonly FileStream source;
        readonly RecoveryVerifiedImage verified;
        readonly RecoveryCheckpointContext context;
        readonly List<RecoveryNativeToolFile> tools;
        readonly long offset, length, maximumFile, maximumCache;
        readonly long? backupBootOffset;
        readonly int sector, maximumFiles;
        readonly TimeSpan deadline;
        readonly CancellationToken cancel;
        readonly Action<string> notify;
        readonly string archiveRoot, outputRoot, reportPath, contextRoot, settings, sourceHash, binding;
        readonly RecoveryMethodJournal<State> journal;
        readonly RecoveryOutputLedger<FileFact> finished;
        readonly RecoveryOutputLedger<CandidateFact> candidates;
        readonly RecoveryOutputLedger<RepairFact> repairs;
        readonly Dictionary<int, RecoveryMethodCheckpoint> repaired = new Dictionary<int, RecoveryMethodCheckpoint>();
        readonly Dictionary<string, CandidateFact> candidateIndex = new Dictionary<string, CandidateFact>();
        State state;
        bool ran;
        Action workerGuard;

        static string Hash(byte[] bytes)
        { using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
        static bool Digest(string value)
        { return value != null && value.Length == 64 && value.All(ch => ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f'); }
        static string Key(long ordinal, uint stream)
        { return ordinal.ToString(CultureInfo.InvariantCulture) + ":" + stream.ToString(CultureInfo.InvariantCulture); }
        static byte[] Encode(object value, int maximum)
        {
            byte[] bytes = new UTF8Encoding(false,true).GetBytes(new JavaScriptSerializer { MaxJsonLength = maximum }.Serialize(value));
            if (bytes.Length > maximum) throw new IOException("NATIVE_NTFS_SERIALIZATION_LIMIT"); return bytes;
        }
        internal RecoveryNativeNtfsVolume(FileStream input, RecoveryVerifiedImage image, RecoveryCheckpointContext checkpoint,
            IList<RecoveryNativeToolFile> executables, long volumeOffset, long volumeBytes, int sectorBytes,
            string archive, string output, long maximumFileBytes, long maximumCacheBytes, int maximumOutputFiles,
            TimeSpan maximumTime, CancellationToken token, Action<string> progress, long? backupBoot = null, string reportFile = null)
        {
            if (input == null || input.CanWrite || image == null || checkpoint == null || checkpoint.Method != "ntfs" ||
                executables == null || executables.Count < 1 || executables.Count > 32 ||
                volumeOffset < 0 || volumeBytes < 512 || volumeOffset > input.Length - volumeBytes ||
                maximumFileBytes < 0 || maximumOutputFiles < 1 || maximumOutputFiles > 1000000)
                throw new IOException("NATIVE_NTFS_VOLUME_CONTEXT_INVALID");
            if(backupBoot.HasValue && (backupBoot.Value<volumeOffset || backupBoot.Value>volumeOffset+volumeBytes-sectorBytes ||
                backupBoot.Value==volumeOffset))throw new IOException("NATIVE_NTFS_BACKUP_VIEW_INVALID");
            source = input; verified = image; context = checkpoint; cancel = token; notify = progress;
            offset = volumeOffset; length = volumeBytes; sector = sectorBytes;
            backupBootOffset=backupBoot;
            maximumFile = maximumFileBytes; maximumCache = maximumCacheBytes; maximumFiles = maximumOutputFiles; deadline = maximumTime;
            archiveRoot = Path.GetFullPath(archive); outputRoot = Path.GetFullPath(output); contextRoot = Path.GetFullPath(context.Directory);
            reportPath=RecoveryCatalog.SafeFile(archiveRoot,reportFile??Path.Combine(outputRoot,"ntfs-volume.json"));
            if(String.Equals(reportPath,Path.GetFullPath(source.Name),StringComparison.OrdinalIgnoreCase))throw new IOException("NATIVE_NTFS_REPORT_SCOPE_INVALID");
            settings = context.Settings; sourceHash = context.SourceSha256;
            tools = executables.Select(x => x == null ? null : new RecoveryNativeToolFile { Path = x.Path, Sha256 = x.Sha256 }).ToList();
            var archiveUri=new Uri(archiveRoot.TrimEnd('\\','/')+Path.DirectorySeparatorChar);
            // Include executable AND DLL digests, geometry and public resource
            // limits. A different worker/configuration cannot resume this state.
            binding = Hash(Encode(new { Offset = offset, Length = length, Sector = sector, MaximumFile = maximumFile,
                MaximumCache = maximumCache, MaximumFiles = maximumFiles, DeadlineTicks = deadline.Ticks, BackupBootOffset=backupBootOffset,
                OutputRole=archiveUri.MakeRelativeUri(new Uri(outputRoot.TrimEnd('\\','/')+Path.DirectorySeparatorChar)).ToString(),
                ContextRole=archiveUri.MakeRelativeUri(new Uri(contextRoot.TrimEnd('\\','/')+Path.DirectorySeparatorChar)).ToString(),
                ReportRole=archiveUri.MakeRelativeUri(new Uri(reportPath)).ToString(),
                Tools = tools.Select(x => x == null ? "invalid" : Path.GetFileName(x.Path) + ":" + x.Sha256).ToArray() }, 65536));
            Guard();
            journal = new RecoveryMethodJournal<State>(source.Name, new State { Binding = binding }, context, cancel); state = journal.Payload;
            if (state.Schema != 1 || state.Binding != binding || state.Phase < 0 || state.Phase > 3 ||
                state.Next < 0 || state.Next > RecoveryNativeNtfsPlans.MaximumRecords || state.Records < state.Next ||
                state.Records > RecoveryNativeNtfsPlans.MaximumRecords || state.Files < 0 || state.Files > maximumFiles ||
                state.DoneStreams < 0 || state.DoneStreams > 4096 || state.Part < 0 || state.Part > 32768 ||
                state.Record != null && !Digest(state.Record) || state.Candidate != null && !Digest(state.Candidate) ||
                state.Candidate == null && (state.ActiveFile != null || state.Part != 0) ||
                state.Record == null && (state.Candidate != null || state.DoneStreams != 0) ||
                state.Records==0 && (state.ClusterBytes!=0 || state.RecordBytes!=0) || state.Records>0 &&
                    (state.ClusterBytes<sector || state.ClusterBytes>2*1024*1024 || (state.ClusterBytes&(state.ClusterBytes-1))!=0 ||
                    state.RecordBytes<sector || state.RecordBytes>65536 || (state.RecordBytes&(state.RecordBytes-1))!=0) ||
                state.Phase > 0 && (state.Next != state.Records || state.Record != null) ||
                state.Phase >= 2 && (!Digest(state.ReportHash) || state.ReportBytes < 1 || state.ReportBytes > MaximumReportBytes) ||
                state.Phase < 2 && (state.ReportHash != null || state.ReportBytes != 0))
                throw new IOException("NATIVE_NTFS_VOLUME_CHECKPOINT_INVALID");
            finished = new RecoveryOutputLedger<FileFact>(Child("files",null,null),state.Finished,maximumFiles,cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
            candidates = new RecoveryOutputLedger<CandidateFact>(Child("candidates",null,null),state.Candidates,maximumFiles,cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
            repairs = new RecoveryOutputLedger<RepairFact>(Child("repairs",null,null),state.Repairs,2000000,cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
            if (finished.Records.Count != state.Files) throw new IOException("NATIVE_NTFS_FILE_COUNT_INVALID");
            for (int i=0;i<finished.Records.Count;i++) {
                var fact=finished.Records[i];
                if(fact.Index!=i || fact.Part<0 || fact.Part>32768 || !Digest(fact.Candidate) || !Digest(fact.Sha256) || fact.Anchor==null)
                    throw new IOException("NATIVE_NTFS_FILE_FACT_INVALID");
            }
            foreach(var fact in candidates.Records) {
                string key=Key(fact.Ordinal,fact.Stream);
                if(fact.Ordinal<0 || fact.Ordinal>state.Next || fact.Stream>=4096 || !Digest(fact.Candidate) || fact.FirstFile<0 ||
                    fact.Files<0 || fact.FirstFile>state.Files-fact.Files || candidateIndex.ContainsKey(key)) throw new IOException("NATIVE_NTFS_CANDIDATE_FACT_INVALID");
                candidateIndex.Add(key,fact);
            }
            foreach(var fact in repairs.Records) {
                if(fact.Index<0 || fact.Index>=state.Files || fact.Anchor==null)throw new IOException("NATIVE_NTFS_REPAIR_FACT_INVALID");
                repaired[fact.Index]=fact.Anchor;
            }
        }
        void Guard()
        {
            cancel.ThrowIfCancellationRequested(); if(workerGuard!=null)workerGuard(); verified.Validate(source,sourceHash);
            if(Path.GetFullPath(context.Directory)!=contextRoot || context.Method!="ntfs" || context.Settings!=settings || context.SourceSha256!=sourceHash)
                throw new IOException("NATIVE_NTFS_VOLUME_CONTEXT_CHANGED");
            RecoveryCatalog.SafeFile(archiveRoot,"guard"); RecoveryCatalog.SafeFile(outputRoot,"guard");RecoveryCatalog.SafeFile(archiveRoot,reportPath);
            string prefix=archiveRoot.TrimEnd('\\','/')+Path.DirectorySeparatorChar;
            if(!outputRoot.StartsWith(prefix,StringComparison.OrdinalIgnoreCase) ||
                contextRoot!=archiveRoot && !contextRoot.StartsWith(prefix,StringComparison.OrdinalIgnoreCase))throw new IOException("NATIVE_NTFS_OUTPUT_SCOPE_INVALID");
        }
        void Save(State next) { Guard(); journal.Save(next); state=next; }
        void Notify(string text) { if(notify!=null)notify(text); Guard(); }
        RecoveryCheckpointContext Child(string role, RecoveryMethodCheckpoint anchor, Action<RecoveryMethodCheckpoint> commit)
        {
            string child=Path.GetDirectoryName(RecoveryCatalog.SafeFile(contextRoot,"ntfs.state/children/"+role+"/guard"));
            RecoveryMethodCheckpoint resume=null;
            if(anchor!=null) {
                if(anchor.Path==null || Path.IsPathRooted(anchor.Path))throw new IOException("NATIVE_NTFS_CHILD_LINK_INVALID");
                resume=new RecoveryMethodCheckpoint {Path=RecoveryCatalog.SafeFile(contextRoot,anchor.Path),Sha256=anchor.Sha256,Sequence=anchor.Sequence};
            }
            return new RecoveryCheckpointContext {Directory=child,Method="ntfs",SourceSha256=sourceHash,Settings=binding+":"+role,Resume=resume,
                Commit=value=>{
                    string prefix=contextRoot.TrimEnd('\\','/')+Path.DirectorySeparatorChar,path=Path.GetFullPath(value.Path);
                    if(commit==null || !path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase))throw new IOException("NATIVE_NTFS_CHILD_COMMIT_INVALID");
                    commit(new RecoveryMethodCheckpoint {Path=path.Substring(prefix.Length).Replace('\\','/'),Sha256=value.Sha256,Sequence=value.Sequence});
                }};
        }
        string PlanPath(string identity)
        {
            if(!Digest(identity))throw new IOException("NATIVE_NTFS_PLAN_ID_INVALID");
            return RecoveryCatalog.SafeFile(contextRoot,"ntfs.state/plans/plan-"+identity+".json");
        }
        string Store(Candidate candidate)
        {
            byte[] bytes=Encode(candidate,MaximumPlanBytes); string identity=Hash(bytes),path=PlanPath(identity);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            if(!File.Exists(path)) {
                string pending=RecoveryCatalog.SafeFile(contextRoot,"ntfs.state/plans/"+Guid.NewGuid().ToString("N")+".partial");
                using(var file=new FileStream(pending,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){file.Write(bytes,0,bytes.Length);file.Flush(true);}
                Guard();File.Move(pending,path);
            }
            Load(identity);return identity;
        }
        Candidate Load(string identity)
        {
            Guard();string path=PlanPath(identity);
            using(var lease=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                if(lease.Length<1 || lease.Length>MaximumPlanBytes)throw new IOException("NATIVE_NTFS_PLAN_CHANGED");
                byte[] bytes=File.ReadAllBytes(path);
                if(Hash(bytes)!=identity)throw new IOException("NATIVE_NTFS_PLAN_CHANGED");
                Candidate candidate;
                try {candidate=new JavaScriptSerializer {MaxJsonLength=MaximumPlanBytes}.Deserialize<Candidate>(new UTF8Encoding(false,true).GetString(bytes));}
                catch(ArgumentException){throw new IOException("NATIVE_NTFS_PLAN_INVALID");}
                catch(InvalidOperationException){throw new IOException("NATIVE_NTFS_PLAN_INVALID");}
                if(candidate==null || candidate.Schema!=1 || candidate.Record==null || candidate.Stream==null)throw new IOException("NATIVE_NTFS_PLAN_INVALID");
                return candidate;
            }
        }
        RecoveryNativeNtfsFile Map(Candidate candidate)
        {return RecoveryNativeNtfsFiles.Build(candidate.Record,candidate.Stream,offset,length,state.ClusterBytes,archiveRoot,outputRoot,maximumFile);}

        void Publish(string identity,int partIndex,int index,RecoveryMethodCheckpoint anchor,bool repair)
        {
            var mapped=Map(Load(identity));
            if(partIndex<0 || partIndex>=mapped.Parts.Count)throw new IOException("NATIVE_NTFS_PART_CHANGED");
            RecoveryMethodCheckpoint latest=anchor;
            var child=Child("file-"+index.ToString(CultureInfo.InvariantCulture),anchor,link=>{
                var next=state.Copy();
                if(repair) {
                    var rows=new List<RepairFact>{new RepairFact {Index=index,Anchor=link}};
                    next.Repairs=repairs.Append(state.Repairs,rows);Save(next);repairs.Accept(rows);repaired[index]=link;
                }else {next.ActiveFile=link;Save(next);}
                latest=link;
            });
            string digest;
            using(var publisher=new RecoveryMappedFilePublisher(source,mapped.Parts[partIndex].Plan,child,cancel,Guard,Notify,verified))digest=publisher.Run();
            if(repair) {
                if(digest!=finished.Records[index].Sha256)throw new IOException("NATIVE_NTFS_REPAIR_HASH_CHANGED");return;
            }
            if(latest==null || index!=state.Files || identity!=state.Candidate || partIndex!=state.Part)throw new IOException("NATIVE_NTFS_FILE_NOT_ANCHORED");
            var files=new List<FileFact>{new FileFact {Index=index,Part=partIndex,Candidate=identity,Sha256=digest,Anchor=latest}};
            var saved=state.Copy();saved.Finished=finished.Append(state.Finished,files);saved.Files++;saved.Part++;saved.ActiveFile=null;
            Save(saved);finished.Accept(files);Notify("ntfs: file "+index+" complete");
        }
        void RestoreFiles()
        {
            foreach(var fact in finished.Records) {
                RecoveryMethodCheckpoint anchor;if(!repaired.TryGetValue(fact.Index,out anchor))anchor=fact.Anchor;
                Publish(fact.Candidate,fact.Part,fact.Index,anchor,true);
            }
        }
        void Stream(RecoveryNativeNtfsRecord record,RecoveryNativeNtfsStream stream)
        {
            string identity=Store(new Candidate {Record=record,Stream=stream});
            if(stream.Index<state.DoneStreams) {
                CandidateFact old;
                if(!candidateIndex.TryGetValue(Key(record.Ordinal,stream.Index),out old) || old.Candidate!=identity)
                    throw new IOException("NATIVE_NTFS_REPLAY_CHANGED");return;
            }
            if(stream.Index!=state.DoneStreams || state.Candidate!=null && state.Candidate!=identity)throw new IOException("NATIVE_NTFS_STREAM_CHANGED");
            if(state.Candidate==null){var next=state.Copy();next.Candidate=identity;Save(next);}
            var mapped=Map(Load(identity));int first=state.Files-state.Part;
            if(state.Part>mapped.Parts.Count || mapped.Parts.Count-state.Part>maximumFiles-state.Files)throw new IOException("NATIVE_NTFS_FILE_LIMIT");
            while(state.Part<mapped.Parts.Count)Publish(identity,state.Part,state.Files,state.ActiveFile,false);
            var rows=new List<CandidateFact>{new CandidateFact {Ordinal=record.Ordinal,Stream=stream.Index,Candidate=identity,
                FirstFile=first,Files=mapped.Parts.Count,Status=mapped.Status}};
            var saved=state.Copy();saved.Candidates=candidates.Append(state.Candidates,rows);saved.DoneStreams++;
            saved.Candidate=null;saved.Part=0;Save(saved);candidates.Accept(rows);candidateIndex.Add(Key(record.Ordinal,stream.Index),rows[0]);
        }
        byte[] Report()
        {
            var plans=new Dictionary<string,RecoveryNativeNtfsFile>();
            var records=new List<object>();
            foreach(var fact in candidates.Records) {
                var candidate=Load(fact.Candidate);var mapped=Map(candidate);plans[fact.Candidate]=mapped;
                records.Add(new {ordinal=fact.Ordinal,stream=fact.Stream,status=fact.Status,plan_sha256=fact.Candidate,
                    original_name=candidate.Record.Name,parent_name=candidate.Record.Parent,stream_name=candidate.Stream.Name,
                    record_sequence=candidate.Record.Sequence,allocation_percent=candidate.Stream.Percent,stream_flags=candidate.Stream.Flags,
                    logical_bytes=mapped.LogicalBytes,missing_bytes=mapped.MissingBytes,initialized_bytes=candidate.Stream.Initialized,
                    runs=candidate.Stream.Runs.Select(r=>new {vcn=r.Vcn,lcn=r.Lcn,clusters=r.Clusters}).ToArray(),
                    first_file=fact.FirstFile,files=fact.Files});
            }
            return Encode(new {Schema=1,SourceSha256=sourceHash,InputBytes=source.Length,SourceUnchanged=true,
                engine="TestDisk NTFS checkpoint worker",status="complete",volume_offset=offset,cluster_bytes=state.ClusterBytes,mft_record_bytes=state.RecordBytes,
                volume_bytes=length,backup_boot_offset=backupBootOffset,records=state.Records,files=state.Files,
                candidates=records.ToArray(),
                outputs=finished.Records.Select(f=>new {index=f.Index,part=f.Part,plan_sha256=f.Candidate,sha256=f.Sha256,
                    file=plans[f.Candidate].Parts[f.Part].Plan.RelativeOutput,logical_offset=plans[f.Candidate].Parts[f.Part].LogicalOffset,
                    bytes=plans[f.Candidate].Parts[f.Part].Plan.Length,
                    ranges=plans[f.Candidate].Parts[f.Part].Plan.Ranges.Select(r=>new {logical_offset=r.LogicalOffset,image_offset=r.ImageOffset,bytes=r.Length}).ToArray()}).ToArray(),
                note="Candidates may contain overwritten data. Unknown intervals remain explicit gaps; sparse and uninitialized bytes are logical zeroes."},MaximumReportBytes);
        }
        void PublishReport()
        {
            byte[] bytes=Report();string digest=Hash(bytes);
            if(state.Phase==1){var next=state.Copy();next.Phase=2;next.ReportHash=digest;next.ReportBytes=bytes.Length;Save(next);Notify("ntfs: report pending");}
            if(state.ReportHash!=digest || state.ReportBytes!=bytes.Length)throw new IOException("NATIVE_NTFS_REPORT_CHANGED");
            string path=reportPath;Directory.CreateDirectory(Path.GetDirectoryName(path));
            if(!File.Exists(path)) {
                string pending=RecoveryCatalog.SafeFile(Path.GetDirectoryName(path),"report-"+Guid.NewGuid().ToString("N")+".partial");
                using(var file=new FileStream(pending,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){file.Write(bytes,0,bytes.Length);file.Flush(true);}
                Guard();File.Move(pending,path);
            }
            using(var lease=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                if(lease.Length!=bytes.Length || RecoveryCore.HashFile(path,cancel,(n,total)=>{})!=digest)throw new IOException("NATIVE_NTFS_REPORT_CHANGED");
                if(state.Phase!=3){var next=state.Copy();next.Phase=3;Save(next);Notify("ntfs: volume complete");}
            }
        }
        internal int Run()
        {
            Guard();if(ran)throw new IOException("NATIVE_NTFS_VOLUME_ALREADY_RUN");ran=true;RestoreFiles();
            if(state.Phase==0) {
                var cache=new RecoveryNativeReadCache(source,verified,Child("cache",state.Cache,link=>{var next=state.Copy();next.Cache=link;Save(next);}),offset,length,maximumCache,cancel);
                var decoder=new RecoveryNativeNtfsPlans(source.Length,offset,length,state.Next,sector);RecoveryNativeNtfsRecord record=null;bool done=false;
                RecoveryNativeWorker.Run(tools,new[]{source.Name,RecoveryNativeWorker.Number(offset),RecoveryNativeWorker.Number(length),RecoveryNativeWorker.Number(state.Next),RecoveryNativeWorker.Number(sector)},deadline,cancel,channel=>{
                    workerGuard=channel.CheckCancellation;
                    try {
                    while(!done) {
                        Guard();var message=channel.Read();object decoded=decoder.Accept(message);byte[] response=null;
                        if(message.Kind==RecoveryNativeKind.Read){
                            var read=(RecoveryMappedRange)decoded;response=cache.Read(read.ImageOffset,(int)read.Length);
                            if(backupBootOffset.HasValue) {
                                long first=Math.Max(read.ImageOffset,offset),last=Math.Min(read.ImageOffset+read.Length,offset+sector);
                                if(last>first) {
                                    // Metadata-only view: the source image and recovered
                                    // file data retain the original physical bytes.
                                    byte[] boot=cache.Read(backupBootOffset.Value+first-offset,(int)(last-first));
                                    Buffer.BlockCopy(boot,0,response,(int)(first-read.ImageOffset),boot.Length);
                                }
                            }
                        }
                        else if(message.Kind==RecoveryNativeKind.Snapshot) {
                            if(state.Records!=0 && (state.Records!=decoder.Records || state.ClusterBytes!=decoder.ClusterBytes || state.RecordBytes!=decoder.RecordBytes))throw new IOException("NATIVE_NTFS_GEOMETRY_CHANGED");
                            var next=state.Copy();next.Records=decoder.Records;next.ClusterBytes=decoder.ClusterBytes;next.RecordBytes=decoder.RecordBytes;Save(next);
                        }else if(message.Kind==RecoveryNativeKind.Record) {
                            record=(RecoveryNativeNtfsRecord)decoded;string hash=Hash(message.Payload);
                            if(state.Record!=null && state.Record!=hash)throw new IOException("NATIVE_NTFS_RECORD_CHANGED");
                            if(state.Record==null){var next=state.Copy();next.Record=hash;Save(next);}
                        }else if(message.Kind==RecoveryNativeKind.Stream)Stream(record,(RecoveryNativeNtfsStream)decoded);
                        else if(message.Kind==RecoveryNativeKind.EndRecord) {
                            if(record!=null && state.DoneStreams!=record.Streams || record==null && state.Record!=null || state.ActiveFile!=null || state.Candidate!=null)
                                throw new IOException("NATIVE_NTFS_RECORD_INCOMPLETE");
                            var next=state.Copy();next.Next=decoder.NextOrdinal;next.Record=null;next.DoneStreams=0;Save(next);record=null;
                            Notify("ntfs: MFT cursor "+state.Next.ToString(CultureInfo.InvariantCulture));
                        }else if(message.Kind==RecoveryNativeKind.Done)done=true;
                        channel.Reply(message,message.Kind==RecoveryNativeKind.Read?RecoveryNativeKind.Bytes:RecoveryNativeKind.Ack,response);
                    }
                    } finally {workerGuard=null;}
                });
                if(!done || state.Next!=state.Records)throw new IOException("NATIVE_NTFS_TRAVERSAL_INCOMPLETE");
                var complete=state.Copy();complete.Phase=1;Save(complete);
            }
            PublishReport();Guard();return state.Files;
        }
    }
}
