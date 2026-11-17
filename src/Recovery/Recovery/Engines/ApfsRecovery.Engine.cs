// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class ApfsRecovery
    {
        const int MaximumEngineLocations = 16389, MaximumReportBytes = 64*1024*1024;
        sealed class EngineState
        {
            public int Schema = 1, Phase, Files;
            public string Limits, Request, Maps, Output, ActivePlan, ReportHash;
            public int ReportBytes;
            public RecoveryMethodCheckpoint Metadata, ActiveFile;
            public RecoveryOutputHead Finished, Repairs;
        }
        sealed class EngineFile
        { public int Index; public string Plan, RelativeOutput; public RecoveryMethodCheckpoint Anchor; }
        sealed class EngineRepair
        { public int Index; public RecoveryMethodCheckpoint Anchor; }

        static RecoveryCheckpointContext ApfsChild(RecoveryCheckpointContext parent, string role,
            RecoveryMethodCheckpoint anchor, Action<RecoveryMethodCheckpoint> commit)
        {
            if (String.IsNullOrEmpty(role) || role.Any(ch => !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-')))
                throw new IOException("APFS_CHILD_ROLE_INVALID");
            string directory = Path.GetDirectoryName(RecoveryCatalog.SafeFile(parent.Directory,"apfs.state/children/"+role+"/guard"));
            RecoveryMethodCheckpoint resume = null;
            if (anchor != null) {
                if (anchor.Path == null || Path.IsPathRooted(anchor.Path)) throw new IOException("APFS_CHILD_LINK_INVALID");
                resume = new RecoveryMethodCheckpoint { Path = RecoveryCatalog.SafeFile(parent.Directory,anchor.Path), Sha256 = anchor.Sha256, Sequence = anchor.Sequence };
            }
            return new RecoveryCheckpointContext { Directory = directory, Method = "apfs", SourceSha256 = parent.SourceSha256,
                Settings = MetadataHash(Encoding.UTF8.GetBytes(parent.Settings))+":"+role, Resume = resume,
                Commit = value => {
                    string root = Path.GetFullPath(parent.Directory).TrimEnd('\\','/')+Path.DirectorySeparatorChar;
                    string path = Path.GetFullPath(value.Path);
                    if (!path.StartsWith(root,StringComparison.OrdinalIgnoreCase) || commit == null) throw new IOException("APFS_CHILD_COMMIT_INVALID");
                    commit(new RecoveryMethodCheckpoint { Path = path.Substring(root.Length).Replace('\\','/'), Sha256 = value.Sha256, Sequence = value.Sequence });
                } };
        }

        sealed class EngineCheckpoint
        {
            readonly Context c;
            readonly RecoveryCheckpointContext context;
            readonly ApfsReadMapLease maps;
            readonly Action<string> progress;
            readonly List<long> requested;
            readonly string limits, request, root, contextRoot, settings, sourceHash;
            readonly RecoveryMethodJournal<EngineState> journal;
            readonly RecoveryOutputLedger<EngineFile> finished;
            readonly RecoveryOutputLedger<EngineRepair> repairs;
            readonly Dictionary<int,RecoveryMethodCheckpoint> repaired = new Dictionary<int,RecoveryMethodCheckpoint>();
            readonly FileStream input;
            readonly Report report;
            readonly RecoveryVerifiedImage verified;
            readonly Action<Entry> publisher;
            EngineState state;
            int fileIndex;
            bool parsing;

            public EngineCheckpoint(Context owner, RecoveryCheckpointContext checkpoint, ApfsReadMapLease readMaps,
                IEnumerable<long> offsets, Action<string> notify)
            {
                c = owner; context = checkpoint; maps = readMaps; progress = notify;
                input = c.Stream; report = c.Report; verified = c.VerifiedImage; publisher = Publish;
                root = Path.GetFullPath(c.Destination); contextRoot = Path.GetFullPath(context.Directory); settings = context.Settings; sourceHash = context.SourceSha256;
                limits = MetadataLimitsIdentity(c.Limits);
                if (offsets != null) { requested = offsets.Take(MaximumEngineLocations+1).ToList(); if (requested.Count > MaximumEngineLocations) throw new IOException("APFS_OFFSET_REQUEST_LIMIT"); }
                request = MetadataHash(Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(requested)));
                string output = new Uri(contextRoot.TrimEnd('\\','/')+Path.DirectorySeparatorChar)
                    .MakeRelativeUri(new Uri(root.TrimEnd('\\','/')+Path.DirectorySeparatorChar)).ToString();
                journal = new RecoveryMethodJournal<EngineState>(c.Stream.Name,new EngineState { Limits = limits, Request = request, Maps = maps.Identity, Output = output },context,c.Cancel);
                state = journal.Payload;
                if (state.Schema != 1 || state.Phase < 0 || state.Phase > 2 || state.Files < 0 || state.Files > c.Limits.MaximumEntries ||
                    state.Limits != limits || state.Request != request || state.Maps != maps.Identity || state.Output != output ||
                    (state.ActivePlan == null) != (state.ActiveFile == null) || state.ActivePlan != null && !MetadataDigest(state.ActivePlan) ||
                    state.Phase > 0 && (state.ActiveFile != null || state.Metadata == null || !MetadataDigest(state.ReportHash) || state.ReportBytes < 1 || state.ReportBytes > MaximumReportBytes) ||
                    state.Phase == 0 && (state.ReportHash != null || state.ReportBytes != 0)) throw new IOException("APFS_ENGINE_CHECKPOINT_INVALID");
                finished = new RecoveryOutputLedger<EngineFile>(context,state.Finished,c.Limits.MaximumEntries,c.Cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
                repairs = new RecoveryOutputLedger<EngineRepair>(ApfsChild(context,"repairs",null,null),state.Repairs,2000000,c.Cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
                if (finished.Records.Count != state.Files) throw new IOException("APFS_ENGINE_FILE_CURSOR_INVALID");
                int number = 0;
                foreach (var fact in finished.Records) {
                    if (fact.Index != number++ || !MetadataDigest(fact.Plan) || fact.Anchor == null || String.IsNullOrWhiteSpace(fact.RelativeOutput)) throw new IOException("APFS_ENGINE_FILE_FACT_INVALID");
                    ApfsChild(context,"file-"+fact.Index.ToString(CultureInfo.InvariantCulture),fact.Anchor,null);
                }
                foreach (var fact in repairs.Records) {
                    if (fact.Index < 0 || fact.Index >= state.Files || fact.Anchor == null) throw new IOException("APFS_ENGINE_REPAIR_FACT_INVALID");
                    ApfsChild(context,"file-"+fact.Index.ToString(CultureInfo.InvariantCulture),fact.Anchor,null); repaired[fact.Index] = fact.Anchor;
                }
                if (!journal.Resumed && (Directory.Exists(root) || File.Exists(root))) throw new IOException("APFS_ENGINE_OUTPUT_EXISTS");
            }
            EngineState Clone()
            { return new EngineState { Phase = state.Phase, Files = state.Files, Limits = state.Limits, Request = state.Request, Maps = state.Maps, Output = state.Output,
                ActivePlan = state.ActivePlan, ActiveFile = state.ActiveFile, Metadata = state.Metadata, Finished = state.Finished, Repairs = state.Repairs,
                ReportHash = state.ReportHash, ReportBytes = state.ReportBytes }; }
            void Guard()
            {
                c.Cancel.ThrowIfCancellationRequested(); maps.Validate();
                if (c.Stream != input || c.Report != report || c.VerifiedImage != verified || parsing && c.PublishFile != publisher)
                    throw new IOException("APFS_ENGINE_OWNER_CHANGED");
                verified.Validate(c.Stream,sourceHash); NoLinks(c.Destination);
                if (Path.GetFullPath(c.Destination) != root || Path.GetFullPath(context.Directory) != contextRoot || context.Method != "apfs" ||
                    context.Settings != settings || context.SourceSha256 != sourceHash || MetadataLimitsIdentity(c.Limits) != limits) throw new IOException("APFS_ENGINE_CONTEXT_CHANGED");
            }
            void Save(EngineState next) { Guard(); journal.Save(next); state = next; }
            void Notify(string message) { if (progress != null) progress(message); Guard(); }
            void Publish(Entry entry)
            {
                Guard(); PrepareFileMap(c,entry); string relative = OutputPath(entry); int index = fileIndex++; string identity = FilePlanIdentity(c,entry);
                if (index > state.Files || index == state.Files && state.Phase != 0) throw new IOException("APFS_ENGINE_FILE_ORDER_CHANGED");
                RecoveryMethodCheckpoint anchor;
                if (index < state.Files) {
                    var fact = finished.Records[index];
                    if (fact.Plan != identity || fact.RelativeOutput != relative) throw new IOException("APFS_ENGINE_FILE_PLAN_CHANGED");
                    if (!repaired.TryGetValue(index,out anchor)) anchor = fact.Anchor;
                } else {
                    if (state.ActivePlan != null && state.ActivePlan != identity) throw new IOException("APFS_ENGINE_ACTIVE_FILE_CHANGED");
                    anchor = state.ActiveFile;
                }
                RecoveryMethodCheckpoint latest = anchor;
                var child = ApfsChild(context,"file-"+index.ToString(CultureInfo.InvariantCulture),anchor,link => {
                    var next = Clone();
                    if (index == state.Files) { next.ActiveFile = link; next.ActivePlan = identity; Save(next); }
                    else {
                        var rows = new List<EngineRepair> { new EngineRepair { Index = index, Anchor = link } };
                        next.Repairs = repairs.Append(state.Repairs,rows); Save(next); repairs.Accept(rows); repaired[index] = link;
                    }
                    latest = link;
                });
                WriteFileCheckpointed(c,entry,child,Notify);
                if (index == state.Files) {
                    if (latest == null || latest != state.ActiveFile) throw new IOException("APFS_ENGINE_FILE_NOT_ANCHORED");
                    var rows = new List<EngineFile> { new EngineFile { Index = index, Plan = identity, RelativeOutput = relative, Anchor = latest } };
                    var next = Clone(); next.Finished = finished.Append(state.Finished,rows); next.Files++;
                    next.ActiveFile = null; next.ActivePlan = null; Save(next); finished.Accept(rows); Notify("apfs: file "+index+" complete");
                }
            }
            void PublishReport(byte[] bytes)
            {
                Guard(); string path = RecoveryCatalog.SafeFile(c.Destination,"report.json");
                if (Directory.Exists(path)) throw new IOException("APFS_REPORT_CHANGED");
                if (!File.Exists(path)) {
                    string temp = RecoveryCatalog.SafeFile(c.Destination,"report-"+Guid.NewGuid().ToString("N")+".partial"); bool own = false;
                    try {
                        using (var file = new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
                        Guard(); File.Move(temp,path);
                    } finally { if (own && File.Exists(temp)) File.Delete(temp); }
                }
                using (var file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                    if (file.Length != state.ReportBytes || HashStream(file,c.Cancel) != state.ReportHash) throw new IOException("APFS_REPORT_CHANGED");
                    if (state.Phase != 2) { Notify("apfs: report ready"); var next = Clone(); next.Phase = 2; Save(next); Notify("apfs: engine complete"); }
                }
            }
            public int Run()
            {
                Guard(); Directory.CreateDirectory(Path.Combine(root,"files"));
                var metadata = ApfsChild(context,"metadata",state.Metadata,link => {
                    if (state.Phase != 0) throw new IOException("APFS_ENGINE_METADATA_AFTER_END");
                    var next = Clone(); next.Metadata = link; Save(next);
                });
                c.PublishFile = publisher; parsing = true;
                try {
                    using (var reader = new MetadataReadCheckpoint(c,metadata,Notify)) { ExecuteRecovery(c,requested,Notify); reader.Finish(); }
                } finally { parsing = false; c.PublishFile = null; }
                Guard();
                if (fileIndex != state.Files || state.ActiveFile != null) throw new IOException("APFS_ENGINE_FILE_TAIL_MISSING");
                c.Report.SourceUnchanged = true; c.Report.Status = c.Report.Limited ? "limited" : "complete";
                c.Report.OutputBytes = c.OutputBytes; c.Report.Candidates = c.Report.Entries.Count;
                c.Report.RecoveredFiles = c.Report.Entries.Count(x => x.Status == "recovered_live");
                c.Report.DeletedCandidates = c.Report.Entries.Count(x => x.Status == "unreferenced_apfs_candidate");
                byte[] bytes = new UTF8Encoding(false,true).GetBytes(new JavaScriptSerializer { MaxJsonLength = MaximumReportBytes }.Serialize(c.Report));
                if (bytes.Length > MaximumReportBytes) throw new IOException("APFS_REPORT_LIMIT");
                string digest = MetadataHash(bytes);
                if (state.Phase == 0) { var next = Clone(); next.Phase = 1; next.ReportHash = digest; next.ReportBytes = bytes.Length; Save(next); Notify("apfs: report pending"); }
                if (state.ReportHash != digest || state.ReportBytes != bytes.Length) throw new IOException("APFS_ENGINE_REPORT_CHANGED");
                PublishReport(bytes); Guard(); return c.Report.Entries.Count;
            }
        }

        static int RecoverCheckpointedCore(Context c, RecoveryCheckpointContext checkpoint, IEnumerable<long> offsets, Action<string> progress)
        {
            if (checkpoint == null || checkpoint.Method != "apfs" || c.Stream == null || c.Stream.CanWrite || c.MetadataRead != null || c.PublishFile != null || c.VerifiedImage != null ||
                c.OutputBytes != 0 || c.EntryCount != 0) throw new IOException("APFS_ENGINE_CONTEXT_INVALID");
            string digest = (checkpoint.SourceSha256 ?? "").ToLowerInvariant(); if (!MetadataDigest(digest)) throw new IOException("METHOD_SOURCE_BINDING_REQUIRED");
            var context = new RecoveryCheckpointContext { Directory = checkpoint.Directory, Method = "apfs", SourceSha256 = digest,
                Settings = checkpoint.Settings, Resume = checkpoint.Resume, Commit = checkpoint.Commit };
            MetadataLimitsIdentity(c.Limits); NoLinks(c.Destination); LocalFile(c.Stream.Name);
            string source = Path.GetFullPath(c.Stream.Name),root = Path.GetFullPath(c.Destination);
            if (source.Equals(root,StringComparison.OrdinalIgnoreCase) || source.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new IOException("APFS_SOURCE_IN_OUTPUT");
            c.Report = new Report { Status = "running", InputBytes = c.Stream.Length, SourceSha256 = digest };

            using (var verified = new RecoveryVerifiedImage(c.Stream,digest,c.Cancel)) using (var maps = new ApfsReadMapLease(c,context)) {
                c.VerifiedImage = verified;
                try { return new EngineCheckpoint(c,context,maps,offsets,progress).Run(); }
                finally { c.VerifiedImage = null; }
            }
        }
        internal static int RecoverCheckpointed(string image, string runDirectory, CancellationToken cancel, Action<string> progress,
            RecoveryCheckpointContext context, IEnumerable<long> offsets = null, Limits limits = null)
        {
            using (var input = new FileStream(LocalFile(image),FileMode.Open,FileAccess.Read,FileShare.Read,1024*1024)) {
                var c = new Context { Stream = input, Destination = Path.GetFullPath(Path.Combine(runDirectory,"apfs")), Cancel = cancel, Limits = limits ?? new Limits() };
                return RecoverCheckpointedCore(c,context,offsets,progress);
            }
        }
    }
}
