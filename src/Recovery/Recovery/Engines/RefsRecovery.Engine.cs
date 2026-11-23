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
    public static partial class RefsRecovery
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

        static RecoveryCheckpointContext RefsChild(RecoveryCheckpointContext parent, string role,
            RecoveryMethodCheckpoint anchor, Action<RecoveryMethodCheckpoint> commit)
        {
            if (String.IsNullOrEmpty(role) || role.Any(ch => !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-')))
                throw new IOException("REFS_CHILD_ROLE_INVALID");
            string directory = Path.GetDirectoryName(RecoveryCatalog.SafeFile(parent.Directory,"refs.state/children/"+role+"/guard"));
            RecoveryMethodCheckpoint resume = null;
            if (anchor != null) {
                if (anchor.Path == null || Path.IsPathRooted(anchor.Path)) throw new IOException("REFS_CHILD_LINK_INVALID");
                resume = new RecoveryMethodCheckpoint { Path = RecoveryCatalog.SafeFile(parent.Directory,anchor.Path), Sha256 = anchor.Sha256, Sequence = anchor.Sequence };
            }
            return new RecoveryCheckpointContext { Directory = directory, Method = "refs", SourceSha256 = parent.SourceSha256,
                Settings = MetadataHash(Encoding.UTF8.GetBytes(parent.Settings))+":"+role, Resume = resume,
                Commit = value => {
                    string root = Path.GetFullPath(parent.Directory).TrimEnd('\\','/')+Path.DirectorySeparatorChar;
                    string path = Path.GetFullPath(value.Path);
                    if (!path.StartsWith(root,StringComparison.OrdinalIgnoreCase) || commit == null) throw new IOException("REFS_CHILD_COMMIT_INVALID");
                    commit(new RecoveryMethodCheckpoint { Path = path.Substring(root.Length).Replace('\\','/'), Sha256 = value.Sha256, Sequence = value.Sequence });
                } };
        }

        sealed class EngineCheckpoint
        {
            readonly Context c;
            readonly RecoveryCheckpointContext context;
            readonly RefsReadMapLease maps;
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
            readonly Action<Entry,byte[],string> publisher;
            EngineState state;
            int fileIndex;
            bool parsing;

            public EngineCheckpoint(Context owner, RecoveryCheckpointContext checkpoint, RefsReadMapLease readMaps,
                IEnumerable<long> offsets, Action<string> notify)
            {
                c = owner; context = checkpoint; maps = readMaps; progress = notify;
                input = c.Input; report = c.Report; verified = c.VerifiedImage; publisher = Publish;
                root = Path.GetFullPath(c.Root); contextRoot = Path.GetFullPath(context.Directory); settings = context.Settings; sourceHash = context.SourceSha256;
                limits = MetadataLimitsIdentity(c.Limits);
                if (offsets != null) { requested = offsets.Take(MaximumEngineLocations+1).ToList(); if (requested.Count > MaximumEngineLocations) throw new IOException("REFS_OFFSET_REQUEST_LIMIT"); }
                request = MetadataHash(Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(requested)));
                string output = new Uri(contextRoot.TrimEnd('\\','/')+Path.DirectorySeparatorChar)
                    .MakeRelativeUri(new Uri(root.TrimEnd('\\','/')+Path.DirectorySeparatorChar)).ToString();
                journal = new RecoveryMethodJournal<EngineState>(c.Input.Name,new EngineState { Limits = limits, Request = request, Maps = maps.Identity, Output = output },context,c.Cancel);
                state = journal.Payload;
                if (state.Schema != 1 || state.Phase < 0 || state.Phase > 2 || state.Files < 0 || state.Files > c.Limits.MaximumEntries ||
                    state.Limits != limits || state.Request != request || state.Maps != maps.Identity || state.Output != output ||
                    (state.ActivePlan == null) != (state.ActiveFile == null) || state.ActivePlan != null && !MetadataDigest(state.ActivePlan) ||
                    state.Phase > 0 && (state.ActiveFile != null || state.Metadata == null || !MetadataDigest(state.ReportHash) || state.ReportBytes < 1 || state.ReportBytes > MaximumReportBytes) ||
                    state.Phase == 0 && (state.ReportHash != null || state.ReportBytes != 0)) throw new IOException("REFS_ENGINE_CHECKPOINT_INVALID");
                finished = new RecoveryOutputLedger<EngineFile>(context,state.Finished,c.Limits.MaximumEntries,c.Cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
                repairs = new RecoveryOutputLedger<EngineRepair>(RefsChild(context,"repairs",null,null),state.Repairs,2000000,c.Cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
                if (finished.Records.Count != state.Files) throw new IOException("REFS_ENGINE_FILE_CURSOR_INVALID");
                int number = 0;
                foreach (var fact in finished.Records) {
                    if (fact.Index != number++ || !MetadataDigest(fact.Plan) || fact.Anchor == null || String.IsNullOrWhiteSpace(fact.RelativeOutput)) throw new IOException("REFS_ENGINE_FILE_FACT_INVALID");
                    RefsChild(context,"file-"+fact.Index.ToString(CultureInfo.InvariantCulture),fact.Anchor,null);
                }
                foreach (var fact in repairs.Records) {
                    if (fact.Index < 0 || fact.Index >= state.Files || fact.Anchor == null) throw new IOException("REFS_ENGINE_REPAIR_FACT_INVALID");
                    RefsChild(context,"file-"+fact.Index.ToString(CultureInfo.InvariantCulture),fact.Anchor,null); repaired[fact.Index] = fact.Anchor;
                }
                if (!journal.Resumed && (Directory.Exists(root) || File.Exists(root))) throw new IOException("REFS_ENGINE_OUTPUT_EXISTS");
            }
            EngineState Clone()
            { return new EngineState { Phase = state.Phase, Files = state.Files, Limits = state.Limits, Request = state.Request, Maps = state.Maps, Output = state.Output,
                ActivePlan = state.ActivePlan, ActiveFile = state.ActiveFile, Metadata = state.Metadata, Finished = state.Finished, Repairs = state.Repairs,
                ReportHash = state.ReportHash, ReportBytes = state.ReportBytes }; }
            void Guard()
            {
                c.Cancel.ThrowIfCancellationRequested(); maps.Validate();
                if (c.Input != input || c.Report != report || c.VerifiedImage != verified || parsing && c.PublishFile != publisher)
                    throw new IOException("REFS_ENGINE_OWNER_CHANGED");
                verified.Validate(c.Input,sourceHash); NoLinks(c.Root);
                if (Path.GetFullPath(c.Root) != root || Path.GetFullPath(context.Directory) != contextRoot || context.Method != "refs" ||
                    context.Settings != settings || context.SourceSha256 != sourceHash || MetadataLimitsIdentity(c.Limits) != limits) throw new IOException("REFS_ENGINE_CONTEXT_CHANGED");
            }
            void Save(EngineState next) { Guard(); journal.Save(next); state = next; }
            void Notify(string message) { if (progress != null) progress(message); Guard(); }
            void Publish(Entry entry, byte[] resident, string relative)
            {
                Guard(); int index = fileIndex++; string identity = FilePlanIdentity(c,entry);
                if (index > state.Files || index == state.Files && state.Phase != 0) throw new IOException("REFS_ENGINE_FILE_ORDER_CHANGED");
                RecoveryMethodCheckpoint anchor;
                if (index < state.Files) {
                    var fact = finished.Records[index];
                    if (fact.Plan != identity || fact.RelativeOutput != relative) throw new IOException("REFS_ENGINE_FILE_PLAN_CHANGED");
                    if (!repaired.TryGetValue(index,out anchor)) anchor = fact.Anchor;
                } else {
                    if (state.ActivePlan != null && state.ActivePlan != identity) throw new IOException("REFS_ENGINE_ACTIVE_FILE_CHANGED");
                    anchor = state.ActiveFile;
                }
                RecoveryMethodCheckpoint latest = anchor;
                var child = RefsChild(context,"file-"+index.ToString(CultureInfo.InvariantCulture),anchor,link => {
                    var next = Clone();
                    if (index == state.Files) { next.ActiveFile = link; next.ActivePlan = identity; Save(next); }
                    else {
                        var rows = new List<EngineRepair> { new EngineRepair { Index = index, Anchor = link } };
                        next.Repairs = repairs.Append(state.Repairs,rows); Save(next); repairs.Accept(rows); repaired[index] = link;
                    }
                    latest = link;
                });
                WriteFileCheckpointed(c,entry,resident,relative,child,Notify);
                if (index == state.Files) {
                    if (latest == null || latest != state.ActiveFile) throw new IOException("REFS_ENGINE_FILE_NOT_ANCHORED");
                    var rows = new List<EngineFile> { new EngineFile { Index = index, Plan = identity, RelativeOutput = relative, Anchor = latest } };
                    var next = Clone(); next.Finished = finished.Append(state.Finished,rows); next.Files++;
                    next.ActiveFile = null; next.ActivePlan = null; Save(next); finished.Accept(rows); Notify("refs: file "+index+" complete");
                }
            }
            void PublishReport(byte[] bytes)
            {
                Guard(); string path = RecoveryCatalog.SafeFile(c.Root,"report.json");
                if (Directory.Exists(path)) throw new IOException("REFS_REPORT_CHANGED");
                if (!File.Exists(path)) {
                    string temp = RecoveryCatalog.SafeFile(c.Root,"report-"+Guid.NewGuid().ToString("N")+".partial"); bool own = false;
                    try {
                        using (var file = new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
                        Guard(); File.Move(temp,path);
                    } finally { if (own && File.Exists(temp)) File.Delete(temp); }
                }
                using (var file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                    if (file.Length != state.ReportBytes || HashStream(file,c.Cancel) != state.ReportHash) throw new IOException("REFS_REPORT_CHANGED");
                    if (state.Phase != 2) { Notify("refs: report ready"); var next = Clone(); next.Phase = 2; Save(next); Notify("refs: engine complete"); }
                }
            }
            public int Run()
            {
                Guard(); Directory.CreateDirectory(Path.Combine(root,"files"));
                var metadata = RefsChild(context,"metadata",state.Metadata,link => {
                    if (state.Phase != 0) throw new IOException("REFS_ENGINE_METADATA_AFTER_END");
                    var next = Clone(); next.Metadata = link; Save(next);
                });
                c.PublishFile = publisher; parsing = true;
                try {
                    using (var reader = new MetadataReadCheckpoint(c,metadata,Notify)) { RunVolumes(c,requested,Notify); reader.Finish(); }
                } finally { parsing = false; c.PublishFile = null; }
                Guard();
                if (fileIndex != state.Files || state.ActiveFile != null) throw new IOException("REFS_ENGINE_FILE_TAIL_MISSING");
                c.Report.SourceUnchanged = true; c.Report.Status = c.Report.Limited ? "limited" : "complete";
                byte[] bytes = new UTF8Encoding(false,true).GetBytes(new JavaScriptSerializer { MaxJsonLength = MaximumReportBytes }.Serialize(c.Report));
                if (bytes.Length > MaximumReportBytes) throw new IOException("REFS_REPORT_LIMIT");
                string digest = MetadataHash(bytes);
                if (state.Phase == 0) { var next = Clone(); next.Phase = 1; next.ReportHash = digest; next.ReportBytes = bytes.Length; Save(next); Notify("refs: report pending"); }
                if (state.ReportHash != digest || state.ReportBytes != bytes.Length) throw new IOException("REFS_ENGINE_REPORT_CHANGED");
                PublishReport(bytes); Guard(); return c.Report.RecoveredFiles;
            }
        }

        static int RecoverCheckpointedCore(Context c, RecoveryCheckpointContext checkpoint, IEnumerable<long> offsets, Action<string> progress)
        {
            if (checkpoint == null || checkpoint.Method != "refs" || c.Input == null || c.Input.CanWrite || c.MetadataRead != null || c.PublishFile != null || c.VerifiedImage != null ||
                c.OutputBytes != 0 || c.DirectoryCount != 0 || c.EntryCount != 0) throw new IOException("REFS_ENGINE_CONTEXT_INVALID");
            string digest = (checkpoint.SourceSha256 ?? "").ToLowerInvariant(); if (!MetadataDigest(digest)) throw new IOException("METHOD_SOURCE_BINDING_REQUIRED");
            var context = new RecoveryCheckpointContext { Directory = checkpoint.Directory, Method = "refs", SourceSha256 = digest,
                Settings = checkpoint.Settings, Resume = checkpoint.Resume, Commit = checkpoint.Commit };
            MetadataLimitsIdentity(c.Limits); NoLinks(c.Root); LocalFile(c.Input.Name);
            string source = Path.GetFullPath(c.Input.Name),root = Path.GetFullPath(c.Root);
            if (source.Equals(root,StringComparison.OrdinalIgnoreCase) || source.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new IOException("REFS_SOURCE_IN_OUTPUT");
            c.Report = new Report { Status = "running", InputBytes = c.Input.Length, SourceSha256 = digest };
            c.Report.Warnings.Add("Восстановление метаданных ReFS. Checksum верифицирует только метаданные; аутентичность исторического содержимого не гарантируется.");
            using (var verified = new RecoveryVerifiedImage(c.Input,digest,c.Cancel)) using (var maps = new RefsReadMapLease(c,context)) {
                c.VerifiedImage = verified;
                try { return new EngineCheckpoint(c,context,maps,offsets,progress).Run(); }
                finally { c.VerifiedImage = null; }
            }
        }
        internal static int RecoverCheckpointed(string image, string runDirectory, CancellationToken cancel, Action<string> progress,
            RecoveryCheckpointContext context, IEnumerable<long> offsets = null, Limits limits = null)
        {
            using (var input = new FileStream(LocalFile(image),FileMode.Open,FileAccess.Read,FileShare.Read,1024*1024)) {
                var c = new Context { Input = input, Root = Path.GetFullPath(Path.Combine(runDirectory,"refs")), Cancel = cancel, Limits = limits ?? new Limits() };
                return RecoverCheckpointedCore(c,context,offsets,progress);
            }
        }
    }
}
