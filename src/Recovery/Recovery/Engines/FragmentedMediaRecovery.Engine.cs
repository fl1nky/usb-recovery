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
    public static partial class FragmentedMediaRecovery
    {
        const int MaximumReportBytes = 32*1024*1024;
        sealed class EngineState
        {
            public int Schema = 1, Phase, Files;
            public string Limits, Maps, ActivePlan, ReportHash;
            public int ReportBytes;
            public RecoveryMethodCheckpoint Metadata, ActiveFile;
            public RecoveryOutputHead Finished, Repairs;
        }
        sealed class EngineFile
        { public int Index; public string Plan, RelativeOutput; public RecoveryMethodCheckpoint Anchor; }
        sealed class EngineRepair
        { public int Index; public RecoveryMethodCheckpoint Anchor; }

        static RecoveryCheckpointContext MediaChild(RecoveryCheckpointContext parent, string role,
            RecoveryMethodCheckpoint anchor, Action<RecoveryMethodCheckpoint> commit)
        {
            if (String.IsNullOrEmpty(role) || role.Any(ch => !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-')))
                throw new IOException("MEDIA_CHILD_ROLE_INVALID");
            string child = "fragmented-media.state/children/" + role;
            // Metadata checkpoints add another state folder and SHA-256 filenames.
            // Keep the original location for existing sessions.
            if (role == "metadata" && !Directory.Exists(Path.Combine(parent.Directory, child)))
                child = "fragmented-media.state/meta";
            string directory = Path.GetDirectoryName(RecoveryCatalog.SafeFile(parent.Directory, child + "/guard"));
            RecoveryMethodCheckpoint resume = null;
            if (anchor != null) {
                if (anchor.Path == null || Path.IsPathRooted(anchor.Path)) throw new IOException("MEDIA_CHILD_LINK_INVALID");
                resume = new RecoveryMethodCheckpoint { Path = RecoveryCatalog.SafeFile(parent.Directory,anchor.Path), Sha256 = anchor.Sha256, Sequence = anchor.Sequence };
            }
            return new RecoveryCheckpointContext { Directory = directory, Method = "fragmented-media", SourceSha256 = parent.SourceSha256,
                Settings = Sha(Encoding.UTF8.GetBytes(parent.Settings))+":"+role, Resume = resume,
                Commit = value => {
                    string root = Path.GetFullPath(parent.Directory).TrimEnd('\\','/')+Path.DirectorySeparatorChar;
                    string path = Path.GetFullPath(value.Path);
                    if (!path.StartsWith(root,StringComparison.OrdinalIgnoreCase) || commit == null) throw new IOException("MEDIA_CHILD_COMMIT_INVALID");
                    commit(new RecoveryMethodCheckpoint { Path = path.Substring(root.Length).Replace('\\','/'), Sha256 = value.Sha256, Sequence = value.Sequence });
                } };
        }

        sealed class EngineCheckpoint
        {
            readonly Context c;
            readonly RecoveryCheckpointContext context;
            readonly MediaReadMapLease maps;
            readonly Action<string> progress;
            readonly Action<long,long> scanProgress;
            readonly string folder;
            readonly string limits, root, contextRoot, settings, sourceHash;
            readonly RecoveryMethodJournal<EngineState> journal;
            readonly RecoveryOutputLedger<EngineFile> finished;
            readonly RecoveryOutputLedger<EngineRepair> repairs;
            readonly Dictionary<int,RecoveryMethodCheckpoint> repaired = new Dictionary<int,RecoveryMethodCheckpoint>();
            readonly FileStream input;
            readonly Report report;
            readonly RecoveryVerifiedImage verified;
            readonly Func<Movie,string,List<Extent>,bool,string,Result> publisher;
            EngineState state;
            int fileIndex;
            bool parsing;

            public EngineCheckpoint(Context owner, RecoveryCheckpointContext checkpoint, MediaReadMapLease readMaps,
                Action<string> notify,Action<long,long> scanNotify)
            {
                c = owner; context = checkpoint; maps = readMaps; progress = notify; scanProgress=scanNotify;
                input = c.Input; report = c.Report; verified = c.VerifiedImage; publisher = Publish;
                root = Path.GetFullPath(context.Directory); folder = Path.Combine(root,"fragmented-media"); contextRoot = Path.GetFullPath(context.Directory); settings = context.Settings; sourceHash = context.SourceSha256;
                limits = LimitsIdentity(c.Limits);
                journal = new RecoveryMethodJournal<EngineState>(c.Input.Name,new EngineState { Limits = limits, Maps = maps.Identity },context,c.Cancel);
                state = journal.Payload;
                if (state.Schema != 1 || state.Phase < 0 || state.Phase > 2 || state.Files < 0 || state.Files > MaximumMovies ||
                    state.Limits != limits || state.Maps != maps.Identity ||
                    (state.ActivePlan == null) != (state.ActiveFile == null) || state.ActivePlan != null && !Digest(state.ActivePlan) ||
                    state.Phase > 0 && (state.ActiveFile != null || state.Metadata == null || !Digest(state.ReportHash) || state.ReportBytes < 1 || state.ReportBytes > MaximumReportBytes) ||
                    state.Phase == 0 && (state.ReportHash != null || state.ReportBytes != 0)) throw new IOException("MEDIA_ENGINE_CHECKPOINT_INVALID");
                finished = new RecoveryOutputLedger<EngineFile>(context,state.Finished,MaximumMovies,c.Cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
                repairs = new RecoveryOutputLedger<EngineRepair>(MediaChild(context,"repairs",null,null),state.Repairs,2000000,c.Cancel,RecoveryLedgerScope.MethodOutput,512L*1024*1024);
                if (finished.Records.Count != state.Files) throw new IOException("MEDIA_ENGINE_FILE_CURSOR_INVALID");
                int number = 0;
                foreach (var fact in finished.Records) {
                    if (fact.Index != number++ || !Digest(fact.Plan) || fact.Anchor == null || String.IsNullOrWhiteSpace(fact.RelativeOutput)) throw new IOException("MEDIA_ENGINE_FILE_FACT_INVALID");
                    MediaChild(context,"file-"+fact.Index.ToString(CultureInfo.InvariantCulture),fact.Anchor,null);
                }
                foreach (var fact in repairs.Records) {
                    if (fact.Index < 0 || fact.Index >= state.Files || fact.Anchor == null) throw new IOException("MEDIA_ENGINE_REPAIR_FACT_INVALID");
                    MediaChild(context,"file-"+fact.Index.ToString(CultureInfo.InvariantCulture),fact.Anchor,null); repaired[fact.Index] = fact.Anchor;
                }
                if (!journal.Resumed && (Directory.Exists(folder) || File.Exists(folder) || File.Exists(Path.Combine(root,"fragmented-media.json")))) throw new IOException("MEDIA_ENGINE_OUTPUT_EXISTS");
            }
            EngineState Clone()
            { return new EngineState { Phase = state.Phase, Files = state.Files, Limits = state.Limits, Maps = state.Maps,
                ActivePlan = state.ActivePlan, ActiveFile = state.ActiveFile, Metadata = state.Metadata, Finished = state.Finished, Repairs = state.Repairs,
                ReportHash = state.ReportHash, ReportBytes = state.ReportBytes }; }
            void Guard()
            {
                c.Cancel.ThrowIfCancellationRequested(); maps.Validate();
                if (c.Input != input || c.Report != report || c.VerifiedImage != verified || parsing && c.PublishCandidate != publisher)
                    throw new IOException("MEDIA_ENGINE_OWNER_CHANGED");
                verified.Validate(c.Input,sourceHash); NoLinks(folder);
                if (Path.GetFullPath(context.Directory) != contextRoot || context.Method != "fragmented-media" ||
                    context.Settings != settings || context.SourceSha256 != sourceHash || LimitsIdentity(c.Limits) != limits) throw new IOException("MEDIA_ENGINE_CONTEXT_CHANGED");
            }
            void Save(EngineState next) { Guard(); journal.Save(next); state = next; }
            void Notify(string message) { if (progress != null) progress(message); Guard(); }
            Result Publish(Movie movie,string outputFolder,List<Extent> extents,bool audioSyntax,string expected)
            {
                Guard(); if(Path.GetFullPath(outputFolder)!=folder)throw new IOException("MEDIA_OUTPUT_SCOPE_CHANGED"); string relative="candidate-{sha256}.mp4"; int index=fileIndex++; string identity=CandidateIdentity(c,movie,extents,audioSyntax,expected);
                if (index > state.Files || index == state.Files && state.Phase != 0) throw new IOException("MEDIA_ENGINE_FILE_ORDER_CHANGED");
                RecoveryMethodCheckpoint anchor;
                if (index < state.Files) {
                    var fact = finished.Records[index];
                    if (fact.Plan != identity || fact.RelativeOutput != relative) throw new IOException("MEDIA_ENGINE_FILE_PLAN_CHANGED");
                    if (!repaired.TryGetValue(index,out anchor)) anchor = fact.Anchor;
                } else {
                    if (state.ActivePlan != null && state.ActivePlan != identity) throw new IOException("MEDIA_ENGINE_ACTIVE_FILE_CHANGED");
                    anchor = state.ActiveFile;
                }
                RecoveryMethodCheckpoint latest = anchor;
                var child = MediaChild(context,"file-"+index.ToString(CultureInfo.InvariantCulture),anchor,link => {
                    var next = Clone();
                    if (index == state.Files) { next.ActiveFile = link; next.ActivePlan = identity; Save(next); }
                    else {
                        var rows = new List<EngineRepair> { new EngineRepair { Index = index, Anchor = link } };
                        next.Repairs = repairs.Append(state.Repairs,rows); Save(next); repairs.Accept(rows); repaired[index] = link;
                    }
                    latest = link;
                });
                Result result=WriteCandidateCheckpointed(c,movie,folder,extents,audioSyntax,expected,child,Notify);
                if (index == state.Files) {
                    if (latest == null || latest != state.ActiveFile) throw new IOException("MEDIA_ENGINE_FILE_NOT_ANCHORED");
                    var rows = new List<EngineFile> { new EngineFile { Index = index, Plan = identity, RelativeOutput = relative, Anchor = latest } };
                    var next = Clone(); next.Finished = finished.Append(state.Finished,rows); next.Files++;
                    next.ActiveFile = null; next.ActivePlan = null; Save(next); finished.Accept(rows); Notify("fragmented-media: file "+index+" complete");
                }
                if(c.Report.Files.Any(x=>x.Sha256==result.Sha256))throw new Reject("duplicate_output");
                return result;
            }
            void PublishReport(byte[] bytes)
            {
                Guard(); string path = RecoveryCatalog.SafeFile(root,"fragmented-media.json");
                if (Directory.Exists(path)) throw new IOException("MEDIA_REPORT_CHANGED");
                if (!File.Exists(path)) {
                    string temp = RecoveryCatalog.SafeFile(root,"report-"+Guid.NewGuid().ToString("N")+".partial"); bool own = false;
                    try {
                        using (var file = new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
                        Guard(); RecoveryLongPath.Move(temp,path);
                    } finally { if (own && File.Exists(temp)) File.Delete(temp); }
                }
                using (var file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                    if (file.Length != state.ReportBytes || HashReportFile(file,c.Cancel) != state.ReportHash) throw new IOException("MEDIA_REPORT_CHANGED");
                    if (state.Phase != 2) { Notify("fragmented-media: report ready"); var next = Clone(); next.Phase = 2; Save(next); Notify("fragmented-media: engine complete"); }
                }
            }
            public int Run()
            {
                Guard(); RecoveryLongPath.CreateDirectory(folder);
                var metadata = MediaChild(context,"metadata",state.Metadata,link => {
                    if (state.Phase != 0) throw new IOException("MEDIA_ENGINE_METADATA_AFTER_END");
                    var next = Clone(); next.Metadata = link; Save(next);
                });
                c.PublishCandidate = publisher; parsing = true;
                try {
                    using (var reader = new ReadCheckpoint(c,metadata,Notify)) { Execute(c,folder,(done,total)=> { if(scanProgress!=null)scanProgress(done,total); Guard(); }); reader.Finish(); }
                } finally { parsing = false; c.PublishCandidate = null; }
                Guard();
                if (fileIndex != state.Files || state.ActiveFile != null) throw new IOException("MEDIA_ENGINE_FILE_TAIL_MISSING");
                c.Report.Status="complete";
                byte[] bytes=ReportBytes(c.Report);
                string digest = Sha(bytes);
                if (state.Phase == 0) { var next = Clone(); next.Phase = 1; next.ReportHash = digest; next.ReportBytes = bytes.Length; Save(next); Notify("fragmented-media: report pending"); }
                if (state.ReportHash != digest || state.ReportBytes != bytes.Length) throw new IOException("MEDIA_ENGINE_REPORT_CHANGED");
                PublishReport(bytes); Guard(); return c.Report.Candidates;
            }
        }

        static int RecoverCheckpointedCore(Context c,RecoveryCheckpointContext checkpoint,Action<long,long> progress,Action<string> notify)
        {
            if(checkpoint==null||checkpoint.Method!="fragmented-media"||c.Input==null||c.Input.CanWrite||c.DurableRead!=null||c.PublishCandidate!=null||c.VerifiedImage!=null)
                throw new IOException("MEDIA_ENGINE_CONTEXT_INVALID");
            string digest=(checkpoint.SourceSha256??"").ToLowerInvariant();if(!Digest(digest))throw new IOException("METHOD_SOURCE_BINDING_REQUIRED");
            var context=new RecoveryCheckpointContext {Directory=checkpoint.Directory,Method="fragmented-media",SourceSha256=digest,Settings=checkpoint.Settings,Resume=checkpoint.Resume,Commit=checkpoint.Commit};
            c.Limits.Validate();Local(FullPath(c.Input.Name));Local(FullPath(context.Directory));
            c.Report=new Report {InputBytes=c.Input.Length};
            using(var verified=new RecoveryVerifiedImage(c.Input,digest,c.Cancel))using(var maps=new MediaReadMapLease(c,context)) {
                c.VerifiedImage=verified;
                try {return new EngineCheckpoint(c,context,maps,notify,progress).Run();}
                finally {c.VerifiedImage=null;}
            }
        }
        internal static int RecoverCheckpointed(string image,string directory,CancellationToken cancel,Action<long,long> progress,
            Action<string> notify,RecoveryCheckpointContext context,Limits limits=null)
        {
            cancel.ThrowIfCancellationRequested();
            if (context == null || Path.GetFullPath(directory) != Path.GetFullPath(context.Directory))
                throw new IOException("MEDIA_ENGINE_OUTPUT_SCOPE_INVALID");
            string source = FullPath(image); Local(source);
            using (var input = new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read,BlockBytes)) {
                var c = new Context { Input = input, Cancel = cancel, Limits = limits ?? new Limits() };
                try { return RecoverCheckpointedCore(c,context,progress,notify); }
                catch (Budget) { throw new IOException("MEDIA_SEARCH_LIMIT_REACHED"); }
            }
        }
    }
}
