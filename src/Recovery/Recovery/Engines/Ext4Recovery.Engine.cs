using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class EngineVolume
        {
            public int Schema = 1, Index, Phase;
            public long Offset;
            public string Kind, Outcome;
            public Dictionary<string,RecoveryMethodCheckpoint> Children = new Dictionary<string,RecoveryMethodCheckpoint>();
            public EngineVolume Copy()
            {
                return new EngineVolume { Index = Index, Phase = Phase, Offset = Offset, Kind = Kind, Outcome = Outcome,
                    Children = new Dictionary<string,RecoveryMethodCheckpoint>(Children,StringComparer.Ordinal) };
            }
        }
        sealed class EngineProgress
        {
            public int Schema = 1, Phase, NextLocation;
            public string Limits, Output, Request, ReadMaps, ReportIdentity;
            public RecoveryMethodCheckpoint Discovery, Report;
            public EngineVolume Active;
            public RecoveryOutputHead Finished;
            public Dictionary<string,RecoveryMethodCheckpoint> Exports = new Dictionary<string,RecoveryMethodCheckpoint>();
        }
        static readonly string[] EngineRoles = { "initialize", "inodes", "journal-load", "history", "names", "export" };

        sealed class EngineCheckpoint
        {
            readonly Context c;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly EngineReadMaps maps;
            readonly List<long> requested;
            readonly RecoveryMethodJournal<EngineProgress> journal;
            readonly RecoveryOutputLedger<EngineVolume> finished;
            EngineProgress state;

            public EngineCheckpoint(Context owner,RecoveryCheckpointContext checkpoint,EngineReadMaps readMaps,
                IEnumerable<long> offsets,Action<string> notify)
            {
                c = owner; context = checkpoint; maps = readMaps;
                progress = message => { if (notify != null) notify(message); maps.Validate(); };
                if (offsets != null) {
                    requested = offsets.Take(MaximumDiscoveryLocations+1).ToList();
                    if (requested.Count > MaximumDiscoveryLocations) throw new IOException("EXT4_OFFSETS_LIMIT");
                    requested = requested.Distinct().ToList();
                }
                string output = new Uri(Path.GetFullPath(context.Directory)+Path.DirectorySeparatorChar)
                    .MakeRelativeUri(new Uri(Path.GetFullPath(c.Root)+Path.DirectorySeparatorChar)).ToString();
                var initial = new EngineProgress { Limits = Ext4LimitsIdentity(c.Limits), Output = output,
                    Request = EngineRequestIdentity(requested), ReadMaps = maps.Identity };
                journal = new RecoveryMethodJournal<EngineProgress>(c.Input.Name,initial,context,c.Cancel); state = journal.Payload;
                if (state.Schema != 1 || state.Limits != initial.Limits || state.Output != initial.Output || state.Request != initial.Request ||
                    state.ReadMaps != initial.ReadMaps || state.Phase < 0 || state.Phase > 3 || state.NextLocation < 0 ||
                    state.NextLocation > MaximumDiscoveryLocations || state.Exports == null ||
                    state.Exports.Any(row => !ExportKey(row.Key,state.NextLocation) || row.Value == null) ||
                    state.Phase == 0 && (state.NextLocation != 0 || state.Active != null || state.Exports.Count != 0) ||
                    state.Phase != 1 && state.Active != null || state.Phase < 2 && (state.Report != null || state.ReportIdentity != null) ||
                    state.Phase >= 2 && !GroupDigest(state.ReportIdentity) || state.Phase == 3 && state.Report == null ||
                    requested != null && state.Discovery != null || requested == null && state.Phase != 0 && state.Discovery == null)
                    throw new IOException("EXT4_ENGINE_CHECKPOINT_INVALID");
                finished = new RecoveryOutputLedger<EngineVolume>(context,state.Finished,MaximumDiscoveryLocations,c.Cancel,
                    RecoveryLedgerScope.MethodOutput,64L*1024*1024);
                if (finished.Records.Count != state.NextLocation || state.Phase == 0 && finished.Records.Count != 0)
                    throw new IOException("EXT4_ENGINE_CURSOR_INVALID");
                foreach (var volume in finished.Records) ValidateVolume(volume,true);
                if (state.Active != null) ValidateVolume(state.Active,false);
                if (!journal.Resumed && (Directory.Exists(c.Root) || File.Exists(c.Root))) throw new IOException("EXT4_ENGINE_OUTPUT_EXISTS");
            }
            static string Key(int index) { return index.ToString(CultureInfo.InvariantCulture); }
            static bool ExportKey(string key,int maximum)
            { int value; return Int32.TryParse(key,NumberStyles.None,CultureInfo.InvariantCulture,out value) && value >= 0 && value < maximum && key == Key(value); }
            void ValidateVolume(EngineVolume volume,bool complete)
            {
                if (volume == null || volume.Schema != 1 || volume.Index < 0 || volume.Index > MaximumDiscoveryLocations ||
                    volume.Phase < 0 || volume.Phase > EngineRoles.Length || volume.Children == null ||
                    volume.Children.Any(row => row.Value == null || !EngineRoles.Contains(row.Key) ||
                        Array.IndexOf(EngineRoles,row.Key) > volume.Phase || complete && row.Key == "export") ||
                    complete && (volume.Phase != EngineRoles.Length || !GroupDigest(volume.Outcome) ||
                        volume.Kind != "invalid-offset" && volume.Kind != "not-ext4" && volume.Kind != "rejected" && volume.Kind != "ready") ||
                    !complete && (volume.Index != state.NextLocation || volume.Kind != null || volume.Outcome != null))
                    throw new IOException("EXT4_ENGINE_VOLUME_INVALID");
            }
            EngineProgress Copy()
            {
                return new EngineProgress { Phase = state.Phase, NextLocation = state.NextLocation, Limits = state.Limits,
                    Output = state.Output, Request = state.Request, ReadMaps = state.ReadMaps, ReportIdentity = state.ReportIdentity,
                    Discovery = state.Discovery, Report = state.Report, Active = state.Active == null ? null : state.Active.Copy(),
                    Finished = state.Finished, Exports = new Dictionary<string,RecoveryMethodCheckpoint>(state.Exports,StringComparer.Ordinal) };
            }
            void Save(EngineProgress next)
            { c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits(); maps.Validate(); journal.Save(next); state = next; }
            List<long> Locations()
            {
                List<long> locations = requested;
                if (requested == null) {
                    Action<RecoveryMethodCheckpoint> commit = null;
                    if (state.Phase == 0) commit = link => { var next = Copy(); next.Discovery = link; Save(next); };
                    locations = DiscoverCheckpointed(c,Ext4Child(context,"discovery",state.Discovery,commit),progress);
                }
                if (state.Phase == 0) { var next = Copy(); next.Phase = 1; Save(next); }
                if (locations.Count > MaximumDiscoveryLocations || state.NextLocation > locations.Count ||
                    state.Active != null && (state.NextLocation >= locations.Count || state.Active.Offset != locations[state.NextLocation]))
                    throw new IOException("EXT4_ENGINE_LOCATIONS_CHANGED");
                return locations;
            }
            void Stage(EngineVolume volume,bool complete,int number,Action<RecoveryCheckpointContext> run)
            {
                c.Cancel.ThrowIfCancellationRequested(); maps.Validate();
                var current = complete ? volume : state.Active;
                string role = EngineRoles[number]; RecoveryMethodCheckpoint anchor;
                if (complete && role == "export") state.Exports.TryGetValue(Key(volume.Index),out anchor);
                else current.Children.TryGetValue(role,out anchor);
                if (current.Phase < number || run == null && anchor != null || run != null && current.Phase > number && anchor == null)
                    throw new IOException("EXT4_ENGINE_PHASE_INVALID");
                if (run != null) {
                    Action<RecoveryMethodCheckpoint> commit = null;
                    if (current.Phase == number || number == EngineRoles.Length-1) commit = link => {
                        var next = Copy();
                        if (complete) next.Exports[Key(volume.Index)] = link; else next.Active.Children[role] = link;
                        Save(next);
                    };
                    string name = "volume-"+Key(volume.Index)+"/"+role;
                    run(Ext4Child(context,name,anchor,commit));
                }
                if (!complete && state.Active.Phase == number) {
                    var next = Copy(); next.Active.Phase = number+1; Save(next);
                    progress("ext4: volume "+volume.Index+" "+role+" complete");
                }
                c.Cancel.ThrowIfCancellationRequested();
            }
            string ProcessVolume(EngineVolume volume,bool complete)
            {
                if (volume.Offset < 0 || (volume.Offset&511) != 0 || volume.Offset > c.Input.Length-2048) {
                    if (volume.Children.Count != 0 || state.Exports.ContainsKey(Key(volume.Index))) throw new IOException("EXT4_ENGINE_INVALID_OFFSET_CHILD");
                    Skip(c,"invalid_partition_offset"); return "invalid-offset";
                }
                Volume v = null;
                Stage(volume,complete,0,child => { v = OpenVolumeCheckpointed(c,volume.Offset,child,progress); });
                bool ready = v != null && v.Report.Status == "ready";
                List<Inode> deleted = null; Dictionary<uint,Inode> directories = null;
                Stage(volume,complete,1,!ready ? null : (Action<RecoveryCheckpointContext>)(child => {
                    ScanInodesCheckpointed(c,v,child,progress,out deleted,out directories);
                }));
                Stage(volume,complete,2,!ready || v.JournalLoaded ? null : (Action<RecoveryCheckpointContext>)(child => {
                    LoadJournalCheckpointed(c,v,child,progress);
                }));
                Dictionary<uint,HistoricalCandidate> historical = null; List<JournalDirectoryBlock> blocks = null;
                Stage(volume,complete,3,!ready || v.Journal == null ? null : (Action<RecoveryCheckpointContext>)(child => {
                    SweepJournalHistoryCheckpointed(c,v,v.Journal,child,progress,out historical,out blocks);
                    v.Report.JournalHistoricalInodesFound = historical.Count;
                }));
                Dictionary<uint,List<NameLink>> names = null;
                Stage(volume,complete,4,!ready ? null : (Action<RecoveryCheckpointContext>)(child => {
                    names = DirectoryNamesCheckpointed(c,v,directories,blocks,child,progress);
                }));
                Stage(volume,complete,5,!ready ? null : (Action<RecoveryCheckpointContext>)(child => {
                    ExportVolumeCandidatesCheckpointed(c,v,deleted,historical,names,child,progress);
                }));
                if (ready) v.Report.Status = c.Report.Limited ? "limited" : "complete";
                return ready ? "ready" : v == null ? "not-ext4" : "rejected";
            }
            void FinishVolume(EngineVolume volume,string kind)
            {
                var fact = state.Active.Copy(); fact.Phase = EngineRoles.Length; fact.Kind = kind; fact.Outcome = EngineOutcomeIdentity(c);
                RecoveryMethodCheckpoint export;
                var next = Copy();
                if (fact.Children.TryGetValue("export",out export)) { next.Exports[Key(volume.Index)] = export; fact.Children.Remove("export"); }
                var rows = new List<EngineVolume> { fact }; next.Finished = finished.Append(state.Finished,rows);
                next.Active = null; next.NextLocation++; Save(next); finished.Accept(rows);
                progress("ext4: finished volume "+volume.Index);
            }
            public int Run()
            {
                if (!journal.Resumed) Save(Copy());
                Directory.CreateDirectory(RecoveryCatalog.SafeFile(c.Root,"files"));
                var locations = Locations(); int processed = 0; var exports = new HashSet<string>(StringComparer.Ordinal);
                for (int index = 0; index < locations.Count; index++) {
                    c.Cancel.ThrowIfCancellationRequested(); maps.Validate();
                    if (c.Report.Volumes.Count >= c.Limits.MaximumVolumes) { c.Report.Limited = true; Skip(c,"volume_limit"); break; }
                    bool complete = index < state.NextLocation; EngineVolume volume;
                    if (complete) volume = finished.Records[index];
                    else {
                        if (state.Phase != 1 || index != state.NextLocation) throw new IOException("EXT4_ENGINE_UNFINISHED_VOLUME");
                        if (state.Active == null) {
                            var next = Copy(); next.Active = new EngineVolume { Index = index, Offset = locations[index] }; Save(next);
                        }
                        volume = state.Active;
                    }
                    if (volume.Index != index || volume.Offset != locations[index]) throw new IOException("EXT4_ENGINE_VOLUME_ORDER_INVALID");
                    string kind = ProcessVolume(volume,complete);
                    if (complete) {
                        if (volume.Kind != kind || volume.Outcome != EngineOutcomeIdentity(c)) throw new IOException("EXT4_ENGINE_VOLUME_OUTCOME_CHANGED");
                    } else FinishVolume(volume,kind);
                    if (kind == "ready") exports.Add(Key(index));
                    processed = index+1;
                }
                if (state.NextLocation != processed || state.Active != null || !exports.SetEquals(state.Exports.Keys))
                    throw new IOException("EXT4_ENGINE_COMPLETION_INVALID");
                using (var verify = new FileStream(c.Input.Name,FileMode.Open,FileAccess.Read,FileShare.Read))
                    c.Report.SourceUnchanged = verify.Length == c.Report.InputBytes && HashStream(verify,c.Cancel) == c.Report.SourceSha256;
                if (!c.Report.SourceUnchanged) throw new IOException("EXT4_ENGINE_SOURCE_CHANGED");
                c.Report.Status = c.Report.Limited ? "limited" : "complete";
                string identity = ReportIdentity(c);
                if (state.Phase == 1) { var next = Copy(); next.Phase = 2; next.ReportIdentity = identity; Save(next); progress("ext4: reports pending"); }
                if (state.ReportIdentity != identity) throw new IOException("EXT4_ENGINE_REPORT_CHANGED");
                var report = Ext4Child(context,"report",state.Report,link => { var next = Copy(); next.Report = link; Save(next); });
                WriteReportCheckpointed(c,report,progress);
                if (state.Phase != 3) { var next = Copy(); next.Phase = 3; Save(next); progress("ext4: engine complete"); }
                c.Cancel.ThrowIfCancellationRequested(); maps.Validate(); return c.Report.RecoveredFiles;
            }
        }
        static int RecoverCheckpointedCore(Context c,RecoveryCheckpointContext context,IEnumerable<long> offsets,Action<string> progress)
        {
            if (context == null || context.Method != "ext4" || c.InodesRead != 0 || c.DirectoryCount != 0 || c.NameCount != 0 || c.DirectoryBytes != 0 || c.Input.CanWrite)
                throw new IOException("EXT4_ENGINE_CONTEXT_INVALID");
            string digest = (context.SourceSha256 ?? "").ToLowerInvariant();
            if (!GroupDigest(digest)) throw new IOException("METHOD_SOURCE_BINDING_REQUIRED");
            context = new RecoveryCheckpointContext { Directory = context.Directory, Method = context.Method,
                Settings = context.Settings, SourceSha256 = digest, Resume = context.Resume, Commit = context.Commit };
            c.Cancel.ThrowIfCancellationRequested(); ValidateExt4Limits(c.Limits); NoLinks(c.Root);
            string source = LocalFile(c.Input.Name),root = Path.GetFullPath(c.Root);
            if (source.Equals(root,StringComparison.OrdinalIgnoreCase) || source.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
                throw new IOException("EXT4_ENGINE_SOURCE_IN_OUTPUT");
            c.Report = NewExt4Report(); c.Report.InputBytes = c.Input.Length; c.Report.SourceSha256 = context.SourceSha256;
            using (new MetadataSourceScope(c,context)) using (var maps = new EngineReadMaps(c,context)) {
                ValidateMetadataSource(c,context); return new EngineCheckpoint(c,context,maps,offsets,progress).Run();
            }
        }
        internal static int RecoverCheckpointed(string image,string runDirectory,CancellationToken cancel,Action<string> progress,
            RecoveryCheckpointContext context,IEnumerable<long> offsets = null,Limits limits = null)
        {
            using (var input = new FileStream(LocalFile(image),FileMode.Open,FileAccess.Read,FileShare.Read,1024*1024)) {
                var c = new Context { Input = input, Root = Path.GetFullPath(Path.Combine(runDirectory,"ext4")), Cancel = cancel, Limits = limits ?? new Limits() };
                return RecoverCheckpointedCore(c,context,offsets,progress);
            }
        }
    }
}
