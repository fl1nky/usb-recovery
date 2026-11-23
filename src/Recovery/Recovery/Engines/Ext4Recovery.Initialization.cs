using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class InitializationProgress
        {
            public int Schema = 1, Phase;
            public long Offset;
            public string Baseline, Limits, Header;
            public Dictionary<string,RecoveryMethodCheckpoint> Children = new Dictionary<string,RecoveryMethodCheckpoint>();
        }
        sealed class InitializationHeader
        {
            public int Schema = 1;
            public long Offset;
            public string Data;
        }
        static readonly string[] InitializationRoles = { "groups-before", "journal-load", "journal-replay", "groups-after" };

        // This controller only opens one volume. Its children own their inner
        // cursors; closed phases rebuild from verified facts with read-only
        // parent links. It is reusable by the future whole-engine coordinator.
        sealed class VolumeInitialization
        {
            readonly Context c;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly RecoveryMethodJournal<InitializationProgress> journal;
            InitializationProgress state;

            public VolumeInitialization(Context owner,long offset,RecoveryCheckpointContext checkpoint,Action<string> notify)
            {
                c = owner; context = checkpoint; progress = notify; ValidateMetadataSource(c,context);
                if (offset < 0 || (offset&511) != 0 || offset > c.Input.Length-2048)
                    throw new IOException("EXT4_INITIALIZATION_OFFSET_INVALID");
                var initial = new InitializationProgress { Offset = offset, Baseline = ReportIdentity(c), Limits = Ext4LimitsIdentity(c.Limits) };
                journal = new RecoveryMethodJournal<InitializationProgress>(c.Input.Name,initial,context,c.Cancel); state = journal.Payload;
                if (state.Schema != 1 || state.Offset != offset || state.Baseline != initial.Baseline || state.Limits != initial.Limits ||
                    state.Phase < 0 || state.Phase > InitializationRoles.Length || state.Children == null ||
                    state.Children.Keys.Any(role => !InitializationRoles.Contains(role)) ||
                    state.Children.Any(row => row.Value == null || Array.IndexOf(InitializationRoles,row.Key) > state.Phase) ||
                    state.Header == null && (journal.Resumed || state.Phase != 0 || state.Children.Count != 0))
                    throw new IOException("EXT4_INITIALIZATION_CHECKPOINT_INVALID");
            }
            InitializationProgress Copy()
            {
                return new InitializationProgress { Offset = state.Offset, Phase = state.Phase, Baseline = state.Baseline,
                    Limits = state.Limits, Header = state.Header,
                    Children = new Dictionary<string,RecoveryMethodCheckpoint>(state.Children,StringComparer.Ordinal) };
            }
            void Save(InitializationProgress next) { c.CheckpointSource.ValidateLimits(); journal.Save(next); state = next; }
            byte[] Header()
            {
                if (state.Header == null) {
                    byte[] data = Read(c,state.Offset+1024,1024);
                    if (data == null || data.Length != 1024) throw new EndOfStreamException("EXT4_INITIALIZATION_HEADER_SHORT_READ");
                    var header = new InitializationHeader { Offset = state.Offset, Data = Convert.ToBase64String(data) };
                    var next = Copy(); next.Header = StoreMetadataPayload(context,"group-blobs",header,c.Cancel); Save(next);
                    if (progress != null) progress("ext4: volume header saved");
                }
                c.Cancel.ThrowIfCancellationRequested();
                var saved = ReadMetadataPayload<InitializationHeader>(context,"group-blobs",state.Header,c.Cancel);
                if (saved == null || saved.Schema != 1 || saved.Offset != state.Offset) throw new IOException("EXT4_INITIALIZATION_HEADER_INVALID");
                return GroupDecode(saved.Data,1024,true);
            }
            void Stage(int number,Action<RecoveryCheckpointContext> run)
            {
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                string role = InitializationRoles[number]; RecoveryMethodCheckpoint anchor; state.Children.TryGetValue(role,out anchor);
                if (state.Phase < number || run == null && anchor != null || run != null && state.Phase > number && anchor == null)
                    throw new IOException("EXT4_INITIALIZATION_PHASE_INVALID");
                if (run != null) {
                    Action<RecoveryMethodCheckpoint> commit = null;
                    if (state.Phase == number) commit = link => {
                        var linked = Copy(); linked.Children[role] = link; Save(linked);
                    };
                    run(Ext4Child(context,role,anchor,commit));
                }
                if (state.Phase == number) {
                    var next = Copy(); next.Phase = number+1; Save(next);
                    if (progress != null) progress("ext4: initialization "+role+" complete");
                }
                c.Cancel.ThrowIfCancellationRequested();
            }
            public Volume Run()
            {
                byte[] sb = Header(); Volume v = ParseVolumeHeader(c,state.Offset,sb);
                bool accepted = v != null && v.Report.Status == "header_ready";
                List<Range> reserved = accepted ? v.Reserved.ToList() : null;
                Stage(0,!accepted ? null : (Action<RecoveryCheckpointContext>)(child => {
                    v.Report.Status = "rejected";
                    ReadGroupsCheckpointed(c,v,(ulong)v.Report.Groups,v.FirstData+1UL,reserved,child,progress);
                }));
                bool dirty = accepted && (v.Incompat&4) != 0; JournalContext jc = null;
                Stage(1,!dirty ? null : (Action<RecoveryCheckpointContext>)(child => { jc = LoadJournalCheckpointed(c,v,child,progress); }));
                Stage(2,!dirty || jc == null ? null : (Action<RecoveryCheckpointContext>)(child => { ReplayJournalCheckpointed(c,jc,child,progress); }));
                if (dirty) {
                    if (jc == null) { accepted = false; v.Report.Reason = v.Report.JournalStatus ?? "journal_unavailable_for_dirty_volume"; }
                    else if (!v.JournalReplayApplied && jc.Start != 0 && v.Report.JournalStatus != "journal_transaction_uncommitted")
                    { accepted = false; v.Report.Reason = v.Report.JournalStatus ?? "journal_replay_failed"; }
                    else if (v.Overlay.Count > 0 && !ReplaySuperblockGeometry(c,v,sb))
                    { accepted = false; v.Report.Reason = v.Report.JournalStatus; }
                }
                Stage(3,!accepted || v.Overlay.Count == 0 ? null : (Action<RecoveryCheckpointContext>)(child => {
                    v.Groups.Clear(); v.Reserved = reserved.ToList();
                    ReadGroupsCheckpointed(c,v,(ulong)v.Report.Groups,v.FirstData+1UL,reserved,child,progress);
                }));
                if (accepted) { v.Report.CheckedGroups = v.Groups.Count(group => group.Valid); v.Report.Status = "ready"; }
                return v;
            }
        }
        static Volume OpenVolumeCheckpointed(Context c,long offset,RecoveryCheckpointContext context,Action<string> progress)
        {
            if (context == null) return OpenVolume(c,offset);
            using (new MetadataSourceScope(c,context)) return new VolumeInitialization(c,offset,context,progress).Run();
        }
    }
}
