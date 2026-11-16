using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        const int MaximumGroupBlobBytes = 1024 * 1024;
        sealed class GroupProgress
        {
            public int Schema = 1;
            public long VolumeOffset;
            public ulong Groups, DescriptorStart;
            public uint NextGroup;
            public string HeaderSha256, OverlaySha256;
            public bool Complete;
            public RecoveryOutputHead Facts;
        }
        sealed class GroupFact { public uint Number; public string BlobSha256; }
        sealed class GroupPayload
        {
            public int Schema = 1;
            public uint Number;
            public string Descriptor, Inodes, Blocks;
        }
        static bool GroupDigest(string value)
        { return value != null && value.Length == 64 && value.All(ch => ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f'); }
        static string GroupBytesHash(byte[] bytes)
        { using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(bytes)); }
        static string GroupOverlayHash(Context c, Volume v)
        {
            using (var sha = SHA256.Create())
            {
                long total = 0;
                if (v.Overlay.Count > c.Limits.MaximumJournalBlocks) throw new IOException("EXT4_GROUP_OVERLAY_INVALID");
                foreach (var row in v.Overlay.OrderBy(x => x.Key))
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    if (!BlockRange(v, row.Key, 1) || row.Value == null || row.Value.Length != v.BlockBytes ||
                        row.Value.Length > c.Limits.MaximumJournalBytes - total) throw new IOException("EXT4_GROUP_OVERLAY_INVALID");
                    total += row.Value.Length;
                    byte[] number = BitConverter.GetBytes(row.Key);
                    sha.TransformBlock(number, 0, number.Length, null, 0);
                    sha.TransformBlock(row.Value, 0, row.Value.Length, null, 0);
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return Hex(sha.Hash);
            }
        }
        static string GroupBlobPath(RecoveryCheckpointContext context, string hash)
        { return MetadataBlobPath(context, "group-blobs", hash); }
        static string MetadataBlobPath(RecoveryCheckpointContext context, string folder, string hash)
        {
            if (!GroupDigest(hash) || folder != "group-blobs" && folder != "inode-blobs" && folder != "journal-blobs")
                throw new IOException("EXT4_GROUP_BLOB_INVALID");
            return RecoveryCatalog.SafeFile(context.Directory, "ext4.state/" + folder + "/blob-" + hash + ".json");
        }
        static string StoreGroupPayload(RecoveryCheckpointContext context, Group group, CancellationToken cancel)
        {
            var payload = new GroupPayload { Number = group.Number,
                Descriptor = Convert.ToBase64String(group.Descriptor),
                Inodes = group.Inodes == null ? null : Convert.ToBase64String(group.Inodes),
                Blocks = group.Blocks == null ? null : Convert.ToBase64String(group.Blocks) };
            return StoreMetadataPayload(context, "group-blobs", payload, cancel);
        }
        static string StoreMetadataPayload(RecoveryCheckpointContext context, string folder, object payload, CancellationToken cancel)
        {
            byte[] bytes = new UTF8Encoding(false, true).GetBytes(new JavaScriptSerializer
                { MaxJsonLength = MaximumGroupBlobBytes }.Serialize(payload));
            if (bytes.Length > MaximumGroupBlobBytes) throw new IOException("EXT4_GROUP_BLOB_LIMIT");
            string hash = GroupBytesHash(bytes), path = MetadataBlobPath(context, folder, hash);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            cancel.ThrowIfCancellationRequested();
            if (!File.Exists(path))
            {
                string temporary = Path.Combine(Path.GetDirectoryName(path), ".blob-" + Guid.NewGuid().ToString("N") + ".partial");
                bool ownsTemporary = false;
                try
                {
                    using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                    { ownsTemporary = true; output.Write(bytes, 0, bytes.Length); output.Flush(true); }
                    cancel.ThrowIfCancellationRequested();
                    File.Move(temporary, path);
                }
                finally { if (ownsTemporary && File.Exists(temporary)) File.Delete(temporary); }
            }
            using (var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                if (guard.Length != bytes.Length || RecoveryCore.HashFile(path, cancel, (a, b) => { }) != hash)
                    throw new IOException("EXT4_GROUP_BLOB_CHANGED");
            return hash;
        }
        static byte[] GroupDecode(string value, int bytes, bool required)
        {
            if (value == null) { if (!required) return null; throw new IOException("EXT4_GROUP_BLOB_INVALID"); }
            if (value.Length != (bytes + 2) / 3 * 4) throw new IOException("EXT4_GROUP_BLOB_INVALID");
            try
            {
                byte[] result = Convert.FromBase64String(value);
                if (result.Length != bytes) throw new IOException("EXT4_GROUP_BLOB_INVALID");
                return result;
            }
            catch (FormatException) { throw new IOException("EXT4_GROUP_BLOB_INVALID"); }
        }
        static GroupMetadataUnit RestoreGroupPayload(Context c, Volume v, List<Range> fixedReserved,
            RecoveryCheckpointContext context, GroupFact fact)
        {
            var payload = ReadMetadataPayload<GroupPayload>(context, "group-blobs", fact.BlobSha256, c.Cancel);
            if (payload == null || payload.Schema != 1 || payload.Number != fact.Number) throw new IOException("EXT4_GROUP_BLOB_INVALID");
            bool usedInodes = false, usedBlocks = false;
            var unit = ParseGroupMetadata(c, v, fact.Number, fixedReserved,
                GroupDecode(payload.Descriptor, v.DescriptorBytes, true), (block, inode) =>
                {
                    if (inode) usedInodes = true; else usedBlocks = true;
                    return GroupDecode(inode ? payload.Inodes : payload.Blocks, v.BlockBytes, true);
                });
            if (!usedInodes && payload.Inodes != null || !usedBlocks && payload.Blocks != null)
                throw new IOException("EXT4_GROUP_BLOB_INVALID");
            return unit;
        }
        static T ReadMetadataPayload<T>(RecoveryCheckpointContext context, string folder, string hash, CancellationToken cancel) where T : class
        {
            string path = MetadataBlobPath(context, folder, hash);
            using (var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (guard.Length <= 0 || guard.Length > MaximumGroupBlobBytes ||
                    RecoveryCore.HashFile(path, cancel, (a, b) => { }) != hash)
                    throw new IOException("EXT4_GROUP_BLOB_CHANGED");
                try
                {
                    T payload = new JavaScriptSerializer { MaxJsonLength = MaximumGroupBlobBytes, RecursionLimit = 8 }
                        .Deserialize<T>(File.ReadAllText(path, new UTF8Encoding(false, true)));
                    if (payload == null) throw new IOException("EXT4_GROUP_BLOB_INVALID");
                    return payload;
                }
                catch (ArgumentException) { throw new IOException("EXT4_GROUP_BLOB_INVALID"); }
                catch (InvalidOperationException) { throw new IOException("EXT4_GROUP_BLOB_INVALID"); }
            }
        }
        static void ValidateMetadataSource(Context c, RecoveryCheckpointContext context)
        {
            if (context == null) return;
            if (context.Method != "ext4") throw new IOException("EXT4_GROUP_CONTEXT_INVALID");
            string source = Path.GetFullPath(c.Input.Name);
            string stateRoot = Path.GetDirectoryName(Path.GetDirectoryName(GroupBlobPath(context, new string('0', 64))));
            if (source.Equals(stateRoot, StringComparison.OrdinalIgnoreCase) ||
                source.StartsWith(stateRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("EXT4_GROUP_SOURCE_IN_STATE");
            if (RecoveryCore.HashFile(source, c.Cancel, (a, b) => { }) != context.SourceSha256)
                throw new IOException("EXT4_GROUP_SOURCE_CHANGED");
        }
        // The future full-engine controller can nest this phase's acknowledged
        // anchor in its own state. Normal legacy initialization shares the same
        // units with a null context; this is not yet whole-engine resume.
        static void ReadGroupsCheckpointed(Context c, Volume v, ulong groups, ulong gdStart,
            List<Range> fixedReserved, RecoveryCheckpointContext context, Action<string> progress)
        {
            if (v.Groups.Count != 0 || groups != (ulong)v.Report.Groups || groups > (ulong)c.Limits.MaximumGroups ||
                v.Superblock == null || v.Superblock.Length != 1024) throw new IOException("EXT4_GROUP_PHASE_INVALID");
            ValidateMetadataSource(c, context);
            var initial = new GroupProgress { VolumeOffset = v.Offset, Groups = groups, DescriptorStart = gdStart,
                HeaderSha256 = context == null ? null : GroupBytesHash(v.Superblock),
                OverlaySha256 = context == null ? null : GroupOverlayHash(c, v) };
            var journal = new RecoveryMethodJournal<GroupProgress>(c.Input.Name, initial, context, c.Cancel);
            GroupProgress state = journal.Payload;
            if (state.Schema != 1 || state.VolumeOffset != initial.VolumeOffset || state.Groups != groups ||
                state.DescriptorStart != gdStart || state.HeaderSha256 != initial.HeaderSha256 ||
                state.OverlaySha256 != initial.OverlaySha256 || state.NextGroup > groups ||
                (state.Facts == null ? 0 : state.Facts.Count) != state.NextGroup || state.Complete && state.NextGroup != groups)
                throw new IOException("EXT4_GROUP_CHECKPOINT_INVALID");
            var ledger = new RecoveryOutputLedger<GroupFact>(context, state.Facts, c.Limits.MaximumGroups,
                c.Cancel, RecoveryLedgerScope.MethodOutput, 64L * 1024 * 1024);
            foreach (GroupFact fact in ledger.Records)
            {
                if (fact.Number != (uint)v.Groups.Count) throw new IOException("EXT4_GROUP_FACT_ORDER_INVALID");
                ApplyGroupMetadata(c, v, RestoreGroupPayload(c, v, fixedReserved, context, fact));
            }
            for (uint number = state.NextGroup; number < groups; number++)
            {
                GroupMetadataUnit unit = ReadGroupMetadata(c, v, gdStart, number, fixedReserved);
                var rows = new List<GroupFact> { new GroupFact { Number = number,
                    BlobSha256 = context == null ? null : StoreGroupPayload(context, unit.Group, c.Cancel) } };
                var next = new GroupProgress { VolumeOffset = initial.VolumeOffset, Groups = groups,
                    DescriptorStart = gdStart, HeaderSha256 = initial.HeaderSha256, OverlaySha256 = initial.OverlaySha256,
                    NextGroup = number + 1, Facts = ledger.Append(state.Facts, rows) };
                journal.Save(next); ledger.Accept(rows); state = next;
                ApplyGroupMetadata(c, v, unit);
                if (progress != null) progress("ext4: groups " + state.NextGroup + "/" + groups);
            }
            ValidateGroupOverlaps(c, v);
            if (!state.Complete) { state.Complete = true; journal.Save(state); }
        }
    }
}
