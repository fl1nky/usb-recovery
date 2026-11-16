using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        const int InodesPerUnit = 256, MaximumInodeUnitBytes = 64 * 1024;
        sealed class InodeProgress
        {
            public int Schema = 1, GroupIndex, BaseInodes, BaseEntries;
            public uint NextInode;
            public long VolumeOffset;
            public string HeaderSha256, OverlaySha256, GroupsSha256, Limits;
            public bool Complete, Limited;
            public RecoveryOutputHead Facts;
        }
        sealed class InodeFact { public string BlobSha256; }
        sealed class InodePayload
        {
            public int Schema = 1, GroupIndex, Count;
            public uint Start;
            public bool BudgetStop;
            public string Data;
        }
        static string InodeGroupsHash(Context c, Volume v)
        {
            using (var sha = SHA256.Create())
            {
                for (int index = 0; index < v.Groups.Count; index++)
                {
                    c.Cancel.ThrowIfCancellationRequested(); Group group = v.Groups[index];
                    if (group.Number != (uint)index) throw new IOException("EXT4_INODE_GROUP_ORDER_INVALID");
                    byte[] flags = { (byte)(group.Valid ? 1 : 0), (byte)(group.InodeMapValid ? 1 : 0), (byte)(group.BlockMapValid ? 1 : 0) };
                    sha.TransformBlock(flags, 0, flags.Length, null, 0);
                    foreach (byte[] bytes in new[] { group.Descriptor, group.Inodes, group.Blocks })
                    {
                        byte[] length = BitConverter.GetBytes(bytes == null ? -1 : bytes.Length);
                        sha.TransformBlock(length, 0, length.Length, null, 0);
                        if (bytes != null) sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
                    }
                }
                sha.TransformFinalBlock(new byte[0], 0, 0); return Hex(sha.Hash);
            }
        }
        static uint GroupInodeCount(Volume v, Group group)
        { return Math.Min(v.InodesPerGroup, v.Inodes - group.Number * v.InodesPerGroup); }
        static void NormalizeInodeCursor(Volume v, ref int group, ref uint at)
        {
            while (group < v.Groups.Count)
            {
                Group current = v.Groups[group];
                if (current.Valid && current.InodeMapValid && at < GroupInodeCount(v, current)) return;
                group++; at = 0;
            }
        }
        static InodePayload ReadInodeUnit(Context c, Volume v, int groupIndex, uint at)
        {
            c.Cancel.ThrowIfCancellationRequested(); Group group = v.Groups[groupIndex];
            var payload = new InodePayload { GroupIndex = groupIndex, Start = at };
            int remaining = c.Limits.MaximumInodes - c.InodesRead;
            if (remaining <= 0) { payload.BudgetStop = true; return payload; }
            payload.Count = (int)Math.Min(GroupInodeCount(v, group) - at,
                (uint)Math.Min(remaining, Math.Min(c.Limits.InodesPerCheckpoint, MaximumInodeUnitBytes / v.InodeBytes)));
            byte[] bytes = new byte[payload.Count * v.InodeBytes]; int done = 0;
            long start = (long)at * v.InodeBytes;
            while (done < bytes.Length)
            {
                c.Cancel.ThrowIfCancellationRequested(); long logical = start + done;
                byte[] block = Block(c, v, group.InodeTable + (ulong)(logical / v.BlockBytes));
                if (block == null || block.Length != v.BlockBytes) throw new EndOfStreamException("EXT4_INODE_TABLE_SHORT_READ");
                int inBlock = (int)(logical % v.BlockBytes), count = Math.Min(bytes.Length - done, v.BlockBytes - inBlock);
                Buffer.BlockCopy(block, inBlock, bytes, done, count); done += count;
            }
            c.Cancel.ThrowIfCancellationRequested(); payload.Data = Convert.ToBase64String(bytes); return payload;
        }
        static void ApplyInodeUnit(Context c, Volume v, InodePayload payload, ref int groupIndex, ref uint at,
            List<Inode> deleted, Dictionary<uint, Inode> directories)
        {
            c.Cancel.ThrowIfCancellationRequested();
            if (payload == null || payload.Schema != 1 || payload.GroupIndex != groupIndex || payload.Start != at || groupIndex >= v.Groups.Count)
                throw new IOException("EXT4_INODE_UNIT_INVALID");
            if (payload.BudgetStop)
            {
                if (payload.Count != 0 || payload.Data != null || c.InodesRead != c.Limits.MaximumInodes)
                    throw new IOException("EXT4_INODE_LIMIT_STATE_INVALID");
                c.Report.Limited = true; Skip(c, "inode_limit"); return;
            }
            Group group = v.Groups[groupIndex];
            if (payload.Count < 1 || payload.Count > c.Limits.InodesPerCheckpoint || payload.Count > MaximumInodeUnitBytes / v.InodeBytes ||
                (uint)payload.Count > GroupInodeCount(v, group) - at || payload.Count > c.Limits.MaximumInodes - c.InodesRead)
                throw new IOException("EXT4_INODE_UNIT_BOUNDS_INVALID");
            byte[] all = GroupDecode(payload.Data, payload.Count * v.InodeBytes, true);
            for (int index = 0; index < payload.Count; index++)
            {
                uint slot = at + (uint)index, number = group.Number * v.InodesPerGroup + slot + 1;
                byte[] bytes = new byte[v.InodeBytes]; Buffer.BlockCopy(all, index * v.InodeBytes, bytes, 0, bytes.Length);
                c.InodesRead++;
                ushort mode = U16(bytes, 0); if ((mode & 0xf000) != 0x8000 && (mode & 0xf000) != 0x4000) continue;
                if (!InodeChecksum(v, number, bytes)) { Skip(c, "inode_checksum_invalid"); continue; }
                v.Report.CheckedInodes++;
                var inode = new Inode { Number = number, Offset = v.Offset + (long)group.InodeTable * v.BlockBytes + (long)slot * v.InodeBytes,
                    Mode = mode, Links = U16(bytes, 0x1a), Dtime = U32(bytes, 0x14), Flags = U32(bytes, 0x20),
                    Generation = U32(bytes, 0x64), Size = U32(bytes, 4) | (ulong)U32(bytes, 0x6c) << 32,
                    Allocated = Bit(group.Inodes, slot), Bytes = bytes };
                if (inode.Allocated && inode.Links > 0 && inode.Dtime == 0)
                {
                    v.Report.LiveInodes++;
                    if ((mode & 0xf000) == 0x4000)
                    {
                        if (directories.Count >= c.Limits.MaximumDirectories) { c.Report.Limited = true; Skip(c, "directory_count_limit"); }
                        else directories[number] = inode;
                    }
                    continue;
                }
                if ((mode & 0xf000) != 0x8000 || inode.Allocated || inode.Links != 0 || inode.Dtime == 0 || number < Math.Max(11, v.FirstInode)) continue;
                if (c.Report.Entries.Count + deleted.Count >= c.Limits.MaximumCandidates)
                { c.Report.Limited = true; Skip(c, "candidate_limit"); continue; }
                deleted.Add(inode);
            }
            at += (uint)payload.Count; NormalizeInodeCursor(v, ref groupIndex, ref at);
        }
        static InodeProgress AdvanceInodeProgress(InodeProgress state, int group, uint at,
            RecoveryOutputHead facts, bool complete, bool limited)
        {
            return new InodeProgress { VolumeOffset = state.VolumeOffset, BaseInodes = state.BaseInodes,
                BaseEntries = state.BaseEntries, HeaderSha256 = state.HeaderSha256, OverlaySha256 = state.OverlaySha256,
                GroupsSha256 = state.GroupsSha256, Limits = state.Limits, GroupIndex = group, NextInode = at,
                Facts = facts, Complete = complete, Limited = limited };
        }
        static void ScanInodesCheckpointed(Context c, Volume v, RecoveryCheckpointContext context, Action<string> progress,
            out List<Inode> deleted, out Dictionary<uint, Inode> directories)
        {
            if (v.Report.CheckedInodes != 0 || v.Report.LiveInodes != 0 || c.InodesRead < 0 || c.InodesRead > c.Limits.MaximumInodes ||
                c.Limits.InodesPerCheckpoint < 1 || c.Limits.InodesPerCheckpoint > InodesPerUnit)
                throw new IOException("EXT4_INODE_PHASE_BASELINE_INVALID");
            ValidateMetadataSource(c, context); deleted = new List<Inode>(); directories = new Dictionary<uint, Inode>();
            int firstGroup = 0; uint firstInode = 0; NormalizeInodeCursor(v, ref firstGroup, ref firstInode);
            var initial = new InodeProgress { VolumeOffset = v.Offset, BaseInodes = c.InodesRead, BaseEntries = c.Report.Entries.Count,
                GroupIndex = firstGroup, NextInode = firstInode, Complete = firstGroup == v.Groups.Count,
                HeaderSha256 = context == null ? null : GroupBytesHash(v.Superblock),
                OverlaySha256 = context == null ? null : GroupOverlayHash(c, v),
                GroupsSha256 = context == null ? null : InodeGroupsHash(c, v), Limits = new JavaScriptSerializer().Serialize(c.Limits) };
            var journal = new RecoveryMethodJournal<InodeProgress>(c.Input.Name, initial, context, c.Cancel);
            InodeProgress state = journal.Payload;
            if (state.Schema != 1 || state.VolumeOffset != initial.VolumeOffset || state.BaseInodes != initial.BaseInodes ||
                state.BaseEntries != initial.BaseEntries || state.HeaderSha256 != initial.HeaderSha256 ||
                state.OverlaySha256 != initial.OverlaySha256 || state.GroupsSha256 != initial.GroupsSha256 || state.Limits != initial.Limits ||
                state.GroupIndex < firstGroup || state.GroupIndex > v.Groups.Count || state.Complete && !state.Limited && state.GroupIndex != v.Groups.Count)
                throw new IOException("EXT4_INODE_CHECKPOINT_INVALID");
            var ledger = new RecoveryOutputLedger<InodeFact>(context, state.Facts,
                (int)Math.Min(Int32.MaxValue, (long)c.Limits.MaximumInodes + 1), c.Cancel,
                RecoveryLedgerScope.MethodOutput, 1024L * 1024 * 1024);
            int group = firstGroup; uint at = firstInode; bool limited = false;
            foreach (InodeFact fact in ledger.Records)
            {
                if (limited || group == v.Groups.Count) throw new IOException("EXT4_INODE_FACT_ORDER_INVALID");
                var payload = ReadMetadataPayload<InodePayload>(context, "inode-blobs", fact.BlobSha256, c.Cancel);
                ApplyInodeUnit(c, v, payload, ref group, ref at, deleted, directories); limited = payload.BudgetStop;
            }
            if (group != state.GroupIndex || at != state.NextInode || limited != state.Limited || limited && !state.Complete)
                throw new IOException("EXT4_INODE_CURSOR_INVALID");
            while (!state.Complete)
            {
                if (group == v.Groups.Count) throw new IOException("EXT4_INODE_COMPLETION_INVALID");
                InodePayload payload = ReadInodeUnit(c, v, group, at);
                int nextGroup = group; uint nextInode = at + (uint)payload.Count;
                NormalizeInodeCursor(v, ref nextGroup, ref nextInode);
                var rows = new List<InodeFact> { new InodeFact { BlobSha256 = context == null ? null :
                    StoreMetadataPayload(context, "inode-blobs", payload, c.Cancel) } };
                var next = AdvanceInodeProgress(state, nextGroup, nextInode, ledger.Append(state.Facts, rows),
                    payload.BudgetStop || nextGroup == v.Groups.Count, payload.BudgetStop);
                journal.Save(next); ledger.Accept(rows); state = next;
                ApplyInodeUnit(c, v, payload, ref group, ref at, deleted, directories);
                if (progress != null) progress("ext4: inode " + c.InodesRead + ", удалённых кандидатов " + deleted.Count);
            }
            if (!journal.Resumed && ledger.Records.Count == 0) journal.Save(state);
        }
    }
}
