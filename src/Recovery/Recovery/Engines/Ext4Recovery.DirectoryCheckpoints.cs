using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class DirectoryProgress
        {
            public int Schema = 1, Next;
            public string Identity, Header, Overlay, Groups, Limits;
            public bool Complete;
            public RecoveryOutputHead Facts;
        }
        sealed class DirectoryUnit
        {
            public int Schema = 1, Number, HistoryIndex = -1;
            public string Kind, Data;
            public uint Directory;
            public ulong Block;
            public int FinalDirectories, FinalNames;
            public long FinalBytes;
            public bool FinalLimited;
        }

        // Replay the same parser from immutable raw metadata. Mapping nodes are
        // units too: cancelling a large indirect/extent tree must not reread its
        // acknowledged prefix. Rebuilding names and paths does no source I/O.
        sealed class DirectoryNameCheckpoint
        {
            readonly Context c;
            readonly Volume v;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly RecoveryMethodJournal<DirectoryProgress> journal;
            readonly RecoveryOutputLedger<JournalFact> ledger;
            DirectoryProgress state;
            int consumed;

            public DirectoryNameCheckpoint(Context owner, Volume volume, Dictionary<uint, Inode> directories,
                List<JournalDirectoryBlock> history, RecoveryCheckpointContext checkpoint, Action<string> notify)
            {
                c = owner; v = volume; context = checkpoint; progress = notify;
                if (v.BlockBytes < 1024 || v.BlockBytes > MaximumJournalUnitBytes || v.Superblock == null ||
                    v.Superblock.Length != 1024 || c.DirectoryCount < 0 || c.DirectoryCount > c.Limits.MaximumDirectories ||
                    c.NameCount < 0 || c.NameCount > c.Limits.MaximumNames || c.DirectoryBytes < 0 ||
                    c.DirectoryBytes > c.Limits.MaximumDirectoryBytes)
                    throw new IOException("EXT4_DIRECTORY_BASELINE_INVALID");
                ValidateMetadataSource(c, context);
                var initial = new DirectoryProgress { Identity = DirectoryInputsHash(c, v, directories, history),
                    Header = GroupBytesHash(v.Superblock), Overlay = GroupOverlayHash(c, v), Groups = InodeGroupsHash(c, v),
                    Limits = Ext4LimitsIdentity(c.Limits) };
                journal = new RecoveryMethodJournal<DirectoryProgress>(c.Input.Name, initial, context, c.Cancel);
                state = journal.Payload;
                if (state.Schema != 1 || state.Next < 0 || state.Identity != initial.Identity || state.Header != initial.Header ||
                    state.Overlay != initial.Overlay || state.Groups != initial.Groups || state.Limits != initial.Limits)
                    throw new IOException("EXT4_DIRECTORY_CHECKPOINT_INVALID");
                long count = Math.Min(directories.Count, c.Limits.MaximumDirectories - c.DirectoryCount);
                long data = Math.Min((c.Limits.MaximumDirectoryBytes - c.DirectoryBytes) / v.BlockBytes,
                    count * (64L * 1024 * 1024 / v.BlockBytes));
                int maximum = (int)Math.Min(Int32.MaxValue, 1 + count * (1L + c.Limits.MaximumTreeBlocks) + data +
                    (history == null ? 0 : history.Count));
                ledger = new RecoveryOutputLedger<JournalFact>(context, state.Facts, maximum, c.Cancel,
                    RecoveryLedgerScope.MethodOutput, Math.Max(1024, (long)maximum * 1024));
                if (state.Next != ledger.Records.Count || state.Complete !=
                    (state.Next != 0 && ReadUnit(state.Next - 1).Kind == "end"))
                    throw new IOException("EXT4_DIRECTORY_CURSOR_INVALID");
            }
            DirectoryUnit ReadUnit(int index)
            {
                var fact = ledger.Records[index];
                var unit = ReadMetadataPayload<DirectoryUnit>(context, "directory-blobs", fact.BlobSha256, c.Cancel);
                if (unit.Schema != 1 || unit.Number != index || unit.Kind != "directory" && unit.Kind != "map" &&
                    unit.Kind != "data" && unit.Kind != "history" && unit.Kind != "end")
                    throw new IOException("EXT4_DIRECTORY_UNIT_INVALID");
                return unit;
            }
            byte[] Capture(DirectoryUnit expected, Func<byte[]> read, int length)
            {
                c.Cancel.ThrowIfCancellationRequested(); expected.Number = consumed;
                DirectoryUnit unit; byte[] bytes;
                if (consumed < ledger.Records.Count)
                {
                    unit = ReadUnit(consumed);
                    if (unit.Kind != expected.Kind || unit.Directory != expected.Directory || unit.Block != expected.Block ||
                        unit.HistoryIndex != expected.HistoryIndex || unit.FinalDirectories != expected.FinalDirectories ||
                        unit.FinalNames != expected.FinalNames || unit.FinalBytes != expected.FinalBytes ||
                        unit.FinalLimited != expected.FinalLimited)
                        throw new IOException("EXT4_DIRECTORY_UNIT_ORDER_INVALID");
                    bytes = GroupDecode(unit.Data, Math.Max(0, length), length >= 0);
                    if (length < 0 && bytes != null) throw new IOException("EXT4_DIRECTORY_UNIT_INVALID");
                }
                else
                {
                    if (state.Complete) throw new IOException("EXT4_DIRECTORY_COMPLETION_INVALID");
                    bytes = read == null ? null : read();
                    if (length >= 0 && (bytes == null || bytes.Length != length))
                        throw new EndOfStreamException("EXT4_DIRECTORY_SHORT_READ");
                    c.Cancel.ThrowIfCancellationRequested(); unit = expected;
                    unit.Data = bytes == null ? null : Convert.ToBase64String(bytes);
                    var rows = new List<JournalFact> { new JournalFact {
                        BlobSha256 = StoreMetadataPayload(context, "directory-blobs", unit, c.Cancel) } };
                    var next = new DirectoryProgress { Identity = state.Identity, Header = state.Header, Overlay = state.Overlay,
                        Groups = state.Groups, Limits = state.Limits, Next = consumed + 1, Complete = unit.Kind == "end",
                        Facts = ledger.Append(state.Facts, rows) };
                    journal.Save(next); ledger.Accept(rows); state = next;
                    if (progress != null) progress("ext4: directory metadata unit " + state.Next + " (" + unit.Kind + ")");
                }
                consumed++; return bytes;
            }
            public void StartDirectory(uint number)
            { Capture(new DirectoryUnit { Kind = "directory", Directory = number }, null, -1); }
            public byte[] ReadBlock(string kind, uint directory, ulong block)
            {
                return Capture(new DirectoryUnit { Kind = kind, Directory = directory, Block = block },
                    () => Block(c, v, block), v.BlockBytes);
            }
            public byte[] HistoryBlock(int index, JournalDirectoryBlock block)
            {
                byte[] bytes = Capture(new DirectoryUnit { Kind = "history", HistoryIndex = index, Block = block.JournalBlock },
                    () => block.Bytes, block.Bytes == null ? -1 : block.Bytes.Length);
                if (bytes != null && !bytes.SequenceEqual(block.Bytes)) throw new IOException("EXT4_DIRECTORY_HISTORY_CHANGED");
                return bytes;
            }
            public void Finish()
            {
                Capture(new DirectoryUnit { Kind = "end", FinalDirectories = c.DirectoryCount,
                    FinalNames = c.NameCount, FinalBytes = c.DirectoryBytes, FinalLimited = c.Report.Limited }, null, -1);
                if (consumed != ledger.Records.Count) throw new IOException("EXT4_DIRECTORY_TRAILING_UNITS");
            }
        }

        static string DirectoryInputsHash(Context c, Volume v, Dictionary<uint, Inode> directories,
            List<JournalDirectoryBlock> history)
        {
            using (var sha = SHA256.Create())
            using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            {
                writer.Write(v.Offset); writer.Write(v.BlockBytes); writer.Write(v.Inodes); writer.Write(v.Incompat);
                writer.Write(v.Csum); writer.Write(c.DirectoryCount); writer.Write(c.NameCount); writer.Write(c.DirectoryBytes);
                writer.Write(c.Report.Limited); writer.Write(c.Report.Skipped.Count);
                foreach (var pair in c.Report.Skipped.OrderBy(x => x.Key, StringComparer.Ordinal))
                { writer.Write(pair.Key); writer.Write(pair.Value); }
                writer.Write(directories.Count);
                foreach (var pair in directories)
                {
                    c.Cancel.ThrowIfCancellationRequested(); Inode inode = pair.Value;
                    if (inode == null || pair.Key != inode.Number || inode.Bytes == null || inode.Bytes.Length != v.InodeBytes)
                        throw new IOException("EXT4_DIRECTORY_INPUT_INVALID");
                    writer.Write(inode.Number); writer.Write(inode.Generation); writer.Write(inode.Flags); writer.Write(inode.Dtime);
                    writer.Write(inode.Mode); writer.Write(inode.Links); writer.Write(inode.Offset); writer.Write(inode.Size);
                    writer.Write(inode.Allocated); writer.Write(inode.Bytes.Length); writer.Write(inode.Bytes);
                }
                writer.Write(history == null ? -1 : history.Count);
                if (history != null) foreach (var block in history)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    if (block == null || !BlockRange(v, block.JournalBlock, 1) || !BlockRange(v, block.TargetDiskBlock, 1) ||
                        block.Bytes != null && block.Bytes.Length > v.BlockBytes)
                        throw new IOException("EXT4_DIRECTORY_HISTORY_INVALID");
                    writer.Write(block.TargetDiskBlock); writer.Write(block.JournalBlock); writer.Write(block.TransactionSequence);
                    writer.Write(block.Bytes == null ? -1 : block.Bytes.Length);
                    if (block.Bytes != null) writer.Write(block.Bytes);
                }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static Dictionary<uint, List<NameLink>> DirectoryNamesCheckpointed(Context c, Volume v, Dictionary<uint, Inode> directories,
            List<JournalDirectoryBlock> history, RecoveryCheckpointContext context, Action<string> progress)
        {
            if (context == null) return DirectoryNames(c, v, directories, history);
            using (new MetadataSourceScope(c, context))
            {
                var checkpoint = new DirectoryNameCheckpoint(c, v, directories, history, context, progress);
                var names = DirectoryNamesCore(c, v, directories, history, checkpoint);
                checkpoint.Finish(); return names;
            }
        }
    }
}
