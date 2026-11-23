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
        sealed class JournalLoadProgress
        {
            public int Schema = 1, Next;
            public string Identity;
            public bool Complete;
            public RecoveryOutputHead Facts;
        }
        sealed class JournalLoadUnit
        {
            public int Schema = 1;
            public string Kind, Data;
            public ulong Block;
        }
        static string JournalLoadIdentity(Context c, Volume v)
        {
            using (var hash = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,hash,CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream,new UTF8Encoding(false,true)))
            {
                writer.Write("ext4-journal-load-v1"); writer.Write(v.Offset);
                writer.Write(GroupBytesHash(v.Superblock)); writer.Write(GroupOverlayHash(c,v));
                writer.Write(InodeGroupsHash(c,v)); writer.Write(Ext4LimitsIdentity(c.Limits));
                writer.Write(c.Report.Limited); writer.Write(c.Report.Candidates); writer.Write(c.Report.RecoveredFiles);
                writer.Write(c.Report.OutputBytes); writer.Write(c.Report.Entries.Count);
                writer.Write(c.Report.Skipped.Count);
                foreach (var row in c.Report.Skipped.OrderBy(x => x.Key,StringComparer.Ordinal)) { writer.Write(row.Key); writer.Write(row.Value); }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(hash.Hash);
            }
        }
        // The ordinary journal parser is replayed from immutable raw reads.
        // Its inode table, extent/indirect nodes and JBD2 superblock each form
        // one bounded unit. Null/invalid metadata is still the parser's verdict;
        // a missing physical read is an I/O failure, never an absent journal.
        sealed class JournalLoadCheckpoint
        {
            readonly Context c;
            readonly Volume v;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly RecoveryMethodJournal<JournalLoadProgress> journal;
            readonly RecoveryOutputLedger<JournalFact> ledger;
            JournalLoadProgress state;
            int consumed;

            public JournalLoadCheckpoint(Context owner, Volume volume, RecoveryCheckpointContext checkpoint, Action<string> notify)
            {
                c = owner; v = volume; context = checkpoint; progress = notify;
                if (v.JournalLoaded || v.Superblock == null || v.Superblock.Length != 1024 ||
                    v.BlockBytes < 1024 || v.BlockBytes > MaximumJournalUnitBytes || c.Limits.MaximumTreeBlocks < 1)
                    throw new IOException("EXT4_JOURNAL_LOAD_PHASE_INVALID");
                ValidateMetadataSource(c,context); string identity = JournalLoadIdentity(c,v);
                journal = new RecoveryMethodJournal<JournalLoadProgress>(c.Input.Name,new JournalLoadProgress { Identity = identity },context,c.Cancel);
                state = journal.Payload;
                int maximum = (int)Math.Min(Int32.MaxValue,(long)c.Limits.MaximumTreeBlocks+3);
                if (state.Schema != 1 || state.Identity != identity || state.Next < 0 || state.Next > maximum)
                    throw new IOException("EXT4_JOURNAL_LOAD_CHECKPOINT_INVALID");
                ledger = new RecoveryOutputLedger<JournalFact>(context,state.Facts,maximum,c.Cancel,
                    RecoveryLedgerScope.MethodOutput,Math.Max(1024,(long)maximum*1024));
                if (state.Next != ledger.Records.Count || state.Complete != (state.Next != 0 && ReadUnit(state.Next-1).Kind == "end"))
                    throw new IOException("EXT4_JOURNAL_LOAD_CURSOR_INVALID");
            }
            JournalLoadUnit ReadUnit(int index)
            {
                var unit = ReadMetadataPayload<JournalLoadUnit>(context,"journal-blobs",ledger.Records[index].BlobSha256,c.Cancel);
                if (unit == null || unit.Schema != 1 || unit.Kind != "block" && unit.Kind != "end" ||
                    unit.Kind == "end" && (unit.Block != 0 || unit.Data != null))
                    throw new IOException("EXT4_JOURNAL_LOAD_UNIT_INVALID");
                return unit;
            }
            void Append(JournalLoadUnit unit)
            {
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                string blob = StoreMetadataPayload(context,"journal-blobs",unit,c.Cancel);
                var next = new JournalLoadProgress { Identity = state.Identity, Next = state.Next+1, Complete = unit.Kind == "end" };
                var rows = new List<JournalFact> { new JournalFact { BlobSha256 = blob } };
                next.Facts = ledger.Append(state.Facts,rows);
                journal.Save(next); ledger.Accept(rows); state = next;
                if (progress != null) progress("ext4: journal mapping "+state.Next+(next.Complete ? " complete" : ""));
            }
            public byte[] ReadBlock(ulong block)
            {
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                JournalLoadUnit unit;
                if (consumed < state.Next) unit = ReadUnit(consumed);
                else {
                    if (state.Complete || !BlockRange(v,block,1)) throw new IOException("EXT4_JOURNAL_LOAD_BLOCK_INVALID");
                    byte[] data = Block(c,v,block);
                    if (data == null || data.Length != v.BlockBytes) throw new EndOfStreamException("EXT4_JOURNAL_LOAD_SHORT_READ");
                    unit = new JournalLoadUnit { Kind = "block", Block = block, Data = Convert.ToBase64String(data) }; Append(unit);
                }
                if (unit.Kind != "block" || unit.Block != block) throw new IOException("EXT4_JOURNAL_LOAD_READ_ORDER_CHANGED");
                consumed++; return GroupDecode(unit.Data,v.BlockBytes,true);
            }
            public void Finish()
            {
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                if (consumed < state.Next) {
                    if (ReadUnit(consumed).Kind != "end" || consumed+1 != state.Next || !state.Complete)
                        throw new IOException("EXT4_JOURNAL_LOAD_END_INVALID");
                } else Append(new JournalLoadUnit { Kind = "end" });
                c.Cancel.ThrowIfCancellationRequested();
            }
        }
        static JournalContext LoadJournalCheckpointed(Context c, Volume v, RecoveryCheckpointContext context, Action<string> progress)
        {
            if (context == null) return LoadJournal(c,v,v.Superblock);
            using (new MetadataSourceScope(c,context)) {
                var checkpoint = new JournalLoadCheckpoint(c,v,context,progress);
                JournalContext result = LoadJournalWithReader(c,v,v.Superblock,checkpoint.ReadBlock);
                checkpoint.Finish(); return result;
            }
        }
    }
}
