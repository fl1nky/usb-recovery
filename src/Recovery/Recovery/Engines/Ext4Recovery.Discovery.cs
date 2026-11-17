using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        const int MaximumDiscoveryEntries = 16384, MaximumDiscoveryLocations = MaximumDiscoveryEntries+5;
        sealed class DiscoveryProgress
        {
            public int Schema = 1, Phase;
            public uint Next;
            public bool Complete;
            public string Limits;
            public RecoveryOutputHead Facts;
        }
        sealed class DiscoveryUnit
        {
            public int Schema = 1, Count;
            public long Offset;
            public uint Start;
            public string Kind, Data;
        }
        sealed class DiscoveryCursor
        {
            public int Phase;
            public uint Next, Count, EntryBytes;
            public long Table;
            public bool Complete;
            public readonly List<long> Locations = new List<long> { 0 };
        }
        static void ApplyDiscoveryUnit(Context c, DiscoveryCursor cursor, DiscoveryUnit unit)
        {
            if (unit == null || unit.Schema != 1 || cursor.Complete || unit.Start != cursor.Next)
                throw new IOException("EXT4_DISCOVERY_UNIT_INVALID");
            if (cursor.Phase == 0)
            {
                if (unit.Kind != "mbr" || unit.Offset != 0 || unit.Count != 0) throw new IOException("EXT4_DISCOVERY_MBR_INVALID");
                byte[] bytes = GroupDecode(unit.Data,c.Input.Length < 512 ? 0 : 512,c.Input.Length >= 512);
                cursor.Phase = 3;
                if (bytes == null || bytes.Length == 0 || U16(bytes,510) != 0xaa55) return;
                for (int i = 0; i < 4; i++) {
                    long offset = (long)U32(bytes,446+i*16+8)*512;
                    if (offset > 0 && offset <= c.Input.Length-2048) cursor.Locations.Add(offset);
                }
                cursor.Phase = 1; return;
            }
            if (cursor.Phase == 1)
            {
                if (unit.Kind != "gpt" || unit.Offset != 512 || unit.Count != 0) throw new IOException("EXT4_DISCOVERY_GPT_INVALID");
                byte[] bytes = GroupDecode(unit.Data,c.Input.Length < 1024 ? 0 : 512,c.Input.Length >= 1024);
                cursor.Phase = 3;
                if (bytes == null || bytes.Length == 0 || Encoding.ASCII.GetString(bytes,0,8) != "EFI PART") return;
                ulong table = U64(bytes,72); uint count = U32(bytes,80),size = U32(bytes,84);
                if (table > (ulong)(c.Input.Length/512) || count > MaximumDiscoveryEntries || size < 128 || size > 4096 ||
                    (ulong)count*size > (ulong)c.Input.Length-table*512) return;
                cursor.Table = (long)table*512; cursor.Count = count; cursor.EntryBytes = size;
                if (count != 0) cursor.Phase = 2; return;
            }
            if (cursor.Phase == 2)
            {
                int count = (int)Math.Min(cursor.Count-cursor.Next,MaximumJournalUnitBytes/cursor.EntryBytes);
                long offset = cursor.Table+(long)cursor.Next*cursor.EntryBytes;
                if (unit.Kind != "entries" || unit.Count != count || unit.Offset != offset || count < 1)
                    throw new IOException("EXT4_DISCOVERY_ENTRIES_INVALID");
                byte[] bytes = GroupDecode(unit.Data,checked(count*(int)cursor.EntryBytes),true);
                for (int index = 0; index < count; index++) {
                    int at = index*(int)cursor.EntryBytes; ulong lba = U64(bytes,at+32);
                    bool used = false; for (int b = 0; b < 16; b++) used |= bytes[at+b] != 0;
                    if (used && lba > 0 && c.Input.Length >= 2048 && lba <= (ulong)((c.Input.Length-2048)/512))
                        cursor.Locations.Add((long)lba*512);
                }
                cursor.Next += (uint)count; if (cursor.Next == cursor.Count) cursor.Phase = 3; return;
            }
            if (cursor.Phase != 3 || unit.Kind != "end" || unit.Offset != 0 || unit.Count != 0 || unit.Data != null)
                throw new IOException("EXT4_DISCOVERY_END_INVALID");
            cursor.Complete = true;
        }
        static DiscoveryUnit ReadDiscoveryUnit(Context c,DiscoveryCursor cursor)
        {
            var unit = new DiscoveryUnit { Start = cursor.Next }; int bytes = 0;
            switch (cursor.Phase) {
                case 0: unit.Kind = "mbr"; bytes = c.Input.Length < 512 ? 0 : 512; break;
                case 1: unit.Kind = "gpt"; unit.Offset = 512; bytes = c.Input.Length < 1024 ? 0 : 512; break;
                case 2:
                    unit.Kind = "entries"; unit.Offset = cursor.Table+(long)cursor.Next*cursor.EntryBytes;
                    unit.Count = (int)Math.Min(cursor.Count-cursor.Next,MaximumJournalUnitBytes/cursor.EntryBytes);
                    bytes = checked(unit.Count*(int)cursor.EntryBytes); break;
                case 3: unit.Kind = "end"; break;
                default: throw new IOException("EXT4_DISCOVERY_PHASE_INVALID");
            }
            if (bytes != 0) {
                byte[] data = Read(c,unit.Offset,bytes);
                if (data == null || data.Length != bytes) throw new EndOfStreamException("EXT4_DISCOVERY_SHORT_READ");
                unit.Data = Convert.ToBase64String(data);
            }
            return unit;
        }
        static List<long> DiscoverCheckpointed(Context c,RecoveryCheckpointContext context,Action<string> progress)
        {
            using (new MetadataSourceScope(c,context)) {
                ValidateMetadataSource(c,context);
                string limits = Ext4LimitsIdentity(c.Limits);
                var journal = new RecoveryMethodJournal<DiscoveryProgress>(c.Input.Name,new DiscoveryProgress { Limits = limits },context,c.Cancel);
                var state = journal.Payload;
                if (state.Schema != 1 || state.Limits != limits || state.Phase < 0 || state.Phase > 3 || state.Next > MaximumDiscoveryEntries || state.Complete && state.Phase != 3)
                    throw new IOException("EXT4_DISCOVERY_CHECKPOINT_INVALID");
                var ledger = new RecoveryOutputLedger<JournalFact>(context,state.Facts,MaximumDiscoveryEntries/16+3,c.Cancel,
                    RecoveryLedgerScope.MethodOutput,4L*1024*1024);
                var cursor = new DiscoveryCursor();
                foreach (var row in ledger.Records)
                    ApplyDiscoveryUnit(c,cursor,ReadMetadataPayload<DiscoveryUnit>(context,"group-blobs",row.BlobSha256,c.Cancel));
                if (cursor.Phase != state.Phase || cursor.Next != state.Next || cursor.Complete != state.Complete)
                    throw new IOException("EXT4_DISCOVERY_CURSOR_INVALID");
                while (!cursor.Complete) {
                    c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                    var unit = ReadDiscoveryUnit(c,cursor); ApplyDiscoveryUnit(c,cursor,unit);
                    var rows = new List<JournalFact> { new JournalFact { BlobSha256 = StoreMetadataPayload(context,"group-blobs",unit,c.Cancel) } };
                    var next = new DiscoveryProgress { Limits = limits, Phase = cursor.Phase, Next = cursor.Next, Complete = cursor.Complete,
                        Facts = ledger.Append(state.Facts,rows) };
                    journal.Save(next); ledger.Accept(rows); state = next;
                    if (progress != null) progress("ext4: partition metadata "+ledger.Records.Count+(cursor.Complete ? " complete" : ""));
                }
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                return cursor.Locations.Distinct().ToList();
            }
        }
    }
}
