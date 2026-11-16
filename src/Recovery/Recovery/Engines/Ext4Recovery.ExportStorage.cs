using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        static RecoveryCheckpointContext Ext4Child(RecoveryCheckpointContext parent, string name,
            RecoveryMethodCheckpoint anchor, Action<RecoveryMethodCheckpoint> commit)
        {
            if (parent == null) return null;
            if (String.IsNullOrEmpty(name) || name.Length > 128 || name.Split('/').Any(part =>
                part.Length == 0 || part.Any(ch => !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-'))))
                throw new IOException("EXT4_CHILD_NAME_INVALID");
            RecoveryMethodCheckpoint resume = null;
            if (anchor != null)
            {
                if (anchor.Path == null || Path.IsPathRooted(anchor.Path)) throw new IOException("EXT4_CHILD_LINK_INVALID");
                resume = new RecoveryMethodCheckpoint { Path = RecoveryCatalog.SafeFile(parent.Directory, anchor.Path),
                    Sha256 = anchor.Sha256, Sequence = anchor.Sequence };
            }
            string directory = Path.GetDirectoryName(RecoveryCatalog.SafeFile(parent.Directory, "ext4.state/children/" + name + "/guard"));
            return new RecoveryCheckpointContext { Directory = directory, Method = "ext4", SourceSha256 = parent.SourceSha256,
                Settings = GroupBytesHash(Encoding.UTF8.GetBytes(parent.Settings)) + ":" + name, Resume = resume,
                Commit = value => { if (commit == null) throw new IOException("EXT4_CHILD_COMMIT_UNEXPECTED"); commit(RelativeJournalChild(parent, value)); } };
        }

        // Plans bind every public field, including nullable provenance and the
        // final output fields. A new unsupported field type fails closed.
        static string Ext4EntryIdentity(object value, CancellationToken cancel)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            { WriteEntryObject(writer, value, cancel); writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash); }
        }
        static void WriteEntryObject(BinaryWriter writer, object value, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested(); writer.Write(value != null); if (value == null) return;
            Type type = value.GetType();
            if (type != typeof(Entry) && type != typeof(Extent) && type != typeof(NameLink)) throw new IOException("EXT4_ENTRY_TYPE_INVALID");
            writer.Write(type.Name);
            var fields = type.GetFields(BindingFlags.Public | BindingFlags.Instance).OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
            writer.Write(fields.Length);
            foreach (var field in fields)
            {
                cancel.ThrowIfCancellationRequested(); writer.Write(field.Name);
                Type scalar = Nullable.GetUnderlyingType(field.FieldType) ?? field.FieldType;
                if (scalar != typeof(string) && scalar != typeof(bool) && scalar != typeof(uint) && scalar != typeof(long) && scalar != typeof(int) &&
                    scalar != typeof(List<Extent>) && scalar != typeof(List<NameLink>)) throw new IOException("EXT4_ENTRY_FIELD_TYPE_UNSUPPORTED");
                object item = field.GetValue(value);
                writer.Write(item != null); if (item == null) continue;
                if (item is string) { writer.Write((byte)1); writer.Write((string)item); }
                else if (item is bool) { writer.Write((byte)2); writer.Write((bool)item); }
                else if (item is uint) { writer.Write((byte)3); writer.Write((uint)item); }
                else if (item is long) { writer.Write((byte)4); writer.Write((long)item); }
                else if (item is int) { writer.Write((byte)5); writer.Write((int)item); }
                else if (item is List<Extent> || item is List<NameLink>)
                {
                    writer.Write((byte)6); var list = (IList)item; writer.Write(list.Count);
                    foreach (object child in list) WriteEntryObject(writer, child, cancel);
                }
                else throw new IOException("EXT4_ENTRY_FIELD_TYPE_UNSUPPORTED");
            }
        }
        sealed class EntryPlanProgress
        {
            public int Schema = 1, Extents, Names;
            public string Identity, Limits, Manifest;
            public bool Complete;
            public RecoveryOutputHead ExtentHead, NameHead;
        }
        sealed class EntryPlanManifest
        {
            public int Schema = 1, Extents, Names;
            public string Identity;
            public Entry Header;
            public RecoveryOutputHead ExtentHead, NameHead;
        }
        static RecoveryOutputLedger<Extent> EntryExtentLedger(Context c, RecoveryCheckpointContext context, RecoveryOutputHead head)
        { return new RecoveryOutputLedger<Extent>(Ext4Child(context, "extents", null, null), head,
            c.Limits.MaximumExtents, c.Cancel, RecoveryLedgerScope.MethodOutput, Math.Max(1024, (long)c.Limits.MaximumExtents * 1024)); }
        static RecoveryOutputLedger<NameLink> EntryNameLedger(Context c, RecoveryCheckpointContext context, RecoveryOutputHead head)
        { return new RecoveryOutputLedger<NameLink>(Ext4Child(context, "names", null, null), head,
            c.Limits.MaximumNames, c.Cancel, RecoveryLedgerScope.MethodOutput, Math.Max(1024, (long)c.Limits.MaximumNames * 256 * 1024)); }

        static string StoreEntryPlan(Context c, Entry entry, RecoveryCheckpointContext context, Action<string> progress)
        {
            ValidateMetadataSource(c, context);
            if (entry == null || entry.Extents == null || entry.Names == null || entry.Extents.Count > c.Limits.MaximumExtents ||
                entry.Names.Count > c.Limits.MaximumNames || entry.Extents.Any(x => x == null) || entry.Names.Any(x => x == null))
                throw new IOException("EXT4_ENTRY_PLAN_INVALID");
            string identity = Ext4EntryIdentity(entry, c.Cancel), limits = Ext4LimitsIdentity(c.Limits);
            var journal = new RecoveryMethodJournal<EntryPlanProgress>(c.Input.Name,
                new EntryPlanProgress { Identity = identity, Limits = limits }, context, c.Cancel);
            var state = journal.Payload;
            if (state.Schema != 1 || state.Identity != identity || state.Limits != limits || state.Extents < 0 || state.Extents > entry.Extents.Count ||
                state.Names < 0 || state.Names > entry.Names.Count || state.Names != 0 && state.Extents != entry.Extents.Count ||
                state.Complete != (state.Manifest != null) || state.Complete && (state.Extents != entry.Extents.Count || state.Names != entry.Names.Count))
                throw new IOException("EXT4_ENTRY_PLAN_CHECKPOINT_INVALID");
            var extents = EntryExtentLedger(c, context, state.ExtentHead); var names = EntryNameLedger(c, context, state.NameHead);
            if (extents.Records.Count != state.Extents || names.Records.Count != state.Names) throw new IOException("EXT4_ENTRY_PLAN_CURSOR_INVALID");
            for (int i = 0; i < extents.Records.Count; i++)
                if (Ext4EntryIdentity(extents.Records[i], c.Cancel) != Ext4EntryIdentity(entry.Extents[i], c.Cancel)) throw new IOException("EXT4_ENTRY_EXTENTS_CHANGED");
            for (int i = 0; i < names.Records.Count; i++)
                if (Ext4EntryIdentity(names.Records[i], c.Cancel) != Ext4EntryIdentity(entry.Names[i], c.Cancel)) throw new IOException("EXT4_ENTRY_NAMES_CHANGED");
            while (!state.Complete)
            {
                c.Cancel.ThrowIfCancellationRequested(); if (c.CheckpointSource != null) c.CheckpointSource.ValidateLimits();
                var next = new EntryPlanProgress { Identity = identity, Limits = limits, Extents = state.Extents, Names = state.Names,
                    ExtentHead = state.ExtentHead, NameHead = state.NameHead };
                List<Extent> extentRows = null; List<NameLink> nameRows = null;
                if (state.Extents < entry.Extents.Count)
                {
                    extentRows = entry.Extents.Skip(state.Extents).Take(128).ToList(); next.Extents += extentRows.Count;
                    next.ExtentHead = extents.Append(state.ExtentHead, extentRows);
                }
                else if (state.Names < entry.Names.Count)
                {
                    nameRows = entry.Names.Skip(state.Names).Take(128).ToList(); next.Names += nameRows.Count;
                    next.NameHead = names.Append(state.NameHead, nameRows);
                }
                else
                {
                    next.Complete = true; next.Manifest = StoreMetadataPayload(context, "export-blobs", new EntryPlanManifest {
                        Identity = identity, Header = entry.HeaderCopy(), Extents = next.Extents, Names = next.Names,
                        ExtentHead = next.ExtentHead, NameHead = next.NameHead }, c.Cancel);
                }
                journal.Save(next); if (extentRows != null) extents.Accept(extentRows); if (nameRows != null) names.Accept(nameRows); state = next;
                if (progress != null) progress("ext4: entry plan extents " + state.Extents + ", names " + state.Names);
            }
            var restored = ReadEntryPlan(c, context, state.Manifest);
            if (Ext4EntryIdentity(restored, c.Cancel) != identity) throw new IOException("EXT4_ENTRY_PLAN_CHANGED");
            return state.Manifest;
        }
        static Entry ReadEntryPlan(Context c, RecoveryCheckpointContext context, string hash)
        {
            var manifest = ReadMetadataPayload<EntryPlanManifest>(context, "export-blobs", hash, c.Cancel);
            if (manifest.Schema != 1 || manifest.Header == null || manifest.Header.Extents == null || manifest.Header.Extents.Count != 0 ||
                manifest.Header.Names == null || manifest.Header.Names.Count != 0 || manifest.Extents < 0 || manifest.Extents > c.Limits.MaximumExtents ||
                manifest.Names < 0 || manifest.Names > c.Limits.MaximumNames || !GroupDigest(manifest.Identity))
                throw new IOException("EXT4_ENTRY_PLAN_MANIFEST_INVALID");
            var extents = EntryExtentLedger(c, context, manifest.ExtentHead); var names = EntryNameLedger(c, context, manifest.NameHead);
            if (extents.Records.Count != manifest.Extents || names.Records.Count != manifest.Names) throw new IOException("EXT4_ENTRY_PLAN_CURSOR_INVALID");
            var entry = manifest.Header; entry.Extents = extents.Records; entry.Names = names.Records;
            if (Ext4EntryIdentity(entry, c.Cancel) != manifest.Identity) throw new IOException("EXT4_ENTRY_PLAN_CHANGED");
            return entry;
        }
    }
}
