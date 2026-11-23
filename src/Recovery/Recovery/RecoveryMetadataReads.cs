// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    internal static class RecoveryMetadataReads
    {
        internal sealed class Context
        {
            public readonly FileStream Input;
            public readonly CancellationToken Cancel;
            public readonly RecoveryVerifiedImage VerifiedImage;
            public readonly Func<string> LimitsIdentity;
            public readonly Action Validate;
            public Func<long,int,byte[]> MetadataRead;
            public Context(FileStream input, CancellationToken cancel, RecoveryVerifiedImage verified, Func<string> identity, Action validate)
            { Input = input; Cancel = cancel; VerifiedImage = verified; LimitsIdentity = identity; Validate = validate; }
        }
        static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant(); }
        static string HashStream(Stream input, CancellationToken cancel)
        {
            input.Position = 0;
            using (var hash = SHA256.Create()) {
                byte[] bytes = new byte[65536]; int count;
                while ((count = input.Read(bytes,0,bytes.Length)) != 0) { cancel.ThrowIfCancellationRequested(); hash.TransformBlock(bytes,0,count,bytes,0); }
                hash.TransformFinalBlock(new byte[0],0,0); return Hex(hash.Hash);
            }
        }
        const int MetadataUnitBytes = 64*1024, MaximumMetadataRequestBytes = 1024*1024;
        const int MaximumMetadataBlobBytes = 128*1024;
        sealed class MetadataProgress
        {
            public int Schema = 1, Next;
            public string Limits;
            public bool Complete;
            public RecoveryOutputHead Facts;
        }
        sealed class MetadataFact { public string Sha256; }
        sealed class MetadataUnit
        {
            public int Schema = 1, Request, RequestBytes, At;
            public long Offset;
            public bool End;
            public string Data;
        }
        static bool MetadataDigest(string value)
        { return value != null && value.Length == 64 && value.All(ch => ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f'); }
        static string MetadataHash(byte[] bytes)
        { using (var hash = SHA256.Create()) return Hex(hash.ComputeHash(bytes)); }
        static string MetadataBlob(RecoveryCheckpointContext context,string digest)
        {
            if (!MetadataDigest(digest)) throw new IOException("METADATA_BLOB_INVALID");
            return RecoveryLongPath.FileName(RecoveryCatalog.SafeFile(context.Directory,context.Method+".state/metadata-blobs/blob-"+digest+".json"));
        }
        static string SaveMetadataUnit(RecoveryCheckpointContext context,MetadataUnit unit,Context c)
        {
            byte[] bytes = new UTF8Encoding(false,true).GetBytes(new JavaScriptSerializer { MaxJsonLength = MaximumMetadataBlobBytes }.Serialize(unit));
            if (bytes.Length > MaximumMetadataBlobBytes) throw new IOException("METADATA_BLOB_LIMIT");
            string digest = MetadataHash(bytes),path = MetadataBlob(context,digest);
            RecoveryLongPath.CreateDirectory(Path.GetDirectoryName(path)); c.Cancel.ThrowIfCancellationRequested();
            if (!File.Exists(path)) {
                string temp = RecoveryLongPath.FileName(Path.Combine(Path.GetDirectoryName(path),Guid.NewGuid().ToString("N")+".partial")); bool own = false;
                try {
                    using (var file = new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
                    { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
                    c.Cancel.ThrowIfCancellationRequested(); RecoveryLongPath.Move(temp,path);
                } finally { if (own && File.Exists(temp)) File.Delete(temp); }
            }
            using (var guard = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
                if (guard.Length != bytes.Length || HashStream(guard,c.Cancel) != digest) throw new IOException("METADATA_BLOB_CHANGED");
            return digest;
        }
        static MetadataUnit LoadMetadataUnit(RecoveryCheckpointContext context,string digest,Context c)
        {
            string path = MetadataBlob(context,digest);
            using (var guard = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                if (guard.Length < 1 || guard.Length > MaximumMetadataBlobBytes || HashStream(guard,c.Cancel) != digest)
                    throw new IOException("METADATA_BLOB_CHANGED");
                try {
                    return new JavaScriptSerializer { MaxJsonLength = MaximumMetadataBlobBytes }
                        .Deserialize<MetadataUnit>(File.ReadAllText(path,new UTF8Encoding(false,true)));
                } catch (ArgumentException) { throw new IOException("METADATA_BLOB_INVALID"); }
                  catch (InvalidOperationException) { throw new IOException("METADATA_BLOB_INVALID"); }
            }
        }

        // Deterministic parser replay consumes saved raw reads in their exact
        // order. An acknowledged unit never needs another source read. This
        // class does not resume output copying or certify filesystem metadata;
        // the existing checksum/geometry parsers still make those decisions.
        internal sealed class MetadataReadCheckpoint : IDisposable
        {
            readonly Context c;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly RecoveryMethodJournal<MetadataProgress> journal;
            readonly RecoveryOutputLedger<MetadataFact> ledger;
            readonly FileStream lease;
            readonly RecoveryVerifiedImage verifiedImage;
            readonly string limits;
            readonly Func<long,int,byte[]> reader;
            MetadataProgress state;
            int consumed,request;
            bool finished,disposed;

            public MetadataReadCheckpoint(Context owner,RecoveryCheckpointContext checkpoint,Action<string> notify)
            {
                c = owner; context = checkpoint; progress = notify;
                if (context == null || !RecoveryStageFiles.Keys.Contains(context.Method) || c.Input == null || c.Input.CanWrite || c.MetadataRead != null)
                    throw new IOException("METADATA_CONTEXT_INVALID");
                limits = c.LimitsIdentity();
                string source = Path.GetFullPath(c.Input.Name),stateRoot = Path.GetDirectoryName(MetadataBlob(context,new string('0',64)));
                stateRoot = Path.GetDirectoryName(stateRoot);
                if (source.Equals(stateRoot,StringComparison.OrdinalIgnoreCase) || source.StartsWith(stateRoot+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
                    throw new IOException("METADATA_SOURCE_IN_STATE");
                verifiedImage = c.VerifiedImage;
                if (verifiedImage == null) lease = new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read);
                try {
                    if (!MetadataDigest((context.SourceSha256 ?? "").ToLowerInvariant()))
                        throw new IOException("METADATA_SOURCE_CHANGED");
                    if (verifiedImage != null) verifiedImage.Validate(c.Input,context.SourceSha256);
                    else if (!String.Equals(HashStream(lease,c.Cancel),context.SourceSha256,StringComparison.OrdinalIgnoreCase)) throw new IOException("METADATA_SOURCE_CHANGED");
                    journal = new RecoveryMethodJournal<MetadataProgress>(source,new MetadataProgress { Limits = limits },context,c.Cancel); state = journal.Payload;
                    if (state.Schema != 1 || state.Limits != limits || state.Next < 0 || journal.Resumed && state.Next == 0)
                        throw new IOException("METADATA_CHECKPOINT_INVALID");
                    ledger = new RecoveryOutputLedger<MetadataFact>(context,state.Facts,2000000,c.Cancel,
                        RecoveryLedgerScope.MethodOutput,512L*1024*1024);
                    if (state.Next != ledger.Records.Count || state.Complete != (state.Next != 0 && Unit(state.Next-1).End))
                        throw new IOException("METADATA_CURSOR_INVALID");
                    reader = ReadBytes; c.MetadataRead = reader;
                } catch { if (lease != null) lease.Dispose(); throw; }
            }
            void Guard()
            {
                c.Cancel.ThrowIfCancellationRequested(); if (c.Validate != null) c.Validate();
                if (disposed || c.LimitsIdentity() != limits || c.MetadataRead != reader || c.VerifiedImage != verifiedImage)
                    throw new IOException("METADATA_CONTEXT_CHANGED");
                if (verifiedImage != null) verifiedImage.Validate(c.Input,context.SourceSha256);
            }
            MetadataUnit Unit(int index)
            {
                var unit = LoadMetadataUnit(context,ledger.Records[index].Sha256,c);
                if (unit == null || unit.Schema != 1 || unit.Request < 0 || unit.RequestBytes < 0 || unit.At < 0 ||
                    unit.End && (unit.Offset != 0 || unit.RequestBytes != 0 || unit.At != 0 || unit.Data != null))
                    throw new IOException("METADATA_UNIT_INVALID");
                return unit;
            }
            void Append(MetadataUnit unit)
            {
                Guard(); var rows = new List<MetadataFact> { new MetadataFact { Sha256 = SaveMetadataUnit(context,unit,c) } };
                var next = new MetadataProgress { Limits = limits, Next = state.Next+1, Complete = unit.End, Facts = ledger.Append(state.Facts,rows) };
                journal.Save(next); ledger.Accept(rows); state = next;
                if (progress != null) progress(context.Method+": metadata unit "+state.Next+(unit.End ? " complete" : ""));
            }
            byte[] Physical(long offset,int count)
            {
                byte[] bytes = new byte[count]; c.Input.Position = offset; int done = 0;
                while (done < count) { Guard(); int n = c.Input.Read(bytes,done,count-done); if (n == 0) throw new EndOfStreamException("METADATA_SHORT_READ"); done += n; }
                return bytes;
            }
            public byte[] ReadBytes(long offset,int bytes)
            {
                Guard(); if (finished) throw new IOException("METADATA_ALREADY_FINISHED");
                if (offset < 0 || bytes <= 0 || offset > c.Input.Length-bytes) return null;
                if (bytes > MaximumMetadataRequestBytes) throw new IOException("METADATA_REQUEST_LIMIT");
                byte[] result = new byte[bytes];
                for (int at = 0; at < bytes;) {
                    Guard(); int count = Math.Min(MetadataUnitBytes,bytes-at); MetadataUnit unit;
                    if (consumed < state.Next) unit = Unit(consumed);
                    else {
                        if (state.Complete) throw new IOException("METADATA_READ_AFTER_END");
                        unit = new MetadataUnit { Request = request, Offset = offset, RequestBytes = bytes, At = at,
                            Data = Convert.ToBase64String(Physical(offset+at,count)) }; Append(unit);
                    }
                    if (unit.End || unit.Request != request || unit.Offset != offset || unit.RequestBytes != bytes || unit.At != at)
                        throw new IOException("METADATA_READ_ORDER_CHANGED");
                    byte[] data;
                    try { data = Convert.FromBase64String(unit.Data ?? ""); } catch (FormatException) { throw new IOException("METADATA_BYTES_INVALID"); }
                    if (data.Length != count) throw new IOException("METADATA_BYTES_INVALID");
                    Buffer.BlockCopy(data,0,result,at,count); consumed++; at += count;
                }
                Guard(); request++; return result;
            }
            public void Finish()
            {
                Guard(); if (finished) throw new IOException("METADATA_ALREADY_FINISHED");
                if (consumed < state.Next) {
                    var unit = Unit(consumed);
                    if (!unit.End || unit.Request != request || consumed+1 != state.Next || !state.Complete)
                        throw new IOException("METADATA_END_INVALID");
                } else Append(new MetadataUnit { End = true, Request = request });
                Guard(); finished = true;
            }
            public void Dispose()
            { if (disposed) return; disposed = true; c.MetadataRead = null; if (lease != null) lease.Dispose(); }
        }
    }
}
