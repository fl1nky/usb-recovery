// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    internal sealed class RecoveryNativeNtfsRecord
    {
        public long Ordinal;
        public uint Sequence, Flags, Percent, Streams;
        public string Name, Parent;
    }
    internal sealed class RecoveryNativeNtfsRun
    { public long Vcn, Lcn, Clusters; }
    internal sealed class RecoveryNativeNtfsStream
    {
        public long Ordinal, Length, Allocated, Initialized;
        public uint Index, Flags, Percent;
        public string Name;
        public byte[] Resident;
        public List<RecoveryNativeNtfsRun> Runs = new List<RecoveryNativeNtfsRun>();
    }

    // Validates typed worker messages before the parent may acknowledge them.
    // Source text is metadata only; names are never interpreted as host paths.
    internal sealed class RecoveryNativeNtfsPlans
    {
        internal const long MaximumRecords = 2000000;
        readonly long sourceBytes, volumeOffset, volumeBytes, start;
        readonly int sector;
        bool hello, layout, done, failed;
        RecoveryNativeNtfsRecord current;
        uint streams;
        internal long NextOrdinal { get; private set; }
        internal long Records { get; private set; }
        internal int ClusterBytes { get; private set; }
        internal int RecordBytes { get; private set; }

        internal RecoveryNativeNtfsPlans(long sourceLength, long offset, long length, long ordinal, int sectorBytes)
        {
            if (sourceLength < 512 || offset < 0 || length < 512 || offset > sourceLength - length ||
                ordinal < 0 || ordinal > MaximumRecords ||
                sectorBytes != 512 && sectorBytes != 1024 && sectorBytes != 2048 && sectorBytes != 4096 ||
                offset % sectorBytes != 0 || length % sectorBytes != 0)
                throw new IOException("NATIVE_NTFS_CONTEXT_INVALID");
            sourceBytes = sourceLength; volumeOffset = offset; volumeBytes = length;
            start = ordinal; sector = sectorBytes; NextOrdinal = ordinal;
        }
        IOException Error() { failed = true; return new IOException("NATIVE_NTFS_PLAN_INVALID"); }

        sealed class Payload
        {
            readonly byte[] data;
            int at;
            internal Payload(byte[] bytes) { data = bytes; }
            internal uint U32()
            {
                if (data == null || at > data.Length - 4) throw new IOException("NATIVE_NTFS_PAYLOAD_INVALID");
                uint n = (uint)(data[at] | (uint)data[at+1] << 8 | (uint)data[at+2] << 16 | (uint)data[at+3] << 24);
                at += 4; return n;
            }
            internal ulong U64() { ulong low = U32(); return low | (ulong)U32() << 32; }
            internal long Size()
            {
                ulong n = U64(); if (n > Int64.MaxValue) throw new IOException("NATIVE_NTFS_PAYLOAD_INVALID");
                return (long)n;
            }
            internal byte[] Bytes(int maximum)
            {
                uint n = U32();
                if (n > maximum || n > data.Length - at) throw new IOException("NATIVE_NTFS_PAYLOAD_INVALID");
                var result = new byte[(int)n]; Buffer.BlockCopy(data, at, result, 0, (int)n); at += (int)n;
                return result;
            }
            internal string Text()
            {
                string text;
                try { text = new UTF8Encoding(false, true).GetString(Bytes(16384)); }
                catch (DecoderFallbackException) { throw new IOException("NATIVE_NTFS_TEXT_INVALID"); }
                if (text.IndexOf('\0') >= 0) throw new IOException("NATIVE_NTFS_TEXT_INVALID");
                return text;
            }
            internal void End() { if (data == null || at != data.Length) throw new IOException("NATIVE_NTFS_PAYLOAD_INVALID"); }
        }

        // Returns a typed record/stream, an absolute read range, or null for a
        // validated control message. State is terminal after any invalid input.
        internal object Accept(RecoveryNativeMessage message)
        {
            if (failed || done || message == null || message.Payload == null) throw Error();
            try { return Decode(message); }
            catch (IOException) { failed = true; throw; }
            catch (OverflowException) { throw Error(); }
        }
        object Decode(RecoveryNativeMessage message)
        {
            var p = new Payload(message.Payload);
            if (!hello) {
                if (message.Kind != RecoveryNativeKind.Hello || p.Size() != sourceBytes ||
                    p.Size() != volumeOffset || p.Size() != volumeBytes || p.Size() != start ||
                    p.U32() != sector || p.U32() != 1) throw Error();
                p.End(); hello = true; return null;
            }
            if (message.Kind == RecoveryNativeKind.Read) {
                long offset = p.Size(); uint length = p.U32(); p.End();
                if (length == 0 || length > RecoveryNativeProtocol.MaximumPayload || offset < volumeOffset ||
                    offset > volumeOffset + volumeBytes - length) throw Error();
                return new RecoveryMappedRange { ImageOffset = offset, Length = length };
            }
            if (message.Kind == RecoveryNativeKind.Snapshot) {
                if (layout || current != null) throw Error();
                long count = p.Size(); uint cluster = p.U32(), record = p.U32(), bytes = p.U32(), profile = p.U32(); p.End();
                if (count > MaximumRecords || count < start || count == 0 ||
                    cluster < sector || cluster > 2 * 1024 * 1024 || (cluster & (cluster - 1)) != 0 ||
                    cluster % sector != 0 || cluster > volumeBytes || record < sector || record > 65536 ||
                    (record & (record - 1)) != 0 || record % sector != 0 || bytes != sector || profile != 1)
                    throw Error();
                Records = count; ClusterBytes = (int)cluster; RecordBytes = (int)record; layout = true; return null;
            }
            if (!layout) throw Error();
            if (message.Kind == RecoveryNativeKind.Record) {
                if (current != null || NextOrdinal >= Records || p.U32() != 1) throw Error();
                var record = new RecoveryNativeNtfsRecord { Ordinal = p.Size(), Sequence = p.U32(), Flags = p.U32(),
                    Percent = p.U32(), Streams = p.U32(), Name = p.Text(), Parent = p.Text() }; p.End();
                if (record.Ordinal != NextOrdinal || record.Sequence > UInt16.MaxValue || record.Flags > UInt16.MaxValue ||
                    (record.Flags & 1) != 0 || record.Percent == 0 || record.Percent > 100 || record.Streams > 4096) throw Error();
                streams = 0; current = record; return record;
            }
            if (message.Kind == RecoveryNativeKind.Stream) {
                if (current == null || streams >= current.Streams) throw Error();
                var stream = new RecoveryNativeNtfsStream { Ordinal = p.Size(), Index = p.U32(), Flags = p.U32(),
                    Length = p.Size(), Allocated = p.Size(), Initialized = p.Size(), Percent = p.U32(), Name = p.Text() };
                if (stream.Ordinal != current.Ordinal || stream.Index != streams || stream.Flags > 7 ||
                    stream.Percent > 100 || stream.Initialized > stream.Length) throw Error();
                if ((stream.Flags & 1) != 0) {
                    stream.Resident = p.Bytes(RecordBytes);
                    if (stream.Resident.LongLength != stream.Length) throw Error();
                } else {
                    uint count = p.U32(); if (count > 32768) throw Error(); long next = 0;
                    for (uint i = 0; i < count; i++) {
                        long vcn = p.Size(), lcn = unchecked((long)p.U64()), length = p.Size();
                        if (vcn != next || length == 0 || length > Int64.MaxValue / ClusterBytes - next || lcn < -2 ||
                            lcn >= 0 && (lcn > volumeBytes / ClusterBytes || length > volumeBytes / ClusterBytes - lcn)) throw Error();
                        stream.Runs.Add(new RecoveryNativeNtfsRun { Vcn = vcn, Lcn = lcn, Clusters = length }); next += length;
                    }
                    // An incomplete run list is retained as an explicit damaged
                    // candidate. It must never be silently padded as intact data.
                }
                p.End(); streams++; return stream;
            }
            if (message.Kind == RecoveryNativeKind.EndRecord) {
                long next = p.Size(); uint outcome = p.U32(); p.End();
                if (NextOrdinal >= Records || next != NextOrdinal + 1 || outcome > 2 ||
                    current != null && (outcome != 2 || streams != current.Streams)) throw Error();
                current = null; streams = 0; NextOrdinal = next; return null;
            }
            if (message.Kind == RecoveryNativeKind.Done) {
                p.End(); if (current != null || NextOrdinal != Records) throw Error(); done = true; return null;
            }
            throw Error();
        }
    }
}
