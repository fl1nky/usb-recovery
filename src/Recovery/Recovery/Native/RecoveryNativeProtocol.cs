// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Threading;

namespace UsbRecovery
{
    internal enum RecoveryNativeKind : byte
    {
        Hello = 1, Read = 2, Bytes = 3, Record = 4, Stream = 5,
        EndRecord = 6, Ack = 7, Done = 8, Fail = 9, Cancel = 10,
        Snapshot = 11, Output = 12
    }

    internal sealed class RecoveryNativeMessage
    {
        internal readonly RecoveryNativeKind Kind;
        internal readonly ulong Sequence;
        internal readonly byte[] Payload;
        internal RecoveryNativeMessage(RecoveryNativeKind kind, ulong sequence, byte[] payload)
        { Kind = kind; Sequence = sequence; Payload = payload; }
    }

    // Framing only. The controller owns process containment, source identity,
    // typed payload validation and durable parent acknowledgement before Reply.
    // Closing its ProcessJob must unblock a read when cancellation/timeout fires.
    internal sealed class RecoveryNativeProtocol
    {
        internal const int HeaderBytes = 24, MaximumPayload = 1024 * 1024;
        readonly Stream input, output;
        readonly CancellationToken cancel;
        ulong next = 1;
        RecoveryNativeMessage pending;
        bool failed;

        internal RecoveryNativeProtocol(Stream fromChild, Stream toChild, CancellationToken token)
        {
            if (fromChild == null || toChild == null || fromChild == toChild ||
                !fromChild.CanRead || !toChild.CanWrite) throw new IOException("NATIVE_PROTOCOL_STREAM_INVALID");
            input = fromChild; output = toChild; cancel = token;
        }
        IOException Error(string code) { failed = true; return new IOException(code); }
        void Guard()
        {
            cancel.ThrowIfCancellationRequested();
            if (failed) throw new IOException("NATIVE_PROTOCOL_ALREADY_FAILED");
        }
        internal void CheckCancellation() { Guard(); }
        static uint Read32(byte[] bytes, int at)
        { return (uint)(bytes[at] | (uint)bytes[at+1] << 8 | (uint)bytes[at+2] << 16 | (uint)bytes[at+3] << 24); }
        static ulong Read64(byte[] bytes, int at)
        { return Read32(bytes,at) | (ulong)Read32(bytes,at+4) << 32; }
        static void Write32(byte[] bytes, int at, uint value)
        { for (int i = 0; i < 4; i++) bytes[at+i] = (byte)(value >> (8*i)); }
        static void Write64(byte[] bytes, int at, ulong value)
        { Write32(bytes,at,(uint)value); Write32(bytes,at+4,(uint)(value >> 32)); }
        void ReadExact(byte[] bytes)
        {
            int at = 0;
            try {
                while (at < bytes.Length) {
                    Guard(); int count = input.Read(bytes,at,bytes.Length-at);
                    if (count == 0) throw Error("NATIVE_PROTOCOL_EOF");
                    at += count;
                }
            } catch (IOException) { failed = true; throw; }
        }
        static bool RequestKind(RecoveryNativeKind kind)
        {
            return kind == RecoveryNativeKind.Hello || kind == RecoveryNativeKind.Read ||
                kind == RecoveryNativeKind.Record || kind == RecoveryNativeKind.Stream ||
                kind == RecoveryNativeKind.EndRecord || kind == RecoveryNativeKind.Done ||
                kind == RecoveryNativeKind.Fail || kind == RecoveryNativeKind.Snapshot || kind == RecoveryNativeKind.Output;
        }
        internal RecoveryNativeMessage Read()
        {
            Guard();
            if (pending != null) throw Error("NATIVE_PROTOCOL_ACK_REQUIRED");
            byte[] header = new byte[HeaderBytes]; ReadExact(header);
            var kind = (RecoveryNativeKind)header[5];
            if (header[0] != 'U' || header[1] != 'R' || header[2] != 'C' || header[3] != '1' ||
                header[4] != 1 || header[6] != 0 || header[7] != 0 || Read32(header,20) != 0 || !RequestKind(kind))
                throw Error("NATIVE_PROTOCOL_HEADER_INVALID");
            ulong sequence = Read64(header,8); uint count = Read32(header,16);
            if (sequence != next || next == UInt64.MaxValue) throw Error("NATIVE_PROTOCOL_SEQUENCE_INVALID");
            if (count > MaximumPayload) throw Error("NATIVE_PROTOCOL_PAYLOAD_LIMIT");
            byte[] payload = new byte[(int)count]; ReadExact(payload); Guard();
            pending = new RecoveryNativeMessage(kind,sequence,payload); next++;
            return pending;
        }
        internal void Reply(RecoveryNativeMessage message, RecoveryNativeKind kind, byte[] payload)
        {
            Guard();
            if (pending == null || !Object.ReferenceEquals(message,pending)) throw Error("NATIVE_PROTOCOL_REPLY_UNPLANNED");
            payload = payload ?? new byte[0];
            if (payload.Length > MaximumPayload) throw Error("NATIVE_PROTOCOL_PAYLOAD_LIMIT");
            if (kind != RecoveryNativeKind.Cancel &&
                kind != (message.Kind == RecoveryNativeKind.Read ? RecoveryNativeKind.Bytes : RecoveryNativeKind.Ack) ||
                kind != RecoveryNativeKind.Bytes && payload.Length != 0) throw Error("NATIVE_PROTOCOL_REPLY_KIND_INVALID");
            byte[] header = new byte[HeaderBytes];
            header[0] = (byte)'U'; header[1] = (byte)'R'; header[2] = (byte)'C'; header[3] = (byte)'1';
            header[4] = 1; header[5] = (byte)kind;
            Write64(header,8,message.Sequence); Write32(header,16,(uint)payload.Length);
            try { output.Write(header,0,header.Length); output.Write(payload,0,payload.Length); output.Flush(); }
            catch (IOException) { failed = true; throw; }
            pending = null;
            if (kind == RecoveryNativeKind.Cancel) { failed = true; return; }
            Guard();
        }
    }
}
