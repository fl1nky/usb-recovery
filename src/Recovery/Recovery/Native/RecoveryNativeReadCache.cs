// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace UsbRecovery
{
    // Unlike ordered metadata replay, an offset-keyed cache permits the native
    // reader to jump to a saved MFT ordinal and issue bootstrap reads in a new
    // order. Every page and ledger head is durable before bytes reach the child.
    internal sealed class RecoveryNativeReadCache
    {
        internal const int PageBytes = 64 * 1024;
        sealed class State
        {
            public int Schema = 1;
            public long Begin, Length, MaximumBytes, Bytes;
            public RecoveryOutputHead Pages;
        }
        sealed class Page { public long Offset; public int Length; public string Sha256; }
        readonly FileStream source;
        readonly RecoveryVerifiedImage verified;
        readonly RecoveryCheckpointContext context;
        readonly CancellationToken cancel;
        readonly RecoveryMethodJournal<State> journal;
        readonly RecoveryOutputLedger<Page> ledger;
        readonly Dictionary<long, Page> pages = new Dictionary<long, Page>();
        readonly long begin, length, maximum;
        readonly string root, method, settings, sourceHash;
        State state;
        internal long PhysicalReadBytes { get; private set; }
        internal long CachedBytes { get { return state.Bytes; } }

        internal RecoveryNativeReadCache(FileStream input, RecoveryVerifiedImage image,
            RecoveryCheckpointContext checkpoint, long offset, long bytes, long maximumBytes, CancellationToken token)
        {
            if (input == null || input.CanWrite || image == null || checkpoint == null ||
                offset < 0 || bytes < 1 || offset > input.Length - bytes ||
                maximumBytes < PageBytes || maximumBytes > 16L * 1024 * 1024 * 1024)
                throw new IOException("NATIVE_CACHE_CONTEXT_INVALID");
            source = input; verified = image; context = checkpoint; cancel = token;
            begin = offset; length = bytes; maximum = maximumBytes;
            root = Path.GetFullPath(context.Directory); method = context.Method;
            settings = context.Settings; sourceHash = context.SourceSha256;
            Guard();
            journal = new RecoveryMethodJournal<State>(source.Name,
                new State { Begin = begin, Length = length, MaximumBytes = maximum }, context, cancel);
            state = journal.Payload;
            if (state.Schema != 1 || state.Begin != begin || state.Length != length || state.MaximumBytes != maximum ||
                state.Bytes < 0 || state.Bytes > maximum) throw new IOException("NATIVE_CACHE_BINDING_INVALID");
            int limit = checked((int)(maximum / PageBytes + 1));
            ledger = new RecoveryOutputLedger<Page>(context, state.Pages, limit, cancel,
                RecoveryLedgerScope.MethodOutput, checked((long)limit * 4096));
            long total = 0;
            foreach (var page in ledger.Records) {
                if (page.Offset < begin || page.Offset >= begin + length || (page.Offset - begin) % PageBytes != 0 ||
                    page.Length != Math.Min(PageBytes, begin + length - page.Offset) || !Digest(page.Sha256) ||
                    pages.ContainsKey(page.Offset)) throw new IOException("NATIVE_CACHE_PAGE_INVALID");
                total = checked(total + page.Length); pages.Add(page.Offset, page);
            }
            if (total != state.Bytes) throw new IOException("NATIVE_CACHE_CURSOR_INVALID");
        }
        static bool Digest(string value)
        { return value != null && value.Length == 64 && value.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f'); }
        static string Hash(byte[] data)
        { using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant(); }
        void Guard()
        {
            cancel.ThrowIfCancellationRequested();
            if (Path.GetFullPath(context.Directory) != root || context.Method != method || context.Settings != settings ||
                context.SourceSha256 != sourceHash) throw new IOException("NATIVE_CACHE_CONTEXT_CHANGED");
            verified.Validate(source, sourceHash);
        }
        string FileFor(Page page)
        {
            return RecoveryCatalog.SafeFile(root, method + ".state/read-cache/" +
                page.Offset.ToString("x16", CultureInfo.InvariantCulture) + "-" + page.Sha256 + ".bin");
        }
        byte[] ReadPage(Page page)
        {
            Guard(); string path = FileFor(page);
            using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                if (input.Length != page.Length) throw new IOException("NATIVE_CACHE_PAGE_CHANGED");
                byte[] bytes = new byte[page.Length]; int done = 0;
                while (done < bytes.Length) {
                    Guard(); int n = input.Read(bytes, done, bytes.Length - done);
                    if (n == 0) throw new IOException("NATIVE_CACHE_SHORT_READ"); done += n;
                }
                if (Hash(bytes) != page.Sha256) throw new IOException("NATIVE_CACHE_PAGE_CHANGED");
                return bytes;
            }
        }
        byte[] Load(long offset)
        {
            Page known; if (pages.TryGetValue(offset, out known)) return ReadPage(known);
            int count = (int)Math.Min(PageBytes, begin + length - offset);
            if (count > maximum - state.Bytes) throw new IOException("NATIVE_CACHE_BYTES_LIMIT");
            var bytes = new byte[count]; source.Position = offset; int done = 0;
            while (done < count) {
                Guard(); int n = source.Read(bytes, done, count - done);
                if (n == 0) throw new IOException("NATIVE_SOURCE_SHORT_READ");
                done += n; PhysicalReadBytes += n;
            }
            var page = new Page { Offset = offset, Length = count, Sha256 = Hash(bytes) };
            string path = FileFor(page); Directory.CreateDirectory(Path.GetDirectoryName(path));
            if (File.Exists(path)) {
                // An orphan from a failed parent commit is usable only after
                // independent verification against the freshly read source.
                ReadPage(page);
            } else {
                string pending = RecoveryCatalog.SafeFile(root, method + ".state/read-cache/" + Guid.NewGuid().ToString("N") + ".partial");
                using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) {
                    Guard(); output.Write(bytes, 0, bytes.Length); output.Flush(true);
                }
                Guard(); File.Move(pending, path);
            }
            var added = new List<Page> { page };
            var next = new State { Begin = begin, Length = length, MaximumBytes = maximum, Bytes = state.Bytes + count,
                Pages = ledger.Append(state.Pages, added) };
            Guard(); journal.Save(next); ledger.Accept(added); state = next; pages.Add(offset, page);
            return bytes;
        }
        internal byte[] Read(long offset, int count)
        {
            Guard();
            if (count < 1 || count > RecoveryNativeProtocol.MaximumPayload || offset < begin || offset > begin + length - count)
                throw new IOException("NATIVE_SOURCE_RANGE_INVALID");
            byte[] output = new byte[count]; int done = 0;
            while (done < count) {
                Guard(); long at = offset + done, pageAt = begin + (at - begin) / PageBytes * PageBytes;
                byte[] page = Load(pageAt); int within = (int)(at - pageAt), n = Math.Min(count - done, page.Length - within);
                Buffer.BlockCopy(page, within, output, done, n); done += n;
            }
            Guard(); return output;
        }
    }
}
