using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class RecoveryOutputHead
    {
        public string Path, Sha256;
        public int Count;
    }

    internal sealed class RecoveryOutputPage<T> where T : class
    {
        public int Schema = 1;
        public RecoveryOutputHead Previous;
        public List<T> Records;
    }

    internal enum RecoveryLedgerScope { MethodOutput, SessionArtifacts }

    // A checkpoint pins one head. Each immutable page pins the previous page,
    // so a large output inventory needs no growing root JSON or full-prefix
    // rehash on every scan block. Orphan pages are never discovered as results.
    internal sealed class RecoveryOutputLedger<T> where T : class
    {
        const int MaximumPageBytes = 256 * 1024, RecordsPerPage = 128;
        readonly RecoveryCheckpointContext context;
        readonly CancellationToken cancel;
        readonly int maximumRecords;
        readonly string prefix;
        readonly long maximumBytes;
        long chainBytes;
        public readonly List<T> Records = new List<T>();

        string Hash(string file)
        {
            return RecoveryCore.HashFile(file, cancel, (done, total) => { });
        }

        string FileFor(RecoveryOutputHead head)
        {
            if (head == null || head.Count < 1 || head.Count > maximumRecords ||
                head.Path == null || !head.Path.StartsWith(prefix, StringComparison.Ordinal) ||
                !head.Path.EndsWith(".json", StringComparison.Ordinal) || head.Path.Length != prefix.Length + 37 ||
                head.Sha256 == null || head.Sha256.Length != 64 ||
                head.Sha256.Any(c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) ||
                head.Path.Substring(prefix.Length, 32).Any(c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')))
                throw new IOException("METHOD_OUTPUT_LEDGER_INVALID");
            return RecoveryCatalog.SafeFile(context.Directory, head.Path);
        }

        static bool Empty(RecoveryOutputHead head)
        {
            return head == null || head.Count == 0 && head.Path == null && head.Sha256 == null;
        }

        public RecoveryOutputLedger(RecoveryCheckpointContext checkpoint, RecoveryOutputHead head,
            int maximum, CancellationToken token, RecoveryLedgerScope scope = RecoveryLedgerScope.MethodOutput,
            long maximumPageChainBytes = Int64.MaxValue)
        {
            context = checkpoint;
            maximumRecords = maximum;
            cancel = token;
            maximumBytes = maximumPageChainBytes;
            if (maximum < 1 || maximumBytes < 1 || scope != RecoveryLedgerScope.MethodOutput && scope != RecoveryLedgerScope.SessionArtifacts)
                throw new ArgumentException("Invalid ledger bounds.");
            if (scope == RecoveryLedgerScope.SessionArtifacts && (context == null || !RecoveryStageFiles.Keys.Contains(context.Method)))
                throw new IOException("SESSION_ARTIFACT_INVENTORY_CONTEXT_INVALID");
            if (context != null) prefix = scope == RecoveryLedgerScope.SessionArtifacts
                ? "session-inventories/" + context.Method + "/page-" : context.Method + ".state/outputs/page-";
            if (Empty(head)) return;
            if (context == null) throw new IOException("METHOD_OUTPUT_LEDGER_CONTEXT_REQUIRED");
            int expected = head.Count;
            var pages = new List<List<T>>();
            while (!Empty(head))
            {
                cancel.ThrowIfCancellationRequested();
                string file = FileFor(head);
                RecoveryOutputPage<T> page;
                using (var guard = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (guard.Length <= 0 || guard.Length > MaximumPageBytes)
                        throw new IOException("METHOD_OUTPUT_LEDGER_CHANGED");
                    if (guard.Length > maximumBytes - chainBytes)
                        throw new IOException("METHOD_OUTPUT_LEDGER_BYTES_LIMIT");
                    chainBytes += guard.Length;
                    if (Hash(file) != head.Sha256)
                        throw new IOException("METHOD_OUTPUT_LEDGER_CHANGED");
                    try
                    {
                        page = new JavaScriptSerializer { MaxJsonLength = MaximumPageBytes }
                            .Deserialize<RecoveryOutputPage<T>>(File.ReadAllText(file, new UTF8Encoding(false, true)));
                    }
                    catch (ArgumentException) { throw new IOException("METHOD_OUTPUT_LEDGER_INVALID"); }
                    catch (InvalidOperationException) { throw new IOException("METHOD_OUTPUT_LEDGER_INVALID"); }
                }
                if (page == null || page.Schema != 1 || page.Records == null ||
                    page.Records.Count < 1 || page.Records.Count > RecordsPerPage || page.Records.Any(x => x == null))
                    throw new IOException("METHOD_OUTPUT_LEDGER_INVALID");
                int prior = Empty(page.Previous) ? 0 : page.Previous.Count;
                if (prior < 0 || prior >= head.Count || head.Count - prior != page.Records.Count)
                    throw new IOException("METHOD_OUTPUT_LEDGER_COUNT_CHANGED");
                pages.Add(page.Records);
                head = page.Previous;
            }
            for (int index = pages.Count - 1; index >= 0; index--) Records.AddRange(pages[index]);
            if (Records.Count != expected) throw new IOException("METHOD_OUTPUT_LEDGER_COUNT_CHANGED");
        }

        public RecoveryOutputHead Append(RecoveryOutputHead head, IList<T> records)
        {
            cancel.ThrowIfCancellationRequested();
            int count = Empty(head) ? 0 : head.Count;
            if (records == null || records.Any(x => x == null) || count != Records.Count || count > maximumRecords - records.Count)
                throw new IOException("METHOD_OUTPUT_LEDGER_LIMIT");
            if (context == null)
            {
                return records.Count == 0 ? head : new RecoveryOutputHead { Count = count + records.Count };
            }
            var json = new JavaScriptSerializer { MaxJsonLength = MaximumPageBytes };
            for (int at = 0; at < records.Count; )
            {
                cancel.ThrowIfCancellationRequested();
                var page = new RecoveryOutputPage<T> { Previous = head, Records = new List<T>() };
                int bytes = Encoding.UTF8.GetByteCount(json.Serialize(page));
                while (at < records.Count && page.Records.Count < RecordsPerPage)
                {
                    string encoded;
                    try { encoded = json.Serialize(records[at]); }
                    catch (ArgumentException) { throw new IOException("METHOD_OUTPUT_LEDGER_RECORD_TOO_LARGE"); }
                    catch (InvalidOperationException) { throw new IOException("METHOD_OUTPUT_LEDGER_RECORD_TOO_LARGE"); }
                    int added = Encoding.UTF8.GetByteCount(encoded) + (page.Records.Count == 0 ? 0 : 1);
                    if (added > MaximumPageBytes - bytes - 8)
                    {
                        if (page.Records.Count == 0) throw new IOException("METHOD_OUTPUT_LEDGER_RECORD_TOO_LARGE");
                        break;
                    }
                    page.Records.Add(records[at++]);
                    bytes += added;
                }
                if (bytes + 8L > maximumBytes - chainBytes)
                    throw new IOException("METHOD_OUTPUT_LEDGER_BYTES_LIMIT");
                string relative = prefix + Guid.NewGuid().ToString("N") + ".json";
                string path = RecoveryCatalog.SafeFile(context.Directory, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                RecoveryCore.SaveJsonBounded(path, page, MaximumPageBytes);
                chainBytes += new FileInfo(path).Length;
                count += page.Records.Count;
                head = new RecoveryOutputHead { Path = relative, Sha256 = Hash(path), Count = count };
            }
            return head;
        }

        // Call only after the parent has acknowledged the new ledger head.
        public void Accept(IList<T> records)
        {
            if (records == null || records.Any(x => x == null) || Records.Count > maximumRecords - records.Count)
                throw new IOException("METHOD_OUTPUT_LEDGER_LIMIT");
            Records.AddRange(records);
        }
    }
}
