using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace UsbRecovery
{
    public static partial class FragmentedZipRecovery
    {
        // A small verification unit avoids two durable writes for each tiny
        // member. It never exceeds 128 records; a large member is its own unit.
        sealed class ZipMemberVerifier
        {
            const long SmallUnitBytes = 1024 * 1024;
            readonly FileStream input;
            readonly Report report;
            readonly ZipScanState state;
            readonly RecoveryMethodJournal<ZipScanState> journal;
            readonly RecoveryOutputLedger<ZipEvent> ledger;
            readonly CancellationToken cancel;
            readonly Action<long, long> progress;
            readonly List<ZipEvent> pending = new List<ZipEvent>();
            long reserved, before;
            bool active;

            public ZipMemberVerifier(FileStream source, Report output, ZipScanState cursor,
                RecoveryMethodJournal<ZipScanState> checkpoints, RecoveryOutputLedger<ZipEvent> index,
                CancellationToken token, Action<long, long> observe)
            {
                input = source; report = output; state = cursor;
                journal = checkpoints; ledger = index; cancel = token; progress = observe;
            }

            public void Flush(bool notify = true)
            {
                if (!active) return;
                long unused = reserved - (report.ExpandedWorkBytes - before);
                if (unused < 0) throw new IOException("FRAGMENTED_ZIP_WORK_ACCOUNTING_INVALID");
                state.ChargedWorkBytes -= unused;
                CommitZip(state, report, journal, ledger, pending);
                pending.Clear(); active = false;
                if (notify && progress != null) progress(state.Position, input.Length);
            }

            public bool Verify(Local item)
            {
                cancel.ThrowIfCancellationRequested();
                if (item.Checked) return item.Valid;
                long needed = item.Method == 0 ? item.Unpacked : item.Unpacked + 65536;
                if (active && (pending.Count == 128 || needed > reserved - (report.ExpandedWorkBytes - before))) Flush();
                cancel.ThrowIfCancellationRequested();
                if (!active)
                {
                    reserved = Math.Min(MaximumWorkBytes - state.ChargedWorkBytes, Math.Max(SmallUnitBytes, needed));
                    if (reserved == 0 && item.Unpacked != 0)
                    {
                        state.Limited = true; report.Status = "limited";
                        CommitZip(state, report, journal, ledger);
                        throw new IOException("Поиск ZIP достиг общего предела проверки распаковки.");
                    }
                    before = report.ExpandedWorkBytes;
                    state.ChargedWorkBytes += reserved;
                    CommitZip(state, report, journal, ledger);
                    active = true;
                }
                long allowance = reserved - (report.ExpandedWorkBytes - before);
                try { FragmentedZipRecovery.Verify(input, item, report, cancel, allowance); }
                catch (IOException)
                {
                    if (report.Status == "limited")
                    {
                        state.Limited = true;
                        // Keep the full reservation on a limited/partial unit;
                        // only already finished member records enter the cache.
                        CommitZip(state, report, journal, ledger, pending);
                        pending.Clear(); active = false;
                    }
                    throw;
                }
                pending.Add(new ZipEvent { Kind = "verified", Offset = item.Offset,
                    Valid = item.Valid, RawSha256 = item.RawSha });
                return item.Valid;
            }
        }
    }
}
