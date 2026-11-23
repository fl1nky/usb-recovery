using System;
using System.Collections.Generic;
using System.Linq;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        static void ExportVolumeCandidatesLegacy(Context c, Volume v, List<Inode> deleted,
            Dictionary<uint,HistoricalCandidate> historicalInodes, Dictionary<uint,List<NameLink>> names)
        {
            foreach (Inode inode in deleted) {
                c.Cancel.ThrowIfCancellationRequested(); c.Report.Candidates++;
                var entry = new Entry { VolumeOffset = v.Offset, InodeOffset = inode.Offset, Inode = inode.Number, Generation = inode.Generation,
                    DeletionTime = inode.Dtime, DeclaredSize = inode.Size > long.MaxValue ? long.MaxValue : (long)inode.Size,
                    InodeChecksumVerified = v.Csum, Status = "not_recovered" };
                c.Report.Entries.Add(entry);
                List<NameLink> links; if (names.TryGetValue(inode.Number, out links)) entry.Names = links;
                if (inode.Size == 0 || inode.Size > (ulong)c.Limits.MaximumFileBytes) {
                    entry.Reason = "empty_or_file_size_limit";
                    if (inode.Size > (ulong)c.Limits.MaximumFileBytes) { c.Report.Limited = true; Skip(c, "file_size_limit"); }
                    continue;
                }
                if (PrepareMappedEntry(c, v, inode, entry)) WriteFile(c, entry);
            }

            if (historicalInodes != null)
            {
                foreach (HistoricalCandidate cand in historicalInodes.Values)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    if (c.Report.Entries.Any(x => x.VolumeOffset == v.Offset && x.Inode == cand.Number && x.Output != null)) continue;
                    if (!IsCandidateDeletedInLiveFs(c, v, cand)) continue;

                    if (c.Report.Entries.Count >= c.Limits.MaximumCandidates)
                    {
                        c.Report.Limited = true;
                        Skip(c, "candidate_limit");
                        break;
                    }

                    var inode = new Inode
                    {
                        Number = cand.Number,
                        Offset = v.Offset + (long)cand.TargetDiskBlock * v.BlockBytes + (long)cand.OffsetInBlock,
                        Mode = cand.Mode,
                        Links = cand.Links,
                        Dtime = cand.Dtime,
                        Flags = cand.Flags,
                        Generation = cand.Generation,
                        Size = cand.Size,
                        Allocated = false,
                        Bytes = cand.InodeBytes
                    };

                    c.Report.Candidates++;
                    var entry = new Entry
                    {
                        VolumeOffset = v.Offset,
                        InodeOffset = inode.Offset,
                        Inode = inode.Number,
                        Generation = inode.Generation,
                        DeletionTime = inode.Dtime,
                        DeclaredSize = inode.Size > long.MaxValue ? long.MaxValue : (long)inode.Size,
                        InodeChecksumVerified = v.Csum,
                        Status = "not_recovered",
                        DeletionEvidence = "journal_transaction_pre_deletion_record",
                        Note = "Историческая карта inode из транзакции журнала JBD2 (seq " + cand.TransactionSeq + "). Свободные блоки могли быть перезаписаны до снимка; контрольной суммы исходного содержимого в ext4 нет."
                    };
                    c.Report.Entries.Add(entry);

                    List<NameLink> links;
                    if (names.TryGetValue(inode.Number, out links)) entry.Names = links;

                    if (PrepareMappedEntry(c, v, inode, entry)) WriteFile(c, entry);
                }
            }

        }
    }
}
