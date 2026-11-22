using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public sealed class ForensicTimelineEvent
    {
        public DateTime TimeStampUtc { get; set; }
        public string Source { get; set; }
        public string Action { get; set; }
        public string TargetPath { get; set; }
        public string Description { get; set; }
        public string ExtraDetails { get; set; }

        public ForensicTimelineEvent()
        {
            TimeStampUtc = DateTime.MinValue;
            Source = String.Empty;
            Action = String.Empty;
            TargetPath = String.Empty;
            Description = String.Empty;
            ExtraDetails = String.Empty;
        }

        public override string ToString()
        {
            return string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "[{0:yyyy-MM-dd HH:mm:ss} UTC] [{1}] {2}: {3} ({4})",
                TimeStampUtc, Source, Action, TargetPath, Description);
        }
    }

    /// <summary>
    /// Pure C# Unified Super-Timeline engine for Digital Forensics and Incident Response (DFIR).
    /// Aggregates, correlates, and sorts events across USN Change Journal, $MFT, Prefetch,
    /// EVTX Event Logs, Browser History, Registry hives, and AppCompatCache (Shimcache).
    /// </summary>
    public sealed class ForensicTimeline
    {
        private readonly List<ForensicTimelineEvent> events;

        public int Count
        {
            get { return events.Count; }
        }

        public IReadOnlyList<ForensicTimelineEvent> Events
        {
            get { return events.AsReadOnly(); }
        }

        public ForensicTimeline()
        {
            events = new List<ForensicTimelineEvent>();
        }

        public void AddEvent(DateTime timeStampUtc, string source, string action, string targetPath, string description, string extraDetails = "")
        {
            if (timeStampUtc == DateTime.MinValue || timeStampUtc.Year < 1995 || timeStampUtc.Year > 2050) return;

            events.Add(new ForensicTimelineEvent
            {
                TimeStampUtc = timeStampUtc,
                Source = source ?? "UNKNOWN",
                Action = action ?? "ACTIVITY",
                TargetPath = targetPath ?? String.Empty,
                Description = description ?? String.Empty,
                ExtraDetails = extraDetails ?? String.Empty
            });
        }

        public void AddUsnRecords(IEnumerable<UsnRecord> usnRecords)
        {
            if (usnRecords == null) return;
            foreach (var r in usnRecords)
            {
                if (r == null || r.TimeStampUtc == DateTime.MinValue) continue;

                string action = "FILE_ACTIVITY";
                if ((r.Reason & UsnReason.FileDelete) != 0) action = "FILE_DELETED";
                else if ((r.Reason & UsnReason.FileCreate) != 0) action = "FILE_CREATED";
                else if ((r.Reason & UsnReason.RenameNewName) != 0) action = "FILE_RENAMED";
                else if ((r.Reason & UsnReason.DataOverwrite) != 0 || (r.Reason & UsnReason.DataExtend) != 0) action = "FILE_MODIFIED";

                AddEvent(
                    r.TimeStampUtc,
                    "USN_JOURNAL",
                    action,
                    r.FileName,
                    string.Format(System.Globalization.CultureInfo.InvariantCulture, "USN #{0}: {1}", r.Usn, r.ReasonText),
                    string.Format(System.Globalization.CultureInfo.InvariantCulture, "MFT:{0}, Parent:{1}", r.MftEntryIndex, r.ParentMftEntryIndex)
                );
            }
        }

        public void AddMftRecords(IEnumerable<MftFileRecord> mftRecords)
        {
            if (mftRecords == null) return;
            foreach (var m in mftRecords)
            {
                if (m == null) continue;

                string state = m.IsAllocated ? "ACTIVE" : "DELETED";

                if (m.CreationTimeUtc != DateTime.MinValue)
                {
                    AddEvent(
                        m.CreationTimeUtc,
                        "MFT",
                        "MFT_RECORD_CREATED",
                        m.FileName,
                        string.Format(System.Globalization.CultureInfo.InvariantCulture, "Status: {0}, Size: {1} bytes", state, m.FileSize),
                        m.IsTimestomped ? "WARNING: Timestomping detected (StandardInfo vs FileName mismatch)" : ""
                    );
                }

                if (m.ModificationTimeUtc != DateTime.MinValue && m.ModificationTimeUtc != m.CreationTimeUtc)
                {
                    AddEvent(
                        m.ModificationTimeUtc,
                        "MFT",
                        "MFT_RECORD_MODIFIED",
                        m.FileName,
                        string.Format(System.Globalization.CultureInfo.InvariantCulture, "Status: {0}, Size: {1} bytes", state, m.FileSize)
                    );
                }
            }
        }

        public void AddPrefetch(PrefetchArtifact pf)
        {
            if (pf == null) return;

            for (int i = 0; i < pf.LastRunTimes.Count; i++)
            {
                DateTime t = pf.LastRunTimes[i];
                AddEvent(
                    t,
                    "PREFETCH",
                    "PROGRAM_EXECUTED",
                    pf.ExecutableName,
                    string.Format(System.Globalization.CultureInfo.InvariantCulture, "Run count: {0}, Hash: {1}", pf.RunCount, pf.Hash),
                    "Version: " + pf.Version
                );
            }
        }

        public void AddBrowserHistory(IEnumerable<BrowserHistoryRecord> records)
        {
            if (records == null) return;
            foreach (var b in records)
            {
                if (b == null) continue;

                if (b.Visits != null && b.Visits.Count > 0)
                {
                    for (int i = 0; i < b.Visits.Count; i++)
                    {
                        var v = b.Visits[i];
                        if (v.VisitTimeUtc != DateTime.MinValue)
                        {
                            AddEvent(
                                v.VisitTimeUtc,
                                "BROWSER_" + b.Browser.ToString().ToUpperInvariant(),
                                "URL_VISITED",
                                b.Url,
                                b.Title,
                                "Type: " + v.VisitType.ToString()
                            );
                        }
                    }
                }
                else if (b.LastVisitUtc != DateTime.MinValue)
                {
                    AddEvent(
                        b.LastVisitUtc,
                        "BROWSER_" + b.Browser.ToString().ToUpperInvariant(),
                        "URL_VISITED",
                        b.Url,
                        b.Title,
                        "Visit count: " + b.VisitCount
                    );
                }
            }
        }

        public void AddEvtxRecords(IEnumerable<EvtxRecord> evtxRecords)
        {
            if (evtxRecords == null) return;
            foreach (var ev in evtxRecords)
            {
                if (ev == null || ev.TimestampUtc == DateTime.MinValue) continue;

                string action = "EVENT_LOG_" + ev.EventId;
                if (ev.EventId == 4624) action = "USER_LOGON";
                else if (ev.EventId == 4634) action = "USER_LOGOFF";
                else if (ev.EventId == 4688) action = "PROCESS_CREATION";
                else if (ev.EventId == 7045) action = "SERVICE_INSTALLED";

                AddEvent(
                    ev.TimestampUtc,
                    "EVTX_" + (String.IsNullOrEmpty(ev.Channel) ? "SECURITY" : ev.Channel),
                    action,
                    ev.ProviderName,
                    string.Format(System.Globalization.CultureInfo.InvariantCulture, "EventID {0} (Record #{1})", ev.EventId, ev.RecordId),
                    ev.ComputerName
                );
            }
        }

        public void AddShimcache(IEnumerable<AppCompatCacheEntry> shimEntries)
        {
            if (shimEntries == null) return;
            foreach (var s in shimEntries)
            {
                if (s == null || s.LastModifiedTimeUtc == DateTime.MinValue) continue;

                AddEvent(
                    s.LastModifiedTimeUtc,
                    "SHIMCACHE",
                    s.Executed ? "PROGRAM_EXECUTED" : "PROGRAM_CACHED",
                    s.Path,
                    "AppCompatCache Entry #" + s.EntryIndex,
                    s.Executed ? "Executed: YES" : "Executed: NO"
                );
            }
        }

        public void AddAmcache(IEnumerable<AmcacheEntry> amcacheEntries)
        {
            if (amcacheEntries == null) return;
            foreach (var a in amcacheEntries)
            {
                if (a == null) continue;
                DateTime ts = a.KeyLastWriteTimeUtc != DateTime.MinValue ? a.KeyLastWriteTimeUtc : a.LinkerTimestampUtc;
                if (ts == DateTime.MinValue) continue;

                string action = a.IsSuspicious ? "SUSPICIOUS_EXECUTION" : "BINARY_INVENTORY";
                string desc = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                    "SHA1: {0}, Size: {1} bytes, Publisher: {2}", a.Sha1, a.FileSize, a.Publisher ?? "N/A");

                AddEvent(
                    ts,
                    "AMCACHE",
                    action,
                    a.Path,
                    desc,
                    a.IsSuspicious ? ("ALERT: " + a.SuspicionReason) : (a.BinaryType ?? "")
                );
            }
        }

        public void AddShellbags(IEnumerable<ShellbagRecord> shellbagRecords)
        {
            if (shellbagRecords == null) return;
            foreach (var s in shellbagRecords)
            {
                if (s == null) continue;
                DateTime ts = s.KeyLastWriteTimeUtc != DateTime.MinValue ? s.KeyLastWriteTimeUtc : s.ModifiedTimeUtc;
                if (ts == DateTime.MinValue) continue;

                string action = (s.ItemType == ShellbagItemType.Drive) ? "DRIVE_ACCESSED" : "FOLDER_VIEWED";
                string desc = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                    "Type: {0}, Source: {1}, MRU: {2}", s.ItemType, s.RegistrySource, s.MruPath);

                AddEvent(
                    ts,
                    "SHELLBAGS",
                    action,
                    s.FullPath,
                    desc,
                    s.ModifiedTimeUtc != DateTime.MinValue ? string.Format(System.Globalization.CultureInfo.InvariantCulture, "Folder Modified: {0:yyyy-MM-dd HH:mm:ss} UTC", s.ModifiedTimeUtc) : ""
                );
            }
        }

        public void AddLnk(LnkArtifact lnk)
        {
            if (lnk == null) return;
            DateTime ts = lnk.WriteTimeUtc != DateTime.MinValue ? lnk.WriteTimeUtc :
                         (lnk.AccessTimeUtc != DateTime.MinValue ? lnk.AccessTimeUtc : lnk.CreationTimeUtc);
            if (ts == DateTime.MinValue) return;

            string target = !String.IsNullOrEmpty(lnk.TargetPath) ? lnk.TargetPath :
                           (!String.IsNullOrEmpty(lnk.RelativePath) ? lnk.RelativePath : "Unknown Target");

            string desc = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "Size: {0} bytes, Arguments: {1}", lnk.TargetFileSize, !String.IsNullOrEmpty(lnk.CommandLineArguments) ? lnk.CommandLineArguments : "None");

            string extra = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "Drive: {0} ({1}), MAC: {2}, Machine: {3}",
                !String.IsNullOrEmpty(lnk.VolumeLabel) ? lnk.VolumeLabel : "N/A",
                !String.IsNullOrEmpty(lnk.DriveSerialNumber) ? lnk.DriveSerialNumber : "N/A",
                !String.IsNullOrEmpty(lnk.MacAddress) ? lnk.MacAddress : "N/A",
                !String.IsNullOrEmpty(lnk.MachineId) ? lnk.MachineId : "N/A");

            AddEvent(
                ts,
                "LNK_SHORTCUT",
                "SHORTCUT_ACCESSED",
                target,
                desc,
                extra
            );
        }

        public void AddLnkRecords(IEnumerable<LnkArtifact> lnkRecords)
        {
            if (lnkRecords == null) return;
            foreach (var l in lnkRecords)
            {
                AddLnk(l);
            }
        }

        public void AddExFatFiles(IEnumerable<ExFatScout.ExFatFileRecord> exFatRecords)
        {
            if (exFatRecords == null) return;
            foreach (var f in exFatRecords)
            {
                if (f == null) continue;
                string action = f.IsDeleted ? "FILE_DELETED (exFAT Carved)" : "FILE_ACTIVE (exFAT)";
                string desc = string.Format("Size: {0} bytes, Cluster: {1}, Contiguous: {2}", f.Size, f.FirstCluster, f.NoFatChain);

                if (f.ModifiedTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.ModifiedTimeUtc, "exFAT", action + " - Modified", f.FullPath ?? f.Name, desc);
                }
                if (f.CreatedTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.CreatedTimeUtc, "exFAT", action + " - Created", f.FullPath ?? f.Name, desc);
                }
                if (f.AccessedTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.AccessedTimeUtc, "exFAT", action + " - Accessed", f.FullPath ?? f.Name, desc);
                }
            }
        }

        public void AddHfsPlusFiles(IEnumerable<HfsPlusScout.HfsPlusFileRecord> hfsRecords)
        {
            if (hfsRecords == null) return;
            foreach (var f in hfsRecords)
            {
                if (f == null) continue;
                string action = f.IsDeleted ? "FILE_DELETED (HFS+ Carved)" : "FILE_ACTIVE (HFS+)";
                string desc = string.Format("Size: {0} bytes, CNID: {1}, ParentCNID: {2}", f.Size, f.Cnid, f.ParentCnid);

                if (f.ModifyTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.ModifyTimeUtc, "HFS+", action + " - Modified", f.FullPath ?? f.Name, desc);
                }
                if (f.CreateTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.CreateTimeUtc, "HFS+", action + " - Created", f.FullPath ?? f.Name, desc);
                }
                if (f.AccessTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.AccessTimeUtc, "HFS+", action + " - Accessed", f.FullPath ?? f.Name, desc);
                }
            }
        }

        public void AddSrumNetworkEntries(IEnumerable<SrumNetworkEntry> srumEntries)
        {
            if (srumEntries == null) return;
            foreach (var n in srumEntries)
            {
                if (n == null || n.TimestampUtc == DateTime.MinValue) continue;
                string action = n.IsSuspicious ? "NETWORK_EXFILTRATION (SRUM Suspicious)" : "NETWORK_USAGE (SRUM)";
                string desc = string.Format("Sent: {0:N0} bytes, Recv: {1:N0} bytes, Interface: {2}{3}",
                    n.BytesSent, n.BytesReceived, n.InterfaceType,
                    n.IsSuspicious ? " [ALERT: " + n.SuspicionReason + "]" : "");
                string details = string.Format("AppId: {0}, UserSid: {1}, InterfaceLuid: 0x{2:X16}", n.AppId, n.UserSid, n.InterfaceLuid);

                AddEvent(n.TimestampUtc, "SRUM", action, n.AppName, desc, details);
            }
        }

        public void AddSrumAppUsageEntries(IEnumerable<SrumAppUsageEntry> usageEntries)
        {
            if (usageEntries == null) return;
            foreach (var u in usageEntries)
            {
                if (u == null || u.TimestampUtc == DateTime.MinValue) continue;
                string action = u.IsSuspicious ? "APP_EXECUTION (SRUM Suspicious)" : "APP_EXECUTION (SRUM)";
                string desc = string.Format("Foreground: {0} ms, CPU Cycles: {1:N0}, Read: {2:N0} bytes, Write: {3:N0} bytes{4}",
                    u.FaceTimeMs, u.CpuCycles, u.BytesRead, u.BytesWritten,
                    u.IsSuspicious ? " [ALERT: " + u.SuspicionReason + "]" : "");
                string details = string.Format("AppId: {0}, UserSid: {1}", u.AppId, u.UserSid);

                AddEvent(u.TimestampUtc, "SRUM", action, u.AppName, desc, details);
            }
        }

        public void AddJumpListEntries(IEnumerable<JumpListEntry> jumpListEntries)
        {
            if (jumpListEntries == null) return;
            foreach (var j in jumpListEntries)
            {
                if (j == null) continue;
                DateTime ts = j.LastAccessUtc != DateTime.MinValue ? j.LastAccessUtc :
                              (j.TargetWriteUtc != DateTime.MinValue ? j.TargetWriteUtc : j.TargetCreationUtc);
                if (ts == DateTime.MinValue) continue;

                string action = j.IsSuspicious ? "MRU_EXECUTION (JumpList Suspicious)" :
                               (j.PinStatus == "Pinned" ? "PINNED_ITEM (JumpList)" : "MRU_ACCESS (JumpList)");

                string desc = string.Format("App: {0} ({1}), AccessCount: {2}, Pin: {3}, Size: {4:N0} bytes{5}",
                    string.IsNullOrEmpty(j.AppName) ? "Unknown" : j.AppName,
                    j.AppId,
                    j.AccessCount,
                    j.PinStatus,
                    j.TargetFileSize,
                    j.IsSuspicious ? " [ALERT: " + j.ThreatDescription + "]" : "");

                string details = string.Format("NetBIOS: {0}, VolSerial: {1}, VolLabel: {2}, MAC: {3}, Category: {4}",
                    j.NetBiosName, j.VolumeSerialNumber, j.VolumeLabel, j.MacAddress, j.Category);

                AddEvent(ts, "JumpList", action, j.TargetPath, desc, details);
            }
        }

        public void AddRecycleBinEntries(IEnumerable<RecycleBinEntry> recycleBinEntries)
        {
            if (recycleBinEntries == null) return;
            foreach (var r in recycleBinEntries)
            {
                if (r == null || r.DeletionTimeUtc == DateTime.MinValue) continue;

                string action = r.IsSuspicious ? "DELETED_FILE (RecycleBin Suspicious)" : "DELETED_FILE (RecycleBin)";
                string desc = string.Format("Original Size: {0:N0} bytes, User SID: {1}, Payload: {2}{3}",
                    r.OriginalFileSize,
                    string.IsNullOrEmpty(r.UserSid) ? "Unknown" : r.UserSid,
                    r.HasDataFile ? "Preserved ($R available)" : "Missing ($R purged)",
                    r.IsSuspicious ? " [ALERT: " + r.ThreatDescription + "]" : "");

                string details = string.Format("IndexFile: {0}, DataFile: {1}, FormatVersion: {2}, Carved: {3}",
                    r.IndexFileName, r.DataFileName, r.FormatVersion, r.IsCarved);

                AddEvent(r.DeletionTimeUtc, "RecycleBin", action, r.OriginalFilePath, desc, details);
            }
        }

        public void AddVssSnapshots(IEnumerable<VssSnapshotRecord> snapshots)
        {
            if (snapshots == null) return;
            foreach (var s in snapshots)
            {
                if (s == null || s.CreationTimeUtc == DateTime.MinValue) continue;

                string action = s.IsCarved ? "SNAPSHOT_ORPHANED (VSS Carved)" : "SNAPSHOT_ACTIVE (VSS)";
                string desc = string.Format("Volume Size: {0:N0} bytes, Allocated: {1:N0} bytes, CoW Blocks: {2}{3}",
                    s.VolumeSize,
                    s.AllocatedBytes,
                    s.StoreBlockCount > 0 ? s.StoreBlockCount : s.BlockMappings.Count,
                    s.IsCarved ? " [ALERT: Orphaned / deleted shadow copy detected (T1490)]" : "");

                string details = string.Format("SnapshotId: {0}, SetId: {1}, Machine: {2}, Attributes: {3}",
                    s.SnapshotId, s.SnapshotSetId, s.MachineName, s.Attributes);

                AddEvent(s.CreationTimeUtc, "VSS", action, "Snapshot " + s.SnapshotId.ToString(), desc, details);
            }
        }

        public void AddIsoUdfFiles(IEnumerable<IsoUdfFileRecord> files)
        {
            if (files == null) return;
            foreach (var f in files)
            {
                if (f == null || f.RecordingTimeUtc == DateTime.MinValue) continue;

                string action = f.IsDirectory ? "DIRECTORY_RECORD" : (f.IsCarved ? "FILE_CARVED (ISO/UDF)" : "FILE_ACTIVE (ISO/UDF)");
                string desc = string.Format("Size: {0:N0} bytes, Extent: 0x{1:X10}, Joliet: {2}, UDF: {3}{4}",
                    f.Size,
                    f.ExtentOffset,
                    f.IsJoliet,
                    f.IsUdf,
                    f.IsCarved ? " [Carved from unallocated/damaged sectors]" : "");

                string details = string.Format("FullPath: {0}, IsHidden: {1}", f.FullPath, f.IsHidden);

                AddEvent(f.RecordingTimeUtc, "ISO9660", action, f.FullPath ?? f.Name, desc, details);
            }
        }

        public void AddBrowserExtensions(IEnumerable<BrowserExtensionArtifact> extensions)
        {
            if (extensions == null) return;
            foreach (var ext in extensions)
            {
                if (ext == null) continue;

                string action = ext.IsSuspicious ? "EXTENSION_SUSPICIOUS (MITRE T1176)" :
                                (ext.Category == "Crypto Wallet" ? "CRYPTO_WALLET_INSTALLED" : "EXTENSION_INVENTORY");

                string desc = string.Format("Name: {0} ({1}), Category: {2}, MV{3}, LevelDB: {4} keys{5}",
                    ext.Name,
                    ext.ExtensionId,
                    ext.Category,
                    ext.ManifestVersion,
                    ext.LevelDbKeyCount,
                    ext.IsSuspicious ? " [ALERT: " + ext.SuspicionReason + "]" : "");

                string details = string.Format("Permissions: {0}, Tokens: {1}, Path: {2}",
                    string.Join(", ", ext.Permissions.ToArray()),
                    string.Join(", ", ext.DiscoveredTokens.ToArray()),
                    ext.SourcePath);

                AddEvent(DateTime.UtcNow, "BrowserExtension", action, ext.Name + " (" + ext.ExtensionId + ")", desc, details);
            }
        }

        public void AddBtrfsFiles(IEnumerable<BtrfsScout.BtrfsFileRecord> records)
        {
            if (records == null) return;
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            foreach (var f in records)
            {
                if (f == null) continue;
                string action = f.IsDirectory ? "DIRECTORY_ENTRY (Btrfs)" : "FILE_ENTRY (Btrfs)";
                string desc = string.Format("Inode: {0}, Size: {1} bytes, Extents: {2}", f.InodeId, f.Size, f.Extents != null ? f.Extents.Count : 0);
                if (f.ModifiedTimeUtcSeconds > 0 && f.ModifiedTimeUtcSeconds < 253402300799L)
                {
                    DateTime ts = epoch.AddSeconds(f.ModifiedTimeUtcSeconds);
                    AddEvent(ts, "BTRFS", action + " - Modified", f.FullPath ?? f.Name, desc);
                }
            }
        }

        public void AddXfsFiles(IEnumerable<XfsScout.XfsFileRecord> records)
        {
            if (records == null) return;
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            foreach (var f in records)
            {
                if (f == null) continue;
                string action = f.IsDirectory ? "DIRECTORY_ENTRY (XFS)" : "FILE_ENTRY (XFS)";
                string desc = string.Format("Inode: {0}, Size: {1} bytes, Extents: {2}, Format: {3}", f.InodeId, f.Size, f.Extents != null ? f.Extents.Count : 0, f.Format);
                if (f.ModifiedTimeSec > 0 && f.ModifiedTimeSec < 253402300799L)
                {
                    DateTime ts = epoch.AddSeconds(f.ModifiedTimeSec);
                    AddEvent(ts, "XFS", action + " - Modified", f.FullPath ?? f.Name, desc);
                }
            }
        }

        public void AddZfsFiles(IEnumerable<ZfsScout.ZfsFileRecord> records)
        {
            if (records == null) return;
            foreach (var f in records)
            {
                if (f == null) continue;
                string action = f.IsDirectory ? "DIRECTORY_ENTRY (ZFS)" : "FILE_ENTRY (ZFS)";
                string desc = string.Format("ObjectId: {0}, Size: {1} bytes, Extents: {2}", f.ObjectId, f.FileSizeBytes, f.BlockExtents != null ? f.BlockExtents.Count : 0);
                AddEvent(DateTime.UtcNow, "ZFS", action, f.FullPath ?? f.Name, desc);
            }
        }

        public void AddF2fsFiles(IEnumerable<F2fsScout.F2fsFileRecord> records)
        {
            if (records == null) return;
            foreach (var f in records)
            {
                if (f == null) continue;
                string action = f.IsDirectory ? "DIRECTORY_ENTRY (F2FS)" : (f.IsInline ? "FILE_INLINE (F2FS)" : "FILE_ENTRY (F2FS)");
                string desc = string.Format("Inode: {0}, Size: {1} bytes, Links: {2}", f.InodeNumber, f.Size, f.Links);
                if (f.ModifiedTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.ModifiedTimeUtc, "F2FS", action + " - Modified", f.FullPath ?? f.Name, desc);
                }
                if (f.CreatedTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.CreatedTimeUtc, "F2FS", action + " - Created", f.FullPath ?? f.Name, desc);
                }
                if (f.AccessedTimeUtc > DateTime.MinValue)
                {
                    AddEvent(f.AccessedTimeUtc, "F2FS", action + " - Accessed", f.FullPath ?? f.Name, desc);
                }
            }
        }

        /// <summary>
        /// Sorts all aggregated events in chronological order.
        /// </summary>
        public void SortChronological(bool ascending = true)
        {
            if (ascending)
            {
                events.Sort((a, b) => a.TimeStampUtc.CompareTo(b.TimeStampUtc));
            }
            else
            {
                events.Sort((a, b) => b.TimeStampUtc.CompareTo(a.TimeStampUtc));
            }
        }

        /// <summary>
        /// Filters events by time window.
        /// </summary>
        public List<ForensicTimelineEvent> FilterByTimeRange(DateTime startUtc, DateTime endUtc)
        {
            var filtered = new List<ForensicTimelineEvent>();
            for (int i = 0; i < events.Count; i++)
            {
                var ev = events[i];
                if (ev.TimeStampUtc >= startUtc && ev.TimeStampUtc <= endUtc)
                {
                    filtered.Add(ev);
                }
            }
            return filtered;
        }

        /// <summary>
        /// Filters events matching a keyword in target path, description, or action.
        /// </summary>
        public List<ForensicTimelineEvent> FilterByKeyword(string keyword)
        {
            var filtered = new List<ForensicTimelineEvent>();
            if (String.IsNullOrEmpty(keyword)) return filtered;

            string q = keyword.ToLowerInvariant();
            for (int i = 0; i < events.Count; i++)
            {
                var ev = events[i];
                if (ev.TargetPath.ToLowerInvariant().Contains(q) ||
                    ev.Description.ToLowerInvariant().Contains(q) ||
                    ev.Action.ToLowerInvariant().Contains(q) ||
                    ev.Source.ToLowerInvariant().Contains(q))
                {
                    filtered.Add(ev);
                }
            }
            return filtered;
        }

        /// <summary>
        /// Exports timeline to standard RFC 4180 CSV for spreadsheet or Autopsy/Plaso import.
        /// </summary>
        public void ExportToCsv(Stream outputStream)
        {
            if (outputStream == null) throw new ArgumentNullException("outputStream");
            using (var writer = new StreamWriter(outputStream, Encoding.UTF8))
            {
                writer.WriteLine("Timestamp (UTC),Source,Action,Target Path,Description,Extra Details");
                for (int i = 0; i < events.Count; i++)
                {
                    var ev = events[i];
                    writer.WriteLine(string.Format(System.Globalization.CultureInfo.InvariantCulture,
                        "\"{0:yyyy-MM-dd HH:mm:ss}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\"",
                        ev.TimeStampUtc,
                        EscapeCsv(ev.Source),
                        EscapeCsv(ev.Action),
                        EscapeCsv(ev.TargetPath),
                        EscapeCsv(ev.Description),
                        EscapeCsv(ev.ExtraDetails)
                    ));
                }
                writer.Flush();
            }
        }

        private static string EscapeCsv(string str)
        {
            if (String.IsNullOrEmpty(str)) return String.Empty;
            return str.Replace("\"", "\"\"").Replace("\r", "").Replace("\n", " ");
        }
    }
}
