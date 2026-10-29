using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    // Reads regular images only. Never opens a physical device and never changes filesystem metadata.
    public static class FilesystemRecovery
    {
        const int MaxDirectories = 10000, MaxEntries = 2000000, MaxClusters = 2000000, MaxCandidates = 100000;
        const long MaxDirectoryBytes = 32L * 1024 * 1024, MaxFileBytes = 64L * 1024 * 1024 * 1024;
        sealed class Candidate
        {
            public string Name, OriginalPath, NameNote;
            public uint Start;
            public long Length, ValidLength;
            public bool Contiguous;
        }
        sealed class DirectoryTask
        {
            public uint Start;
            public long Length;
            public bool Contiguous, Deleted, FixedRoot;
            public string Path;
            public int Depth;
        }
        sealed class Volume
        {
            public long Offset, Length, FatOffset, FatLength, DataOffset, RootOffset, RootBytes, ClusterBytes;
            public uint ClusterCount, RootCluster;
            public int Bits;
            public string Kind;
            public bool Exfat, AllocationComplete = true;
            public int ActiveFat;
            public uint BitmapStart;
            public long BitmapLength;
            public List<uint> BitmapChain;
            public readonly HashSet<uint> LiveClusters = new HashSet<uint>();
            public readonly HashSet<uint> Directories = new HashSet<uint>();
            public readonly List<Candidate> Candidates = new List<Candidate>();
        }
        sealed class ImageReader : IDisposable
        {
            readonly FileStream stream;
            readonly CancellationToken cancel;
            byte[] cached = new byte[65536];
            long cacheOffset = -1;
            int cacheLength;
            public long Length { get { return stream.Length; } }
            public ImageReader(string path, CancellationToken token)
            {
                cancel = token;
                stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.RandomAccess);
            }
            public void Read(long offset, byte[] buffer, int count)
            {
                cancel.ThrowIfCancellationRequested();
                if (offset < 0 || count < 0 || offset > Length - count) throw new InvalidDataException("Image range is outside the file.");
                stream.Position = offset;
                int done = 0;
                while (done < count)
                {
                    cancel.ThrowIfCancellationRequested();
                    int n = stream.Read(buffer, done, count - done);
                    if (n == 0) throw new EndOfStreamException();
                    done += n;
                }
            }
            public byte[] Read(long offset, int count) { byte[] b = new byte[count]; Read(offset, b, count); return b; }
            public uint Integer(long offset, int count)
            {
                if (offset < cacheOffset || offset + count > cacheOffset + cacheLength)
                {
                    cacheOffset = offset - offset % cached.Length;
                    cacheLength = (int)Math.Min(cached.Length, Length - cacheOffset);
                    Read(cacheOffset, cached, cacheLength);
                }
                int p = (int)(offset - cacheOffset);
                if (p + count > cacheLength)
                {
                    byte[] acrossPage = Read(offset, count);
                    uint acrossValue = 0;
                    for (int i = 0; i < count; i++) acrossValue |= (uint)acrossPage[i] << (8 * i);
                    return acrossValue;
                }
                uint result = 0;
                for (int i = 0; i < count; i++) result |= (uint)cached[p + i] << (8 * i);
                return result;
            }
            public void Dispose() { stream.Dispose(); }
        }
        static ushort U16(byte[] b, int p) { return (ushort)(b[p] | b[p + 1] << 8); }
        static uint U32(byte[] b, int p) { return (uint)(b[p] | b[p + 1] << 8 | b[p + 2] << 16 | b[p + 3] << 24); }
        static ulong U64(byte[] b, int p) { return U32(b, p) | ((ulong)U32(b, p + 4) << 32); }
        static bool PowerTwo(long v) { return v > 0 && (v & (v - 1)) == 0; }
        static bool Range(long start, long count, long limit) { return start >= 0 && count >= 0 && start <= limit - count; }
        static bool ClusterValid(Volume v, uint c) { return c >= 2 && c <= v.ClusterCount + 1; }
        static long ClusterOffset(Volume v, uint c)
        {
            if (!ClusterValid(v, c)) throw new InvalidDataException("Cluster is outside the volume.");
            long result = v.DataOffset + ((long)c - 2) * v.ClusterBytes;
            if (!Range(result - v.Offset, v.ClusterBytes, v.Length)) throw new InvalidDataException("Cluster exceeds the volume.");
            return result;
        }
        static uint Fat(ImageReader image, Volume v, uint c)
        {
            if (!ClusterValid(v, c)) return UInt32.MaxValue;
            long at = v.Bits == 12 ? c + c / 2 : (long)c * (v.Bits / 8);
            int bytes = v.Bits == 12 ? 2 : v.Bits / 8;
            if (!Range(at, bytes, v.FatLength)) return UInt32.MaxValue;
            uint value = image.Integer(v.FatOffset + at, bytes);
            if (v.Bits == 12) value = (c & 1) == 0 ? value & 0xFFF : value >> 4;
            if (v.Bits == 32 && !v.Exfat) value &= 0x0FFFFFFF;
            return value;
        }
        static bool End(Volume v, uint value)
        {
            return value >= (v.Exfat ? 0xFFFFFFF8 : v.Bits == 12 ? 0xFF8U : v.Bits == 16 ? 0xFFF8U : 0x0FFFFFF8U);
        }
        static bool ExfatBootChecksum(ImageReader image, long offset, int sectorBytes, long available)
        {
            if (available < sectorBytes * 12L) return false;
            byte[] boot = image.Read(offset, sectorBytes * 11);
            uint checksum = 0;
            for (int i = 0; i < boot.Length; i++)
            {
                if (i == 106 || i == 107 || i == 112) continue;
                checksum = unchecked(((checksum & 1) != 0 ? 0x80000000U : 0) + (checksum >> 1) + boot[i]);
            }
            byte[] checksumSector = image.Read(offset + sectorBytes * 11L, sectorBytes);
            for (int i = 0; i < checksumSector.Length; i += 4) if (U32(checksumSector, i) != checksum) return false;
            return true;
        }
        static uint Crc32(byte[] bytes)
        {
            uint crc = 0xFFFFFFFF;
            for (int p = 0; p < bytes.Length; p++)
            {
                crc ^= bytes[p];
                for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320U : crc >> 1;
            }
            return ~crc;
        }
        static List<uint> Chain(ImageReader image, Volume v, uint first, long length, bool contiguous, out bool complete, CancellationToken cancel)
        {
            var result = new List<uint>();
            var visited = new HashSet<uint>();
            long wanted = length < 0 ? Math.Min(MaxClusters, MaxDirectoryBytes / v.ClusterBytes) : (length + v.ClusterBytes - 1) / v.ClusterBytes;
            complete = false;
            if (wanted == 0) { complete = true; return result; }
            if (wanted > MaxClusters) wanted = MaxClusters;
            uint current = first;
            for (long i = 0; i < wanted; i++)
            {
                cancel.ThrowIfCancellationRequested();
                if (!ClusterValid(v, current) || !visited.Add(current)) return result;
                result.Add(current);
                if (length >= 0 && (long)result.Count * v.ClusterBytes >= length) { complete = true; return result; }
                uint next = contiguous ? current + 1 : Fat(image, v, current);
                if (!contiguous && End(v, next)) { complete = length < 0; return result; }
                current = next;
            }
            return result;
        }
        static bool MarkLive(ImageReader image, Volume v, uint first, long length, bool contiguous, CancellationToken cancel)
        {
            if (length == 0) return true;
            bool complete;
            List<uint> chain = Chain(image, v, first, length, contiguous, out complete, cancel);
            foreach (uint cluster in chain)
            {
                if (v.LiveClusters.Count >= MaxClusters && !v.LiveClusters.Contains(cluster)) { v.AllocationComplete = false; return false; }
                v.LiveClusters.Add(cluster);
            }
            if (!complete) v.AllocationComplete = false;
            return complete;
        }

        static Volume ParseVolume(ImageReader image, long offset, long partitionLength, long bootOffset = -1, int forcedFat = -1)
        {
            if (!Range(offset, 512, image.Length)) return null;
            long boot = bootOffset < 0 ? offset : bootOffset;
            if (!Range(boot, 512, image.Length)) return null;
            byte[] b = image.Read(boot, 512);
            if (b[510] != 0x55 || b[511] != 0xAA) return null;
            long available = Math.Min(image.Length - offset, partitionLength);
            if (Encoding.ASCII.GetString(b, 3, 8) == "EXFAT   ")
            {
                int sectorShift = b[108], clusterShift = b[109], fats = b[110];
                if (sectorShift < 9 || sectorShift > 12 || clusterShift + sectorShift > 25 || fats < 1 || fats > 2 || U16(b, 104) != 0x100) return null;
                for (int i = 11; i < 64; i++) if (b[i] != 0) return null;
                long sector = 1L << sectorShift;
                if (!ExfatBootChecksum(image, boot, (int)sector, image.Length - boot)) return null;
                ulong sectors = U64(b, 72);
                if (sectors > (ulong)(available / sector) || sectors < 24) return null;
                long volumeLength = (long)sectors * sector;
                uint fatSector = U32(b, 80), fatSectors = U32(b, 84), heap = U32(b, 88), clusters = U32(b, 92), root = U32(b, 96);
                long clusterBytes = 1L << (sectorShift + clusterShift);
                int active = (U16(b, 106) & 1);
                if (active >= fats || fatSector < 24 || fatSectors == 0 || clusters == 0 || clusters > 0xFFFFFFF5 || root < 2 || root > clusters + 1) return null;
                if ((ulong)fatSectors * (ulong)sector < ((ulong)clusters + 2) * 4 || (ulong)fatSector + (ulong)fatSectors * (ulong)fats > heap) return null;
                if (!Range((long)heap * sector, (long)clusters * clusterBytes, volumeLength)) return null;
                return new Volume { Offset = offset, Length = volumeLength, Exfat = true, Bits = 32, Kind = "exFAT", ActiveFat = active,
                    FatOffset = offset + ((long)fatSector + (long)active * fatSectors) * sector, FatLength = (long)fatSectors * sector,
                    DataOffset = offset + (long)heap * sector, ClusterBytes = clusterBytes, ClusterCount = clusters, RootCluster = root };
            }
            int bps = U16(b, 11), spc = b[13], reserved = U16(b, 14), numberFats = b[16], rootEntries = U16(b, 17);
            uint total = U16(b, 19); if (total == 0) total = U32(b, 32);
            uint fatSize = U16(b, 22); if (fatSize == 0) fatSize = U32(b, 36);
            if (bps < 512 || bps > 4096 || !PowerTwo(bps) || spc > 128 || !PowerTwo(spc) || reserved == 0 || numberFats < 1 || numberFats > 2 || total == 0 || fatSize == 0) return null;
            long rootSectors = ((long)rootEntries * 32 + bps - 1) / bps;
            long dataSector = reserved + (long)numberFats * fatSize + rootSectors;
            long volumeBytes = (long)total * bps;
            if (dataSector >= total || volumeBytes > available) return null;
            long count = (total - dataSector) / spc;
            int bits = count < 4085 ? 12 : count < 65525 ? 16 : 32;
            if (count < 1 || count > 0x0FFFFFF5 || (bits == 32 && (rootEntries != 0 || U16(b, 22) != 0)) || (bits != 32 && rootEntries == 0)) return null;
            long minimumFatBytes = bits == 12 ? ((count + 2) * 3 + 1) / 2 : (count + 2) * (bits / 8);
            if ((long)fatSize * bps < minimumFatBytes) return null;
            int fatIndex = 0;
            if (bits == 32 && (U16(b, 40) & 0x80) != 0) fatIndex = U16(b, 40) & 0xF;
            if (forcedFat >= 0) fatIndex = forcedFat;
            if (fatIndex >= numberFats) return null;
            uint rootCluster = bits == 32 ? U32(b, 44) & 0x0FFFFFFF : 0;
            if (bits == 32 && (rootCluster < 2 || rootCluster > count + 1)) return null;
            return new Volume { Offset = offset, Length = volumeBytes, Bits = bits, Kind = "FAT" + bits + (forcedFat >= 0 ? "-copy" + (forcedFat + 1) : ""), ClusterCount = (uint)count, ClusterBytes = (long)bps * spc,
                FatOffset = offset + (reserved + (long)fatIndex * fatSize) * bps, FatLength = (long)fatSize * bps, DataOffset = offset + dataSector * bps,
                RootOffset = offset + (reserved + (long)numberFats * fatSize) * bps, RootBytes = (long)rootEntries * 32, RootCluster = rootCluster };
        }
        sealed class Partition { public long Offset, Length; }
        static List<Volume> Discover(ImageReader image, List<string> notes, CancellationToken cancel, IList<BootCandidate> discovered = null, bool alternateFat = false)
        {
            var partitions = new List<Partition>();
            partitions.Add(new Partition { Offset = 0, Length = image.Length });
            if (image.Length >= 512)
            {
                byte[] mbr = image.Read(0, 512);
                if (mbr[510] == 0x55 && mbr[511] == 0xAA)
                    for (int i = 0; i < 4; i++)
                    {
                        int at = 446 + i * 16;
                        if (mbr[at + 4] == 0 || U32(mbr, at + 8) == 0 || U32(mbr, at + 12) == 0) continue;
                        foreach (int sector in new int[] { 512, 4096 })
                        {
                            long offset = (long)U32(mbr, at + 8) * sector, length = (long)U32(mbr, at + 12) * sector;
                            if (Range(offset, length, image.Length)) partitions.Add(new Partition { Offset = offset, Length = length });
                        }
                    }
            }
            foreach (int sector in new int[] { 512, 4096 })
            {
                cancel.ThrowIfCancellationRequested();
                if (image.Length < sector + 92) continue;
                byte[] header = image.Read(sector, 92);
                if (Encoding.ASCII.GetString(header, 0, 8) != "EFI PART") continue;
                uint size = U32(header, 12), entries = U32(header, 80), entryBytes = U32(header, 84);
                ulong tableLba = U64(header, 72);
                if (size < 92 || size > sector || U64(header, 24) != 1 || entries > 4096 || entryBytes < 128 || entryBytes > 4096 || entries * (ulong)entryBytes > 4 * 1024 * 1024 || tableLba > (ulong)(image.Length / sector)) continue;
                long table = (long)tableLba * sector;
                if (!Range(table, (long)entries * entryBytes, image.Length)) continue;
                byte[] fullHeader = image.Read(sector, (int)size);
                uint expectedHeaderCrc = U32(fullHeader, 16);
                for (int i = 16; i < 20; i++) fullHeader[i] = 0;
                if (Crc32(fullHeader) != expectedHeaderCrc || Crc32(image.Read(table, (int)(entries * entryBytes))) != U32(header, 88))
                { notes.Add("GPT checksum validation failed; partition entries not trusted."); continue; }
                for (uint i = 0; i < entries; i++)
                {
                    cancel.ThrowIfCancellationRequested();
                    byte[] entry = image.Read(table + i * (long)entryBytes, 48);
                    bool empty = true; for (int p = 0; p < 16; p++) if (entry[p] != 0) empty = false;
                    if (empty) continue;
                    ulong first = U64(entry, 32), last = U64(entry, 40);
                    if (last < first || last >= (ulong)(image.Length / sector)) continue;
                    partitions.Add(new Partition { Offset = (long)first * sector, Length = (long)(last - first + 1) * sector });
                }
            }
            var volumes = new List<Volume>();
            var offsets = new HashSet<long>();
            foreach (Partition p in partitions)
            {
                cancel.ThrowIfCancellationRequested();
                if (!offsets.Add(p.Offset)) continue;
                Volume volume = ParseVolume(image, p.Offset, p.Length);
                if (volume != null) { volumes.Add(volume); continue; }
                if (Range(p.Offset, 11, image.Length) && Encoding.ASCII.GetString(image.Read(p.Offset, 11), 3, 8) == "NTFS    ")
                    notes.Add("NTFS at offset " + p.Offset + ": metadata recovery is not implemented; use the signature scan / TestDisk.");
            }
            // Bounded fallback for damaged/missing partition tables, never a whole-image boot-sector sweep.
            if (volumes.Count == 0)
            {
                long limit = Math.Min(image.Length - 512, 1024 * 1024);
                for (long p = 512; p <= limit && volumes.Count < 16; p += 512)
                {
                    cancel.ThrowIfCancellationRequested();
                    bool inside = false; foreach (Volume existing in volumes) if (p >= existing.Offset && p < existing.Offset + existing.Length) inside = true;
                    if (inside) continue;
                    Volume found = ParseVolume(image, p, image.Length - p);
                    if (found != null) { volumes.Add(found); notes.Add("Volume found by bounded boot-sector search at offset " + p + "."); }
                }
            }
            if (discovered != null) foreach (var boot in discovered.Where(x => x.Kind != "NTFS")) {
                cancel.ThrowIfCancellationRequested();
                if (volumes.Any(v => v.Offset == boot.Offset)) continue;
                Volume recovered = ParseVolume(image, boot.Offset, boot.Length, boot.BootOffset);
                if (recovered != null) { volumes.Add(recovered); notes.Add("Full-image boot search: " + boot.Origin + " at " + boot.Offset + ", boot=" + boot.BootOffset + "."); }
            }
            if (alternateFat) foreach (var original in volumes.ToArray()) {
                if (original.Exfat) continue;
                var known = discovered == null ? null : discovered.FirstOrDefault(x => x.Offset == original.Offset);
                long boot = known == null ? original.Offset : known.BootOffset;
                byte[] header = image.Read(boot, 512);
                if (header[16] != 2) continue;
                long fatBytes = original.FatLength; int current = original.FatOffset == original.Offset + (long)U16(header,14) * U16(header,11) ? 0 : 1;
                Volume alternate = ParseVolume(image, original.Offset, original.Length, boot, 1 - current);
                if (alternate != null && alternate.FatOffset != original.FatOffset && fatBytes == alternate.FatLength) { volumes.Add(alternate); notes.Add("Alternative FAT copy used independently at " + original.Offset + "; candidates require verification."); }
            }
            return volumes;
        }
        static byte[] DirectoryBytes(ImageReader image, Volume v, DirectoryTask task, CancellationToken cancel)
        {
            if (task.FixedRoot) return image.Read(v.RootOffset, (int)v.RootBytes);
            bool complete;
            long length = task.Length > 0 ? task.Length : -1;
            List<uint> clusters = Chain(image, v, task.Start, length, task.Contiguous, out complete, cancel);
            if (!complete) v.AllocationComplete = false;
            long bytes = Math.Min(MaxDirectoryBytes, (long)clusters.Count * v.ClusterBytes);
            if (task.Length > 0) bytes = Math.Min(bytes, task.Length);
            if (bytes < 0 || bytes > Int32.MaxValue) return new byte[0];
            byte[] result = new byte[(int)bytes];
            int position = 0;
            foreach (uint c in clusters)
            {
                cancel.ThrowIfCancellationRequested();
                if (position >= result.Length) break;
                int n = (int)Math.Min(v.ClusterBytes, result.Length - position);
                byte[] buffer = image.Read(ClusterOffset(v, c), n);
                Buffer.BlockCopy(buffer, 0, result, position, n);
                position += n;
            }
            return result;
        }
        static string ShortName(byte[] data, int at, bool deleted)
        {
            byte[] name = new byte[11]; Buffer.BlockCopy(data, at, name, 0, 11);
            if (deleted) name[0] = (byte)'_'; else if (name[0] == 5) name[0] = 0xE5;
            // OEM code page 866 is available in the Windows Framework and preserves Russian short names.
            string stem = Encoding.GetEncoding(866).GetString(name, 0, 8).TrimEnd(' '), ext = Encoding.GetEncoding(866).GetString(name, 8, 3).TrimEnd(' ');
            if (stem.Length == 0) return "unnamed";
            return stem + (ext.Length == 0 ? "" : "." + ext);
        }
        static bool ValidShortName(byte[] bytes, int at, bool deleted)
        {
            for (int i = 0; i < 11; i++)
            {
                if (i == 0 && (deleted || bytes[at] == 5)) continue;
                byte value = bytes[at + i];
                if (value < 32 || value == 127 || (value < 128 && "\"*+,./:;<=>?[\\]|".IndexOf((char)value) >= 0)) return false;
            }
            return true;
        }
        static int ShortChecksum(byte[] data, int at, int first)
        {
            int sum = 0;
            for (int i = 0; i < 11; i++) sum = (((sum & 1) != 0 ? 128 : 0) + (sum >> 1) + (i == 0 ? first : data[at + i])) & 255;
            return sum;
        }
        static string LongDeletedName(byte[] data, int shortAt, List<int> parts)
        {
            if (parts.Count == 0 || parts.Count > 20) return null;
            byte checksum = data[parts[0] + 13];
            foreach (int at in parts) if (data[at] != 0xE5 || data[at + 13] != checksum || data[at + 12] != 0 || U16(data, at + 26) != 0) return null;
            bool match = false;
            for (int first = 1; first < 256; first++) if (first != 0xE5 && ShortChecksum(data, shortAt, first) == checksum) { match = true; break; }
            if (!match) return null;
            var text = new StringBuilder();
            int[] locations = new int[] { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
            bool end = false;
            for (int p = parts.Count - 1; p >= 0; p--)
                foreach (int within in locations)
                {
                    ushort c = U16(data, parts[p] + within);
                    if (c == 0 || c == 0xFFFF) { end = true; continue; }
                    if (end || c < 32) return null;
                    text.Append((char)c);
                }
            return text.Length > 0 && text.Length <= 255 ? text.ToString() : null;
        }
        static void FatDirectory(ImageReader image, Volume v, byte[] bytes, DirectoryTask parent, Queue<DirectoryTask> queue, ref int entries, CancellationToken cancel)
        {
            var lfn = new List<int>();
            for (int at = 0; at + 32 <= bytes.Length; at += 32)
            {
                cancel.ThrowIfCancellationRequested();
                if (++entries > MaxEntries) { v.AllocationComplete = false; break; }
                byte first = bytes[at], attr = bytes[at + 11];
                if (first == 0) break;
                if (attr == 0x0F)
                {
                    if (first == 0xE5 && lfn.Count < 20) lfn.Add(at); else lfn.Clear();
                    continue;
                }
                bool deleted = first == 0xE5, directory = (attr & 0x10) != 0;
                if ((attr & 0xC8) != 0 || first == '.' || (!deleted && first < 32)) { lfn.Clear(); continue; }
                if (!ValidShortName(bytes, at, deleted)) { if (!deleted && !parent.Deleted) v.AllocationComplete = false; lfn.Clear(); continue; }
                string name = ShortName(bytes, at, deleted), longName = deleted ? LongDeletedName(bytes, at, lfn) : null;
                lfn.Clear();
                uint start = U16(bytes, at + 26); if (v.Bits == 32) start |= (uint)U16(bytes, at + 20) << 16;
                if (v.Bits == 32) start &= 0x0FFFFFFF;
                long length = U32(bytes, at + 28);
                if (!ClusterValid(v, start) && length != 0) continue;
                if (longName != null) name = longName;
                string original = parent.Path + "/" + name;
                if (directory)
                {
                    if (!deleted && !parent.Deleted) MarkLive(image, v, start, -1, false, cancel);
                    if (ClusterValid(v, start) && parent.Depth < 64 && queue.Count < MaxDirectories && v.Directories.Add(start))
                        queue.Enqueue(new DirectoryTask { Start = start, Deleted = deleted || parent.Deleted, Path = original, Depth = parent.Depth + 1 });
                    else if (parent.Depth >= 64 || queue.Count >= MaxDirectories || !deleted && !parent.Deleted) v.AllocationComplete = false;
                    continue;
                }
                if (!deleted && !parent.Deleted)
                {
                    if (!parent.Deleted) MarkLive(image, v, start, length, false, cancel);
                    continue;
                }
                if (length > 0)
                {
                    if (v.Candidates.Count >= MaxCandidates) v.AllocationComplete = false;
                    else v.Candidates.Add(new Candidate { Name = name, OriginalPath = original, Start = start, Length = length, ValidLength = length,
                        NameNote = parent.Deleted ? "from removed/unlinked directory; original parent and file deletion state unknown" : longName == null ? "short name: first character lost" : "surviving long name; deleted LFN order inferred" });
                }
            }
        }
        static ushort ExfatChecksum(byte[] bytes, int at, int count, bool undelete)
        {
            int checksum = 0;
            for (int i = 0; i < count; i++)
            {
                if (i == 2 || i == 3) continue;
                byte value = bytes[at + i]; if (undelete && i % 32 == 0) value |= 0x80;
                checksum = (((checksum & 1) != 0 ? 0x8000 : 0) + (checksum >> 1) + value) & 0xFFFF;
            }
            return (ushort)checksum;
        }
        static void ExfatDirectory(ImageReader image, Volume v, byte[] bytes, DirectoryTask parent, Queue<DirectoryTask> queue, ref int entries, CancellationToken cancel)
        {
            for (int at = 0; at + 32 <= bytes.Length; at += 32)
            {
                cancel.ThrowIfCancellationRequested();
                if (++entries > MaxEntries) { v.AllocationComplete = false; break; }
                byte type = bytes[at]; if (type == 0) break;
                if (type == 0x81 && parent.Depth == 0 && (bytes[at + 1] & 1) == v.ActiveFat)
                {
                    ulong size = U64(bytes, at + 24);
                    if (size >= ((ulong)v.ClusterCount + 7) / 8 && size <= (ulong)MaxDirectoryBytes)
                    { v.BitmapStart = U32(bytes, at + 20); v.BitmapLength = (long)size; }
                }
                if (type != 0x85 && type != 0x05) continue;
                bool deleted = type == 0x05;
                int secondary = bytes[at + 1], setBytes = (secondary + 1) * 32;
                if (secondary < 2 || secondary > 18 || at > bytes.Length - setBytes) { if (!deleted && !parent.Deleted) v.AllocationComplete = false; continue; }
                byte streamType = (byte)(deleted ? 0x40 : 0xC0), nameType = (byte)(deleted ? 0x41 : 0xC1);
                if (bytes[at + 32] != streamType || (bytes[at + 33] & 1) == 0 || ExfatChecksum(bytes, at, setBytes, deleted) != U16(bytes, at + 2))
                { if (!deleted && !parent.Deleted) v.AllocationComplete = false; at += setBytes - 32; continue; }
                int nameLength = bytes[at + 35];
                var name = new StringBuilder(); bool valid = nameLength > 0;
                for (int item = 2; item <= secondary; item++)
                {
                    int part = at + item * 32;
                    if (bytes[part] != nameType) { valid = false; break; }
                    for (int i = 0; i < 15 && name.Length < nameLength; i++)
                    { ushort c = U16(bytes, part + 2 + i * 2); if (c < 32 || c == 0xFFFF) valid = false; name.Append((char)c); }
                }
                ulong unsignedLength = U64(bytes, at + 56), unsignedValid = U64(bytes, at + 40);
                uint start = U32(bytes, at + 52);
                bool contiguous = (bytes[at + 33] & 2) != 0, directory = (U16(bytes, at + 4) & 0x10) != 0;
                if (!valid || name.Length != nameLength || unsignedLength > (ulong)MaxFileBytes || unsignedValid > unsignedLength || (unsignedLength != 0 && !ClusterValid(v, start)))
                { if (!deleted && !parent.Deleted) v.AllocationComplete = false; at += setBytes - 32; continue; }
                long length = (long)unsignedLength;
                string original = parent.Path + "/" + name;
                if (directory)
                {
                    if (!deleted && !parent.Deleted) MarkLive(image, v, start, length, contiguous, cancel);
                    if (length > 0 && length <= MaxDirectoryBytes && parent.Depth < 64 && queue.Count < MaxDirectories && v.Directories.Add(start))
                        queue.Enqueue(new DirectoryTask { Start = start, Length = length, Contiguous = contiguous, Deleted = deleted || parent.Deleted, Path = original, Depth = parent.Depth + 1 });
                    else if (length > MaxDirectoryBytes || parent.Depth >= 64 || queue.Count >= MaxDirectories || !deleted && !parent.Deleted) v.AllocationComplete = false;
                }
                else if (!deleted) { if (!parent.Deleted) MarkLive(image, v, start, length, contiguous, cancel); }
                else if (length > 0)
                {
                    if (v.Candidates.Count >= MaxCandidates) v.AllocationComplete = false;
                    else v.Candidates.Add(new Candidate { Name = name.ToString(), OriginalPath = original, Start = start, Length = length, ValidLength = (long)unsignedValid,
                        Contiguous = contiguous, NameNote = "surviving Unicode name; entry-set checksum verified after restoring InUse bits" });
                }
                at += setBytes - 32;
            }
        }
        static void Enumerate(ImageReader image, Volume v, List<string> notes, CancellationToken cancel)
        {
            var queue = new Queue<DirectoryTask>();
            queue.Enqueue(new DirectoryTask { FixedRoot = !v.Exfat && v.Bits != 32, Start = v.RootCluster, Path = "", Depth = 0 });
            if (v.RootCluster != 0) { v.Directories.Add(v.RootCluster); MarkLive(image, v, v.RootCluster, -1, false, cancel); }
            int visited = 0, entries = 0;
            while (queue.Count > 0 && visited < MaxDirectories && entries < MaxEntries)
            {
                cancel.ThrowIfCancellationRequested();
                DirectoryTask task = queue.Dequeue(); visited++;
                byte[] bytes = DirectoryBytes(image, v, task, cancel);
                if (v.Exfat) ExfatDirectory(image, v, bytes, task, queue, ref entries, cancel);
                else FatDirectory(image, v, bytes, task, queue, ref entries, cancel);
            }
            if (queue.Count > 0 || entries >= MaxEntries) { v.AllocationComplete = false; notes.Add(v.Kind + ": directory traversal limit reached; allocated FAT candidates will be skipped."); }
            if (v.Exfat && v.BitmapStart != 0)
            {
                bool complete;
                v.BitmapChain = Chain(image, v, v.BitmapStart, v.BitmapLength, false, out complete, cancel);
                if (!complete) { v.BitmapChain = null; v.AllocationComplete = false; notes.Add("exFAT: allocation bitmap is truncated or corrupt; deleted candidates will be skipped."); }
            }
            if (v.Exfat && v.BitmapChain == null) { v.AllocationComplete = false; notes.Add("exFAT: no valid active allocation bitmap; deleted candidates will be skipped."); }
            if (!v.AllocationComplete) notes.Add(v.Kind + ": current allocation ownership could not be completely enumerated.");
            notes.Add(v.Kind + " at offset " + v.Offset + ": " + visited + " directories, " + v.Candidates.Count + " deleted file records.");
        }
        static bool BitmapAllocated(ImageReader image, Volume v, uint c)
        {
            if (v.BitmapChain == null) return true;
            long bit = (long)c - 2, byteIndex = bit / 8, chainIndex = byteIndex / v.ClusterBytes;
            if (byteIndex >= v.BitmapLength || chainIndex >= v.BitmapChain.Count) return true;
            long offset = ClusterOffset(v, v.BitmapChain[(int)chainIndex]) + byteIndex % v.ClusterBytes;
            return (image.Integer(offset, 1) & (1U << (int)(bit % 8))) != 0;
        }
        static void OrphanDirectories(ImageReader image,Volume v,List<string> notes,CancellationToken cancel,Action<string> progress)
        {
            if(v.Exfat){notes.Add("Orphan-directory sweep: exFAT is not supported by this detector.");return;}
            if(!v.AllocationComplete){notes.Add("Orphan-directory sweep skipped: live ownership incomplete.");return;}
            int found=0,entries=0;long visited=0;byte[] dot=Encoding.ASCII.GetBytes(".          "),dotdot=Encoding.ASCII.GetBytes("..         ");
            long chunk=Math.Max(4L*1024*1024,v.ClusterBytes);byte[] data=new byte[(int)chunk];
            for(long first=0;first<v.ClusterCount;){
                cancel.ThrowIfCancellationRequested();int clusters=(int)Math.Min(chunk/v.ClusterBytes,v.ClusterCount-first);int count=(int)(clusters*v.ClusterBytes);image.Read(v.DataOffset+first*v.ClusterBytes,data,count);
                for(int c=0;c<clusters;c++){
                    uint cluster=(uint)(first+c+2);int at=(int)(c*v.ClusterBytes);if(v.Directories.Contains(cluster)||v.LiveClusters.Contains(cluster))continue;
                    bool signature=true;for(int n=0;n<11;n++)if(data[at+n]!=dot[n]||data[at+32+n]!=dotdot[n]){signature=false;break;}
                    if(!signature||data[at+11]!=0x10||data[at+43]!=0x10||U32(data,at+28)!=0||U32(data,at+60)!=0)continue;
                    uint self=U16(data,at+26),parent=U16(data,at+58);if(v.Bits==32){self|=(uint)U16(data,at+20)<<16;parent|=(uint)U16(data,at+52)<<16;}
                    if(self!=cluster||(parent!=0&&!ClusterValid(v,parent))||data[at+64]==0)continue;
                    bool useful=false;for(int entry=64;entry+32<=Math.Min(v.ClusterBytes,4096);entry+=32){if(data[at+entry]==0)break;if(data[at+entry+11]!=0x0f&&ValidShortName(data,at+entry,data[at+entry]==0xe5)&&(data[at+entry+11]&0xc8)==0){useful=true;break;}}
                    if(!useful)continue;
                    var queue=new Queue<DirectoryTask>();v.Directories.Add(cluster);queue.Enqueue(new DirectoryTask{Start=cluster,Deleted=true,Path="/orphan-directory-cluster-"+cluster,Depth=0});
                    while(queue.Count>0&&visited<MaxDirectories&&entries<MaxEntries){cancel.ThrowIfCancellationRequested();var task=queue.Dequeue();visited++;var bytes=DirectoryBytes(image,v,task,cancel);FatDirectory(image,v,bytes,task,queue,ref entries,cancel);}
                    found++;if(found>=10000||visited>=MaxDirectories||entries>=MaxEntries){notes.Add("Orphan-directory sweep limit reached.");v.AllocationComplete=false;return;}
                }
                first+=clusters;if(progress!=null)progress("Потерянные каталоги FAT: "+(first*100/Math.Max(1,v.ClusterCount))+"%");
            }
            notes.Add("Orphan-directory candidates: "+found+". Parent/deletion state not inferred; live clusters excluded.");
        }
        static string SafeName(string name)
        {
            var clean = new StringBuilder();
            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (Char.IsHighSurrogate(c))
                {
                    if (i + 1 < name.Length && Char.IsLowSurrogate(name[i + 1])) { clean.Append(c); clean.Append(name[++i]); }
                    else clean.Append('_');
                }
                else clean.Append(c < 32 || Char.IsLowSurrogate(c) || "<>:\"/\\|?*".IndexOf(c) >= 0 ? '_' : c);
            }
            string result = clean.ToString().Trim(' ', '.');
            if (result.Length > 120)
            {
                string extension = Path.GetExtension(result);
                if (extension.Length > 16) extension = "";
                int stemLength = 120 - extension.Length;
                if (Char.IsHighSurrogate(result[stemLength - 1])) stemLength--;
                result = result.Substring(0, stemLength) + extension;
            }
            return result.Length == 0 ? "unnamed" : result;
        }
        static string Quote(string value) { return "\"" + (value ?? "").Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ") + "\""; }
        static string OutputPath(string root, string child)
        {
            string path = Path.GetFullPath(Path.Combine(root, child));
            if (!path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Output path escapes the recovery directory.");
            return path;
        }
        static void RejectReparseParents(string path)
        {
            string current = Path.GetFullPath(path);
            while (!String.IsNullOrEmpty(current))
            {
                if ((Directory.Exists(current) || File.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Recovery paths must not contain junctions or symbolic links.");
                DirectoryInfo parent = Directory.GetParent(current); current = parent == null ? null : parent.FullName;
            }
        }
        static long RecoverCandidate(ImageReader image, Volume v, Candidate candidate, string volumeDirectory, int number, StreamWriter csv, CancellationToken cancel, StreamWriter evidence, string runRoot)
        {
            bool contiguous = candidate.Contiguous;
            string method, reason = "", status = "candidate", output = "";
            long written = 0;
            var ranges = new List<FileExtent>();
            bool mappingComplete = true;
            string copiedSha256 = null;
            bool complete;
            if (candidate.Length <= 0 || candidate.Length > MaxFileBytes || candidate.Length > v.Length) reason = "invalid size";
            else if (v.Exfat && v.BitmapChain == null) reason = "allocation bitmap unavailable";
            if (v.Exfat) method = contiguous ? "exfat-contiguous" : "exfat-fat-chain";
            else
            {
                uint firstFat = Fat(image, v, candidate.Start);
                contiguous = firstFat == 0;
                method = contiguous ? "contiguous-guess" : "retained-fat-uncertain";
                if (!contiguous && !v.AllocationComplete) reason = "current ownership incomplete; retained FAT allocation not safe to attribute";
            }
            if (reason.Length == 0)
            {
                List<uint> chain = Chain(image, v, candidate.Start, candidate.Length, contiguous, out complete, cancel);
                var accepted = new List<uint>();
                foreach (uint c in chain)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (v.LiveClusters.Contains(c)) { reason = "cluster currently owned by a live file/directory"; break; }
                    if (v.Exfat && BitmapAllocated(image, v, c)) { reason = "cluster marked allocated in active exFAT bitmap"; break; }
                    if (!v.Exfat && contiguous && Fat(image, v, c) != 0) { reason = "cluster currently allocated in FAT; contiguous reconstruction stopped"; break; }
                    accepted.Add(c);
                }
                if (accepted.Count > 0)
                {
                    bool partial = !complete || accepted.Count != chain.Count || (long)accepted.Count * v.ClusterBytes < candidate.Length;
                    status = partial ? "partial" : (method == "contiguous-guess" || method == "retained-fat-uncertain" ? "uncertain" : "candidate");
                    if (reason.Length == 0 && !complete) reason = "incomplete/corrupt cluster chain";
                    if(candidate.OriginalPath.StartsWith("/orphan-directory-",StringComparison.Ordinal))method="orphan-"+method;
                    string directory = OutputPath(volumeDirectory, method);
                    RejectReparseParents(directory); Directory.CreateDirectory(directory);
                    string prefix = number.ToString("D6", CultureInfo.InvariantCulture) + (partial ? "_PARTIAL_" : "_");
                    output = OutputPath(directory, prefix + SafeName(candidate.Name));
                    RejectReparseParents(output);
                    string temporary = output + "." + Guid.NewGuid().ToString("N") + ".partial";
                    try
                    {
                        using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        using (var hash = System.Security.Cryptography.SHA256.Create())
                        {
                            byte[] buffer = new byte[(int)Math.Min(1024 * 1024, v.ClusterBytes)];
                            foreach (uint c in accepted)
                            {
                                cancel.ThrowIfCancellationRequested();
                                long offset = ClusterOffset(v, c), amount = Math.Min(v.ClusterBytes, candidate.Length - written);
                                long position = 0;
                                while (position < amount)
                                {
                                    int count = (int)Math.Min(buffer.Length, amount - position);
                                    // exFAT bytes after ValidDataLength are uninitialized and must read as zero.
                                    long valid = Math.Max(0, Math.Min(count, candidate.ValidLength - written));
                                    if (valid > 0) {
                                        image.Read(offset + position, buffer, (int)valid);
                                        long sourceOffset=offset+position;
                                        if(ranges.Count>0 && ranges[ranges.Count-1].Offset+ranges[ranges.Count-1].Length==sourceOffset)ranges[ranges.Count-1].Length+=valid;
                                        else if(ranges.Count<100000)ranges.Add(new FileExtent{Offset=sourceOffset,Length=valid});
                                        else mappingComplete=false;
                                    }
                                    if (valid < count) Array.Clear(buffer, (int)valid, count - (int)valid);
                                    file.Write(buffer, 0, count); hash.TransformBlock(buffer,0,count,null,0); written += count; position += count;
                                }
                            }
                            hash.TransformFinalBlock(new byte[0],0,0);copiedSha256=BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
                        }
                        cancel.ThrowIfCancellationRequested();
                        File.Move(temporary, output);
                    }
                    catch { if (File.Exists(temporary)) File.Delete(temporary); throw; }
                }
                else status = "skipped";
            }
            else status = "skipped";
            if (method == "retained-fat-uncertain" && reason.Length == 0) reason = "FAT chain retained but allocation is ambiguous; no known live owner; content not validated";
            if (method == "contiguous-guess" && reason.Length == 0) reason = "FAT chain erased; consecutive free clusters assumed; fragmentation cannot be reconstructed";
            if (v.Exfat && reason.Length == 0) reason = "metadata checksum and allocation checked; content may still be overwritten";
            csv.WriteLine(Quote(v.Kind) + "," + v.Offset + "," + Quote(candidate.OriginalPath) + "," + candidate.Start + "," + candidate.Length + "," + written + "," + Quote(method) + "," + Quote(status) + "," + Quote(reason) + "," + Quote(candidate.NameNote) + "," + Quote(output));
            csv.Flush();
            if(written>0) {
                evidence.WriteLine(new System.Web.Script.Serialization.JavaScriptSerializer { MaxJsonLength=16*1024*1024 }.Serialize(new { path=output.Substring(runRoot.TrimEnd('\\').Length+1).Replace('\\','/'),ranges=ranges,mappingComplete=mappingComplete,status=status,expectedBytes=candidate.Length,bytes=written,sha256=copiedSha256,originalPath=candidate.OriginalPath,volumeOffset=v.Offset,nameEvidence=candidate.NameNote,initializedBytes=Math.Min(candidate.ValidLength,written),note="Ranges identify source bytes copied, not proof of original content. Bytes after exFAT valid-data length are logical zeroes." }));
                evidence.Flush();
            }
            return written;
        }

        public static int Recover(string imagePath, string runDirectory, CancellationToken cancel, Action<string> progress)
        { return Recover(imagePath, runDirectory, cancel, progress, null, false); }
        public static int Recover(string imagePath, string runDirectory, CancellationToken cancel, Action<string> progress, IList<BootCandidate> discovered, bool alternateFat, bool orphanDirectories = false)
        {
            cancel.ThrowIfCancellationRequested();
            string imageFull = Path.GetFullPath(imagePath), runFull = Path.GetFullPath(runDirectory);
            if (imageFull.StartsWith("\\\\", StringComparison.Ordinal) || imageFull.IndexOf(':', 2) >= 0 || !File.Exists(imageFull) || (File.GetAttributes(imageFull) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Filesystem recovery requires a regular local image file.");
            RejectReparseParents(imageFull); RejectReparseParents(runFull);
            string recoveryRoot = OutputPath(runFull, "filesystem");
            if (imageFull.Equals(recoveryRoot, StringComparison.OrdinalIgnoreCase) || imageFull.StartsWith(recoveryRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Source image must be outside the recovery output directory.");
            if (Directory.Exists(recoveryRoot)) throw new IOException("Filesystem output directory already exists; choose a fresh recovery run.");
            Directory.CreateDirectory(recoveryRoot);
            var notes = new List<string>();
            int recovered = 0, number = 0;
            long recoveredBytes = 0;
            int supportedVolumes = 0;
            bool limited = false, completed = false;
            try
            {
                using (var image = new ImageReader(imageFull, cancel))
                using (var csv = new StreamWriter(Path.Combine(recoveryRoot, "metadata.csv"), false, new UTF8Encoding(true)))
                using (var evidence = new StreamWriter(Path.Combine(recoveryRoot, "file-extents.jsonl"), false, new UTF8Encoding(false)))
                {
                    csv.WriteLine("filesystem,volume_offset,original_path,start_cluster,expected_bytes,recovered_bytes,method,status,reason,name_evidence,output_path");
                    List<Volume> volumes = Discover(image, notes, cancel, discovered, alternateFat);
                    supportedVolumes = volumes.Count;
                    if (volumes.Count == 0) notes.Add("No supported FAT/exFAT volume found. Signature recovery remains available; damaged boot metadata and NTFS are outside this parser's scope.");
                    for (int i = 0; i < volumes.Count; i++)
                    {
                        cancel.ThrowIfCancellationRequested();
                        Volume volume = volumes[i];
                        if (progress != null) progress("Поиск удалённых записей " + volume.Kind + "…");
                        Enumerate(image, volume, notes, cancel);
                        if(orphanDirectories)OrphanDirectories(image,volume,notes,cancel,progress);
                        if (!volume.AllocationComplete) limited = true;
                        string filesDirectory = OutputPath(recoveryRoot, "files");
                        Directory.CreateDirectory(filesDirectory);
                        string volumeDirectory = OutputPath(filesDirectory, "volume-" + (i + 1).ToString("D3") + "-" + volume.Kind);
                        Directory.CreateDirectory(volumeDirectory);
                        foreach (Candidate candidate in volume.Candidates)
                        {
                            cancel.ThrowIfCancellationRequested();
                            if (number >= MaxCandidates || candidate.Length > image.Length * 2L - recoveredBytes) { limited = true; notes.Add("Recovery output budget reached; remaining metadata candidates not exported."); break; }
                            long bytes = RecoverCandidate(image, volume, candidate, volumeDirectory, ++number, csv, cancel, evidence, runFull);
                            if (bytes > 0) { recovered++; recoveredBytes += bytes; }
                            if (number % 100 == 0 && progress != null) progress("По метаданным сохранено: " + recovered + "; проверено записей: " + number);
                        }
                        // Drop potentially large ownership/name collections before the next independent partition.
                        volumes[i] = null;
                    }
                }
                notes.Add((limited ? "Incomplete metadata scan. " : "Completed. ") + "Exported " + recovered + " metadata candidates (including partial/uncertain files), " + recoveredBytes + " bytes. No content-integrity guarantee.");
                completed = !limited;
            }
            catch (OperationCanceledException) { notes.Add("Cancelled. Previously completed exports retained. The current interrupted export was removed."); throw; }
            catch (Exception ex) { limited = true; notes.Add("Metadata recovery interrupted: " + ex.Message); throw; }
            finally
            {
                string explanation = "ПОИСК ПО ЗАПИСЯМ ФАЙЛОВОЙ СИСТЕМЫ\r\n\r\n" +
                    "Исходный образ открыт только для чтения. Здесь находятся файлы с сохранившимися удалёнными записями FAT12/FAT16/FAT32/exFAT. Имена и путь из записей перечислены в metadata.csv.\r\n" +
                    "contiguous-guess: цепочка FAT стёрта; предполагается последовательное расположение. Фрагментированный файл так восстановить нельзя.\r\n" +
                    "retained-fat-uncertain: цепочка FAT сохранилась, но принадлежность выделенных кластеров неоднозначна; известные текущие файлы исключены.\r\n" +
                    "exfat-contiguous / exfat-fat-chain: используются сведения exFAT и карта занятости; занятые кластеры не копируются.\r\n" +
                    "PARTIAL: сохранена только безопасная начальная часть. Удалённые короткие имена FAT теряют первый символ. Длинные имена могут сохраниться, но порядок удалённых LFN-записей выводится по их расположению.\r\n" +
                    "Отсутствие занятости не доказывает сохранность данных. Статус candidate означает найденный вариант, а не гарантированное восстановление. NTFS, повреждённые загрузочные записи и сложные утраченные цепочки требуют отдельного поиска.\r\n\r\n" + String.Join("\r\n", notes.ToArray());
                File.WriteAllText(Path.Combine(recoveryRoot, "ПРОЧИТАЙ О РЕЗУЛЬТАТАХ.txt"), explanation, new UTF8Encoding(true));
                File.WriteAllText(Path.Combine(recoveryRoot, "report.json"), "{\"supportedVolumes\":" + supportedVolumes + ",\"recovered\":" + recovered +
                    ",\"recoveredBytes\":" + recoveredBytes + ",\"limited\":" + (limited ? "true" : "false") + ",\"completed\":" + (completed ? "true" : "false") + "}", new UTF8Encoding(false));
            }
            if (limited) throw new IOException("Поиск по метаданным завершён частично: повреждение или предел обработки. Сохранённые кандидаты и отчёт доступны в filesystem.");
            return recovered;
        }
    }
}
