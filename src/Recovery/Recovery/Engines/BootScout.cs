using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    public sealed class BootCandidate
    {
        public long Offset, BootOffset, Length;
        public int SectorSize;
        public string Kind, Origin;
    }
    // Detection only: no partition table/boot/FAT repair on an input image.
    public static class BootScout
    {
        public const int MaximumVolumes = 128;
        static bool Power(int n) { return n > 0 && (n & (n - 1)) == 0; }
        public static List<BootCandidate> Find(string image, CancellationToken cancel, Action<long, long> progress)
        {
            if(!File.Exists(image)||image.StartsWith(@"\\",StringComparison.Ordinal)||Path.GetFullPath(image).IndexOf(':',2)>=0)throw new IOException("Разделы ищутся только в обычном локальном образе.");
            var found = new List<BootCandidate>();
            using (var stream = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 4 * 1024 * 1024)) {
                byte[] block = new byte[4 * 1024 * 1024]; long position = 0; int read;
                while ((read = stream.Read(block, 0, block.Length)) > 0) {
                    cancel.ThrowIfCancellationRequested();
                    for (int at = 0; at + 512 <= read; at += 512) {
                        if (block[at + 510] != 0x55 || block[at + 511] != 0xaa) continue;
                        byte[] boot = new byte[512]; Buffer.BlockCopy(block, at, boot, 0, 512);
                        long offset = position + at;
                        BootCandidate candidate = Decode(boot, offset, stream.Length);
                        if (candidate == null) continue;
                        // Backup signatures inside an already recognized volume
                        // are not separate partitions. Retain the actual primary.
                        if (found.Any(x => offset >= x.Offset && offset < x.Offset + x.Length)) continue;
                        long backupDistance = candidate.Kind == "exFAT" ? 12L * candidate.SectorSize : candidate.Kind == "FAT32" ? (long)BitConverter.ToUInt16(boot, 50) * candidate.SectorSize : candidate.Kind == "NTFS" ? candidate.Length - candidate.SectorSize : 0;
                        if (backupDistance > 0 && offset >= backupDistance) {
                            long start = offset - backupDistance;
                            // A plausible backup must describe a volume inside
                            // the image; matching hidden-sector fields strengthen
                            // FAT evidence. Geometry is rechecked by each parser.
                            ulong hidden = candidate.Kind == "exFAT" ? BitConverter.ToUInt64(boot, 64) : BitConverter.ToUInt32(boot, 28);
                            if (start <= stream.Length - candidate.Length && hidden == (ulong)(start / candidate.SectorSize)) {
                                found.Add(new BootCandidate { Offset = start, BootOffset = offset, Length = candidate.Length, SectorSize = candidate.SectorSize, Kind = candidate.Kind, Origin = "backup_boot_candidate" });
                                if (found.Count >= MaximumVolumes) break;
                            }
                        }
                        if (candidate.Length <= stream.Length - offset && !found.Any(x => x.Offset == offset)) found.Add(candidate);
                        if (found.Count >= MaximumVolumes) break;
                    }
                    position += read; if (progress != null) progress(position, stream.Length);
                    if (found.Count >= MaximumVolumes) break;
                }
            }
            return found;
        }
        static BootCandidate Decode(byte[] boot, long offset, long imageLength)
        {
            string oem = Encoding.ASCII.GetString(boot, 3, 8), kind; int sector; ulong sectors;
            if (oem == "EXFAT   ") {
                if (boot[108] < 9 || boot[108] > 12 || boot[109] + boot[108] > 25 || boot[110] < 1 || boot[110] > 2) return null;
                sector = 1 << boot[108]; sectors = BitConverter.ToUInt64(boot, 72); kind = "exFAT";
            } else {
                sector = BitConverter.ToUInt16(boot, 11);
                if (sector < 512 || sector > 4096 || !Power(sector) || !Power(boot[13]) || boot[13] > 128) return null;
                if (oem == "NTFS    ") {
                    // NTFS stores the final sector number (TestDisk 7.2 adds
                    // one when deriving volume bytes), unlike FAT sector counts.
                    sectors = BitConverter.ToUInt64(boot, 40); if(sectors==UInt64.MaxValue)return null; sectors++; kind = "NTFS";
                    if (sectors < 16 || BitConverter.ToUInt64(boot, 48) >= sectors / boot[13]) return null;
                } else {
                    if (boot[0] != 0xeb && boot[0] != 0xe9) return null;
                    int reserved = BitConverter.ToUInt16(boot, 14), fats = boot[16];
                    if (reserved == 0 || fats < 1 || fats > 2) return null;
                    sectors = BitConverter.ToUInt16(boot, 19); if (sectors == 0) sectors = BitConverter.ToUInt32(boot, 32);
                    uint fat = BitConverter.ToUInt16(boot, 22); if (fat == 0) fat = BitConverter.ToUInt32(boot, 36);
                    if (fat == 0 || sectors <= (ulong)reserved + (ulong)fat * (uint)fats) return null;
                    kind = BitConverter.ToUInt16(boot, 17) == 0 && BitConverter.ToUInt16(boot, 22) == 0 ? "FAT32" : "FAT";
                }
            }
            if (sectors == 0 || sectors > (ulong)(imageLength / sector)) return null;
            return new BootCandidate { Offset = offset, BootOffset = offset, Length = (long)sectors * sector, SectorSize = sector, Kind = kind, Origin = "boot_signature_candidate" };
        }
    }
}
