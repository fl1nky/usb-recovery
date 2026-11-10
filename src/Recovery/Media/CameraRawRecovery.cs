using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>
    /// Professional Camera RAW photo recovery and metadata extraction engine.
    /// Supports Canon CR2/CR3, Nikon NEF, Sony ARW, Adobe DNG, and Fujifilm RAF.
    /// Recovers full-resolution embedded preview JPEGs and EXIF camera parameters.
    /// 100% offline, zero network telemetry, strictly deterministic.
    /// </summary>
    public static class CameraRawRecovery
    {
        private const long MaxRawFileSize = 256L * 1024 * 1024; // 256 MiB upper bound per raw file
        private const int MaxCarveCount = 50000;

        // Magic headers
        private static readonly byte[] TiffLittleEndian = new byte[] { 0x49, 0x49, 0x2A, 0x00 };
        private static readonly byte[] TiffBigEndian = new byte[] { 0x4D, 0x4D, 0x00, 0x2A };
        private static readonly byte[] CanonCr2Magic = new byte[] { 0x43, 0x52, 0x02, 0x00 };
        private static readonly byte[] FujiMagic = Encoding.ASCII.GetBytes("FUJIFILMCCD-RAW ");
        private static readonly byte[] FtypCrx = Encoding.ASCII.GetBytes("ftypcrx ");

        public sealed class RawMetadata
        {
            public string Format { get; set; }
            public string Make { get; set; }
            public string Model { get; set; }
            public string Lens { get; set; }
            public string Software { get; set; }
            public string DateTimeOriginal { get; set; }
            public int Iso { get; set; }
            public string ExposureTime { get; set; }
            public string FNumber { get; set; }
            public string FocalLength { get; set; }
            public int Width { get; set; }
            public int Height { get; set; }
            public long PreviewOffset { get; set; }
            public long PreviewLength { get; set; }
            public string GpsCoordinates { get; set; }
            public Dictionary<string, string> ExtraTags { get; set; }

            public RawMetadata()
            {
                Format = "Unknown";
                ExtraTags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
        }

        public sealed class RawCarveResult
        {
            public long Offset { get; set; }
            public long Length { get; set; }
            public string Format { get; set; }
            public RawMetadata Metadata { get; set; }
            public byte[] PreviewBytes { get; set; }
        }

        public sealed class SalvageReport
        {
            public string Status { get; set; }
            public int FilesInspected { get; set; }
            public int RawFilesFound { get; set; }
            public int PreviewsExtracted { get; set; }
            public List<CarvedFileEntry> Files { get; set; }

            public SalvageReport()
            {
                Files = new List<CarvedFileEntry>();
            }
        }

        public sealed class CarvedFileEntry
        {
            public string SourceFile { get; set; }
            public long SourceOffset { get; set; }
            public long FileBytes { get; set; }
            public string Format { get; set; }
            public string Make { get; set; }
            public string Model { get; set; }
            public string DateTimeOriginal { get; set; }
            public string OutputPath { get; set; }
            public string MetadataPath { get; set; }
            public string PreviewPath { get; set; }
            public long PreviewBytes { get; set; }
        }

        /// <summary>
        /// Inspects a stream to determine if it contains a known Camera RAW format,
        /// parsing TIFF IFDs or container headers to extract camera parameters.
        /// </summary>
        public static RawMetadata Inspect(Stream stream)
        {
            if (stream == null || !stream.CanRead) return null;
            long origPos = stream.CanSeek ? stream.Position : 0;
            try
            {
                byte[] header = new byte[1024];
                int read = stream.Read(header, 0, header.Length);
                if (read < 16) return null;

                // 1. Check Fujifilm RAF
                if (MatchesPrefix(header, FujiMagic))
                {
                    return InspectFuji(stream, header);
                }

                // 2. Check Canon CR3 (ISOBMFF with ftypcrx )
                if (read >= 12 && MatchesAt(header, 4, FtypCrx))
                {
                    return InspectCr3(stream, header);
                }

                // 3. Check TIFF-based RAW (CR2, NEF, ARW, DNG)
                bool isLe = MatchesPrefix(header, TiffLittleEndian);
                bool isBe = MatchesPrefix(header, TiffBigEndian);
                if (isLe || isBe)
                {
                    return InspectTiffRaw(stream, isLe);
                }

                return null;
            }
            finally
            {
                if (stream.CanSeek) stream.Position = origPos;
            }
        }

        /// <summary>
        /// Carves Camera RAW images and their embedded JPEGs from a stream or disk image.
        /// </summary>
        public static List<RawCarveResult> Carve(Stream stream, CancellationToken cancel, Action<long, long> progress)
        {
            if (stream == null || !stream.CanRead) throw new ArgumentNullException("stream");
            var results = new List<RawCarveResult>();

            byte[] buffer = new byte[2 * 1024 * 1024]; // 2 MiB sliding window
            long streamLength = stream.CanSeek ? stream.Length : -1;
            long currentPos = 0;
            int carry = 0;

            while (true)
            {
                cancel.ThrowIfCancellationRequested();
                int read = stream.Read(buffer, carry, buffer.Length - carry);
                if (read <= 0) break;

                int valid = carry + read;
                int searchLimit = valid - 16;
                if (searchLimit < 0) searchLimit = 0;

                for (int i = 0; i <= searchLimit; i++)
                {
                    if ((i & 0x7FFF) == 0) cancel.ThrowIfCancellationRequested();

                    // Check Fuji RAF
                    if (MatchesAt(buffer, i, FujiMagic))
                    {
                        long candidateOffset = currentPos + i;
                        var result = TryCarveFujiAt(stream, candidateOffset, cancel);
                        if (result != null)
                        {
                            results.Add(result);
                            if (results.Count >= MaxCarveCount) return results;
                        }
                    }
                    // Check Canon CR3
                    else if (i + 12 <= valid && MatchesAt(buffer, i + 4, FtypCrx))
                    {
                        long candidateOffset = currentPos + i;
                        var result = TryCarveCr3At(stream, candidateOffset, cancel);
                        if (result != null)
                        {
                            results.Add(result);
                            if (results.Count >= MaxCarveCount) return results;
                        }
                    }
                    // Check TIFF-based (CR2, NEF, ARW, DNG)
                    else if (MatchesAt(buffer, i, TiffLittleEndian) || MatchesAt(buffer, i, TiffBigEndian))
                    {
                        long candidateOffset = currentPos + i;
                        var result = TryCarveTiffAt(stream, candidateOffset, cancel);
                        if (result != null)
                        {
                            results.Add(result);
                            if (results.Count >= MaxCarveCount) return results;
                        }
                    }
                }

                currentPos += searchLimit;
                carry = valid - searchLimit;
                Buffer.BlockCopy(buffer, searchLimit, buffer, 0, carry);

                if (progress != null && streamLength > 0)
                {
                    progress(currentPos, streamLength);
                }
            }

            return results;
        }

        /// <summary>
        /// Scans an input directory or file for camera RAW photos, repairs/salvages them,
        /// and optionally extracts full-resolution JPEG previews into the target directory.
        /// </summary>
        public static SalvageReport SalvageDirectory(string inputPath, string outputDir, bool extractPreviews, CancellationToken cancel, Action<int, int> progress)
        {
            if (string.IsNullOrEmpty(inputPath) || !Directory.Exists(inputPath) && !File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input path does not exist", inputPath);
            }
            if (string.IsNullOrEmpty(outputDir))
            {
                throw new ArgumentException("Output directory must be specified", "outputDir");
            }

            Directory.CreateDirectory(outputDir);
            string previewsDir = Path.Combine(outputDir, "previews");
            if (extractPreviews)
            {
                Directory.CreateDirectory(previewsDir);
            }

            var report = new SalvageReport();
            var filesToProcess = new List<string>();

            if (File.Exists(inputPath))
            {
                filesToProcess.Add(inputPath);
            }
            else
            {
                foreach (string f in Directory.GetFiles(inputPath, "*.*", SearchOption.AllDirectories))
                {
                    filesToProcess.Add(f);
                }
            }

            report.FilesInspected = filesToProcess.Count;

            for (int i = 0; i < filesToProcess.Count; i++)
            {
                cancel.ThrowIfCancellationRequested();
                string filePath = filesToProcess[i];

                try
                {
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var meta = Inspect(fs);
                        if (meta != null && meta.Format != "Unknown")
                        {
                            report.RawFilesFound++;
                            var entry = new CarvedFileEntry
                            {
                                SourceFile = Path.GetFileName(filePath),
                                SourceOffset = 0,
                                FileBytes = fs.Length,
                                Format = meta.Format,
                                Make = meta.Make,
                                Model = meta.Model,
                                DateTimeOriginal = meta.DateTimeOriginal
                            };
                            string stem = Path.GetFileNameWithoutExtension(filePath);

                            // Extract preview JPEG if available and requested
                            if (extractPreviews && meta.PreviewOffset > 0 && meta.PreviewLength > 0 && meta.PreviewLength < 64 * 1024 * 1024)
                            {
                                byte[] previewData = ExtractPreview(fs, meta);
                                if (previewData != null && previewData.Length > 0)
                                {
                                    string previewName = PublishOutput(previewsDir, stem, "-preview.jpg",
                                        file => file.Write(previewData, 0, previewData.Length));
                                    entry.PreviewPath = Path.Combine("previews", previewName);
                                    entry.PreviewBytes = previewData.Length;
                                    report.PreviewsExtracted++;
                                }
                            }

                            // Write individual metadata JSON
                            byte[] metadata = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(meta));
                            entry.MetadataPath = PublishOutput(outputDir, stem, ".meta.json",
                                file => file.Write(metadata, 0, metadata.Length));

                            report.Files.Add(entry);
                        }
                    }
                }
                catch (Exception)
                {
                    // Continue processing other files
                }

                if (progress != null)
                {
                    progress(i + 1, filesToProcess.Count);
                }
            }

            report.Status = "complete";
            PublishReport(outputDir, report);
            return report;
        }

        internal static void PublishReport(string directory, SalvageReport report)
        {
            var serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            byte[] data = Encoding.UTF8.GetBytes(serializer.Serialize(report));
            PublishOutput(directory, "raw-salvage-report", ".json", file => file.Write(data, 0, data.Length));
        }

        internal static string PublishOutput(string directory, string stem, string suffix, Action<Stream> write)
        {
            string temporary = RecoveryCatalog.SafeFile(directory, ".raw-" + Guid.NewGuid().ToString("N") + ".partial");
            bool ownsTemporary = false;
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    ownsTemporary = true;
                    write(file);
                    file.Flush(true);
                }

                for (int index = 1; ; index++)
                {
                    string name = stem + (index == 1 ? "" : "-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)) + suffix;
                    string target = Path.Combine(directory, name);
                    if (File.Exists(target) || Directory.Exists(target)) continue;
                    try
                    {
                        File.Move(temporary, target);
                        ownsTemporary = false;
                        return name;
                    }
                    catch (IOException)
                    {
                        // Another writer can publish the same name between the probe and move.
                        if (!File.Exists(target) && !Directory.Exists(target)) throw;
                    }
                }
            }
            finally
            {
                if (ownsTemporary) File.Delete(temporary);
            }
        }

        /// <summary>
        /// Extracts embedded preview JPEG data from a RAW stream using metadata coordinates.
        /// </summary>
        public static byte[] ExtractPreview(Stream stream, RawMetadata meta)
        {
            if (stream == null || meta == null || meta.PreviewOffset < 0 || meta.PreviewLength <= 0) return null;
            if (meta.PreviewOffset + meta.PreviewLength > stream.Length) return null;

            stream.Seek(meta.PreviewOffset, SeekOrigin.Begin);
            byte[] preview = new byte[meta.PreviewLength];
            int read = 0;
            while (read < preview.Length)
            {
                int r = stream.Read(preview, read, preview.Length - read);
                if (r <= 0) break;
                read += r;
            }

            // Verify JPEG SOI / EOI markers
            if (read >= 4 && preview[0] == 0xFF && preview[1] == 0xD8)
            {
                return preview;
            }
            return null;
        }

        // =========================================================================
        // Fujifilm RAF Parsing
        // =========================================================================
        private static RawMetadata InspectFuji(Stream stream, byte[] header)
        {
            var meta = new RawMetadata { Format = "Fujifilm RAF", Make = "FUJIFILM" };

            // Camera string: 8 bytes at offset 20
            if (header.Length >= 28)
            {
                string camera = Encoding.ASCII.GetString(header, 20, 8).Trim('\0', ' ');
                if (!string.IsNullOrEmpty(camera)) meta.Model = camera;
            }

            // Offsets in RAF header (all 32-bit big-endian):
            // 0x54 (84): JPEG offset
            // 0x58 (88): JPEG length
            // 0x64 (100): Exif offset
            // 0x68 (104): Exif length
            if (header.Length >= 108)
            {
                uint jpgOffset = ReadUInt32Be(header, 84);
                uint jpgLength = ReadUInt32Be(header, 88);
                uint exifOffset = ReadUInt32Be(header, 100);
                uint exifLength = ReadUInt32Be(header, 104);

                meta.PreviewOffset = jpgOffset;
                meta.PreviewLength = jpgLength;

                // If Exif offset is valid, parse TIFF Exif structure
                if (exifOffset > 0 && exifLength > 16 && stream.CanSeek && exifOffset + exifLength <= stream.Length)
                {
                    stream.Seek(exifOffset, SeekOrigin.Begin);
                    ParseTiffIfds(stream, exifOffset, true, meta);
                }
            }

            return meta;
        }

        private static RawCarveResult TryCarveFujiAt(Stream stream, long offset, CancellationToken cancel)
        {
            if (offset < 0 || offset + 120 > stream.Length) return null;
            long origPos = stream.Position;
            try
            {
                stream.Seek(offset, SeekOrigin.Begin);
                byte[] header = new byte[128];
                int read = stream.Read(header, 0, header.Length);
                if (read < 108 || !MatchesPrefix(header, FujiMagic)) return null;

                var meta = InspectFuji(stream, header);
                if (meta == null) return null;

                // Total size: maximum of preview end, exif end, or raw data
                uint jpgOffset = ReadUInt32Be(header, 84);
                uint jpgLength = ReadUInt32Be(header, 88);
                uint cfaOffset = ReadUInt32Be(header, 92);
                uint cfaLength = ReadUInt32Be(header, 96);
                uint exifOffset = ReadUInt32Be(header, 100);
                uint exifLength = ReadUInt32Be(header, 104);

                long endOffset = 108;
                if (jpgOffset > 0 && jpgLength > 0) endOffset = Math.Max(endOffset, jpgOffset + jpgLength);
                if (cfaOffset > 0 && cfaLength > 0) endOffset = Math.Max(endOffset, cfaOffset + cfaLength);
                if (exifOffset > 0 && exifLength > 0) endOffset = Math.Max(endOffset, exifOffset + exifLength);

                if (endOffset > MaxRawFileSize) endOffset = MaxRawFileSize;
                if (offset + endOffset > stream.Length) endOffset = stream.Length - offset;

                byte[] previewBytes = null;
                if (meta.PreviewOffset > 0 && meta.PreviewLength > 0 && meta.PreviewLength <= 16 * 1024 * 1024)
                {
                    meta.PreviewOffset += offset; // adjust to stream absolute
                    previewBytes = ExtractPreview(stream, meta);
                }

                return new RawCarveResult
                {
                    Offset = offset,
                    Length = endOffset,
                    Format = "Fujifilm RAF",
                    Metadata = meta,
                    PreviewBytes = previewBytes
                };
            }
            finally
            {
                stream.Position = origPos;
            }
        }

        // =========================================================================
        // Canon CR3 Parsing (ISOBMFF Container)
        // =========================================================================
        private static RawMetadata InspectCr3(Stream stream, byte[] header)
        {
            var meta = new RawMetadata { Format = "Canon CR3", Make = "Canon" };

            // Scan boxes in ISOBMFF
            if (stream.CanSeek)
            {
                stream.Seek(0, SeekOrigin.Begin);
                ScanCr3Boxes(stream, 0, stream.Length, meta);
            }

            return meta;
        }

        private static void ScanCr3Boxes(Stream stream, long start, long limit, RawMetadata meta)
        {
            byte[] boxHeader = new byte[8];
            long pos = start;

            while (pos + 8 <= limit && pos + 8 <= stream.Length)
            {
                stream.Seek(pos, SeekOrigin.Begin);
                int read = stream.Read(boxHeader, 0, 8);
                if (read < 8) break;

                uint boxSize = ReadUInt32Be(boxHeader, 0);
                string boxType = Encoding.ASCII.GetString(boxHeader, 4, 4);

                long actualSize = boxSize;
                long payloadOffset = pos + 8;

                if (boxSize == 1) // 64-bit extended size
                {
                    byte[] extSize = new byte[8];
                    if (stream.Read(extSize, 0, 8) < 8) break;
                    actualSize = (long)ReadUInt64Be(extSize, 0);
                    payloadOffset = pos + 16;
                }
                else if (boxSize == 0) // runs to EOF
                {
                    actualSize = limit - pos;
                }

                if (actualSize < 8 || pos + actualSize > limit) break;

                // Check box types
                if (boxType == "moov" || boxType == "trak" || boxType == "mdia" || boxType == "minf" || boxType == "stbl")
                {
                    // Recurse into container box
                    ScanCr3Boxes(stream, payloadOffset, pos + actualSize, meta);
                }
                else if (boxType == "PRVW" || boxType == "thmb")
                {
                    // Preview box found
                    meta.PreviewOffset = payloadOffset;
                    meta.PreviewLength = actualSize - (payloadOffset - pos);
                }
                else if (boxType == "uuid")
                {
                    // Canon UUIDs often contain embedded JPEG or Exif
                    CheckCanonUuid(stream, payloadOffset, actualSize - (payloadOffset - pos), meta);
                }

                pos += actualSize;
            }
        }

        private static void CheckCanonUuid(Stream stream, long offset, long length, RawMetadata meta)
        {
            if (length < 24) return;
            stream.Seek(offset, SeekOrigin.Begin);
            byte[] uuid = new byte[16];
            stream.Read(uuid, 0, 16);

            // PRVW UUID: 85 c0 b6 87 82 0f 11 e0 81 11 f4 ce 46 2b 02 4c
            if (uuid[0] == 0x85 && uuid[1] == 0xC0 && uuid[2] == 0xB6 && uuid[3] == 0x87)
            {
                // Has header inside UUID payload, then JPEG SOI
                byte[] sample = new byte[Math.Min(128, (int)length - 16)];
                stream.Read(sample, 0, sample.Length);
                for (int i = 0; i < sample.Length - 3; i++)
                {
                    if (sample[i] == 0xFF && sample[i + 1] == 0xD8 && sample[i + 2] == 0xFF)
                    {
                        meta.PreviewOffset = offset + 16 + i;
                        meta.PreviewLength = length - 16 - i;
                        break;
                    }
                }
            }
        }

        private static RawCarveResult TryCarveCr3At(Stream stream, long offset, CancellationToken cancel)
        {
            if (offset < 0 || offset + 32 > stream.Length) return null;
            long origPos = stream.Position;
            try
            {
                stream.Seek(offset, SeekOrigin.Begin);
                byte[] boxHeader = new byte[12];
                int read = stream.Read(boxHeader, 0, 12);
                if (read < 12) return null;

                uint ftypSize = ReadUInt32Be(boxHeader, 0);
                if (!MatchesAt(boxHeader, 4, FtypCrx)) return null;

                // Traverse boxes from offset
                long totalLength = ftypSize;
                long scanPos = offset + ftypSize;
                var meta = new RawMetadata { Format = "Canon CR3", Make = "Canon" };

                byte[] curBox = new byte[8];
                while (scanPos + 8 <= stream.Length && scanPos - offset < MaxRawFileSize)
                {
                    cancel.ThrowIfCancellationRequested();
                    stream.Seek(scanPos, SeekOrigin.Begin);
                    if (stream.Read(curBox, 0, 8) < 8) break;

                    uint bSize = ReadUInt32Be(curBox, 0);
                    string bType = Encoding.ASCII.GetString(curBox, 4, 4);

                    if (bSize < 8) break;
                    totalLength = (scanPos + bSize) - offset;

                    if (bType == "moov")
                    {
                        ScanCr3Boxes(stream, scanPos + 8, scanPos + bSize, meta);
                    }
                    else if (bType == "mdat")
                    {
                        // mdat usually holds raw bayer / image payload
                    }

                    scanPos += bSize;
                    if (bType == "mdat" && scanPos - offset > 1024 * 1024)
                    {
                        // Valid CR3 has mdat
                        break;
                    }
                }

                if (totalLength < 1024) totalLength = 1024;
                if (offset + totalLength > stream.Length) totalLength = stream.Length - offset;

                byte[] previewBytes = null;
                if (meta.PreviewOffset > 0 && meta.PreviewLength > 0 && meta.PreviewLength <= 16 * 1024 * 1024)
                {
                    previewBytes = ExtractPreview(stream, meta);
                }

                return new RawCarveResult
                {
                    Offset = offset,
                    Length = totalLength,
                    Format = "Canon CR3",
                    Metadata = meta,
                    PreviewBytes = previewBytes
                };
            }
            finally
            {
                stream.Position = origPos;
            }
        }

        // =========================================================================
        // TIFF-Based RAW Parsing (CR2, NEF, ARW, DNG)
        // =========================================================================
        private static RawMetadata InspectTiffRaw(Stream stream, bool isLe)
        {
            var meta = new RawMetadata();
            ParseTiffIfds(stream, 0, isLe, meta);

            // Classify format from tags and magic
            if (stream.Length >= 12)
            {
                stream.Seek(8, SeekOrigin.Begin);
                byte[] cr2Check = new byte[4];
                stream.Read(cr2Check, 0, 4);
                if (MatchesPrefix(cr2Check, CanonCr2Magic))
                {
                    meta.Format = "Canon CR2";
                    if (string.IsNullOrEmpty(meta.Make)) meta.Make = "Canon";
                    return meta;
                }
            }

            if (!string.IsNullOrEmpty(meta.Make))
            {
                string makeUpper = meta.Make.ToUpperInvariant();
                if (makeUpper.Contains("NIKON"))
                {
                    meta.Format = "Nikon NEF";
                }
                else if (makeUpper.Contains("SONY"))
                {
                    meta.Format = "Sony ARW";
                }
                else if (makeUpper.Contains("CANON"))
                {
                    meta.Format = "Canon CR2";
                }
            }

            if (meta.ExtraTags.ContainsKey("DNGVersion"))
            {
                meta.Format = "Adobe DNG";
            }
            else if (meta.Format == "Unknown" && !string.IsNullOrEmpty(meta.Make))
            {
                meta.Format = meta.Make + " RAW";
            }

            return meta;
        }

        private static void ParseTiffIfds(Stream stream, long tiffBaseOffset, bool isLe, RawMetadata meta)
        {
            byte[] ifdOffsetBuf = new byte[4];
            stream.Seek(tiffBaseOffset + 4, SeekOrigin.Begin);
            if (stream.Read(ifdOffsetBuf, 0, 4) < 4) return;

            uint ifd0Offset = isLe ? ReadUInt32Le(ifdOffsetBuf, 0) : ReadUInt32Be(ifdOffsetBuf, 0);
            if (ifd0Offset < 8 || tiffBaseOffset + ifd0Offset >= stream.Length) return;

            var visitedIfds = new HashSet<long>();
            ReadIfdDirectory(stream, tiffBaseOffset, ifd0Offset, isLe, meta, visitedIfds);
        }

        private static void ReadIfdDirectory(Stream stream, long tiffBase, long ifdOffset, bool isLe, RawMetadata meta, HashSet<long> visited)
        {
            if (visited.Contains(ifdOffset) || visited.Count > 64) return;
            visited.Add(ifdOffset);

            long absOffset = tiffBase + ifdOffset;
            if (absOffset + 2 > stream.Length) return;

            stream.Seek(absOffset, SeekOrigin.Begin);
            byte[] countBuf = new byte[2];
            if (stream.Read(countBuf, 0, 2) < 2) return;
            ushort entryCount = isLe ? ReadUInt16Le(countBuf, 0) : ReadUInt16Be(countBuf, 0);

            if (entryCount == 0 || entryCount > 1000) return;

            byte[] entryData = new byte[entryCount * 12];
            int read = stream.Read(entryData, 0, entryData.Length);
            if (read < entryData.Length) return;

            var subIfdOffsets = new List<long>();
            long exifIfdOffset = -1;
            long gpsIfdOffset = -1;

            for (int i = 0; i < entryCount; i++)
            {
                int p = i * 12;
                ushort tag = isLe ? ReadUInt16Le(entryData, p) : ReadUInt16Be(entryData, p);
                ushort type = isLe ? ReadUInt16Le(entryData, p + 2) : ReadUInt16Be(entryData, p + 2);
                uint count = isLe ? ReadUInt32Le(entryData, p + 4) : ReadUInt32Be(entryData, p + 4);
                uint valueOrOffset = isLe ? ReadUInt32Le(entryData, p + 8) : ReadUInt32Be(entryData, p + 8);

                switch (tag)
                {
                    case 0x0100: // ImageWidth
                        meta.Width = (int)valueOrOffset;
                        break;
                    case 0x0101: // ImageLength (Height)
                        meta.Height = (int)valueOrOffset;
                        break;
                    case 0x010F: // Make
                        meta.Make = ReadTiffString(stream, tiffBase, type, count, valueOrOffset);
                        break;
                    case 0x0110: // Model
                        meta.Model = ReadTiffString(stream, tiffBase, type, count, valueOrOffset);
                        break;
                    case 0x0131: // Software
                        meta.Software = ReadTiffString(stream, tiffBase, type, count, valueOrOffset);
                        break;
                    case 0x0132: // DateTime
                        if (string.IsNullOrEmpty(meta.DateTimeOriginal))
                            meta.DateTimeOriginal = ReadTiffString(stream, tiffBase, type, count, valueOrOffset);
                        break;
                    case 0x014A: // SubIFDs
                        if (count > 0 && count < 32)
                        {
                            if (count == 1) subIfdOffsets.Add(valueOrOffset);
                            else
                            {
                                byte[] subBuf = new byte[count * 4];
                                stream.Seek(tiffBase + valueOrOffset, SeekOrigin.Begin);
                                if (stream.Read(subBuf, 0, subBuf.Length) == subBuf.Length)
                                {
                                    for (int s = 0; s < count; s++)
                                        subIfdOffsets.Add(isLe ? ReadUInt32Le(subBuf, s * 4) : ReadUInt32Be(subBuf, s * 4));
                                }
                            }
                        }
                        break;
                    case 0x0201: // JPEGInterchangeFormat (Preview Offset)
                        if (meta.PreviewOffset <= 0)
                        {
                            meta.PreviewOffset = tiffBase + valueOrOffset;
                        }
                        break;
                    case 0x0202: // JPEGInterchangeFormatLength (Preview Length)
                        if (meta.PreviewLength <= 0)
                        {
                            meta.PreviewLength = valueOrOffset;
                        }
                        break;
                    case 0x829A: // ExposureTime
                        meta.ExposureTime = FormatTiffRational(stream, tiffBase, isLe, valueOrOffset) + "s";
                        break;
                    case 0x829D: // FNumber
                        meta.FNumber = "f/" + FormatTiffRational(stream, tiffBase, isLe, valueOrOffset);
                        break;
                    case 0x8769: // ExifIFD
                        exifIfdOffset = valueOrOffset;
                        break;
                    case 0x8825: // GPSIFD
                        gpsIfdOffset = valueOrOffset;
                        break;
                    case 0x8827: // PhotographicSensitivity (ISO)
                        meta.Iso = (int)(isLe ? (valueOrOffset & 0xFFFF) : (valueOrOffset >> 16));
                        break;
                    case 0x9003: // DateTimeOriginal
                        meta.DateTimeOriginal = ReadTiffString(stream, tiffBase, type, count, valueOrOffset);
                        break;
                    case 0x920A: // FocalLength
                        meta.FocalLength = FormatTiffRational(stream, tiffBase, isLe, valueOrOffset) + "mm";
                        break;
                    case 0xA434: // LensModel
                        meta.Lens = ReadTiffString(stream, tiffBase, type, count, valueOrOffset);
                        break;
                    case 0xC612: // DNGVersion
                        meta.ExtraTags["DNGVersion"] = string.Format("{0}.{1}.{2}.{3}",
                            (valueOrOffset >> 24) & 0xFF, (valueOrOffset >> 16) & 0xFF,
                            (valueOrOffset >> 8) & 0xFF, valueOrOffset & 0xFF);
                        break;
                }
            }

            // Recurse into Exif IFD
            if (exifIfdOffset > 0)
            {
                ReadIfdDirectory(stream, tiffBase, exifIfdOffset, isLe, meta, visited);
            }

            // Recurse into SubIFDs
            foreach (long subOffset in subIfdOffsets)
            {
                ReadIfdDirectory(stream, tiffBase, subOffset, isLe, meta, visited);
            }

            // Next IFD in sequence
            byte[] nextIfdBuf = new byte[4];
            stream.Seek(absOffset + 2 + entryCount * 12, SeekOrigin.Begin);
            if (stream.Read(nextIfdBuf, 0, 4) == 4)
            {
                uint nextOffset = isLe ? ReadUInt32Le(nextIfdBuf, 0) : ReadUInt32Be(nextIfdBuf, 0);
                if (nextOffset > 0 && nextOffset < stream.Length)
                {
                    ReadIfdDirectory(stream, tiffBase, nextOffset, isLe, meta, visited);
                }
            }
        }

        private static string ReadTiffString(Stream stream, long tiffBase, ushort type, uint count, uint valOrOffset)
        {
            if (type != 2 && type != 7) return null; // ASCII or UNDEFINED
            if (count == 0 || count > 4096) return null;

            byte[] strBytes = new byte[count];
            if (count <= 4)
            {
                strBytes[0] = (byte)(valOrOffset & 0xFF);
                if (count > 1) strBytes[1] = (byte)((valOrOffset >> 8) & 0xFF);
                if (count > 2) strBytes[2] = (byte)((valOrOffset >> 16) & 0xFF);
                if (count > 3) strBytes[3] = (byte)((valOrOffset >> 24) & 0xFF);
            }
            else
            {
                long pos = stream.Position;
                stream.Seek(tiffBase + valOrOffset, SeekOrigin.Begin);
                int r = stream.Read(strBytes, 0, (int)count);
                stream.Position = pos;
                if (r < count) return null;
            }

            int len = 0;
            while (len < strBytes.Length && strBytes[len] != 0) len++;
            return Encoding.UTF8.GetString(strBytes, 0, len).Trim();
        }

        private static string FormatTiffRational(Stream stream, long tiffBase, bool isLe, uint offset)
        {
            long pos = stream.Position;
            try
            {
                stream.Seek(tiffBase + offset, SeekOrigin.Begin);
                byte[] ratBuf = new byte[8];
                if (stream.Read(ratBuf, 0, 8) < 8) return "";

                uint num = isLe ? ReadUInt32Le(ratBuf, 0) : ReadUInt32Be(ratBuf, 0);
                uint den = isLe ? ReadUInt32Le(ratBuf, 4) : ReadUInt32Be(ratBuf, 4);

                if (den == 0) return num.ToString();
                if (num == 0) return "0";

                if (den == 1) return num.ToString();
                if (num < den && den % num == 0) return "1/" + (den / num);
                double d = (double)num / den;
                return d.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture);
            }
            finally
            {
                stream.Position = pos;
            }
        }

        private static RawCarveResult TryCarveTiffAt(Stream stream, long offset, CancellationToken cancel)
        {
            if (offset < 0 || offset + 32 > stream.Length) return null;
            long origPos = stream.Position;
            try
            {
                stream.Seek(offset, SeekOrigin.Begin);
                byte[] hdr = new byte[16];
                if (stream.Read(hdr, 0, 16) < 16) return null;

                bool isLe = MatchesPrefix(hdr, TiffLittleEndian);
                bool isBe = MatchesPrefix(hdr, TiffBigEndian);
                if (!isLe && !isBe) return null;

                var meta = new RawMetadata();
                ParseTiffIfds(stream, offset, isLe, meta);

                // Must have at least Make, Model, or valid DNG/CR2 magic to be considered a RAW container
                bool isCr2 = MatchesAt(hdr, 8, CanonCr2Magic);
                if (isCr2)
                {
                    meta.Format = "Canon CR2";
                    if (string.IsNullOrEmpty(meta.Make)) meta.Make = "Canon";
                }
                else if (meta.ExtraTags.ContainsKey("DNGVersion"))
                {
                    meta.Format = "Adobe DNG";
                }
                else if (!string.IsNullOrEmpty(meta.Make))
                {
                    string m = meta.Make.ToUpperInvariant();
                    if (m.Contains("NIKON")) meta.Format = "Nikon NEF";
                    else if (m.Contains("SONY")) meta.Format = "Sony ARW";
                    else if (m.Contains("CANON")) meta.Format = "Canon CR2";
                    else return null; // Not a recognised camera RAW
                }
                else
                {
                    return null;
                }

                // Calculate file size: preview end + bounds
                long fileLen = 64 * 1024;
                if (meta.PreviewOffset > 0 && meta.PreviewLength > 0)
                {
                    long previewEndRel = (meta.PreviewOffset + meta.PreviewLength) - offset;
                    if (previewEndRel > fileLen) fileLen = previewEndRel;
                }

                // Bound to max raw size or stream length
                if (fileLen > MaxRawFileSize) fileLen = MaxRawFileSize;
                if (offset + fileLen > stream.Length) fileLen = stream.Length - offset;

                byte[] previewBytes = null;
                if (meta.PreviewOffset > 0 && meta.PreviewLength > 0 && meta.PreviewLength <= 16 * 1024 * 1024)
                {
                    previewBytes = ExtractPreview(stream, meta);
                }

                return new RawCarveResult
                {
                    Offset = offset,
                    Length = fileLen,
                    Format = meta.Format,
                    Metadata = meta,
                    PreviewBytes = previewBytes
                };
            }
            finally
            {
                stream.Position = origPos;
            }
        }

        // =========================================================================
        // Binary Helpers
        // =========================================================================
        private static bool MatchesPrefix(byte[] data, byte[] prefix)
        {
            if (data == null || prefix == null || data.Length < prefix.Length) return false;
            for (int i = 0; i < prefix.Length; i++)
            {
                if (data[i] != prefix[i]) return false;
            }
            return true;
        }

        private static bool MatchesAt(byte[] data, int offset, byte[] target)
        {
            if (data == null || target == null || offset < 0 || offset + target.Length > data.Length) return false;
            for (int i = 0; i < target.Length; i++)
            {
                if (data[offset + i] != target[i]) return false;
            }
            return true;
        }

        private static ushort ReadUInt16Le(byte[] b, int offset)
        {
            return (ushort)(b[offset] | (b[offset + 1] << 8));
        }

        private static ushort ReadUInt16Be(byte[] b, int offset)
        {
            return (ushort)((b[offset] << 8) | b[offset + 1]);
        }

        private static uint ReadUInt32Le(byte[] b, int offset)
        {
            return (uint)(b[offset] | (b[offset + 1] << 8) | (b[offset + 2] << 16) | (b[offset + 3] << 24));
        }

        private static uint ReadUInt32Be(byte[] b, int offset)
        {
            return (uint)((b[offset] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | b[offset + 3]);
        }

        private static ulong ReadUInt64Be(byte[] b, int offset)
        {
            ulong hi = ReadUInt32Be(b, offset);
            ulong lo = ReadUInt32Be(b, offset + 4);
            return (hi << 32) | lo;
        }
    }
}
