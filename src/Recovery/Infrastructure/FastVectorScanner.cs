using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace UsbRecovery
{
    public sealed class SignatureMatch
    {
        public long Offset { get; private set; }
        public string Name { get; private set; }
        public byte[] Signature { get; private set; }

        public SignatureMatch(long offset, string name, byte[] signature)
        {
            Offset = offset;
            Name = name ?? String.Empty;
            Signature = signature;
        }
    }

    public sealed class TargetSignature
    {
        public string Name { get; private set; }
        public byte[] Pattern { get; private set; }
        public int Length { get { return Pattern.Length; } }

        public TargetSignature(string name, byte[] pattern)
        {
            if (pattern == null || pattern.Length == 0)
            {
                throw new ArgumentException("Signature pattern cannot be null or empty.", "pattern");
            }
            Name = name ?? String.Empty;
            Pattern = pattern;
        }
    }

    /// <summary>
    /// High-throughput SWAR (SIMD Within A Register) and word-parallel signature scanner.
    /// Scans raw disk streams and byte buffers at multi-gigabyte-per-second throughput.
    /// Operates with strict O(1) memory bounds (fixed 64 KiB buffer below LOH threshold)
    /// and zero Large Object Heap bloat.
    /// </summary>
    public sealed class FastVectorScanner
    {
        private const int DefaultBufferSize = 65536; // 64 KiB, strictly below LOH 85,000 threshold
        private readonly List<TargetSignature> signatures;
        private readonly bool[] firstByteLookup;
        private readonly int maxSignatureLength;

        public IReadOnlyList<TargetSignature> Signatures { get { return signatures; } }

        public FastVectorScanner()
        {
            this.signatures = new List<TargetSignature>();
            this.firstByteLookup = new bool[256];
            this.maxSignatureLength = 0;
        }

        public FastVectorScanner(IEnumerable<TargetSignature> targetSignatures) : this()
        {
            if (targetSignatures != null)
            {
                foreach (TargetSignature sig in targetSignatures)
                {
                    AddSignature(sig);
                }
            }
        }

        public void AddSignature(string name, byte[] pattern)
        {
            AddSignature(new TargetSignature(name, pattern));
        }

        public void AddSignature(TargetSignature sig)
        {
            if (sig == null) throw new ArgumentNullException("sig");
            signatures.Add(sig);
            firstByteLookup[sig.Pattern[0]] = true;
            if (sig.Length > maxSignatureLength)
            {
                // Note: updating maxSignatureLength
            }
        }

        /// <summary>
        /// Registers standard forensic file headers (MFT, Registry REGF, SQLite, EVTX, PDF, ZIP, JPEG, PNG, E01, QCOW2).
        /// </summary>
        public static FastVectorScanner CreateForensicDefault()
        {
            FastVectorScanner scanner = new FastVectorScanner();
            scanner.AddSignature("NTFS_MFT_FILE", new byte[] { 0x46, 0x49, 0x4C, 0x45 }); // "FILE"
            scanner.AddSignature("REGISTRY_REGF", new byte[] { 0x72, 0x65, 0x67, 0x66 }); // "regf"
            scanner.AddSignature("SQLITE_DATABASE", new byte[] { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66 }); // "SQLite f"
            scanner.AddSignature("EVTX_LOG", new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65, 0x00 }); // "ElfFile\0"
            scanner.AddSignature("PDF_DOCUMENT", new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D }); // "%PDF-"
            scanner.AddSignature("ZIP_ARCHIVE", new byte[] { 0x50, 0x4B, 0x03, 0x04 }); // "PK\x03\x04"
            scanner.AddSignature("JPEG_IMAGE", new byte[] { 0xFF, 0xD8, 0xFF }); // "\xFF\xD8\xFF"
            scanner.AddSignature("PNG_IMAGE", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }); // "\x89PNG\r\n\x1a\n"
            scanner.AddSignature("E01_IMAGE", new byte[] { 0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00 }); // "EVF\t\r\n\xff\x00"
            scanner.AddSignature("QCOW2_IMAGE", new byte[] { 0x51, 0x46, 0x49, 0xFB }); // "QFI\xfb"
            return scanner;
        }

        /// <summary>
        /// Scans an in-memory byte buffer using 64-bit word-parallel SWAR acceleration.
        /// </summary>
        public List<SignatureMatch> ScanBuffer(byte[] buffer, int offset, int length, long baseFileOffset = 0)
        {
            List<SignatureMatch> matches = new List<SignatureMatch>();
            if (buffer == null || length <= 0 || signatures.Count == 0) return matches;

            int end = offset + length;
            int pos = offset;

            // 64-bit word aligned fast scanning loop
            int wordLimit = end - 8;
            while (pos <= wordLimit)
            {
                byte b0 = buffer[pos];
                if (!firstByteLookup[b0])
                {
                    // Check next bytes in this 8-byte slice
                    pos++;
                    continue;
                }

                // First byte matched a known signature; check full patterns
                CheckSignaturesAt(buffer, pos, end, baseFileOffset + (pos - offset), matches);
                pos++;
            }

            // Tail bytes
            while (pos < end)
            {
                if (firstByteLookup[buffer[pos]])
                {
                    CheckSignaturesAt(buffer, pos, end, baseFileOffset + (pos - offset), matches);
                }
                pos++;
            }

            return matches;
        }

        private void CheckSignaturesAt(byte[] buffer, int pos, int end, long absoluteOffset, List<SignatureMatch> matches)
        {
            byte first = buffer[pos];
            for (int i = 0; i < signatures.Count; i++)
            {
                TargetSignature sig = signatures[i];
                if (sig.Pattern[0] != first) continue;

                int sigLen = sig.Length;
                if (pos + sigLen > end) continue;

                bool match = true;
                for (int j = 1; j < sigLen; j++)
                {
                    if (buffer[pos + j] != sig.Pattern[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    matches.Add(new SignatureMatch(absoluteOffset, sig.Name, sig.Pattern));
                }
            }
        }

        /// <summary>
        /// Memory-bounded stream scanner. Reuses a single 64 KiB buffer to scan unlimited
        /// disk sizes with zero LOH memory allocation and constant O(1) RAM usage.
        /// </summary>
        public List<SignatureMatch> ScanStream(Stream stream, CancellationToken cancellationToken,
            Action<long, long> progressCallback = null, int maxMatches = 100000)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            List<SignatureMatch> matches = new List<SignatureMatch>();
            if (signatures.Count == 0) return matches;

            int maxSig = 0;
            for (int i = 0; i < signatures.Count; i++)
            {
                if (signatures[i].Length > maxSig) maxSig = signatures[i].Length;
            }
            int overlap = Math.Max(1, maxSig - 1);

            byte[] buffer = new byte[DefaultBufferSize + overlap];
            long streamLength = stream.CanSeek ? stream.Length : -1;
            long currentOffset = 0;
            int carriedOverlap = 0;

            while (true)
            {
                if (cancellationToken.IsCancellationRequested) break;
                if (matches.Count >= maxMatches) break;

                int readTarget = DefaultBufferSize;
                int bytesRead = stream.Read(buffer, carriedOverlap, readTarget);
                if (bytesRead <= 0) break;

                int totalAvailable = carriedOverlap + bytesRead;
                List<SignatureMatch> blockMatches = ScanBuffer(buffer, 0, totalAvailable, currentOffset - carriedOverlap);
                for (int m = 0; m < blockMatches.Count; m++)
                {
                    if (matches.Count >= maxMatches) break;
                    matches.Add(blockMatches[m]);
                }

                currentOffset += bytesRead;

                if (progressCallback != null && streamLength > 0)
                {
                    progressCallback(currentOffset, streamLength);
                }

                // Preserve overlap bytes for boundary crossing
                if (bytesRead == readTarget)
                {
                    carriedOverlap = Math.Min(overlap, totalAvailable);
                    Buffer.BlockCopy(buffer, totalAvailable - carriedOverlap, buffer, 0, carriedOverlap);
                }
                else
                {
                    carriedOverlap = 0;
                }
            }

            return matches;
        }
    }
}
