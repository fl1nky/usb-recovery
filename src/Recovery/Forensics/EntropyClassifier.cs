using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public enum EntropyCategory
    {
        ZeroOrSparse = 0,
        PlainTextOrCode = 1,
        StructuredBinary = 2,
        CompressedData = 3,
        EncryptedOrRansomware = 4
    }

    public sealed class EntropyBlockResult
    {
        public long Offset { get; set; }
        public int Length { get; set; }
        public double Entropy { get; set; }
        public EntropyCategory Category { get; set; }
    }

    public sealed class EntropyReport
    {
        public long TotalBytesAnalyzed { get; set; }
        public double MeanEntropy { get; set; }
        public double MinEntropy { get; set; }
        public double MaxEntropy { get; set; }
        public double StandardDeviation { get; set; }
        public EntropyCategory DominantCategory { get; set; }
        public int TotalBlocks { get; set; }
        public int SparseBlocks { get; set; }
        public int PlainTextBlocks { get; set; }
        public int StructuredBlocks { get; set; }
        public int CompressedBlocks { get; set; }
        public int EncryptedOrRansomwareBlocks { get; set; }
        public bool IsSuspiciousRansomware { get; set; }
        public string SuspicionReason { get; set; }
        public List<EntropyBlockResult> BlockProfiles { get; set; }

        public EntropyReport()
        {
            BlockProfiles = new List<EntropyBlockResult>();
            SuspicionReason = String.Empty;
            MinEntropy = 8.0;
            MaxEntropy = 0.0;
        }

        public string ToJson()
        {
            var serializer = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
            return serializer.Serialize(this);
        }
    }

    /// <summary>
    /// Pure C# Shannon Entropy Classifier and Ransomware Detection Engine.
    /// Calculates Shannon entropy H = -Sum(p * log2(p)) across data blocks,
    /// identifies encrypted partitions/payloads, and flags anomalous ransomware activity.
    /// 100% offline, zero network telemetry, strictly bounded 64 KiB memory.
    /// </summary>
    public static class EntropyClassifier
    {
        private const int DefaultBlockSize = 65536; // 64 KiB
        private const double RansomwareThreshold = 7.92; // High entropy threshold for AES/ChaCha/RSA ciphertext

        // =========================================================================
        // Core Mathematical Entropy Calculation
        // =========================================================================

        public static double ComputeEntropy(byte[] buffer, int offset, int length)
        {
            if (buffer == null || length <= 0 || offset < 0 || offset + length > buffer.Length) return 0.0;

            int[] counts = new int[256];
            for (int i = 0; i < length; i++)
            {
                counts[buffer[offset + i]]++;
            }

            double entropy = 0.0;
            double lenRecip = 1.0 / length;

            for (int i = 0; i < 256; i++)
            {
                int count = counts[i];
                if (count > 0)
                {
                    double p = count * lenRecip;
                    entropy -= p * Math.Log(p, 2.0);
                }
            }

            if (entropy < 0.0) return 0.0;
            if (entropy > 8.0) return 8.0;
            return entropy;
        }

        public static EntropyCategory Classify(double entropy)
        {
            if (entropy < 1.0) return EntropyCategory.ZeroOrSparse;
            if (entropy < 4.5) return EntropyCategory.PlainTextOrCode;
            if (entropy < 6.8) return EntropyCategory.StructuredBinary;
            if (entropy < RansomwareThreshold) return EntropyCategory.CompressedData;
            return EntropyCategory.EncryptedOrRansomware;
        }

        // =========================================================================
        // Stream Analysis & Ransomware Detection
        // =========================================================================

        public static EntropyReport AnalyzeStream(Stream stream, long maxBytes = -1, int blockSize = DefaultBlockSize, CancellationToken cancellationToken = default(CancellationToken))
        {
            var report = new EntropyReport();
            if (stream == null || !stream.CanRead)
            {
                report.SuspicionReason = "Invalid or unreadable stream";
                return report;
            }

            if (blockSize <= 0 || blockSize > 65536) blockSize = DefaultBlockSize;
            byte[] buffer = new byte[blockSize];

            long bytesRemaining = maxBytes > 0 ? maxBytes : (stream.CanSeek ? (stream.Length - stream.Position) : long.MaxValue);
            long totalRead = 0;
            long streamStart = stream.CanSeek ? stream.Position : 0;

            var entropyValues = new List<double>();
            bool hasArchiveHeader = false;

            while (bytesRemaining > 0 && !cancellationToken.IsCancellationRequested)
            {
                int toRead = (int)Math.Min(blockSize, bytesRemaining);
                int read = stream.Read(buffer, 0, toRead);
                if (read <= 0) break;

                // Check for standard archive headers on the very first block
                if (totalRead == 0)
                {
                    hasArchiveHeader = IsStandardArchiveHeader(buffer, read);
                }

                double h = ComputeEntropy(buffer, 0, read);
                EntropyCategory cat = Classify(h);

                entropyValues.Add(h);
                if (h < report.MinEntropy) report.MinEntropy = h;
                if (h > report.MaxEntropy) report.MaxEntropy = h;

                report.TotalBlocks++;
                switch (cat)
                {
                    case EntropyCategory.ZeroOrSparse: report.SparseBlocks++; break;
                    case EntropyCategory.PlainTextOrCode: report.PlainTextBlocks++; break;
                    case EntropyCategory.StructuredBinary: report.StructuredBlocks++; break;
                    case EntropyCategory.CompressedData: report.CompressedBlocks++; break;
                    case EntropyCategory.EncryptedOrRansomware: report.EncryptedOrRansomwareBlocks++; break;
                }

                // Sample block profiles (limit to 500 for compact JSON)
                if (report.BlockProfiles.Count < 500)
                {
                    report.BlockProfiles.Add(new EntropyBlockResult
                    {
                        Offset = streamStart + totalRead,
                        Length = read,
                        Entropy = Math.Round(h, 4),
                        Category = cat
                    });
                }

                totalRead += read;
                if (maxBytes > 0) bytesRemaining -= read;
            }

            report.TotalBytesAnalyzed = totalRead;

            if (report.TotalBlocks == 0)
            {
                report.MinEntropy = 0.0;
                report.MaxEntropy = 0.0;
                report.MeanEntropy = 0.0;
                report.DominantCategory = EntropyCategory.ZeroOrSparse;
                return report;
            }

            // Calculate Mean & Standard Deviation
            double sum = 0.0;
            for (int i = 0; i < entropyValues.Count; i++) sum += entropyValues[i];
            report.MeanEntropy = sum / entropyValues.Count;

            double sumSquares = 0.0;
            for (int i = 0; i < entropyValues.Count; i++)
            {
                double diff = entropyValues[i] - report.MeanEntropy;
                sumSquares += diff * diff;
            }
            report.StandardDeviation = Math.Sqrt(sumSquares / entropyValues.Count);

            // Determine Dominant Category
            report.DominantCategory = Classify(report.MeanEntropy);

            // Ransomware detection heuristics
            double encryptedRatio = (double)report.EncryptedOrRansomwareBlocks / report.TotalBlocks;
            if (encryptedRatio >= 0.70 && !hasArchiveHeader && report.MeanEntropy >= 7.90)
            {
                report.IsSuspiciousRansomware = true;
                report.SuspicionReason = string.Format(CultureInfo.InvariantCulture,
                    "CRITICAL: {0:P1} of blocks exhibit cryptographic entropy (H >= {1}) without valid container signatures. Probable ransomware or raw encrypted volume.",
                    encryptedRatio, RansomwareThreshold);
            }
            else if (encryptedRatio >= 0.40 && !hasArchiveHeader)
            {
                report.IsSuspiciousRansomware = true;
                report.SuspicionReason = string.Format(CultureInfo.InvariantCulture,
                    "WARNING: Significant encrypted block clusters ({0:P1}) detected without recognized compression headers.",
                    encryptedRatio);
            }
            else
            {
                report.IsSuspiciousRansomware = false;
                report.SuspicionReason = "Normal entropy profile.";
            }

            return report;
        }

        private static bool IsStandardArchiveHeader(byte[] b, int length)
        {
            if (b == null || length < 4) return false;

            // ZIP "PK\x03\x04"
            if (b[0] == 0x50 && b[1] == 0x4B && (b[2] == 0x03 || b[2] == 0x05 || b[2] == 0x07)) return true;

            // 7-Zip "7z\xBC\xAF\x27\x1C"
            if (length >= 6 && b[0] == 0x37 && b[1] == 0x7A && b[2] == 0xBC && b[3] == 0xAF && b[4] == 0x27 && b[5] == 0x1C) return true;

            // GZIP "\x1F\x8B"
            if (b[0] == 0x1F && b[1] == 0x8B) return true;

            // RAR "Rar!\x1A\x07"
            if (length >= 6 && b[0] == 0x52 && b[1] == 0x61 && b[2] == 0x72 && b[3] == 0x21 && b[4] == 0x1A && b[5] == 0x07) return true;

            // BZIP2 "BZh"
            if (length >= 3 && b[0] == 0x42 && b[1] == 0x5A && b[2] == 0x68) return true;

            // XZ "\xFD7zXZ\x00"
            if (length >= 6 && b[0] == 0xFD && b[1] == 0x37 && b[2] == 0x7A && b[3] == 0x58 && b[4] == 0x5A && b[5] == 0x00) return true;

            return false;
        }
    }
}
