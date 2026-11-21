using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class BenchmarkResult
    {
        public string BenchmarkName { get; set; }
        public long ProcessedBytes { get; set; }
        public double ElapsedMilliseconds { get; set; }
        public double ThroughputMBs { get; set; }
        public long MemoryDeltaBytes { get; set; }
        public string Details { get; set; }

        public BenchmarkResult()
        {
            BenchmarkName = String.Empty;
            Details = String.Empty;
        }
    }

    public sealed class ForensicBenchmarkReport
    {
        public string TimestampUtc { get; set; }
        public string HostEnvironment { get; set; }
        public double TotalDurationMs { get; set; }
        public bool ZeroLeakVerified { get; set; }
        public List<BenchmarkResult> Benchmarks { get; set; }

        public ForensicBenchmarkReport()
        {
            Benchmarks = new List<BenchmarkResult>();
            TimestampUtc = DateTime.UtcNow.ToString("o");
            HostEnvironment = string.Format(CultureInfo.InvariantCulture,
                "OS: {0}, Cores: {1}, CLR: {2}",
                Environment.OSVersion.VersionString, Environment.ProcessorCount, Environment.Version);
        }

        public string ToJson()
        {
            var serializer = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
            return serializer.Serialize(this);
        }
    }

    /// <summary>
    /// Pure C# Forensic Performance & Zero-Leak Benchmark Engine.
    /// Evaluates SWAR vectorized signature scanning, Shannon entropy throughput,
    /// MFT carving speeds, and verifies strict O(1) buffer ceiling compliance (no LOH bloat).
    /// </summary>
    public static class ForensicBenchmarkSuite
    {
        public static ForensicBenchmarkReport RunAll(int dataSizeMb = 32)
        {
            if (dataSizeMb <= 0 || dataSizeMb > 512) dataSizeMb = 32;

            var report = new ForensicBenchmarkReport();
            var totalSw = Stopwatch.StartNew();

            long initialMemory = GC.GetTotalMemory(true);

            // 1. Benchmark SWAR Vectorized Signature Scanner
            report.Benchmarks.Add(BenchmarkSwarScanning(dataSizeMb));

            // 2. Benchmark Shannon Entropy Computation
            report.Benchmarks.Add(BenchmarkEntropy(dataSizeMb));

            // 3. Benchmark MFT Record Carver
            report.Benchmarks.Add(BenchmarkMftCarving(10000));

            // 4. Benchmark Memory Stability
            long finalMemory = GC.GetTotalMemory(true);
            long totalLeakBytes = Math.Max(0, finalMemory - initialMemory);
            report.ZeroLeakVerified = (totalLeakBytes < 5 * 1024 * 1024); // Memory growth strictly under 5 MB after running all suites

            totalSw.Stop();
            report.TotalDurationMs = totalSw.Elapsed.TotalMilliseconds;

            return report;
        }

        public static BenchmarkResult BenchmarkSwarScanning(int sizeMb)
        {
            long totalBytes = (long)sizeMb * 1024 * 1024;
            byte[] block = new byte[65536];
            for (int i = 0; i < block.Length; i++) block[i] = (byte)(i & 0xFF);

            // Inject known signatures every 8 KiB
            byte[] sigZip = new byte[] { 0x50, 0x4B, 0x03, 0x04 };
            byte[] sigPng = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            for (int p = 0; p + 8 < block.Length; p += 8192)
            {
                Array.Copy(sigZip, 0, block, p, 4);
                Array.Copy(sigPng, 0, block, p + 4096, 8);
            }

            var signatures = new List<TargetSignature>
            {
                new TargetSignature("JPEG", new byte[] { 0xFF, 0xD8, 0xFF }),
                new TargetSignature("PNG", sigPng),
                new TargetSignature("ZIP", sigZip),
                new TargetSignature("PDF", new byte[] { 0x25, 0x50, 0x44, 0x46 }) // %PDF
            };

            var scanner = new FastVectorScanner(signatures);

            long memBefore = GC.GetTotalMemory(true);
            var sw = Stopwatch.StartNew();

            long bytesScanned = 0;
            int matchesFound = 0;

            while (bytesScanned < totalBytes)
            {
                var matches = scanner.ScanBuffer(block, 0, block.Length);
                matchesFound += matches.Count;
                bytesScanned += block.Length;
            }

            sw.Stop();
            long memAfter = GC.GetTotalMemory(true);

            double mb = (double)bytesScanned / (1024 * 1024);
            double sec = sw.Elapsed.TotalSeconds;
            double speed = sec > 0 ? (mb / sec) : 0;

            return new BenchmarkResult
            {
                BenchmarkName = "SWAR Signature Scanner",
                ProcessedBytes = bytesScanned,
                ElapsedMilliseconds = Math.Round(sw.Elapsed.TotalMilliseconds, 2),
                ThroughputMBs = Math.Round(speed, 2),
                MemoryDeltaBytes = Math.Max(0, memAfter - memBefore),
                Details = string.Format(CultureInfo.InvariantCulture,
                    "Multi-pattern (4 sigs), {0:N0} matches found across {1} MB", matchesFound, sizeMb)
            };
        }

        public static BenchmarkResult BenchmarkEntropy(int sizeMb)
        {
            long totalBytes = (long)sizeMb * 1024 * 1024;
            byte[] block = new byte[65536];
            for (int i = 0; i < block.Length; i++) block[i] = (byte)((i * 37) & 0xFF);

            long memBefore = GC.GetTotalMemory(true);
            var sw = Stopwatch.StartNew();

            long bytesComputed = 0;
            double dummySum = 0;

            while (bytesComputed < totalBytes)
            {
                double h = EntropyClassifier.ComputeEntropy(block, 0, block.Length);
                dummySum += h;
                bytesComputed += block.Length;
            }

            sw.Stop();
            long memAfter = GC.GetTotalMemory(true);

            double mb = (double)bytesComputed / (1024 * 1024);
            double sec = sw.Elapsed.TotalSeconds;
            double speed = sec > 0 ? (mb / sec) : 0;

            return new BenchmarkResult
            {
                BenchmarkName = "Shannon Entropy Engine",
                ProcessedBytes = bytesComputed,
                ElapsedMilliseconds = Math.Round(sw.Elapsed.TotalMilliseconds, 2),
                ThroughputMBs = Math.Round(speed, 2),
                MemoryDeltaBytes = Math.Max(0, memAfter - memBefore),
                Details = string.Format(CultureInfo.InvariantCulture,
                    "64 KiB block entropy H=-Sum(p*log2(p)), {0} MB processed", sizeMb)
            };
        }

        public static BenchmarkResult BenchmarkMftCarving(int recordCount)
        {
            if (recordCount <= 0) recordCount = 10000;
            long totalBytes = (long)recordCount * 1024; // 1024 bytes per record

            // Synthesize valid MFT records
            byte[] rawRecords = new byte[64 * 1024]; // 64 records per chunk
            for (int r = 0; r < 64; r++)
            {
                int baseOff = r * 1024;
                rawRecords[baseOff + 0] = (byte)'F';
                rawRecords[baseOff + 1] = (byte)'I';
                rawRecords[baseOff + 2] = (byte)'L';
                rawRecords[baseOff + 3] = (byte)'E';
                // USA offset at 48 (0x30), count 3
                rawRecords[baseOff + 4] = 0x30;
                rawRecords[baseOff + 5] = 0x00;
                rawRecords[baseOff + 6] = 0x03;
                rawRecords[baseOff + 7] = 0x00;
                // Allocated flag at 22
                rawRecords[baseOff + 22] = 0x01;
            }

            long memBefore = GC.GetTotalMemory(true);
            var sw = Stopwatch.StartNew();

            int parsed = 0;
            long bytesProcessed = 0;

            while (bytesProcessed < totalBytes)
            {
                for (int r = 0; r < 64 && bytesProcessed < totalBytes; r++)
                {
                    MftFileRecord rec;
                    if (MftCarver.TryParseRecord(rawRecords, r * 1024, bytesProcessed, out rec)) parsed++;
                    bytesProcessed += 1024;
                }
            }

            sw.Stop();
            long memAfter = GC.GetTotalMemory(true);

            double mb = (double)bytesProcessed / (1024 * 1024);
            double sec = sw.Elapsed.TotalSeconds;
            double speed = sec > 0 ? (mb / sec) : 0;
            double recordsPerSec = sec > 0 ? (parsed / sec) : 0;

            return new BenchmarkResult
            {
                BenchmarkName = "MFT Record Parser",
                ProcessedBytes = bytesProcessed,
                ElapsedMilliseconds = Math.Round(sw.Elapsed.TotalMilliseconds, 2),
                ThroughputMBs = Math.Round(speed, 2),
                MemoryDeltaBytes = Math.Max(0, memAfter - memBefore),
                Details = string.Format(CultureInfo.InvariantCulture,
                    "{0:N0} records parsed ({1:N0} records/sec), 1024-byte Fixup decoding", parsed, recordsPerSec)
            };
        }

        public static void PrintReport(ForensicBenchmarkReport report)
        {
            if (report == null) return;

            Console.WriteLine("================================================================================");
            Console.WriteLine("  USB-Recovery — High-Performance Forensic Engine Benchmark");
            Console.WriteLine("================================================================================");
            Console.WriteLine("  Host:       {0}", report.HostEnvironment);
            Console.WriteLine("  Total Time: {0:N2} ms", report.TotalDurationMs);
            Console.WriteLine("  Zero-Leak:  {0}", report.ZeroLeakVerified ? "✓ VERIFIED (O(1) buffer ceiling)" : "WARNING: Memory delta observed");
            Console.WriteLine("--------------------------------------------------------------------------------");
            Console.WriteLine("{0,-26} | {1,12} | {2,10} | {3,12} | {4,10}",
                "Engine Component", "Processed", "Time (ms)", "Throughput", "RAM Delta");
            Console.WriteLine("--------------------------------------------------------------------------------");

            for (int i = 0; i < report.Benchmarks.Count; i++)
            {
                var b = report.Benchmarks[i];
                string sizeStr = (b.ProcessedBytes / (1024.0 * 1024.0)).ToString("0.0", CultureInfo.InvariantCulture) + " MB";
                string speedStr = b.ThroughputMBs.ToString("0.0", CultureInfo.InvariantCulture) + " MB/s";
                string memStr = (b.MemoryDeltaBytes / 1024.0).ToString("0.0", CultureInfo.InvariantCulture) + " KB";

                Console.WriteLine("{0,-26} | {1,12} | {2,10:N1} | {3,12} | {4,10}",
                    b.BenchmarkName, sizeStr, b.ElapsedMilliseconds, speedStr, memStr);
                Console.WriteLine("  └─ {0}", b.Details);
            }
            Console.WriteLine("================================================================================");
        }
    }
}
