using System;
using System.IO;
using UsbRecovery;

public static class ForensicBenchmarkTests
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
        {
            throw new Exception("Check failed: " + message);
        }
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("Running ForensicBenchmarkTests...");

        try
        {
            // Run quick benchmark with 8 MB sample to ensure fast deterministic testing
            var report = ForensicBenchmarkSuite.RunAll(8);
            Check(report != null, "Report should not be null");
            Check(report.Benchmarks.Count >= 3, "Report must have at least 3 benchmark suites");

            var swar = report.Benchmarks.Find(delegate(BenchmarkResult b) { return b.BenchmarkName.Contains("SWAR"); });
            Check(swar != null, "SWAR benchmark must be present");
            Check(swar.ThroughputMBs > 50.0, "SWAR throughput must exceed 50 MB/s (was " + swar.ThroughputMBs + " MB/s)");

            var entropy = report.Benchmarks.Find(delegate(BenchmarkResult b) { return b.BenchmarkName.Contains("Entropy"); });
            Check(entropy != null, "Entropy benchmark must be present");
            Check(entropy.ThroughputMBs > 20.0, "Entropy throughput must exceed 20 MB/s (was " + entropy.ThroughputMBs + " MB/s)");

            var mft = report.Benchmarks.Find(delegate(BenchmarkResult b) { return b.BenchmarkName.Contains("MFT"); });
            Check(mft != null, "MFT benchmark must be present");
            Check(mft.ProcessedBytes > 0, "MFT processed bytes must be > 0");

            Check(report.ZeroLeakVerified, "Zero-leak audit must pass (memory growth bounded strictly)");

            string json = report.ToJson();
            Check(json.Contains("SWAR Signature Scanner"), "JSON must contain SWAR scanner result");
            Check(json.Contains("ZeroLeakVerified\":true"), "JSON must verify ZeroLeakVerified");

            Console.WriteLine("PASS ForensicBenchmarkTests: {0} checks passed; SWAR scanner speed, Entropy engine throughput, MFT parser rate, and Zero-Leak memory boundaries verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error in benchmark test: {0}", ex.Message);
            return 1;
        }
    }
}
