using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UsbRecovery;

public static class EntropyClassifierTests
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
        Console.WriteLine("Running EntropyClassifierTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "entropy-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            TestZeroAndSparseEntropy();
            TestPlainTextEntropy();
            TestStructuredBinaryEntropy();
            TestEncryptedHighEntropy();
            TestStreamingAnalysisAndRansomwareDetection(testDir);

            Console.WriteLine("PASS EntropyClassifierTests: {0} checks passed; mathematical Shannon entropy, category classification, streaming multi-block analysis, and ransomware detection verified.", checks);
            return 0;
        }
        finally
        {
            try
            {
                if (Directory.Exists(testDir))
                {
                    Directory.Delete(testDir, true);
                }
            }
            catch { }
        }
    }

    private static void TestZeroAndSparseEntropy()
    {
        byte[] zeros = new byte[4096];
        double hZeros = EntropyClassifier.ComputeEntropy(zeros, 0, zeros.Length);
        Check(hZeros == 0.0, "All-zero buffer must have exactly 0.0 entropy");
        Check(EntropyClassifier.Classify(hZeros) == EntropyCategory.ZeroOrSparse, "Classify(0.0) must be ZeroOrSparse");

        // Single repeating byte
        byte[] repeated = new byte[1024];
        for (int i = 0; i < repeated.Length; i++) repeated[i] = 0xAA;
        double hRep = EntropyClassifier.ComputeEntropy(repeated, 0, repeated.Length);
        Check(hRep == 0.0, "Single repeating byte must have 0.0 entropy");
    }

    private static void TestPlainTextEntropy()
    {
        string sampleText = "The quick brown fox jumps over the lazy dog. Digital forensics and incident response requires mathematical precision and cryptographic integrity.";
        byte[] textBytes = Encoding.UTF8.GetBytes(sampleText);
        double hText = EntropyClassifier.ComputeEntropy(textBytes, 0, textBytes.Length);

        Check(hText > 3.0 && hText < 4.8, "English text entropy should typically be between 3.5 and 4.8 bits/byte");
        Check(EntropyClassifier.Classify(hText) == EntropyCategory.PlainTextOrCode ||
              EntropyClassifier.Classify(hText) == EntropyCategory.StructuredBinary,
              "Text should be PlainTextOrCode or structured");
    }

    private static void TestStructuredBinaryEntropy()
    {
        // Synthesize structured binary data with moderate entropy (~5.5)
        byte[] structured = new byte[8192];
        for (int i = 0; i < structured.Length; i++)
        {
            structured[i] = (byte)((i % 32) + (i % 4));
        }
        double h = EntropyClassifier.ComputeEntropy(structured, 0, structured.Length);
        Check(h >= 4.0 && h < 6.8, "Structured binary entropy should be between 4.0 and 6.8 bits/byte");
        Check(EntropyClassifier.Classify(h) == EntropyCategory.StructuredBinary ||
              EntropyClassifier.Classify(h) == EntropyCategory.PlainTextOrCode,
              "Structured buffer should classify accordingly");
    }

    private static void TestEncryptedHighEntropy()
    {
        // Cryptographically random bytes
        byte[] cryptoRandom = new byte[16384];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(cryptoRandom);
        }

        double h = EntropyClassifier.ComputeEntropy(cryptoRandom, 0, cryptoRandom.Length);
        Check(h >= 7.95, "Cryptographic random bytes must have entropy >= 7.95 bits/byte (was " + h + ")");
        Check(EntropyClassifier.Classify(h) == EntropyCategory.EncryptedOrRansomware, "Must classify as EncryptedOrRansomware");
    }

    private static void TestStreamingAnalysisAndRansomwareDetection(string testDir)
    {
        // 1. Test normal mixed stream (sparse + text + random)
        string mixedFile = Path.Combine(testDir, "mixed_disk.img");
        using (var fs = new FileStream(mixedFile, FileMode.Create, FileAccess.ReadWrite))
        {
            // Block 1: 64 KiB zeros
            fs.Write(new byte[65536], 0, 65536);

            // Block 2: 64 KiB text
            byte[] textBlock = new byte[65536];
            byte[] t = Encoding.UTF8.GetBytes("Forensic analysis log entry line #");
            for (int i = 0; i < textBlock.Length; i++) textBlock[i] = t[i % t.Length];
            fs.Write(textBlock, 0, textBlock.Length);

            fs.Flush();
            fs.Position = 0;

            var report = EntropyClassifier.AnalyzeStream(fs);
            Check(report.TotalBlocks == 2, "Should have 2 blocks");
            Check(report.TotalBytesAnalyzed == 131072, "Total bytes should be 128 KiB");
            Check(report.SparseBlocks == 1, "Should have 1 sparse block");
            Check(report.PlainTextBlocks == 1, "Should have 1 plaintext block");
            Check(!report.IsSuspiciousRansomware, "Mixed stream should NOT be flagged as ransomware");
        }

        // 2. Test Ransomware payload simulation (100% cryptographic noise without archive header)
        string ransomwareFile = Path.Combine(testDir, "encrypted_drive.img");
        using (var fs = new FileStream(ransomwareFile, FileMode.Create, FileAccess.ReadWrite))
        {
            byte[] cipher = new byte[65536];
            using (var rng = new RNGCryptoServiceProvider())
            {
                for (int b = 0; b < 4; b++)
                {
                    rng.GetBytes(cipher);
                    fs.Write(cipher, 0, cipher.Length);
                }
            }
            fs.Flush();
            fs.Position = 0;

            var rReport = EntropyClassifier.AnalyzeStream(fs);
            Check(rReport.TotalBlocks == 4, "Should have 4 blocks");
            Check(rReport.MeanEntropy >= 7.95, "Mean entropy should be >= 7.95");
            Check(rReport.EncryptedOrRansomwareBlocks == 4, "All 4 blocks must be classified as EncryptedOrRansomware");
            Check(rReport.IsSuspiciousRansomware, "High-entropy unheadered stream MUST trigger ransomware detection");
            Check(rReport.SuspicionReason.Contains("CRITICAL") || rReport.SuspicionReason.Contains("ransomware"),
                "Suspicion reason must cite probable ransomware or encryption");

            string json = rReport.ToJson();
            Check(json.Contains("IsSuspiciousRansomware\":true"), "JSON must reflect ransomware detection");
        }
    }
}
