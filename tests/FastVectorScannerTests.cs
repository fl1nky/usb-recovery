using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class FastVectorScannerTests
{
    public static void Main()
    {
        int passed = 0;

        // 1. In-memory buffer scan
        FastVectorScanner scanner = FastVectorScanner.CreateForensicDefault();
        Assert(scanner.Signatures.Count >= 10, "Forensic default signatures loaded");
        passed++;

        byte[] testBuf = new byte[1024];
        // Embed ZIP header at 100
        testBuf[100] = 0x50; testBuf[101] = 0x4B; testBuf[102] = 0x03; testBuf[103] = 0x04;
        // Embed PDF header at 500
        testBuf[500] = 0x25; testBuf[501] = 0x50; testBuf[502] = 0x44; testBuf[503] = 0x46; testBuf[504] = 0x2D;

        List<SignatureMatch> matches = scanner.ScanBuffer(testBuf, 0, testBuf.Length, 0);
        Assert(matches.Count == 2, "Found both signatures in buffer");
        passed++;

        Assert(matches[0].Name == "ZIP_ARCHIVE" && matches[0].Offset == 100, "ZIP match at offset 100");
        passed++;

        Assert(matches[1].Name == "PDF_DOCUMENT" && matches[1].Offset == 500, "PDF match at offset 500");
        passed++;

        // 2. Overlap boundary crossing test (64 KiB boundary)
        // Buffer size is 65536. Place a signature spanning offset 65534..65538
        int totalStreamSize = 131072; // 128 KiB
        byte[] streamData = new byte[totalStreamSize];

        // Place QCOW2 magic at boundary: 65534, 65535, 65536, 65537
        int boundaryOffset = 65534;
        streamData[boundaryOffset] = 0x51;
        streamData[boundaryOffset + 1] = 0x46;
        streamData[boundaryOffset + 2] = 0x49;
        streamData[boundaryOffset + 3] = 0xFB;

        using (MemoryStream ms = new MemoryStream(streamData))
        {
            List<SignatureMatch> streamMatches = scanner.ScanStream(ms, CancellationToken.None);
            Assert(streamMatches.Count >= 1, "Boundary match detected");
            passed++;

            bool foundBoundary = false;
            for (int i = 0; i < streamMatches.Count; i++)
            {
                if (streamMatches[i].Name == "QCOW2_IMAGE" && streamMatches[i].Offset == boundaryOffset)
                {
                    foundBoundary = true;
                    break;
                }
            }
            Assert(foundBoundary, "QCOW2 match accurately found spanning 64 KiB block boundary");
            passed++;
        }

        // 3. Cancellation test
        CancellationTokenSource cts = new CancellationTokenSource();
        cts.Cancel(); // pre-cancel
        using (MemoryStream ms = new MemoryStream(streamData))
        {
            List<SignatureMatch> cancelledMatches = scanner.ScanStream(ms, cts.Token);
            Assert(cancelledMatches.Count == 0, "Cancelled scan aborted immediately");
            passed++;
        }
        cts.Dispose();

        // 4. Memory footprint verification (O(1) buffer)
        byte[] dummyChunk = new byte[1048576]; // 1 MB
        using (MemoryStream ms = new MemoryStream(dummyChunk))
        {
            long beforeAlloc = GC.GetTotalMemory(true);
            scanner.ScanStream(ms, CancellationToken.None);
            long afterAlloc = GC.GetTotalMemory(false);
            long diff = afterAlloc - beforeAlloc;
            Assert(diff < 200000, "Memory bounded during stream scan (<200KB delta)");
            passed++;
        }

        Console.WriteLine("PASS FastVectorScannerTests: {0} checks passed; SWAR scanning, multi-signature lookup, boundary crossing, and memory bounds verified.", passed);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception("Assertion failed: " + message);
        }
    }
}
