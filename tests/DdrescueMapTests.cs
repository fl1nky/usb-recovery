using System;
using System.IO;
using System.Text;
using UsbRecovery;

public static class DdrescueMapTests
{
    static int checks;

    static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
            throw new Exception("Assertion failed: " + message);
    }

    public static int Main(string[] args)
    {
        try
        {
            string sampleMap = @"# Mapfile. Initial status after rescue
# Command line: ddrescue -b 512 /dev/sdb image.dd mapfile
# Current_pos       Current_status  Current_pass
0x00010000          ?               1
# Pos               Size            Status
0x00000000          0x00001000      +
0x00001000          0x00000200      -
0x00001200          0x00000E00      +
0x00002000          0x00002000      ?
0x00004000          0x00001000      *
0x00005000          0x00001000      /
0x00006000          0x00002000      +
";

            // Test 1: Parse sample GNU ddrescue mapfile
            var map = DdrescueMap.Parse(sampleMap);
            Check(map != null, "Map should not be null");
            Check(map.Blocks.Count == 7, "Should parse 7 blocks");
            Check(map.CurrentPos == 0x10000, "CurrentPos should match 0x10000");
            Check(map.CurrentStatus == '?', "CurrentStatus should be ?");
            Check(map.CurrentPass == 1, "CurrentPass should be 1");

            // Test 2: Verify block values
            var b0 = map.Blocks[0];
            Check(b0.Offset == 0, "Block 0 offset 0");
            Check(b0.Length == 0x1000, "Block 0 length 0x1000 (4096 bytes)");
            Check(b0.IsFinished, "Block 0 is finished (+)");
            Check(!b0.IsBad, "Block 0 is not bad");

            var b1 = map.Blocks[1];
            Check(b1.Offset == 0x1000, "Block 1 offset 0x1000");
            Check(b1.Length == 0x200, "Block 1 length 512 bytes");
            Check(b1.IsBad, "Block 1 is bad (-)");
            Check(!b1.IsFinished, "Block 1 is not finished");

            var b2 = map.Blocks[2];
            Check(b2.Offset == 0x1200, "Block 2 offset 0x1200");
            Check(b2.Length == 0xE00, "Block 2 length 0xE00");
            Check(b2.IsFinished, "Block 2 is finished");

            var b3 = map.Blocks[3];
            Check(b3.IsNonTried, "Block 3 is non-tried (?)");

            var b4 = map.Blocks[4];
            Check(b4.IsNonTrimmed, "Block 4 is non-trimmed (*)");

            var b5 = map.Blocks[5];
            Check(b5.IsNonScraped, "Block 5 is non-scraped (/)");

            var b6 = map.Blocks[6];
            Check(b6.IsFinished, "Block 6 is finished (+)");

            // Test 3: Total calculations
            long expectedRescued = 0x1000 + 0xE00 + 0x2000;
            Check(map.TotalRescuedBytes == expectedRescued, "Total rescued bytes calculation");
            Check(map.TotalBadBytes == 0x200, "Total bad bytes calculation (512 bytes)");
            Check(map.TotalMapSpan == 0x8000, "Total map span calculation");

            // Test 4: IsRangeRescued queries
            Check(map.IsRangeRescued(0, 0x1000), "0..0x1000 is fully rescued");
            Check(map.IsRangeRescued(0, 0x800), "0..0x800 sub-range is fully rescued");
            Check(!map.IsRangeRescued(0, 0x1001), "0..0x1001 spans into bad sector");
            Check(!map.IsRangeRescued(0x1000, 0x200), "0x1000..0x1200 is bad sector");
            Check(map.IsRangeRescued(0x1200, 0xE00), "0x1200..0x2000 is rescued");
            Check(!map.IsRangeRescued(0x2000, 0x1000), "0x2000..0x3000 is non-tried");
            Check(map.IsRangeRescued(0x6000, 0x2000), "0x6000..0x8000 is rescued");

            // Test 5: HasBadSectors queries
            Check(!map.HasBadSectors(0, 0x1000), "0..0x1000 has no bad sectors");
            Check(map.HasBadSectors(0, 0x1100), "0..0x1100 contains bad sector at 0x1000");
            Check(map.HasBadSectors(0x1000, 0x200), "0x1000 exact bad sector detected");
            Check(!map.HasBadSectors(0x1200, 0x4000), "0x1200..0x5200 has no bad sectors (only ? and *)");

            // Test 6: Empty map
            var emptyMap = DdrescueMap.Parse("");
            Check(emptyMap.Blocks.Count == 0, "Empty text produces empty map");
            Check(emptyMap.IsRangeRescued(0, 1000), "Empty map treats ranges as available");
            Check(!emptyMap.HasBadSectors(0, 1000), "Empty map has no bad sectors");

            // Test 7: Load from disk
            string tempFile = Path.Combine(Path.GetTempPath(), "ddrescue_test_" + Guid.NewGuid().ToString("N") + ".map");
            try
            {
                File.WriteAllText(tempFile, sampleMap, Encoding.UTF8);
                var loadedMap = DdrescueMap.Load(tempFile);
                Check(loadedMap.Blocks.Count == 7, "Loaded map from disk has 7 blocks");
                Check(loadedMap.TotalRescuedBytes == expectedRescued, "Loaded map rescued bytes match");
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }

            Console.WriteLine("PASS DdrescueMap: {0} checks; GNU ddrescue v1/v2 mapfile parsing, block status classification, and interval query verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL DdrescueMap: {0}", ex.Message);
            return 1;
        }
    }
}
