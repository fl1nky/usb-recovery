using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class MetadataRescueTests
{
    static int assertions;
    static string fixtures;
    static void Assert(bool value, string message) { assertions++; if (!value) throw new Exception(message); }
    static void Throws<T>(Action action, string message) where T : Exception { try { action(); } catch (T) { assertions++; return; } throw new Exception(message); }
    static void Set(byte[] b, int p, ushort v) { Buffer.BlockCopy(BitConverter.GetBytes(v), 0, b, p, 2); }
    static void Set(byte[] b, int p, uint v) { Buffer.BlockCopy(BitConverter.GetBytes(v), 0, b, p, 4); }
    static void Set(byte[] b, int p, long v) { Buffer.BlockCopy(BitConverter.GetBytes(v), 0, b, p, 8); }
    static string Hash(string path) { using (var source = File.OpenRead(path)) using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(source)); }
    static byte[] Pattern(int length) { return Enumerable.Range(0, length).Select(i => (byte)(i * 37 + 11)).ToArray(); }
    static int Round(int length) { return (length + 7) / 8 * 8; }
    static byte[] Resident(uint type, byte[] value)
    {
        byte[] a = new byte[Round(24 + value.Length)]; Set(a, 0, type); Set(a, 4, (uint)a.Length); Set(a, 16, (uint)value.Length); Set(a, 20, (ushort)24); Buffer.BlockCopy(value, 0, a, 24, value.Length); return a;
    }
    static byte[] Nonresident(long size, long initialized, long allocated, long highestVcn, byte[] pairs, ushort flags = 0)
    {
        byte[] a = new byte[Round(64 + pairs.Length)]; Set(a, 0, 0x80U); Set(a, 4, (uint)a.Length); a[8] = 1; Set(a, 12, flags);
        Set(a, 24, highestVcn); Set(a, 32, (ushort)64); Set(a, 40, allocated); Set(a, 48, size); Set(a, 56, initialized); Buffer.BlockCopy(pairs, 0, a, 64, pairs.Length); return a;
    }
    static byte[] Record(string name, uint number, byte[] data, ushort flags = 0, byte[] extra = null)
    {
        byte[] text = Encoding.Unicode.GetBytes(name), value = new byte[66 + text.Length]; Set(value, 0, 5L | (1L << 48)); value[64] = (byte)name.Length; value[65] = 1; Buffer.BlockCopy(text, 0, value, 66, text.Length);
        byte[] filename = Resident(0x30, value), record = new byte[1024]; Buffer.BlockCopy(Encoding.ASCII.GetBytes("FILE"), 0, record, 0, 4);
        Set(record, 4, (ushort)48); Set(record, 6, (ushort)3); Set(record, 16, (ushort)7); Set(record, 20, (ushort)56); Set(record, 22, flags); Set(record, 28, 1024U); Set(record, 44, number);
        int at = 56; if (extra != null) { Buffer.BlockCopy(extra, 0, record, at, extra.Length); at += extra.Length; }
        Buffer.BlockCopy(filename, 0, record, at, filename.Length); at += filename.Length;
        if (data != null) { Buffer.BlockCopy(data, 0, record, at, data.Length); at += data.Length; }
        Set(record, at, UInt32.MaxValue); Set(record, 24, (uint)(at + 8));
        Set(record, 48, (ushort)0xa5b6); for (int sector = 1; sector <= 2; sector++) { Set(record, 48 + sector * 2, BitConverter.ToUInt16(record, sector * 512 - 2)); Set(record, sector * 512 - 2, (ushort)0xa5b6); }
        return record;
    }
    static string Image(string name, byte[] record, int at = 8 * 1024 * 1024)
    {
        string path = Path.Combine(fixtures, name + ".dd"); using (var f = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) { f.SetLength(at + 2048); f.Position = at; f.Write(record, 0, record.Length); } return path;
    }
    static string Run(string name, string image, out MetadataRescue.Report report, Action<string> progress = null, CancellationToken cancel = default(CancellationToken))
    {
        string root = Path.Combine(fixtures, name); MetadataRescue.Recover(image, root, cancel, progress);
        report = ReadReport(root); return root;
    }
    static MetadataRescue.Report ReadReport(string root) { return new JavaScriptSerializer { MaxJsonLength = 128 * 1024 * 1024 }.Deserialize<MetadataRescue.Report>(File.ReadAllText(Path.Combine(root, "metadata-rescue", "report.json"))); }
    static void Json(string path, object value) { File.WriteAllText(path, new JavaScriptSerializer().Serialize(value), Encoding.UTF8); }
    static string Output(string root, MetadataRescue.Entry item) { return Path.Combine(root, "metadata-rescue", item.Output.Replace('/', Path.DirectorySeparatorChar)); }
    static void Bytes(string file, byte[] expected, string message) { Assert(File.ReadAllBytes(file).SequenceEqual(expected), message); }
    static string VolumeImage(string name, bool allocatedFirst = false, bool allocatedSecond = false, bool bitmapActive = true, bool fragmentedMft = false, long initialized = 5500, byte[] overridePairs = null)
    {
        const int cluster = 4096, length = 2 * 1024 * 1024;
        string path = Path.Combine(fixtures, name + ".dd"); byte[] boot = new byte[512]; boot[0] = 0xeb; boot[1] = 0x52; boot[2] = 0x90; Buffer.BlockCopy(Encoding.ASCII.GetBytes("NTFS    "), 0, boot, 3, 8);
        Set(boot, 11, (ushort)512); boot[13] = 8; Set(boot, 40, length / 512 - 1L); Set(boot, 48, 4L); Set(boot, 56, 16L); boot[64] = unchecked((byte)-10); boot[510] = 0x55; boot[511] = 0xaa;
        byte[] bitmap = new byte[length / cluster / 8]; bitmap[0] = 0xff;
        if (fragmentedMft) bitmap[1] |= 7;
        if (allocatedFirst) bitmap[45 / 8] |= 1 << (45 & 7); if (allocatedSecond) bitmap[40 / 8] |= 1 << (40 & 7);
        byte[] mft = Record("$MFT", 0, Nonresident(16384, 16384, 16384, 3, fragmentedMft ? new byte[] { 0x11, 1, 4, 0x11, 3, 4, 0 } : new byte[] { 0x11, 4, 4, 0 }), 1);
        byte[] map = Record("$Bitmap", 6, Resident(0x80, bitmap), bitmapActive ? (ushort)1 : (ushort)0);
        byte[] removed = Record("important.bin", 42, Nonresident(5500, initialized, 8192, 1, overridePairs ?? new byte[] { 0x11, 1, 45, 0x11, 1, 0xfb, 0 }));
        byte[] content = Pattern(5500);
        using (var f = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
            f.SetLength(length); f.Write(boot, 0, 512); f.Position = 4 * cluster; f.Write(mft, 0, 1024);
            f.Position = fragmentedMft ? 8 * cluster + 2048 : 4 * cluster + 6 * 1024; f.Write(map, 0, 1024);
            f.Position = 1024 * 1024; f.Write(removed, 0, 1024); f.Position = 45 * cluster; f.Write(content, 0, 4096); f.Position = 40 * cluster; f.Write(content, 4096, content.Length - 4096);
        }
        return path;
    }
    static void ResidentAndValidation()
    {
        byte[] expected = Pattern(700), record = Record("прабабушка.txt", 42, Resident(0x80, expected));
        string image = Image("resident", record), before = Hash(image); MetadataRescue.Report report;
        File.SetAttributes(image, FileAttributes.ReadOnly);
        string root = Run("resident-result", image, out report);
        Assert(report.ScannedBytes == new FileInfo(image).Length && report.ValidatedRecords == 1 && report.RecoveredFiles == 1, "Full image scan beyond first MiB");
        Bytes(Output(root, report.Entries[0]), expected, "Resident payload includes restored USA tail bytes");
        Assert(report.Entries[0].UsaFixupsRestored && report.Entries[0].RecordOffset == 8 * 1024 * 1024 && report.Entries[0].ParentRecordNumber == 5 && report.Entries[0].ParentSequence == 1, "Resident provenance and parent reference are explicit");
        Assert(report.Entries[0].Note.Contains("не точная побайтовая карта"), "Resident fixup provenance limitation is explicit");
        Assert(report.Entries[0].Status == "resident_candidate" && report.Entries[0].Sha256.Length == 64 && report.Entries[0].VolumeOffset == null, "No volume/deletion certainty invented");
        Assert(Hash(image) == before, "Read-only resident image unchanged");
        root = Run("block-boundary-result", Image("block-boundary", record, 4 * 1024 * 1024 - 512), out report);
        Bytes(Output(root, report.Entries.Single()), expected, "A FILE record crossing scan blocks is reconstructed once");
        string safe = Image("traversal-name", Record("..\\..\\outside.txt", 42, Resident(0x80, Pattern(20))));
        root = Run("safe-result", safe, out report);
        Assert(report.RecoveredFiles == 1 && Output(root, report.Entries[0]).StartsWith(Path.Combine(root, "metadata-rescue", "files") + Path.DirectorySeparatorChar), "Filename cannot escape destination");
        var corruptions = new Dictionary<string, Action<byte[]>> {
            { "usa-tail", b => b[510] ^= 1 }, { "usa-count", b => Set(b, 6, (ushort)2) },
            { "legacy-usa42", b => Set(b, 4, (ushort)42) }, { "legacy-usa44", b => Set(b, 4, (ushort)44) }, { "legacy-usa46", b => Set(b, 4, (ushort)46) },
            { "usa-overlap", b => Set(b, 4, (ushort)54) }, { "first-attribute", b => Set(b, 20, (ushort)57) },
            { "used-overflow", b => Set(b, 24, 0x80000000U) }, { "used-zero", b => Set(b, 24, 0U) },
            { "attribute-length", b => Set(b, 60, 0xfffffff8U) }, { "extension", b => Set(b, 32, 123L) },
            { "resident-value", b => Set(b, 56 + Round(24 + 66 + "ok.bin".Length * 2) + 16, UInt32.MaxValue) },
            { "invalid-unicode", b => { b[56 + 24 + 66] = 0; b[56 + 24 + 67] = 0xd8; } }
        };
        foreach (var pair in corruptions) {
            byte[] bad = Record("ok.bin", 42, Resident(0x80, Pattern(20))); pair.Value(bad);
            Run("bad-" + pair.Key, Image("bad-" + pair.Key, bad, 4096), out report);
            Assert(report.RecoveredFiles == 0 && report.InvalidSignatures == 1, "Reject malformed " + pair.Key);
        }
        foreach (ushort flags in new ushort[] { 1, 2, 3, 4, 8 }) {
            Run("active-" + flags, Image("active-" + flags, Record("current.txt", 42, Resident(0x80, Pattern(20)), flags), 4096), out report);
            Assert(report.RecoveredFiles == 0, "Do not publish active/directory/index record " + flags);
        }
        byte[] compressed = Resident(0x80, Pattern(20)); Set(compressed, 12, (ushort)1);
        Run("compressed-result", Image("compressed", Record("compressed.bin", 42, compressed), 4096), out report);
        Assert(report.RecoveredFiles == 0 && report.Entries[0].Reason == "compressed_encrypted_or_sparse", "No invented decompression");
        byte[] protectedFile = Record("protected.bin", 42, Resident(0x80, Pattern(20))); Set(protectedFile, 56 + 24 + 56, 0x4000U);
        Run("protected-file-result", Image("protected-file", protectedFile, 4096), out report);
        Assert(report.RecoveredFiles == 0 && report.Entries[0].Reason == "compressed_encrypted_or_sparse", "EFS filename flags also block unsupported data");
        Run("attrlist-result", Image("attrlist", Record("multi.bin", 42, Resident(0x80, Pattern(20)), 0, Resident(0x20, Pattern(8))), 4096), out report);
        Assert(report.RecoveredFiles == 0 && report.Entries[0].Reason == "attribute_list_unsupported", "No guessed split stream");
        Run("large-result", Image("large", Record("large.bin", 42, Nonresident(MetadataRescue.MaximumFileBytes + 1, MetadataRescue.MaximumFileBytes + 1, 4L * 1024 * 1024 * 1024, 0, new byte[] { 0x11, 1, 45, 0 })), 4096), out report);
        Assert(report.RecoveredFiles == 0 && report.Entries[0].Reason == "file_size_limit", "Per-file output budget");
        Throws<IOException>(() => MetadataRescue.Recover(@"\\.\PhysicalDrive0", Path.Combine(fixtures, "device"), CancellationToken.None, null), "Physical devices refused before opening");
        Throws<IOException>(() => MetadataRescue.Recover(image, root, CancellationToken.None, null), "Existing output never overwritten");
        var cancel = new CancellationTokenSource(); cancel.Cancel(); string cancelled = Path.Combine(fixtures, "cancelled-before");
        Throws<OperationCanceledException>(() => MetadataRescue.Recover(image, cancelled, cancel.Token, null), "Cancel before scan");
        Assert(!Directory.Exists(cancelled), "Pre-cancel creates no output");
        cancel = new CancellationTokenSource(); cancelled = Path.Combine(fixtures, "cancelled-during");
        Throws<OperationCanceledException>(() => MetadataRescue.Recover(image, cancelled, cancel.Token, s => cancel.Cancel()), "Cancel during scan");
        Assert(ReadReport(cancelled).Cancelled && !Directory.EnumerateFiles(Path.Combine(cancelled, "metadata-rescue", "files")).Any(), "Cancelled report and no fabricated files");
    }
    static void NonresidentAndOwnership()
    {
        MetadataRescue.Report report; string image = VolumeImage("fragmented"), before = Hash(image);
        string root = Run("fragmented-result", image, out report); var item = report.Entries.Single();
        Assert(report.RecoveredFiles == 1 && item.Status == "unallocated_candidate" && item.VolumeOffset == 0, "Validated bitmap permits free clusters");
        Bytes(Output(root, item), Pattern(5500), "Negative LCN delta recovers exact fragmented file");
        Assert(item.Extents.Count == 2 && item.Extents[0].ImageOffset == 45 * 4096 && item.Extents[1].ImageOffset == 40 * 4096 && item.Extents[1].LogicalOffset == 4096, "Physical and logical extents retained");
        Assert(Hash(image) == before, "Nonresident image unchanged");
        root = Run("reused-second-result", VolumeImage("reused-second", false, true), out report); item = report.Entries.Single();
        Assert(report.RecoveredFiles == 1 && item.Status == "partial_candidate" && item.RecoveredBytes == 4096 && item.DeclaredSize == 5500 && item.Reason == "allocated_cluster_stop", "Reused cluster stops extraction before current data");
        Bytes(Output(root, item), Pattern(5500).Take(4096).ToArray(), "Only verified free prefix published");
        Run("reused-first-result", VolumeImage("reused-first", true), out report);
        Assert(report.RecoveredFiles == 0 && report.Entries.Single().Reason == "allocated_cluster_stop", "Allocated first cluster publishes no file");
        Run("no-bitmap-result", VolumeImage("no-bitmap", false, false, false), out report);
        Assert(report.RecoveredFiles == 0 && report.Entries.Single().Reason == "current_bitmap_unavailable", "Absent active bitmap never treated as all-free");
        string zeroed = VolumeImage("zeroed-bitmap");
        using (var f = new FileStream(zeroed, FileMode.Open, FileAccess.Write)) { f.Position = 4 * 4096 + 6 * 1024 + 184; f.Write(new byte[64], 0, 64); }
        Run("zeroed-bitmap-result", zeroed, out report);
        Assert(report.RecoveredFiles == 0 && report.Warnings.Any(s => s.Contains("allocation_metadata_inconsistent")), "Corrupt zero bitmap cannot claim active MFT clusters are free");
        root = Run("fragmented-mft-result", VolumeImage("fragmented-mft", false, false, true, true), out report);
        Assert(report.RecoveredFiles == 1, "Bitmap read through fragmented MFT mapping"); Bytes(Output(root, report.Entries.Single()), Pattern(5500), "Fragmented MFT path payload exact");
        root = Run("uninitialized-result", VolumeImage("uninitialized", false, false, true, false, 3000), out report);
        Assert(report.RecoveredFiles == 1 && report.Entries.Single().Reason == "uninitialized_tail_not_invented" && report.Entries.Single().Status == "partial_candidate", "Uninitialized tail reported without zero filling");
        Bytes(Output(root, report.Entries.Single()), Pattern(5500).Take(3000).ToArray(), "Initialized prefix exact");
        Run("out-of-bounds-result", VolumeImage("out-of-bounds", false, false, true, false, 5500, new byte[] { 0x21, 2, 0x00, 0x02, 0 }), out report);
        Assert(report.RecoveredFiles == 0, "Out-of-volume runs rejected");
        foreach (ushort flags in new ushort[] { 0x8000, 0x4000 }) {
            string sparse = Image("unsupported-" + flags, Record("unsupported.bin", 42, Nonresident(10, 10, 4096, 0, new byte[] { 0x11, 1, 45, 0 }, flags)), 4096);
            Run("unsupported-result-" + flags, sparse, out report);
            Assert(report.RecoveredFiles == 0 && report.Entries.Single().Reason == "compressed_encrypted_or_sparse", "Sparse/encrypted stream rejected " + flags);
        }
        foreach (byte[] pairs in new[] { new byte[] { 0x11, 0, 45, 0 }, new byte[] { 0x01, 1, 0 }, new byte[] { 0x11, 1, 0xff, 0 }, new byte[] { 0x99, 1, 0 } }) {
            string suffix = Guid.NewGuid().ToString("N");
            Run("bad-pairs-" + suffix, Image("bad-pairs-" + suffix, Record("bad.bin", 42, Nonresident(10, 10, 4096, 0, pairs)), 4096), out report);
            Assert(report.RecoveredFiles == 0 && report.InvalidSignatures == 1, "Malformed/sparse run list not guessed");
        }
    }
    static void KnownPayloadFixture(string project)
    {
        string image = Path.Combine(project, "tests", "AdvancedNtfs.dd"), expected = Path.Combine(project, "tests", "photorec-20261011T231546120952Z", "fixtures", "expected.jpg");
        Assert(File.Exists(image) && File.Exists(expected), "Existing NTFS fixture and known expected photo present");
        string before = Hash(image); MetadataRescue.Report report; string root = Run("known-ntfs-result", image, out report);
        Assert(report.RecoveredFiles == 0 && report.InvalidSignatures > 0, "Existing legacy fixture with invalid deleted-record USA must be rejected");
        // This older test image's sole deleted record stores already restored
        // sector tails (0000), rather than its on-disk USA sequence (0005).
        // Repair those four bytes on a generated COPY, never on the fixture.
        string copy = Path.Combine(fixtures, "known-payload-valid-usa.dd"); File.Copy(image, copy);
        using (var f = new FileStream(copy, FileMode.Open, FileAccess.ReadWrite)) {
            byte[] sequence = new byte[2]; f.Position = 81920 + 48; f.Read(sequence, 0, 2);
            f.Position = 81920 + 510; f.Write(sequence, 0, 2); f.Position = 81920 + 1022; f.Write(sequence, 0, 2);
        }
        string copyBefore = Hash(copy); root = Run("known-payload-valid-usa-result", copy, out report);
        Assert(report.RecoveredFiles >= 1, "Known fragmented payload recovered from on-spec USA copy");
        var photos = report.Entries.Where(e => e.Output != null && Hash(Output(root, e)) == Hash(expected)).ToList();
        Assert(photos.Count == 1 && photos[0].Name == "grandma-photo.jpg" && photos[0].Extents.Count > 1, "Known fragmented deleted JPEG exact SHA256 and filename after fixture repair");
        Assert(Hash(image) == before && Hash(copy) == copyBefore, "Both original NTFS fixture and generated copy unchanged by recovery");
    }
    static void ReadErrorAllocationBoundary()
    {
        // Only the bitmap byte for user clusters 40..47 is unread/zero-filled.
        // All reserved-system bits remain intact, so self-allocation checks
        // alone cannot certify this byte or a candidate's free-cluster claim.
        string image = VolumeImage("unread-user-bitmap", false, true);
        long hole = 4 * 4096 + 6 * 1024 + 184 + 5;
        using (var f = new FileStream(image, FileMode.Open, FileAccess.Write)) { f.Position = hole; f.WriteByte(0); }
        string before = Hash(image), root = Path.Combine(fixtures, "unread-run-map-result"); Directory.CreateDirectory(root);
        Json(Path.Combine(root, "source-read-errors.json"), new { unreadBytes = 1, ranges = new[] { new { Offset = hole, Length = 1 } } });
        int count = MetadataRescue.Recover(image, root, CancellationToken.None, null); MetadataRescue.Report report = ReadReport(root);
        Assert(count == 0 && report.Entries.Single().Reason == "source_read_errors_allocation_untrusted", "Unread user-allocation byte disables nonresident extraction");
        Assert(report.Entries.Single().Extents.Count == 0 && !Directory.EnumerateFiles(Path.Combine(root, "metadata-rescue", "files")).Any(), "Zero-filled bitmap never claims a verified-free payload");
        Json(image + ".read-errors.json", new { status = "complete_with_read_errors", unreadBytes = 1, ranges = new[] { new { Offset = hole, Length = 1 } } });
        root = Run("unread-sidecar-result", image, out report);
        Assert(report.RecoveredFiles == 0 && report.Entries.Single().Reason == "source_read_errors_allocation_untrusted", "Standalone image sidecar also prevents allocation claims");
        Assert(Hash(image) == before, "Unread-image boundary never modifies the input image");
        string healthy = VolumeImage("zero-errors-map"); root = Path.Combine(fixtures, "zero-errors-map-result"); Directory.CreateDirectory(root);
        Json(Path.Combine(root, "source-read-errors.json"), new { status = "complete", size = new FileInfo(healthy).Length, unreadBytes = 0, ranges = new object[0] });
        count = MetadataRescue.Recover(healthy, root, CancellationToken.None, null); report = ReadReport(root);
        Assert(count == 1 && report.Entries.Single().Status == "unallocated_candidate", "Validated complete zero-error map preserves normal recovery");
        string[] invalid = { "{", "null", "[]", "{\"unreadBytes\":0}", "{\"unreadBytes\":\"0\",\"ranges\":[]}",
            "{\"unreadBytes\":0,\"ranges\":[{\"Offset\":1,\"Length\":1}]}", "{\"unreadBytes\":0,\"ranges\":[],\"status\":\"copying\"}",
            "{\"unreadBytes\":0,\"ranges\":[],\"size\":1}", "{\"unreadBytes\":-1,\"ranges\":[]}",
            "{\"unreadBytes\":0,\"ranges\":[]}", "{\"unreadBytes\":0,\"ranges\":[],\"status\":\"complete\"}",
            "{\"unreadBytes\":0,\"ranges\":[],\"size\":" + new FileInfo(healthy).Length + "}" };
        for (int i = 0; i < invalid.Length; i++) {
            root = Path.Combine(fixtures, "untrusted-map-" + i); Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, "source-read-errors.json"), invalid[i], Encoding.UTF8);
            count = MetadataRescue.Recover(healthy, root, CancellationToken.None, null); report = ReadReport(root);
            Assert(count == 0 && report.Entries.Single().Reason == "source_read_errors_allocation_untrusted", "Invalid/inconsistent read map is conservative " + i);
        }
        string resident = Image("resident-read-map", Record("fragment.txt", 42, Resident(0x80, Pattern(50))), 4096);
        Json(resident + ".read-errors.json", new { unreadBytes = 1, ranges = new[] { new { Offset = 4600, Length = 1 } } });
        root = Run("resident-read-map-result", resident, out report);
        Assert(report.RecoveredFiles == 1 && report.Entries.Single().Note.Contains("пропуски чтения") && report.Entries.Single().Status == "resident_candidate", "Resident candidates keep explicit source-gap uncertainty");
    }
    static byte[] FileName(string name, uint parent, int sequence, byte space = 1)
    {
        byte[] text = Encoding.Unicode.GetBytes(name), value = new byte[66 + text.Length];
        Set(value, 0, (long)parent | ((long)sequence << 48)); value[64] = (byte)name.Length; value[65] = space; Buffer.BlockCopy(text, 0, value, 66, text.Length); return Resident(0x30, value);
    }
    static byte[] PathRecord(string name, uint number, ushort flags, uint parent, int parentSequence, int sequence, byte[] data = null, byte[] extraName = null)
    {
        byte[] record = Record(name, number, data, flags, extraName); Set(record, 16, (ushort)sequence);
        // These fields are in the first sector, outside the USA words.
        int filename = extraName == null ? 56 : 56 + extraName.Length;
        Set(record, filename + 24, (long)parent | ((long)parentSequence << 48)); return record;
    }
    static long MftAt(uint number, bool fragmented)
    {
        long logical = number * 1024L; return fragmented && logical >= 16384 ? 24 * 4096L + logical - 16384 : 4 * 4096L + logical;
    }
    static string PathVolume(string name, Dictionary<uint, byte[]> records, bool fragmented = false, int recordCount = 64)
    {
        const int length = 2 * 1024 * 1024; int mftBytes = recordCount * 1024, clusters = mftBytes / 4096;
        string path = Path.Combine(fixtures, name + ".dd"); byte[] boot = new byte[512], bitmap = new byte[64];
        boot[0] = 0xeb; boot[1] = 0x52; boot[2] = 0x90; Buffer.BlockCopy(Encoding.ASCII.GetBytes("NTFS    "), 0, boot, 3, 8);
        Set(boot, 11, (ushort)512); boot[13] = 8; Set(boot, 40, length / 512 - 1L); Set(boot, 48, 4L); Set(boot, 56, 16L); boot[64] = unchecked((byte)-10); boot[510] = 0x55; boot[511] = 0xaa;
        byte[] pairs = fragmented ? new byte[] { 0x11, 4, 4, 0x11, (byte)(clusters - 4), 20, 0 } : new byte[] { 0x11, (byte)clusters, 4, 0 };
        for (int logicalCluster = 0; logicalCluster < clusters; logicalCluster++) { int lcn = fragmented && logicalCluster >= 4 ? 24 + logicalCluster - 4 : 4 + logicalCluster; bitmap[lcn / 8] |= (byte)(1 << (lcn & 7)); }
        using (var f = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
            f.SetLength(length); f.Write(boot, 0, boot.Length);
            byte[] mft = Record("$MFT", 0, Nonresident(mftBytes, mftBytes, mftBytes, clusters - 1L, pairs), 1);
            f.Position = MftAt(0, fragmented); f.Write(mft, 0, mft.Length);
            byte[] map = Record("$Bitmap", 6, Resident(0x80, bitmap), 1); f.Position = MftAt(6, fragmented); f.Write(map, 0, map.Length);
            foreach (var item in records) { f.Position = MftAt(item.Key, fragmented); f.Write(item.Value, 0, item.Value.Length); }
        }
        return path;
    }
    static Dictionary<uint, byte[]> PathRecords()
    {
        return new Dictionary<uint, byte[]> {
            { 5, PathRecord(".", 5, 3, 5, 1, 1) },
            { 20, PathRecord("Семья", 20, 3, 5, 1, 9) },
            { 21, PathRecord("Рецепты", 21, 3, 20, 9, 12) },
            { 42, PathRecord("Пирожки.txt", 42, 0, 21, 12, 3, Resident(0x80, Pattern(700))) }
        };
    }
    static void DirectoryStructure()
    {
        MetadataRescue.Report report; string image = PathVolume("path-verified", PathRecords()), before = Hash(image), root = Run("path-verified-result", image, out report);
        var item = report.Entries.Single();
        Assert(item.OriginalPath == "/Семья/Рецепты/Пирожки.txt" && item.PathStatus == "verified_parent_chain" && item.PathVolumeOffset == 0, "Unicode original directory chain bound to current MFT");
        Assert(report.ResolvedPaths == 1 && report.UnresolvedPaths == 0 && report.Schema == 2, "Report explicitly counts reconstructed paths");
        Assert(item.DirectoryChain.Select(d => d.RecordNumber).SequenceEqual(new long[] { 21, 20, 5 }) && item.DirectoryChain.Select(d => d.Sequence).SequenceEqual(new[] { 12, 9, 1 }), "Every parent record and exact sequence retained");
        Assert(item.DirectoryChain.All(d => d.InUse) && item.DirectoryChainComplete && item.PathEvidence.Contains("снимка"), "Current snapshot path is not a historical-path claim");
        Bytes(Output(root, item), Pattern(700), "Path reconstruction leaves resident content exact"); Assert(Hash(image) == before, "Path resolution never writes original image");
        Assert(Path.GetDirectoryName(Output(root, item)) == Path.Combine(root, "metadata-rescue", "files"), "Original path is metadata, not a trusted output filesystem path");
        image = PathVolume("path-fragmented-mft", PathRecords(), true); before = Hash(image); root = Run("path-fragmented-mft-result", image, out report); item = report.Entries.Single();
        Assert(item.OriginalPath == "/Семья/Рецепты/Пирожки.txt" && item.DirectoryChain[0].RecordOffset == MftAt(21, true), "Directory chain follows fragmented MFT run mapping"); Assert(Hash(image) == before, "Fragmented MFT path input unchanged");
        var cases = new Dictionary<string, Action<Dictionary<uint, byte[]>>> {
            { "stale_parent_reference", records => records[42] = PathRecord("Пирожки.txt", 42, 0, 21, 13, 3, Resident(0x80, Pattern(700))) },
            { "missing_parent_sequence", records => records[42] = PathRecord("Пирожки.txt", 42, 0, 21, 0, 3, Resident(0x80, Pattern(700))) },
            { "parent_not_directory", records => records[21] = PathRecord("Рецепты", 21, 1, 20, 9, 12) },
            { "directory_cycle", records => records[20] = PathRecord("Семья", 20, 3, 21, 12, 9) },
            { "invalid_root_directory", records => records[5] = PathRecord(".", 5, 3, 7, 1, 1) },
            { "invalid_file_component", records => records[42] = PathRecord("../Пирожки.txt", 42, 0, 21, 12, 3, Resident(0x80, Pattern(700))) },
            { "invalid_parent_component", records => records[21] = PathRecord("Папка/Рецепты", 21, 3, 20, 9, 12) },
            { "invalid_parent_record", records => records[21] = PathRecord("Рецепты", 22, 3, 20, 9, 12) },
            { "ambiguous_file_names", records => records[42] = PathRecord("Пирожки.txt", 42, 0, 21, 12, 3, Resident(0x80, Pattern(100)), FileName("Другая-ссылка.txt", 20, 9)) },
            { "ambiguous_parent_names", records => records[21] = PathRecord("Рецепты", 21, 3, 20, 9, 12, null, FileName("Другая-папка", 5, 1)) }
        };
        foreach (var test in cases) {
            var records = PathRecords(); test.Value(records); image = PathVolume("path-" + test.Key, records); before = Hash(image); root = Run("path-" + test.Key + "-result", image, out report); item = report.Entries.Single();
            Assert(item.OriginalPath == null && item.PathStatus == test.Key && !item.DirectoryChainComplete && report.UnresolvedPaths == 1, "Unknown path instead of false folder: " + test.Key);
            Assert(report.RecoveredFiles == 1 && Hash(image) == before, "Unknown path still preserves safe candidate/source: " + test.Key);
        }
        var valid = PathRecords(); valid[20] = PathRecord("Семья", 20, 2, 5, 1, 9); image = PathVolume("deleted-parent", valid); root = Run("deleted-parent-result", image, out report); item = report.Entries.Single();
        Assert(item.OriginalPath == "/Семья/Рецепты/Пирожки.txt" && !item.DirectoryChain.Single(d => d.RecordNumber == 20).InUse, "Retained deleted directory only linked when exact sequence still matches");
        valid = PathRecords(); valid[42] = PathRecord("Пирожки.txt", 42, 0, 21, 12, 3, Resident(0x80, Pattern(100)), FileName("PIROZH~1.TXT", 21, 12, 2)); image = PathVolume("dos-alias", valid); root = Run("dos-alias-result", image, out report);
        Assert(report.Entries.Single().OriginalPath == "/Семья/Рецепты/Пирожки.txt", "DOS alias does not override long Win32 name or create ambiguity");
        valid = PathRecords(); valid[41] = valid[42]; valid.Remove(42); image = PathVolume("wrong-mft-slot", valid); root = Run("wrong-mft-slot-result", image, out report);
        Assert(report.RecoveredFiles == 1 && report.Entries.Single().OriginalPath == null && report.Entries.Single().PathStatus == "record_outside_current_mft", "Carved record number outside its MFT slot cannot attach to tree");
        image = PathVolume("path-unread", PathRecords()); Json(image + ".read-errors.json", new { unreadBytes = 1, ranges = new[] { new { Offset = MftAt(20, false) + 80, Length = 1 } } }); root = Run("path-unread-result", image, out report);
        Assert(report.RecoveredFiles == 1 && report.Entries.Single().OriginalPath == null && report.Entries.Single().PathStatus == "source_read_errors", "Unread metadata never confirms directory ownership");
        image = PathVolume("path-corrupt-bitmap", PathRecords()); using (var f = new FileStream(image, FileMode.Open, FileAccess.Write)) { f.Position = MftAt(6, false) + 184; f.Write(new byte[64], 0, 64); } root = Run("path-corrupt-bitmap-result", image, out report);
        Assert(report.RecoveredFiles == 1 && report.Entries.Single().OriginalPath == null && report.Warnings.Any(s => s.Contains("allocation_metadata_inconsistent")), "Contradictory system allocation cannot certify current folder tree");
        var deep = new Dictionary<uint, byte[]> { { 5, PathRecord(".", 5, 3, 5, 1, 1) }, { 250, PathRecord("leaf.txt", 250, 0, 229, 1, 3, Resident(0x80, Pattern(8))) } };
        for (uint number = 100; number <= 229; number++) deep.Add(number, PathRecord("d" + number, number, 3, number == 100 ? 5U : number - 1, 1, 1));
        image = PathVolume("path-depth", deep, false, 256); root = Run("path-depth-result", image, out report);
        Assert(report.Entries.Single().OriginalPath == null && report.Entries.Single().PathStatus == "path_depth_limit" && report.PathResolutionLimited, "Directory-depth work is bounded without invented partial path");
        Assert(report.Entries.Single().DirectoryChain.Count == 128 && report.RecoveredFiles == 1, "Bounded ancestry evidence retains recovered candidate");
    }
    public static int Main(string[] args)
    {
        try {
            string project = args.Length == 0 ? Directory.GetCurrentDirectory() : Path.GetFullPath(args[0]);
            fixtures = Path.Combine(project, ".build", "metadata-rescue-tests-" + DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ")); Directory.CreateDirectory(fixtures);
            ResidentAndValidation(); NonresidentAndOwnership(); KnownPayloadFixture(project); ReadErrorAllocationBoundary(); DirectoryStructure();
            string summary = "PASS MetadataRescue: " + assertions + " assertions; whole-image NTFS FILE scan, USA/resident/Unicode/provenance, signed fragmented runs, current $Bitmap ownership including fragmented MFT, partial stops, unsupported/corrupt records, cancellation/per-file budget/path isolation; original paths only through validated current-MFT slot, exact parent sequences/root, Unicode/DOS namespace, deleted-directory evidence; stale/cyclic/unsafe/ambiguous paths remain unknown and ancestry depth bounded; old fixture with torn USA rejected; known fragmented JPEG SHA256 exact after USA repair on generated copy; unread/invalid maps disable nonresident allocation and path claims; source SHA256 unchanged. Synthetic/known-payload tests only. Fixtures: " + fixtures;
            Console.WriteLine(summary); File.WriteAllText(Path.Combine(project, "tests", "MetadataRescueTests.result.txt"), summary, Encoding.UTF8); return 0;
        } catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
