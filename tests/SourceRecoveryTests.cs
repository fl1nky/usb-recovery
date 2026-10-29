using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class SourceRecoveryTests
{
    static int tests;
    static string root;
    static void Assert(bool value, string message) { if (!value) throw new Exception(message); }
    static string Folder(string name) { string path = Path.Combine(root, name); Directory.CreateDirectory(path); return path; }
    static AcquisitionManifest Manifest(string run) { return new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AcquisitionManifest>(File.ReadAllText(Path.Combine(run, "acquisition.json"), Encoding.UTF8)); }
    static void Case(string name, Action test) { test(); tests++; Console.WriteLine("PASS " + name); }
    static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    sealed class FakeSource : IRecoverySource
    {
        public readonly List<SourceEntry> Entries = new List<SourceEntry>();
        public readonly Dictionary<string, byte[]> Bytes = new Dictionary<string, byte[]>();
        public int Reads;
        public Func<SourceEntry, Stream> Factory;
        public SourceInfo Info { get { return new SourceInfo { Id = "synthetic-device", Name = "Synthetic", Kind = "fixture", Status = "ready" }; } }
        public IEnumerable<SourceEntry> Enumerate(string selectedRoot, CancellationToken cancel) { foreach (var entry in Entries) { cancel.ThrowIfCancellationRequested(); yield return entry; } }
        public Stream OpenRead(SourceEntry entry, CancellationToken cancel) { Reads++; cancel.ThrowIfCancellationRequested(); return Factory == null ? new MemoryStream(Bytes[entry.Id], false) : Factory(entry); }
        public void Add(string id, string relative, byte[] bytes, string modified)
        {
            Entries.Add(new SourceEntry { Id = id, RelativePath = relative, OriginalPath = "fixture:/" + relative, Size = bytes.LongLength, Modified = modified }); Bytes.Add(id, bytes);
        }
    }
    sealed class FailingStream : MemoryStream
    {
        bool first = true;
        readonly CancellationTokenSource cancellation;
        public FailingStream(byte[] bytes, CancellationTokenSource cancellation) : base(bytes, false) { this.cancellation = cancellation; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!first) { if (cancellation != null) cancellation.Cancel(); else throw new IOException("Synthetic interruption"); }
            first = false; return base.Read(buffer, offset, Math.Min(count, 65536));
        }
    }
    static FakeSource One() { var source = new FakeSource(); source.Add("a", "DCIM/прабабушка фото.jpg", Encoding.UTF8.GetBytes("synthetic-image-only"), "2026-01-01T00:00:00Z"); return source; }
    public static int Main()
    {
        root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Source-fixtures-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(root);
        try
        {
            Case("Drive root remains absolute and containment respects drive", () => { Assert(SourcePaths.Full(@"C:\") == @"C:\", "absolute root"); Assert(SourcePaths.Within(@"C:\example", @"C:\") && !SourcePaths.Within(@"D:\example", @"C:\"), "containment"); });
            Case("ADB binary listing preserves newline Unicode and quotes without executing input", () => {
                string androidRoot = "/storage/emulated/0", name = "Фото/семья\n'$(example);.jpg"; string listing = "directory|0|1\n" + androidRoot + "/Фото\0regular file|23|123\n" + androidRoot + "/" + name + "\0"; var warnings = new List<string>(); var entries = AdbRecoverySource.ParseListing(Encoding.UTF8.GetBytes(listing), androidRoot, warnings, CancellationToken.None).ToArray(); Assert(entries.Length == 2 && entries[0].IsDirectory && entries[1].RelativePath == name && entries[1].Size == 23 && warnings.Count == 0, "binary records"); Assert(AdbProcess.UnixQuote("a'b") == "'a'\"'\"'b'", "shell quoting"); Throws<ArgumentException>(() => AdbProcess.ValidateSerial("-s other")); Throws<IOException>(() => AdbRecoverySource.AndroidRoot("/data/data"));
            });
            Case("Read-only copy, hash provenance, Unicode, empty file and duplicate basename", () => {
                var source = One(); source.Add("b", "Cache/прабабушка фото.jpg", new byte[] { 1, 2, 3 }, "1"); source.Add("empty", "empty.db", new byte[0], "1"); source.Entries.Add(new SourceEntry { Id = "folder", RelativePath = "Cache", OriginalPath = "Cache", IsDirectory = true });
                string run = Folder("unicode-copy"); string snapshot = SourceAcquisition.Copy(source, "", run, CancellationToken.None, null);
                var manifest = Manifest(run); Assert(manifest.Status == "finished" && manifest.Files.Count == 3, "manifest"); Assert(source.Reads == 3, "files only"); Assert(manifest.Files.Select(f => f.LocalPath).Distinct().Count() == 3, "collision");
                foreach (var file in manifest.Files) { Assert(file.Status == "complete" && file.Sha256.Length == 64, "hash"); Assert(File.Exists(Path.Combine(run, file.LocalPath.Replace('/', '\\'))), "copied"); }
                Assert(snapshot == Path.Combine(run, "snapshot"), "snapshot"); Assert(!Directory.GetFiles(snapshot, "*.partial", SearchOption.AllDirectories).Any(), "no partial");
            });
            Case("Resume checks complete file hash and metadata", () => {
                var source = One(); string run = Folder("resume"); SourceAcquisition.Copy(source, "", run, CancellationToken.None, null); Assert(source.Reads == 1, "first read"); SourceAcquisition.Copy(source, "", run, CancellationToken.None, null); Assert(source.Reads == 1, "valid reuse");
                string copied = Path.Combine(run, Manifest(run).Files[0].LocalPath.Replace('/', '\\')); File.WriteAllText(copied, "corrupted"); SourceAcquisition.Copy(source, "", run, CancellationToken.None, null); Assert(source.Reads == 2 && File.ReadAllBytes(copied).SequenceEqual(source.Bytes["a"]), "corrupt copy reread");
                source.Entries[0].Modified = "2"; SourceAcquisition.Copy(source, "", run, CancellationToken.None, null); Assert(source.Reads == 3, "metadata changed");
            });
            Case("Interrupted stream never promotes partial, successful resume restarts it", () => {
                var source = new FakeSource(); source.Add("large", "photo.jpg", new byte[200000], "1"); source.Factory = e => new FailingStream(source.Bytes[e.Id], null); string run = Folder("failure");
                Throws<IOException>(() => SourceAcquisition.Copy(source, "", run, CancellationToken.None, null)); var manifest = Manifest(run); Assert(manifest.Status == "incomplete" && manifest.Files[0].Status == "partial", "partial status"); string copied = Path.Combine(run, manifest.Files[0].LocalPath.Replace('/', '\\')); string partial = Path.Combine(run, manifest.Files[0].PartialPath.Replace('/', '\\')); Assert(!File.Exists(copied) && File.Exists(partial), "transactional partial");
                source.Factory = null; SourceAcquisition.Copy(source, "", run, CancellationToken.None, null); Assert(Manifest(run).Status == "finished" && !File.Exists(partial), "resume");
            });
            Case("Cancellation preserves incomplete file and manifest", () => {
                var source = new FakeSource(); source.Add("large", "video.bin", new byte[200000], "1"); var cancellation = new CancellationTokenSource(); source.Factory = e => new FailingStream(source.Bytes[e.Id], cancellation); string run = Folder("cancel");
                Throws<OperationCanceledException>(() => SourceAcquisition.Copy(source, "", run, cancellation.Token, null)); var manifest = Manifest(run); Assert(manifest.Status == "cancelled" && manifest.Files[0].Status == "partial", "cancelled"); cancellation.Dispose();
            });
            Case("Traversal and oversized file cannot create output outside snapshot", () => {
                var source = One(); source.Entries[0].RelativePath = "../../escaped.jpg"; string run = Folder("traversal"); Throws<IOException>(() => SourceAcquisition.Copy(source, "", run, CancellationToken.None, null)); Assert(!File.Exists(Path.Combine(root, "escaped.jpg")) && source.Reads == 0, "traversal blocked");
                source.Entries[0].RelativePath = "large.bin"; source.Entries[0].Size = SourceLimits.MaximumFileBytes + 1; Throws<IOException>(() => SourceAcquisition.Copy(source, "", Folder("huge"), CancellationToken.None, null)); Assert(source.Reads == 0, "huge blocked");
            });
            Case("Local selected SQLite file includes WAL/SHM and source stays unchanged", () => {
                string input = Folder("local-source"); string db = Path.Combine(input, "сообщения.sqlite"); File.WriteAllText(db, "fixture-database"); File.WriteAllText(db + "-wal", "fixture-wal"); File.WriteAllText(db + "-shm", "fixture-shm"); File.WriteAllText(Path.Combine(input, "other.txt"), "not selected");
                var source = new LocalFolderSource(input); var entries = source.Enumerate(Path.GetFileName(db), CancellationToken.None).ToList(); Assert(entries.Count == 3, "siblings"); string run = Folder("local-results"); SourceAcquisition.Copy(source, db, run, CancellationToken.None, null); Assert(Manifest(run).Files.Count == 3 && File.ReadAllText(db) == "fixture-database", "read only");
                Throws<IOException>(() => SourceAcquisition.ValidateOutput(source, "", Path.Combine(input, "results"))); Throws<IOException>(() => source.SelectedPath(Path.Combine(root, "other")));
            });
            Case("Source changed after local enumeration is rejected", () => {
                string input = Folder("changing-source"); string file = Path.Combine(input, "image.jpg"); File.WriteAllText(file, "a"); var source = new LocalFolderSource(input); SourceEntry entry = source.Enumerate("", CancellationToken.None).Single(); File.WriteAllText(file, "new content"); Throws<IOException>(() => source.OpenRead(entry, CancellationToken.None));
            });
            Case("Different selected source cannot reuse an existing acquisition", () => {
                var source = One(); string run = Folder("different-root"); SourceAcquisition.Copy(source, "one", run, CancellationToken.None, null); Throws<IOException>(() => SourceAcquisition.Copy(source, "two", run, CancellationToken.None, null));
            });
            Case("Snapshot preserves backup trees and SQLite siblings", () => {
                var source = new FakeSource(); source.Add("manifest", "Manifest.db", new byte[] { 1 }, "1"); source.Add("payload", "ab/abcdef012345", new byte[] { 2 }, "1"); source.Add("db", "signal/signal.db", new byte[] { 3 }, "1"); source.Add("wal", "signal/signal.db-wal", new byte[] { 4 }, "1"); source.Add("literal-partial", "signal/signal.db.partial", new byte[] { 5 }, "1");
                string run = Folder("backup-tree"); string snapshot = SourceAcquisition.Copy(source, "", run, CancellationToken.None, null); Assert(File.Exists(Path.Combine(snapshot, "Manifest.db")) && File.Exists(Path.Combine(snapshot, "ab", "abcdef012345")), "iOS tree"); Assert(File.Exists(Path.Combine(snapshot, "signal", "signal.db-wal")) && File.ReadAllBytes(Path.Combine(snapshot, "signal", "signal.db.partial"))[0] == 5, "siblings and literal partial");
            });
            Case("Windows case collision preserves both payloads with explicit warning", () => {
                var source = new FakeSource(); source.Add("one", "Cache/A.jpg", new byte[] { 1 }, "1"); source.Add("two", "Cache/a.jpg", new byte[] { 2 }, "1"); string run = Folder("case-collision"); SourceAcquisition.Copy(source, "", run, CancellationToken.None, null); var manifest = Manifest(run); Assert(manifest.Status == "finished_with_warnings" && manifest.Files.Count == 2 && manifest.Files[1].LocalPath.Contains("path-conflicts"), "case collision");
            });
            Case("Read-only providers never expose writable streams", () => { var source = One(); using (Stream stream = source.OpenRead(source.Entries[0], CancellationToken.None)) Assert(!stream.CanWrite, "read only"); });
            Case("Local junction is not followed and output junction is rejected", () => {
                string input = Folder("junction-input"), target = Folder("junction-target"); File.WriteAllText(Path.Combine(target, "outside.txt"), "synthetic outside"); string link = Path.Combine(input, "linked");
                string script = "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path '" + link.Replace("'", "''") + "' -Value '" + target.Replace("'", "''") + "' | Out-Null";
                var start = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script))) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
                using (var process = Process.Start(start)) { process.WaitForExit(30000); Assert(process.ExitCode == 0, "junction fixture"); }
                var source = new LocalFolderSource(input); Assert(!source.Enumerate("", CancellationToken.None).Any(), "junction skipped"); Assert(source.Warnings.Count > 0 && File.ReadAllText(Path.Combine(target, "outside.txt")) == "synthetic outside", "warning, unchanged"); Throws<IOException>(() => SourceAcquisition.ValidateOutput(One(), "", Path.Combine(link, "output")));
            });
            Case("Source count bound stops malicious provider without copying", () => {
                var source = new FakeSource(); for (int i = 0; i <= SourceLimits.MaximumEntries; i++) source.Entries.Add(new SourceEntry { Id = i.ToString(), RelativePath = "directory" + i, IsDirectory = true }); Throws<IOException>(() => SourceAcquisition.Copy(source, "", Folder("bounded-provider"), CancellationToken.None, null)); Assert(source.Reads == 0, "bounded");
            });
            Console.WriteLine("TOTAL " + tests + " passed; fixture directory: " + root); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
