using System;
using System.IO;
using System.Reflection;
using System.Threading;
using UsbRecovery;

// Tests the initialization unit on a copied native-format image. It does not
// claim a persisted ext4 engine cursor or any physical-device behavior.
public static class Ext4GroupMetadataTests
{
    static int checks, failures;
    static void Check(bool value, string label) { checks++; if (!value) { failures++; Console.WriteLine("FAIL " + label); } }
    static void Set(object value, string name, object field) { value.GetType().GetField(name).SetValue(value, field); }
    sealed class Source : FileStream
    {
        public long ZeroAt = -1; public int ZeroCalls;
        public Action<long, int> BeforeRead;
        public Source(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1) { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (BeforeRead != null) BeforeRead(Position, count);
            if (Position == ZeroAt) { ZeroCalls++; return 0; }
            return base.Read(buffer, offset, count);
        }
    }
    static byte[] ReadAt(string path, long offset, int count)
    {
        using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            input.Position = offset; var bytes = new byte[count]; int done = 0;
            while (done < count) { int read = input.Read(bytes, done, count - done); if (read == 0) throw new EndOfStreamException(); done += read; }
            return bytes;
        }
    }
    static ulong Wide(byte[] bytes, int low, int high)
    { return BitConverter.ToUInt32(bytes, low) | (bytes.Length >= high + 4 ? (ulong)BitConverter.ToUInt32(bytes, high) << 32 : 0); }
    static object Open(Source source, CancellationToken cancel, out Ext4Recovery.Report report)
    {
        var type = typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic);
        var context = Activator.CreateInstance(type, true); report = new Ext4Recovery.Report();
        Set(context, "Input", source); Set(context, "Cancel", cancel);
        Set(context, "Limits", new Ext4Recovery.Limits()); Set(context, "Report", report);
        try { return typeof(Ext4Recovery).GetMethod("OpenVolume", BindingFlags.Static | BindingFlags.NonPublic).Invoke(null, new[] { context, (object)0L }); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }
    static int Checked(Ext4Recovery.Report report) { return report.Volumes.Count == 1 ? report.Volumes[0].CheckedGroups : -1; }
    public static int Main(string[] args)
    {
        try
        {
            string root = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-group-units-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root); string image = Path.Combine(root, "owned.dd");
            File.Copy(Path.Combine(Path.GetFullPath(args[1]), "extent-deleted.dd"), image);
            string before = RecoveryCore.HashFile(image, CancellationToken.None, (a, b) => { });
            byte[] sb = ReadAt(image, 1024, 1024); int blockBytes = 1024 << (int)BitConverter.ToUInt32(sb, 0x18);
            bool wide = (BitConverter.ToUInt32(sb, 0x60) & 0x80) != 0;
            byte[] descriptor = ReadAt(image, ((long)BitConverter.ToUInt32(sb, 0x14) + 1) * blockBytes,
                wide ? BitConverter.ToUInt16(sb, 0xfe) : 32);
            long inodeBitmap = (long)Wide(descriptor, 4, 0x24) * blockBytes;
            long blockBitmap = (long)Wide(descriptor, 0, 0x20) * blockBytes;
            Check((BitConverter.ToUInt16(descriptor, 0x12) & 3) == 0 && inodeBitmap != blockBitmap, "native first group has both initialized bitmap blocks");

            Ext4Recovery.Report report = null; bool failed = false;
            using (var lease = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var input = new Source(image))
            {
                lease.Lock(inodeBitmap, 1);
                try { Open(input, CancellationToken.None, out report); } catch (IOException) { failed = true; }
                finally { lease.Unlock(inodeBitmap, 1); }
            }
            Check(failed, "OS source range lock interrupts bitmap reading");
            Check(Checked(report) == 0, "read failure never acknowledges the unfinished first group");

            failed = false;
            using (var input = new Source(image) { ZeroAt = inodeBitmap })
            {
                try { Open(input, CancellationToken.None, out report); } catch (EndOfStreamException) { failed = true; }
                Check(input.ZeroCalls == 1, "injected in-bounds zero read is exercised");
            }
            Check(failed && Checked(report) == 0, "short bitmap read remains an I/O failure, not a completed corrupt group");

            bool cancelled = false;
            using (var cancel = new CancellationTokenSource())
            using (var input = new Source(image))
            {
                input.BeforeRead = (at, count) => { if (at == blockBitmap) cancel.Cancel(); };
                try { Open(input, cancel.Token, out report); } catch (OperationCanceledException) { cancelled = true; }
            }
            Check(cancelled && Checked(report) == 0, "cancellation during the last bitmap read leaves the group unacknowledged");

            using (var input = new Source(image))
                Check(Open(input, CancellationToken.None, out report) != null && report.Volumes[0].Status == "ready" &&
                    report.Volumes[0].CheckedGroups == report.Volumes[0].Groups, "fresh successful initialization accounts for every complete group");
            Check(RecoveryCore.HashFile(image, CancellationToken.None, (a, b) => { }) == before, "all failures preserve copied source bytes");
            Console.WriteLine((failures == 0 ? "PASS" : "FAIL") + " Ext4GroupMetadata: " + checks + " checks, " + failures + " failures; initialization unit only, no persisted engine/device claim");
            return failures == 0 ? 0 : 1;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 2; }
    }
}
