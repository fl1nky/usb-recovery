using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using UsbRecovery;

// Fault injection over an owned ordinary FileStream. This is not a USB test.
public static class ArchiveIoFailureTests
{
    sealed class UnexpectedEnd : FileStream
    {
        public UnexpectedEnd(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.Read) { }
        public override int Read(byte[] buffer, int offset, int count) { return 0; }
    }
    public static int Main(string[] args)
    {
        try
        {
            string folder = Path.Combine(Path.GetFullPath(args[0]), ".build", "archive-io-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            string image = Path.Combine(folder, "owned.dd");
            File.WriteAllBytes(image, new byte[4096]);
            string before = RecoveryCore.HashFile(image, CancellationToken.None, (a, b) => { });
            int checks = 0;
            using (var source = new UnexpectedEnd(image))
            {
                var read = typeof(ArchiveSalvage).GetMethod("Read", BindingFlags.NonPublic | BindingFlags.Static);
                bool io = false;
                try { read.Invoke(null, new object[] { source, 0L, 30 }); }
                catch (TargetInvocationException error) { io = error.InnerException is IOException; }
                if (!io) throw new Exception("An in-bounds ZIP header I/O failure must abort, not become a skipped malformed candidate");
                checks++;
                var type = typeof(ArchiveSalvage).GetNestedType("SliceStream", BindingFlags.NonPublic);
                var constructor = type.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).Single();
                using (var slice = (Stream)constructor.Invoke(new object[] { source, 0L, 16L }))
                {
                    io = false;
                    try { slice.Read(new byte[16], 0, 16); }
                    catch (IOException) { io = true; }
                    catch (Exception) { }
                    if (!io) throw new Exception("An in-bounds ZIP body I/O failure must abort, not become a skipped truncated member");
                    checks++;
                }
            }
            if (RecoveryCore.HashFile(image, CancellationToken.None, (a, b) => { }) != before) throw new Exception("Source changed");
            checks++;
            Console.WriteLine("PASS ArchiveIoFailure: " + checks + " checks; in-bounds header/body zero reads propagate as I/O errors; injected regular-file faults, no device claim");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
