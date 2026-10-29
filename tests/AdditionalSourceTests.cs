using System;
using System.IO;
using System.Linq;
using System.Threading;
using UsbRecovery;

public static class AdditionalSourceTests
{
    static int assertions;
    static void Check(bool value, string name) { if (!value) throw new Exception(name); assertions++; Console.WriteLine("PASS " + name); }
    static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
    public static int Main()
    {
        string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Additional-source-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string path = Path.Combine(root, "image.dd"); File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4 });
        var image = new ImageRecoverySource(path); var entry = image.Enumerate("", CancellationToken.None).Single();
        Check(image.Info.Kind == "image" && entry.Size == 4 && entry.OriginalPath == path, "image abstraction retains original file identity");
        using (var read = image.OpenRead(entry, CancellationToken.None)) Check(read.CanRead && !read.CanWrite && read.ReadByte() == 1, "image stream read-only");
        File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4, 5 }); Check(Throws<IOException>(() => image.OpenRead(entry, CancellationToken.None)), "changed image rejected before scan");
        Check(Throws<IOException>(() => new ImageRecoverySource(@"\\.\PhysicalDrive0")), "physical source never enters logical image adapter");
        string folder = Path.Combine(root, "backup"); Directory.CreateDirectory(folder); File.WriteAllText(Path.Combine(folder, "Manifest.db"), "synthetic");
        var backup = new BackupRecoverySource(folder); Check(backup.Info.Kind == "backup" && backup.Enumerate("", CancellationToken.None).Count() == 1, "backup is a logical file source");
        Check(Throws<IOException>(() => SourceAcquisition.ValidateOutput(backup, "", Path.Combine(folder, "results"))), "backup output cannot be inside source");
        Check(Throws<OperationCanceledException>(() => image.Enumerate("", new CancellationToken(true)).ToArray()), "image enumeration honors cancellation");
        Console.WriteLine("AdditionalSources: " + assertions + " assertions passed"); return 0;
    }
}
