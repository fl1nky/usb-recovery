using System;
using System.IO;
using System.Reflection;
using System.Threading;
using UsbRecovery;

// Ordinary owned files only. No device, filesystem metadata or UI is opened.
public static class Ext4OutputSafetyTests
{
    static int checks;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static void Set(object obj, string name, object value) { obj.GetType().GetField(name).SetValue(obj, value); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a,b) => { }); }
    public static int Main(string[] args)
    {
        try {
            string root = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-output-safety-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(root, "ext4", "files"));
            string image = Path.Combine(root, "owned.dd"); byte[] bytes = new byte[4096];
            for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)(i * 37 + 11);
            File.WriteAllBytes(image, bytes); string before = Hash(image);
            string temporary = Path.Combine(root, "ext4", "files", "volume_0_inode_13_generation_7.bin.partial");
            File.WriteAllText(temporary, "pre-existing user file; preserve exactly"); string protectedSha = Hash(temporary);
            using (var input = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                object c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
                var report = new Ext4Recovery.Report(); Set(c, "Input", input); Set(c, "Root", Path.Combine(root, "ext4"));
                Set(c, "Cancel", CancellationToken.None); Set(c, "Report", report); Set(c, "Limits", new Ext4Recovery.Limits());
                var entry = new Ext4Recovery.Entry { Inode = 13, Generation = 7, DeclaredSize = bytes.Length,
                    Extents = { new Ext4Recovery.Extent { ImageOffset = 0, LogicalOffset = 0, Length = bytes.Length } } };
                bool rejected = false;
                try { typeof(Ext4Recovery).GetMethod("WriteFile", Private).Invoke(null, new[] { c, entry }); }
                catch (TargetInvocationException error) { if (!(error.InnerException is IOException)) throw; rejected = true; }
                Check(rejected, "existing partial is refused without overwriting");
                Check(File.Exists(temporary) && Hash(temporary) == protectedSha, "failed CreateNew never deletes another file");
                Check(entry.Output == null && report.RecoveredFiles == 0 && report.OutputBytes == 0, "failed publication never counts as recovery");
                Check(Hash(image) == before, "source bytes remain unchanged");
            }
            Console.WriteLine("PASS Ext4OutputSafety: " + checks + " checks; owned regular files only"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
