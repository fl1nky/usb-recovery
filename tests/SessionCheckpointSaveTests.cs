using System;
using System.IO;
using System.Threading;
using UsbRecovery;

public static class SessionCheckpointSaveTests
{
    static int checks;
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    public static int Main(string[] args)
    {
        try
        {
            string root = Path.Combine(Path.GetFullPath(args[0]), ".build", "checkpoint-save-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            string source = Path.Combine(root, "source.dd"); File.WriteAllBytes(source, new byte[4096]);
            string job = Path.Combine(root, "job"); Directory.CreateDirectory(job);
            var session = RecoverySession.Start(job, source, Hash(source), new RecoveryOptions(), CancellationToken.None);
            session.Begin("fragmented-photos");
            string states = Path.Combine(job, "fragmented-photos.state"); Directory.CreateDirectory(states);
            string first = Path.Combine(states, "checkpoint-000000000001.json"), second = Path.Combine(states, "checkpoint-000000000002.json");
            File.WriteAllText(first, "{\"owned\":1}"); File.WriteAllText(second, "{\"owned\":2}");
            session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint { Path = first, Sha256 = Hash(first), Sequence = 1 });
            string metadata = Path.Combine(job, RecoverySession.FileName), before = Hash(metadata);
            bool denied = false;
            File.SetAttributes(metadata, File.GetAttributes(metadata) | FileAttributes.ReadOnly);
            try { session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint { Path = second, Sha256 = Hash(second), Sequence = 2 }); }
            catch (IOException) { denied = true; }
            catch (UnauthorizedAccessException) { denied = true; }
            finally { File.SetAttributes(metadata, File.GetAttributes(metadata) & ~FileAttributes.ReadOnly); }
            Check(denied && Hash(metadata) == before, "denied checkpoint update retains the old named metadata");
            Check(session.PhotoCheckpoint().Sequence == 1, "failed checkpoint capture rolls back the in-memory anchor");
            session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint { Path = second, Sha256 = Hash(second), Sequence = 2 });
            var saved = RecoverySession.Read(job).Stages.Find(x => x.Key == "fragmented-photos");
            Check(saved.CheckpointSequence == 2 && saved.CheckpointSha256 == Hash(second), "retry of the same generation must actually persist it");
            Check(File.Exists(first) && File.Exists(second), "capture failure does not remove either immutable generation");
            Console.WriteLine("PASS SessionCheckpointSave: " + checks + " checks; denied-write rollback and same-generation retry; owned files only");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
