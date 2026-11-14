using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using UsbRecovery;

// Ordinary owned files only. No UI, removable media or administrator privileges.
public static class RecoveryRestartTests
{
    static int checks;
    static string work, source;
    static readonly List<string> failures = new List<string>();
    static void Check(bool value, string why)
    {
        checks++;
        if (!value) throw new Exception(why);
    }
    static string Hash(string path)
    {
        using (var stream = File.OpenRead(path))
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
    static string Put(string root, string relative, string value)
    {
        string path = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        File.WriteAllText(path, value);
        return path;
    }
    static RecoveryOptions Options() { return new RecoveryOptions { TextFragments = true, TextQuery = "needle" }; }
    static RecoverySession Start(string root, string key)
    {
        Directory.CreateDirectory(root);
        var session = RecoverySession.Start(root, source, Hash(source), Options(), CancellationToken.None);
        session.Begin(key);
        return session;
    }
    static string Checkpoint(RecoverySession session, string root)
    {
        string path = Put(root, "fragmented-photos.state/checkpoint-000000000001.json", "{\"owned_test\":true}");
        session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint { Path = path, Sha256 = Hash(path), Sequence = 1 });
        return path;
    }
    static void Stop(RecoverySession session, string key)
    {
        session.Fail(key, "cancelled", "owned test interruption");
        session.Status("cancelled");
    }
    static void DeniedIntent(string key, string relative)
    {
        string root = Path.Combine(work, "denied-" + key);
        var session = Start(root, key);
        string payload = Put(root, relative, "retained bytes " + key);
        string checkpoint = key == "fragmented-photos" ? Checkpoint(session, root) : null;
        Stop(session, key);
        var previous = session.State.Stages.Single();
        string state = Path.Combine(root, RecoverySession.FileName), before = Hash(state);
        bool denied = false;
        File.SetAttributes(state, File.GetAttributes(state) | FileAttributes.ReadOnly);
        try { session.Begin(key); }
        catch (IOException) { denied = true; }
        catch (UnauthorizedAccessException) { denied = true; }
        finally { File.SetAttributes(state, File.GetAttributes(state) & ~FileAttributes.ReadOnly); }
        Check(denied && Hash(state) == before, key + ": failed intent must preserve durable state");
        Check(File.Exists(payload) && (checkpoint == null || File.Exists(checkpoint)), key + ": no output moves before durable intent");
        Check(Object.ReferenceEquals(session.State.Stages.Single(), previous), key + ": in-memory stage rolled back after denied intent");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), key + ": denied intent creates no history");
        RecoverySession.Open(root, source, Options(), CancellationToken.None, message => { });
        Check(true, key + ": previous session remains resumable");
    }
    static void PartlyArchived()
    {
        const string key = "fragmented-photos";
        string root = Path.Combine(work, "partial-archive");
        var session = Start(root, key);
        string payload = Put(root, key + "/candidate.jpg", "retained candidate");
        string checkpoint = Checkpoint(session, root);
        string report = Put(root, "fragmented-photo-search.json", "retained old report");
        string[] expected = new[] { Hash(payload), Hash(checkpoint), Hash(report) };
        Stop(session, key);
        bool failed = false;
        using (var locked = new FileStream(report, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            try { session.Begin(key); }
            catch (IOException) { failed = true; }
        }
        Check(failed && !File.Exists(payload) && File.Exists(report), "fixture failed after some moves, before all moves");
        var saved = RecoverySession.Read(root).Stages.Single();
        Check(saved.Status == "running" && saved.CheckpointPath == null, "durable retry intent cannot reference a moved checkpoint");
        string history = Path.Combine(root, "attempt-history");
        Check(Directory.GetFiles(history, "note.json", SearchOption.AllDirectories).Length == 1, "partly moved history is labelled before the first move");
        var resumed = RecoverySession.Open(root, source, Options(), CancellationToken.None, message => { });
        resumed.Begin(key);
        Check(!File.Exists(report), "a second restart safely archives the remaining report");
        string[] retained = Directory.GetFiles(history, "*", SearchOption.AllDirectories).Where(p => Path.GetFileName(p) != "note.json").Select(Hash).ToArray();
        Check(expected.OrderBy(x => x).SequenceEqual(retained.OrderBy(x => x)), "every old byte survives partial archive and retry");
    }
    static void ConfirmedContinuation()
    {
        string root = Path.Combine(work, "continue-photo");
        var session = Start(root, "fragmented-photos");
        string checkpoint = Checkpoint(session, root), before = Hash(checkpoint);
        Stop(session, "fragmented-photos");
        session = RecoverySession.Open(root, source, Options(), CancellationToken.None, message => { });
        session.Begin("fragmented-photos", true);
        Check(Hash(checkpoint) == before && session.PhotoCheckpoint().Sha256 == before, "explicit verified photo continuation retains its checkpoint");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "continuation does not archive active output");
    }
    static void InvalidMethod()
    {
        string root = Path.Combine(work, "invalid-method");
        var session = Start(root, "text");
        string path = Path.Combine(root, RecoverySession.FileName), before = Hash(path);
        foreach (string key in new[] { "unknown", "../text", "", null })
        {
            bool rejected = false;
            try { session.Begin(key); }
            catch (ArgumentException) { rejected = true; }
            Check(rejected && Hash(path) == before && session.State.Stages.Count == 1, "unknown method must be rejected before state changes");
        }
    }
    static void Run(string name, Action action)
    {
        try { action(); }
        catch (Exception error) { failures.Add(name + ": " + error.Message); }
    }
    public static int Main(string[] args)
    {
        work = Path.Combine(Path.GetFullPath(args[0]), ".build", "restart-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        source = Put(work, "source.dd", "owned read-only synthetic source");
        string before = Hash(source);
        string[,] methods = {
            {"partitions", "partition-search.json"}, {"fat", "filesystem/candidate.bin"},
            {"ntfs", "ntfs/candidate.bin"}, {"ext4", "ext4/candidate.bin"},
            {"refs", "refs/candidate.bin"}, {"apfs", "apfs/candidate.bin"},
            {"ntfs-records", "metadata-rescue/candidate.bin"}, {"photorec", "files.1/candidate.bin"},
            {"photos", "extra-photos/candidate.bin"}, {"containers", "containers/candidate.bin"},
            {"archive-members", "salvage-content/candidate.bin"}, {"fragmented-zip", "fragmented-archives/candidate.bin"},
            {"fragmented-photos", "fragmented-photos/candidate.bin"}, {"fragmented-media", "fragmented-media/candidate.bin"},
            {"user-signatures", "user-signatures/candidate.bin"}, {"text", "text-fragments/candidate.bin"}
        };
        for (int index = 0; index < methods.GetLength(0); index++)
        {
            string key = methods[index, 0], relative = methods[index, 1];
            Run(key, () => DeniedIntent(key, relative));
        }
        Run("partial archive", PartlyArchived);
        Run("photo continuation", ConfirmedContinuation);
        Run("invalid method", InvalidMethod);
        Run("unchanged source", () => Check(Hash(source) == before, "source unchanged"));
        foreach (string failure in failures) Console.Error.WriteLine("FAIL " + failure);
        Console.WriteLine((failures.Count == 0 ? "PASS" : "FAIL") + " RecoveryRestart: " + checks + " checks, " + failures.Count + " failures; owned-file failures only, no device claim");
        return failures.Count == 0 ? 0 : 1;
    }
}
