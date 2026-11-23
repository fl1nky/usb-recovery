using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class Ext4HistoryCandidateCheckpointTests
{
    static int checks;
    static string work, fixtures;
    static List<Tuple<long, int>> reads;
    static long descriptorAt, dataAt, rootInodeAt;
    static int blockBytes;
    static byte[] journalUuid;
    static long[] ring;
    static uint inodeSeed;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static object Get(object value, string name) { return value.GetType().GetField(name).GetValue(value); }
    static void Set(object value, string name, object field) { value.GetType().GetField(name).SetValue(value, field); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static string BytesHash(byte[] bytes) { using (var hash = System.Security.Cryptography.SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(bytes)); }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long, int>> Reads = new List<Tuple<long, int>>();
        public Source(string image) : base(image, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1) { }
        public override int Read(byte[] bytes, int at, int count)
        { Reads.Add(Tuple.Create(Position, count)); if (ZeroNext) return 0; return base.Read(bytes, at, count); }
    }
    sealed class Result { public string[] Candidates, Directories; public List<Tuple<long, int>> Reads; public bool Limited; }
    static string Parent(string root) { return Path.Combine(root, "anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root), Encoding.UTF8)) : null; }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint value)
    {
        string temp = Parent(root) + "." + Guid.NewGuid().ToString("N") + ".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value));
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { own = true; output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temp, Parent(root), null); else File.Move(temp, Parent(root));
        } finally { if (own && File.Exists(temp)) File.Delete(temp); }
    }
    static Dictionary<string, object> State(string root)
    {
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "parent pins exact history-data cursor");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8))["Payload"];
    }
    static string Image(string name, out string root, string fixture = "native-journal-v3-multiple-descriptors")
    {
        root = Path.Combine(work, name + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); File.Copy(Path.Combine(fixtures, fixture + ".dd"), image);
        File.SetAttributes(image, File.GetAttributes(image) & ~FileAttributes.ReadOnly); return image;
    }
    static string[] CandidateRows(object value)
    {
        return ((IDictionary)value).Values.Cast<object>().Select(item => Json.Serialize(new {
            Number = Get(item, "Number"), Sequence = Get(item, "TransactionSeq"), Journal = Get(item, "JournalBlock"), Target = Get(item, "TargetDiskBlock"),
            Offset = Get(item, "OffsetInBlock"), Mode = Get(item, "Mode"), Links = Get(item, "Links"), Dtime = Get(item, "Dtime"),
            Flags = Get(item, "Flags"), Generation = Get(item, "Generation"), Size = Get(item, "Size"), Bytes = BytesHash((byte[])Get(item, "InodeBytes"))
        })).OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }
    static string[] DirectoryRows(object value)
    {
        return ((IEnumerable)value).Cast<object>().Select(item => Json.Serialize(new {
            Journal = Get(item, "JournalBlock"), Target = Get(item, "TargetDiskBlock"), Sequence = Get(item, "TransactionSequence"),
            Bytes = BytesHash((byte[])Get(item, "Bytes"))
        })).ToArray();
    }
    static Result Run(string image, string root, string hash, CancellationToken token, Action<string> progress,
        bool durable = true, bool zeroRead = false, bool changeTransactions = false, bool whole = false)
    {
        using (var input = new Source(image)) {
            var c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            var report = new Ext4Recovery.Report(); Set(c, "Input", input); Set(c, "Root", Path.Combine(root, "ext4"));
            Set(c, "Report", report); Set(c, "Cancel", token); Set(c, "Limits", new Ext4Recovery.Limits());
            object volume = typeof(Ext4Recovery).GetMethod("OpenVolume", Private).Invoke(null, new[] { c, (object)0L });
            var vr = (Ext4Recovery.VolumeReport)Get(volume, "Report"); Check(vr.Status == "ready", "native filesystem metadata validates");
            object jc = typeof(Ext4Recovery).GetMethod("LoadJournal", Private).Invoke(null, new[] { c, volume, Get(volume, "Superblock") });
            object transactions = whole ? null : typeof(Ext4Recovery).GetMethod("ReadJournalHistoryTransactionsCheckpointed", Private).Invoke(null, new[] { c, jc, null, null });
            Check(whole || transactions != null, "upstream checksum-validated transaction list is complete or belongs to the whole controller");
            if (changeTransactions) {
                object first = ((IList)transactions)[0]; Set(first, "Sequence", (uint)Get(first, "Sequence") + 1);
            }
            var map = (IList)Get(jc, "Blocks"); blockBytes = vr.BlockBytes;
            uint firstBlock = (uint)Get(jc, "First");
            descriptorAt = (long)(ulong)map[(int)firstBlock] * blockBytes; dataAt = (long)(ulong)map[(int)firstBlock + 1] * blockBytes;
            journalUuid = (byte[])Get(jc, "Uuid"); object group = ((IList)Get(volume, "Groups"))[0];
            ring = map.Cast<ulong>().Select(block => (long)block * blockBytes).ToArray(); inodeSeed = (uint)Get(volume, "Seed");
            rootInodeAt = (long)(ulong)Get(group, "InodeTable") * blockBytes + vr.InodeBytes;
            object checkpoint = null;
            if (durable) {
                checkpoint = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
                Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", hash);
                Set(checkpoint, "Settings", "owned-history-data-v1"); Set(checkpoint, "Resume", Anchor(root));
                Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(value => SaveAnchor(root, value)));
            }
            input.Reads.Clear(); reads = input.Reads;
            Action<string> notify = message => { if (zeroRead) input.ZeroNext = true; if (progress != null) progress(message); };
            object[] args = whole ? new object[] { c, volume, jc, checkpoint, notify, null, null } :
                new object[] { c, volume, jc, transactions, checkpoint, notify, null, null };
            try { typeof(Ext4Recovery).GetMethod(whole ? "SweepJournalHistoryCheckpointed" : "CollectJournalHistoryCheckpointed", Private).Invoke(null, args); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return new Result { Candidates = CandidateRows(args[whole ? 5 : 6]), Directories = DirectoryRows(args[whole ? 6 : 7]), Reads = input.Reads, Limited = report.Limited };
        }
    }
    static Result Reference(string image, string hash)
    { string root = Path.Combine(work, "reference-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image, root, hash, CancellationToken.None, null, false); }
    static void Compare(Result a, Result b)
    {
        Check(a.Candidates.SequenceEqual(b.Candidates), "historical inode bytes, generation, sequence and both locations match uninterrupted processing");
        Check(a.Directories.SequenceEqual(b.Directories), "historical directory byte hashes and source locations survive continuation");
    }
    static void Cancel(string image, string root, string hash)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        { try { Run(image, root, hash, cancel.Token, m => cancel.Cancel()); } catch (OperationCanceledException) { stopped = true; } }
        Check(stopped && Convert.ToInt32(State(root)["Next"]) == 64 && !(bool)State(root)["Complete"], "cancel saves a real 64-block prefix inside native multiple-descriptor history");
    }
    static void Complete(string image, string root, string hash)
    {
        var result = Run(image, root, hash, CancellationToken.None, null); Compare(Reference(image, hash), result);
        var repeat = Run(image, root, hash, CancellationToken.None, m => { throw new Exception("completed history data restarted"); });
        Compare(result, repeat); Check(repeat.Reads.Count == 0, "completed history data restores from verified raw facts without phase source reads");
        Check((bool)State(root)["Complete"] && Hash(image) == hash, "history collection completes without changing the source");
    }
    static void CancelResume()
    {
        string root, image = Image("cancel", out root), hash = Hash(image); Cancel(image, root, hash); var prefix = reads.ToArray();
        var resumed = Run(image, root, hash, CancellationToken.None, null); Compare(Reference(image, hash), resumed);
        Check(resumed.Candidates.Length > 0 && !resumed.Reads.Any(row => prefix.Any(p => p.Item1 == row.Item1)), "resumed candidate collection never rereads the acknowledged source-data prefix");
        Complete(image, root, hash);
    }
    static void ParentFailure()
    {
        string root, image = Image("parent-failure", out root), hash = Hash(image), parent = null; FileStream held = null; bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, m => { if (held == null) { parent = Hash(Parent(root)); held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read); } }); }
        catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && held != null && Hash(Parent(root)) == parent && Convert.ToInt32(State(root)["Next"]) == 64,
            "OS parent replacement denial does not acknowledge the unread history suffix"); Complete(image, root, hash);
    }
    static void SourceFailure(bool synthetic)
    {
        string root, image = Image("source-failure", out root), hash = Hash(image), parent = null; FileStream held = null; bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, m => {
            if (synthetic || held != null) return; parent = Hash(Parent(root)); held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read); held.Lock(0, held.Length);
        }, true, synthetic); } catch (IOException) { failed = true; }
        finally { if (held != null) { held.Unlock(0, held.Length); held.Dispose(); } }
        Check(failed && Convert.ToInt32(State(root)["Next"]) == 64 && (synthetic || Hash(Parent(root)) == parent),
            "in-bounds zero read or actual OS source range denial cannot become completed history"); Complete(image, root, hash);
    }
    static void Tamper(bool source)
    {
        string root, image = Image("tamper", out root), hash = Hash(image); Cancel(image, root, hash);
        string file = source ? image : Directory.GetFiles(Path.Combine(root, "ext4.state", "history-blobs"), "blob-*.json").Single();
        using (var output = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        { output.Position = source ? output.Length - 1 : 0; int value = output.ReadByte(); output.Position--; output.WriteByte((byte)(value ^ 1)); }
        string parent = Hash(Parent(root)), changed = Hash(file); bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && Hash(Parent(root)) == parent && Hash(file) == changed, "changed source or acknowledged history data are rejected and preserved");
    }
    static void ChangedTransactionSet()
    {
        string root, image = Image("changed-transactions", out root), hash = Hash(image); Cancel(image, root, hash);
        string parent = Hash(Parent(root)); bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, null, true, false, true); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && Hash(Parent(root)) == parent, "changed upstream transaction identity cannot reuse old history facts");
    }
    static uint Crc(uint seed, byte[] data, int at, int count)
    {
        uint crc = seed; for (int index = at; index < at + count; index++) {
            crc ^= data[index]; for (int bit = 0; bit < 8; bit++) crc = crc >> 1 ^ ((crc & 1) != 0 ? 0x82f63b78U : 0);
        } return crc;
    }
    static void BigEndian(byte[] bytes, int at, uint value)
    { for (int index = 3; index >= 0; index--) { bytes[at + index] = (byte)value; value >>= 8; } }
    static uint BigEndian(byte[] bytes, int at)
    { return (uint)(bytes[at] << 24 | bytes[at + 1] << 16 | bytes[at + 2] << 8 | bytes[at + 3]); }
    static void DirectoryDerivative()
    {
        string root, image = Image("directory-derivative", out root, "native-journal-v3-history"); Reference(image, Hash(image));
        byte[] bytes = File.ReadAllBytes(image); int inode = checked((int)rootInodeAt);
        Check((BitConverter.ToUInt32(bytes, inode + 0x20) & 0x80000) != 0 && BitConverter.ToUInt16(bytes, inode + 0x28) == 0xf30a &&
            BitConverter.ToUInt16(bytes, inode + 0x2e) == 0, "directory derivative uses the native root inode's depth-zero extent");
        ulong physical = BitConverter.ToUInt32(bytes, inode + 0x3c) | (ulong)BitConverter.ToUInt16(bytes, inode + 0x3a) << 32;
        byte[] directory = bytes.Skip(checked((int)(physical * (uint)blockBytes))).Take(blockBytes).ToArray();
        Buffer.BlockCopy(directory, 0, bytes, checked((int)dataAt), blockBytes);
        int descriptor = checked((int)descriptorAt); uint sequence = BigEndian(bytes, descriptor + 8), seed = Crc(0xffffffff, journalUuid, 0, 16);
        BigEndian(bytes, descriptor + 12, (uint)physical); BigEndian(bytes, descriptor + 20, (uint)(physical >> 32));
        byte[] seq = new byte[4]; BigEndian(seq, 0, sequence);
        BigEndian(bytes, descriptor + 24, Crc(Crc(seed, seq, 0, 4), directory, 0, directory.Length));
        Array.Clear(bytes, descriptor + blockBytes - 4, 4);
        BigEndian(bytes, descriptor + blockBytes - 4, Crc(seed, bytes, descriptor, blockBytes)); File.WriteAllBytes(image, bytes);
        string hash = Hash(image); var result = Run(image, root, hash, CancellationToken.None, null);
        Check(result.Candidates.Length == 0 && result.Directories.Length == 1 && result.Directories[0].Contains(BytesHash(directory)),
            "checksum-valid derived journal transaction retains exact directory bytes separately from file inode candidates");
        Complete(image, root, hash);
    }
    static void NativeCases()
    {
        foreach (string fixture in new[] { "native-journal-v2-replay", "native-journal-v3-history", "native-journal-v3-ring-wrap", "native-journal-v3-escape", "native-journal-v3-revoked", "native-journal-v3-sequence-wrap-revoked" }) {
            string root, image = Image(fixture, out root, fixture), hash = Hash(image); var result = Run(image, root, hash, CancellationToken.None, null);
            if (fixture.EndsWith("-revoked")) Check(result.Candidates.Length == 0 && result.Directories.Length == 0, "committed later revokes suppress stale historical inode bytes");
            Complete(image, root, hash);
        }
    }
    static void LatestVersion(bool wrap)
    {
        string root, image = Image("latest-generation", out root, wrap ? "native-journal-v3-sequence-wrap-revoked" : "native-journal-v3-history");
        // The revoked native case has no surviving candidate. Locate the first
        // inode from the corresponding native one-transaction control instead.
        string controlRoot, control = Image("inode-reference", out controlRoot, "native-journal-v3-history");
        var reference = Reference(control, Hash(control));
        var identity = Json.Deserialize<Dictionary<string, object>>(reference.Candidates.Single());
        uint number = Convert.ToUInt32(identity["Number"]), generation = unchecked(Convert.ToUInt32(identity["Generation"]) + 1);
        int slot = Convert.ToInt32(identity["Offset"]);
        Reference(image, Hash(image)); byte[] bytes = File.ReadAllBytes(image);
        int block = blockBytes, descriptor = checked((int)descriptorAt), originalData = checked((int)dataAt);
        byte[] desc = bytes.Skip(descriptor).Take(block).ToArray(), data = bytes.Skip(originalData).Take(block).ToArray();
        byte[] commit = bytes.Skip(checked((int)ring[3])).Take(block).ToArray();
        uint sequence = unchecked(BigEndian(desc, 8) + 1), seed = Crc(0xffffffff, journalUuid, 0, 16);
        int inodeBytes = BitConverter.ToUInt16(bytes, 1024 + 0x58);
        byte[] inode = data.Skip(slot).Take(inodeBytes).ToArray();
        Buffer.BlockCopy(BitConverter.GetBytes(generation), 0, inode, 0x64, 4);
        inode[124] = inode[125] = 0; bool high = inode.Length >= 132 && BitConverter.ToUInt16(inode, 128) >= 4;
        if (high) inode[130] = inode[131] = 0;
        uint checksum = Crc(Crc(Crc(inodeSeed, BitConverter.GetBytes(number), 0, 4), BitConverter.GetBytes(generation), 0, 4), inode, 0, inode.Length);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)checksum), 0, inode, 124, 2);
        if (high) Buffer.BlockCopy(BitConverter.GetBytes((ushort)(checksum >> 16)), 0, inode, 130, 2);
        Buffer.BlockCopy(inode, 0, data, slot, inode.Length);
        BigEndian(desc, 8, sequence); byte[] seq = new byte[4]; BigEndian(seq, 0, sequence);
        BigEndian(desc, 24, Crc(Crc(seed, seq, 0, 4), data, 0, data.Length));
        Array.Clear(desc, block - 4, 4); BigEndian(desc, block - 4, Crc(seed, desc, 0, block));
        BigEndian(commit, 8, sequence); Array.Clear(commit, 16, 4); BigEndian(commit, 16, Crc(seed, commit, 0, block));
        // Explicit derivative replaces/adds the second transaction with a
        // newer inode generation and independently recalculated inode/JBD2 CRCs.
        Buffer.BlockCopy(desc, 0, bytes, checked((int)ring[4]), block);
        Buffer.BlockCopy(data, 0, bytes, checked((int)ring[5]), block);
        Buffer.BlockCopy(commit, 0, bytes, checked((int)ring[6]), block); File.WriteAllBytes(image, bytes);
        string hash = Hash(image); var result = Run(image, root, hash, CancellationToken.None, null);
        var candidate = Json.Deserialize<Dictionary<string, object>>(result.Candidates.Single());
        Check(Convert.ToUInt32(candidate["Generation"]) == generation && Convert.ToUInt32(candidate["Sequence"]) == sequence &&
            Convert.ToUInt64(candidate["Journal"]) * (uint)block == (ulong)ring[5], "latest inode generation and exact second-transaction source win, including uint32 sequence wrap");
        Complete(image, root, hash);
    }
    static void RepinnedCursor()
    {
        string root, image = Image("repinned-cursor", out root), hash = Hash(image); Cancel(image, root, hash);
        var anchor = Anchor(root); var envelope = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8));
        var state = (Dictionary<string, object>)envelope["Payload"]; state["Next"] = Convert.ToInt32(state["Next"]) + 1;
        File.WriteAllText(anchor.Path, Json.Serialize(envelope), new UTF8Encoding(false)); anchor.Sha256 = Hash(anchor.Path); SaveAnchor(root, anchor);
        string parent = Hash(Parent(root)); bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && Hash(Parent(root)) == parent, "rehashed inconsistent history cursor is rejected before source reads or parent writes");
    }
    static void WholeSweep(bool denied)
    {
        string root, image = Image("whole-sweep", out root), hash = Hash(image), parent = null;
        FileStream held = null; bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, hash, cancel.Token, m => {
                if (!m.StartsWith("ext4: historical data blocks", StringComparison.Ordinal) || held != null) return;
                if (denied) { parent = Hash(Parent(root)); held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read); }
                else cancel.Cancel();
            }, true, false, false, true); }
            catch (OperationCanceledException) { stopped = !denied; } catch (IOException) { stopped = denied; }
            finally { if (held != null) held.Dispose(); }
        }
        Check(stopped && (string)State(root)["Phase"] == "candidates" && (!denied || Hash(Parent(root)) == parent),
            "whole history controller pins the active child across cancellation or OS parent replacement denial");
        var result = Run(image, root, hash, CancellationToken.None, null, true, false, false, true); Compare(Reference(image, hash), result);
        var repeat = Run(image, root, hash, CancellationToken.None, m => { throw new Exception("completed whole history restarted"); }, true, false, false, true);
        Compare(result, repeat); Check(repeat.Reads.Count == 0 && (string)State(root)["Phase"] == "complete" && Hash(image) == hash,
            "completed transaction and candidate children restore as one whole history stage without phase source reads");
    }
    static void LimitedWholeSweep()
    {
        string root, image = Image("limited-whole", out root, "native-journal-v3-replay"); Reference(image, Hash(image));
        byte[] bytes = File.ReadAllBytes(image);
        byte[] descriptor = bytes.Skip((int)ring[1]).Take(blockBytes).ToArray(), data = bytes.Skip((int)ring[2]).Take(blockBytes).ToArray(),
            commit = bytes.Skip((int)ring[3]).Take(blockBytes).ToArray();
        // Explicit overlap derivative: no single start covers all headers with
        // this sequence; independent JBD2 controls already verify this budget.
        for (int index = 1; index < 64; index++) Array.Clear(bytes, (int)ring[index], blockBytes);
        for (int index = 0; index < 20; index++) {
            Buffer.BlockCopy(descriptor, 0, bytes, (int)ring[1 + index * 2], blockBytes);
            Buffer.BlockCopy(data, 0, bytes, (int)ring[2 + index * 2], blockBytes);
        }
        Buffer.BlockCopy(commit, 0, bytes, (int)ring[41], blockBytes);
        Buffer.BlockCopy(descriptor, 0, bytes, (int)ring[43], blockBytes);
        int super = (int)ring[0]; BigEndian(bytes, super + 16, 64); Array.Clear(bytes, super + 0xfc, 4);
        BigEndian(bytes, super + 0xfc, Crc(0xffffffff, bytes, super, 1024)); File.WriteAllBytes(image, bytes); string hash = Hash(image);
        var result = Run(image, root, hash, CancellationToken.None, null, true, false, false, true);
        var state = State(root);
        Check(result.Limited && result.Candidates.Length == 0 && result.Directories.Length == 0 &&
            (bool)state["Limited"] && (string)state["Phase"] == "complete" && state["Candidates"] == null,
            "exhausted real transaction budget never starts data extraction or promotes incomplete history to complete candidates");
        var repeat = Run(image, root, hash, CancellationToken.None, m => { throw new Exception("limited history restarted"); }, true, false, false, true);
        Check(repeat.Limited && repeat.Reads.Count == 0 && Hash(image) == hash, "limited whole-stage replay retains coverage without a new source sweep");
    }
    static void KilledProcess()
    {
        string root, image = Image("worker", out root), hash = Hash(image), ready = Path.Combine(root, "ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var watch = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned history-data worker reaches a persisted prefix"); child.Kill(); Check(child.WaitForExit(10000), "owned worker killed without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Complete(image, root, hash);
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("CollectJournalHistoryCheckpointed", Private) == null)
            { Console.WriteLine("FAIL: baseline lacks persisted historical inode/directory processing"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1], args[2], Hash(args[1]), CancellationToken.None, m => { File.WriteAllText(args[3], "acknowledged"); Thread.Sleep(Timeout.Infinite); }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-history-data-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            CancelResume(); ParentFailure(); SourceFailure(false); SourceFailure(true); Tamper(true); Tamper(false); ChangedTransactionSet(); RepinnedCursor();
            DirectoryDerivative(); NativeCases(); LatestVersion(false); LatestVersion(true); WholeSweep(false); WholeSweep(true); LimitedWholeSweep(); KilledProcess();
            Console.WriteLine("PASS Ext4HistoryCandidateCheckpoint: " + checks + " checks; historical data component only, full ext4 engine/device resume not claimed"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
