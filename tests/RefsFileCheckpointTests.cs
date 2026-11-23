// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Supplied plans, owned regular images and actual child/parent writes.
// Whole ReFS parsing/session acceptance is a separate integration gate.
public static class RefsFileCheckpointTests
{
    const int MiB = 1024 * 1024;
    static int checks;
    static string work;
    static List<Tuple<long,int>> reads;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * MiB };
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string file) { return RecoveryCore.HashFile(file, CancellationToken.None, (a,b) => { }); }
    static void Set(object value, string name, object field) { value.GetType().GetField(name).SetValue(value, field); }
    static string Parent(string root) { return Path.Combine(root, "anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root), Encoding.UTF8)) : null; }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint value)
    {
        string temp = Parent(root) + "." + Guid.NewGuid().ToString("N") + ".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value));
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temp, Parent(root), null); else File.Move(temp, Parent(root));
        } finally { if (own && File.Exists(temp)) File.Delete(temp); }
    }
    static Dictionary<string,object> State(string root)
    {
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "parent pins exact file state");
        return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(anchor.Path, Encoding.UTF8))["Payload"];
    }
    static string Scratch(string root) { return Path.Combine(root,"refs.state","work","copy-"+(string)State(root)["WorkId"]+".partial"); }
    static string Output(string root) { return Path.Combine(root,"refs","files","рецепт.bin"); }
    static string Image(string name, out string root)
    {
        root = Path.Combine(work, name+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        byte[] bytes = new byte[10*MiB]; new Random(713).NextBytes(bytes);
        string file = Path.Combine(root,"owned.dd"); File.WriteAllBytes(file,bytes); return file;
    }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long,int>> Reads = new List<Tuple<long,int>>();
        public Source(string file) : base(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1) { }
        public override int Read(byte[] bytes, int at, int count)
        { Reads.Add(Tuple.Create(Position,count)); return ZeroNext ? 0 : base.Read(bytes,at,count); }
    }
    static RefsRecovery.Entry Plan(string kind)
    {
        var entry = new RefsRecovery.Entry { VolumeOffset = 4096, ObjectId = UInt64.MaxValue, ParentObjectId = 2,
            Name = "рецепт.bin", RelativePath = "семья/рецепт.bin", Status = "unreferenced_refs_candidate", Note = "supplied copy plan; deletion unknown",
            MetadataChecksumVerified = true, CreationTimeUtc = new DateTime(2020,1,2,3,4,5,DateTimeKind.Utc) };
        if (kind == "resident" || kind == "empty") { entry.IsResident = true; entry.DeclaredSize = kind == "empty" ? 0 : 17; return entry; }
        entry.DeclaredSize = 4L*MiB+39;
        entry.Extents.Add(new RefsRecovery.Extent { ImageOffset = 4096, LogicalOffset = 0, Length = MiB+17 });
        entry.Extents.Add(new RefsRecovery.Extent { ImageOffset = kind == "holes" ? -1 : 4L*MiB, LogicalOffset = MiB+17, Length = MiB+13 });
        entry.Extents.Add(new RefsRecovery.Extent { ImageOffset = kind == "clone" ? 4096 : 6L*MiB, LogicalOffset = 2L*MiB+30, Length = 2L*MiB+9 });
        if (kind == "empty-mapped") { entry.Extents.Clear(); entry.DeclaredSize = 0; }
        return entry;
    }
    static byte[] Resident(RefsRecovery.Entry entry)
    { return !entry.IsResident ? null : Encoding.UTF8.GetBytes(entry.DeclaredSize == 0 ? "" : "family recipe 123"); }
    static byte[] Expected(string image, string kind)
    {
        var entry = Plan(kind); byte[] resident = Resident(entry); if (resident != null) return resident;
        using (var input = File.OpenRead(image)) using (var output = new MemoryStream()) {
            foreach (var range in entry.Extents) {
                byte[] bytes = new byte[(int)range.Length];
                if (range.ImageOffset >= 0) { input.Position = range.ImageOffset; int done = 0;
                    while (done < bytes.Length) { int n = input.Read(bytes,done,bytes.Length-done); if (n == 0) throw new EndOfStreamException(); done += n; } }
                output.Write(bytes,0,bytes.Length);
            }
            return output.ToArray();
        }
    }
    static RefsRecovery.Entry Run(string image, string root, string sha, CancellationToken token, Action<string> progress,
        string change = null, string kind = "mapped")
    {
        using (var input = new Source(image)) {
            var entry = Plan(kind); byte[] resident = Resident(entry); var limits = new RefsRecovery.Limits();
            var report = new RefsRecovery.Report { OutputBytes = 123, RecoveredFiles = 2, Candidates = 3 };
            object c = Activator.CreateInstance(typeof(RefsRecovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            Set(c,"Input",input); Set(c,"Root",Path.Combine(root,"refs")); Set(c,"Cancel",token); Set(c,"Limits",limits); Set(c,"Report",report); Set(c,"OutputBytes",123L);
            object checkpoint = Activator.CreateInstance(typeof(RefsRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
            Set(checkpoint,"Directory",root); Set(checkpoint,"Method","refs"); Set(checkpoint,"SourceSha256",sha); Set(checkpoint,"Settings","owned-refs-file-v1");
            Set(checkpoint,"Resume",Anchor(root)); Set(checkpoint,"Commit",(Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(root,a)));
            string relative = "files/рецепт.bin";
            if (change == "mapping") entry.Extents[0].ImageOffset++;
            if (change == "name") entry.Name += "changed";
            if (change == "baseline") report.OutputBytes++;
            if (change == "limits") limits.MaximumOutputBytes--;
            if (change == "gap") entry.Extents[0].LogicalOffset++;
            if (change == "negative-range") entry.Extents[0].ImageOffset = -2;
            if (change == "out-of-image") entry.Extents[0].ImageOffset = Int64.MaxValue;
            if (change == "path") relative = "../escape.bin";
            if (change == "budget") limits.MaximumOutputBytes = 123;
            if (change == "null-range") entry.Extents[0] = null;
            if (change == "resident-length") resident = new byte[16];
            reads = input.Reads;
            Action<string> notify = m => {
                if (change == "mid-plan") entry.ObjectId--;
                if (change == "mid-limits") limits.MaximumOutputBytes--;
                if (change == "mid-context") Set(checkpoint,"Settings","changed");
                if (change == "zero" && Convert.ToInt64(State(root)["Next"]) >= MiB) input.ZeroNext = true;
                if (progress != null) progress(m);
            };
            try { typeof(RefsRecovery).GetMethod("WriteFileCheckpointed",BindingFlags.Static|BindingFlags.NonPublic)
                .Invoke(null,new object[] { c,entry,resident,relative,checkpoint,notify }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            Check(report.RecoveredFiles == 2 && report.OutputBytes == 123 && (long)c.GetType().GetField("OutputBytes").GetValue(c) == 123,
                "copy child leaves aggregate accounting to the owning controller");
            return entry;
        }
    }
    static List<Tuple<long,int>> Cancel(string image, string root, string sha)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (Convert.ToInt64(State(root)["Next"]) >= MiB) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Convert.ToInt64(State(root)["Next"]) == MiB && !File.Exists(Output(root)),"cancel saves a real logical position before final publication");
        return reads.ToList();
    }
    static void Complete(string image, string root, string sha, List<Tuple<long,int>> prefix = null, string kind = "mapped")
    {
        var entry = Run(image,root,sha,CancellationToken.None,null,null,kind); var suffix = reads.ToArray();
        Check(File.ReadAllBytes(Output(root)).SequenceEqual(Expected(image,kind)),"published bytes equal independent mapped/resident/sparse assembly");
        Check(entry.Sha256 == Hash(Output(root)) && entry.RecoveredBytes == entry.DeclaredSize && !entry.ContentAuthenticityVerified && entry.DeletionEvidence == null,
            "publication preserves digest, size and unknown authenticity/deletion");
        if (prefix != null) Check(!suffix.Any(x => prefix.Any(p => p.Item1 < x.Item1+x.Item2 && x.Item1 < p.Item1+p.Item2)),"resume skips every acknowledged source-copy prefix range");
        Run(image,root,sha,CancellationToken.None,m => { throw new Exception("published copy restarted"); },null,kind);
        Check(reads.Count == 0 && (string)State(root)["Phase"] == "published" && Hash(image) == sha,"repeat verifies published file without source-copy reads or source changes");
    }
    static void IoFailure(string mode)
    {
        string root,image = Image(mode,out root),sha = Hash(image),before = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            var state = State(root); if (held != null || Convert.ToInt64(state["Next"]) < MiB) return;
            if (mode == "parent") { before = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); }
            if (mode == "read") { held = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read); held.Lock(0,held.Length); }
            if (mode == "write") { held = new FileStream(Scratch(root),FileMode.Open,FileAccess.Read,FileShare.ReadWrite); held.Lock(0,10L*MiB); }
        },mode == "zero" ? "zero" : null); } catch (IOException) { failed = true; }
        finally { if (held != null) { if (mode == "read" || mode == "write") held.Unlock(0,mode == "read" ? held.Length : 10L*MiB); held.Dispose(); } }
        Check(failed,"actual "+mode+" failure is reported");
        if (before != null) Check(Hash(Parent(root)) == before,"failed parent replacement cannot advance cursor");
        Complete(image,root,sha);
    }
    static void Tamper(string mode)
    {
        string root,image = Image(mode,out root),sha = Hash(image); Cancel(image,root,sha); string scratch = Scratch(root),before = null;
        if (mode == "work") { byte[] bytes = File.ReadAllBytes(scratch); bytes[0] ^= 1; File.WriteAllBytes(scratch,bytes); before = Hash(scratch); }
        if (mode == "source") { using (var file = new FileStream(image,FileMode.Open,FileAccess.Write)) file.WriteByte(19); }
        if (mode == "state") { var a = Anchor(root); File.AppendAllText(a.Path,"changed"); }
        bool failed = false; try { Run(image,root,sha,CancellationToken.None,null,mode); } catch (IOException) { failed = true; }
        Check(failed && !File.Exists(Output(root)),"changed "+mode+" fails closed without successful output");
        if (before != null) Check(Hash(scratch) == before,"changed partial is preserved for inspection");
    }
    static void Repairs()
    {
        string root,image = Image("repair",out root),sha = Hash(image); Cancel(image,root,sha); File.Delete(Scratch(root));
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (Convert.ToInt64(State(root)["WorkBytes"]) > 0) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped,"missing partial repair has its own durable progress"); Complete(image,root,sha);
        File.Delete(Output(root)); Complete(image,root,sha);
        File.WriteAllText(Output(root),"foreign file",Encoding.UTF8); string before = Hash(Output(root)); bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,null); } catch (IOException) { failed = true; }
        Check(failed && Hash(Output(root)) == before,"different existing final output is preserved and never accepted");
    }
    static void PublicationFailure()
    {
        string root,image = Image("publish",out root),sha = Hash(image),before = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held == null && (string)State(root)["Phase"] == "ready") {
                before = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read);
            }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && File.Exists(Output(root)) && Hash(Parent(root)) == before,"rename before failed publication acknowledgement retains ready parent and exact output");
        Complete(image,root,sha);
    }
    static void Kill()
    {
        string root,image = Image("kill",out root),sha = Hash(image),ready = Path.Combine(root,"worker-ready");
        var start = new ProcessStartInfo { FileName = Assembly.GetExecutingAssembly().Location,
            Arguments = "worker \""+image+"\" \""+root+"\" "+sha+" \""+ready+"\"",UseShellExecute = false,CreateNoWindow = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.ElapsedMilliseconds < 15000) Thread.Sleep(25);
                Check(File.Exists(ready) && !child.HasExited,"owned worker reaches anchored copy cursor before kill"); child.Kill(); child.WaitForExit(); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(); } }
        }
        Check(Convert.ToInt64(State(root)["Next"]) == MiB,"process kill retains acknowledged prefix"); Complete(image,root,sha);
    }
    static void ParsedFixture(string fixtures)
    {
        string root = Path.Combine(work,"parsed-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(fixtures,"refs-v314-minimal.dd"),sha = Hash(image),reference = Path.Combine(root,"reference"); Directory.CreateDirectory(reference);
        RefsRecovery.Recover(image,reference,CancellationToken.None);
        var expected = Json.Deserialize<RefsRecovery.Report>(File.ReadAllText(Path.Combine(reference,"refs","report.json"),Encoding.UTF8));
        bool cancelled = false; RefsRecovery.Report actual = null;
        for (int attempt = 0; attempt < 2; attempt++) using (var cancel = new CancellationTokenSource()) using (var input = new Source(image)) {
            int fileIndex = 0; var report = new RefsRecovery.Report();
            object c = Activator.CreateInstance(typeof(RefsRecovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            string outputRoot = Path.Combine(root,"refs"); Directory.CreateDirectory(Path.Combine(outputRoot,"files"));
            Set(c,"Input",input); Set(c,"Root",outputRoot); Set(c,"Cancel",cancel.Token); Set(c,"Report",report); Set(c,"Limits",new RefsRecovery.Limits());
            Action<RefsRecovery.Entry,byte[],string> publish = (entry,resident,relative) => {
                string child = Path.Combine(root,"refs.state","file-children",(fileIndex++).ToString()); Directory.CreateDirectory(child);
                object checkpoint = Activator.CreateInstance(typeof(RefsRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
                Set(checkpoint,"Directory",child); Set(checkpoint,"Method","refs"); Set(checkpoint,"SourceSha256",sha); Set(checkpoint,"Settings","parsed-copy-v1");
                Set(checkpoint,"Resume",Anchor(child)); Set(checkpoint,"Commit",(Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(child,a)));
                Action<string> progress = m => { if (attempt == 0) cancel.Cancel(); };
                try { typeof(RefsRecovery).GetMethod("WriteFileCheckpointed",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[] { c,entry,resident,relative,checkpoint,progress }); }
                catch (TargetInvocationException error) { throw error.InnerException; }
            };
            Set(c,"PublishFile",publish);
            try {
                object geometry = typeof(RefsRecovery).GetMethod("ReadVbr",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new[] { c,(object)0L });
                Check(geometry != null,"actual fixture parser supplies file-copy geometry");
                typeof(RefsRecovery).GetMethod("ScanVolume",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[] { c,geometry,new RefsRecovery.VolumeReport(),null });
                actual = report;
            } catch (TargetInvocationException error) { if (error.InnerException is OperationCanceledException) cancelled = true; else throw error.InnerException; }
        }
        Check(cancelled && actual != null && actual.RecoveredFiles > 0,"real ScanVolume/ProcessFileRecord path resumes child copying after cancellation");
        Check(Json.Serialize(actual.Entries) == Json.Serialize(expected.Entries),"parser-derived published entries match legacy provenance, dates, extents, names and digests exactly");
        foreach (var entry in actual.Entries.Where(x => x.Output != null)) {
            string relative = entry.Output.Replace('/',Path.DirectorySeparatorChar);
            Check(File.ReadAllBytes(Path.Combine(root,"refs",relative)).SequenceEqual(File.ReadAllBytes(Path.Combine(reference,"refs",relative))),"actual parsed fixture output equals independent legacy output");
        }
        Check(Hash(image) == sha,"actual parsed fixture source is unchanged");
    }
    public static int Main(string[] args)
    {
        try {
            if (args[0] == "worker") { Run(args[1],args[2],args[3],CancellationToken.None,m => {
                if (Convert.ToInt64(State(args[2])["Next"]) >= MiB) { File.WriteAllText(args[4],"ready"); Thread.Sleep(Timeout.Infinite); }
            }); return 0; }
            work = Path.Combine(Path.GetFullPath(args[0]),".build","refs-file-tests-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            string root,image = Image("cancel",out root),sha = Hash(image); Complete(image,root,sha,Cancel(image,root,sha));
            foreach (string kind in new[] { "holes","clone","resident","empty","empty-mapped" }) { image = Image(kind,out root); Complete(image,root,Hash(image),null,kind); }
            foreach (string mode in new[] { "parent","read","write","zero" }) IoFailure(mode);
            foreach (string mode in new[] { "mapping","name","baseline","limits","work","source","state" }) Tamper(mode);
            foreach (string mode in new[] { "gap","negative-range","out-of-image","path","budget","null-range","mid-plan","mid-limits","mid-context" }) {
                image = Image(mode,out root); bool failed = false;
                try { Run(image,root,Hash(image),CancellationToken.None,null,mode); } catch (IOException) { failed = true; }
                Check(failed && !File.Exists(Output(root)),"invalid or mutated "+mode+" plan cannot publish");
            }
            image = Image("resident-length",out root); bool invalid = false;
            try { Run(image,root,Hash(image),CancellationToken.None,null,"resident-length","resident"); } catch (IOException) { invalid = true; }
            Check(invalid,"resident size mismatch is rejected"); Repairs(); PublicationFailure(); Kill(); ParsedFixture(Path.GetFullPath(args[1]));
            Console.WriteLine("PASS RefsFileCheckpoint: "+checks+" checks; supplied plans, no whole-engine/device claim"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
