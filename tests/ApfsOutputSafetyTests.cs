// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ApfsOutputSafetyTests
{
    static int checks;
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path,CancellationToken.None,(a,b) => { }); }
    static void Set(object value,string name,object field) { value.GetType().GetField(name).SetValue(value,field); }
    static void Write(string image,string root,ApfsRecovery.Entry entry)
    {
        using (var input = File.OpenRead(image)) {
            object ctx = Activator.CreateInstance(typeof(ApfsRecovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            Set(ctx,"Stream",input); Set(ctx,"Destination",Path.Combine(root,"apfs")); Set(ctx,"Cancel",CancellationToken.None);
            try { typeof(ApfsRecovery).GetMethod("WriteFileLegacy",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new[] { ctx,(object)entry }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
        }
    }
    static ApfsRecovery.Entry Plan(string name,ulong id = 42)
    { return new ApfsRecovery.Entry { Name = name, RelativePath = name, ObjectId = id, TransactionId = 3, DeclaredSize = 1024,
        Extents = { new ApfsRecovery.Extent { ImageOffset = 4096, LogicalOffset = 0, Length = 1024, PhysicalBlockNumber = 1 } } }; }
    public static int Main(string[] args)
    {
        try {
            string root = Path.Combine(Path.GetFullPath(args[0]),".build","apfs-output-safety-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            string image = Path.Combine(root,"source.dd"); byte[] source = new byte[8192]; new Random(81).NextBytes(source); File.WriteAllBytes(image,source); string sha = Hash(image);
            var escape = Plan("../../не трогать.txt"); Write(image,root,escape);
            string payload = RecoveryCatalog.SafeFile(Path.Combine(root,"apfs"),escape.Output);
            Check(escape.Output.StartsWith("files/",StringComparison.Ordinal) && Path.GetFileName(payload).Contains("не трогать"),"untrusted original name is retained as evidence and sanitized inside a unique output name");
            Check(File.ReadAllBytes(payload).SequenceEqual(source.Skip(4096).Take(1024)),"safe output preserves exact mapped bytes");
            Check(!File.Exists(Path.Combine(root,"не трогать.txt")),"directory traversal in source name cannot write outside method output");
            bool collision = false; string before = Hash(payload);
            try { Write(image,root,Plan("../../не трогать.txt")); } catch (IOException) { collision = true; }
            Check(collision && Hash(payload) == before,"an existing result is never truncated or replaced");
            var other = Plan("../../не трогать.txt",43); Write(image,root,other);
            Check(other.Output != escape.Output,"distinct objects sharing a source name receive distinct output files");
            foreach (string mode in new[] { "gap","overlap","outside" }) {
                var entry = Plan(mode);
                if (mode == "gap") entry.Extents[0].LogicalOffset = 1;
                if (mode == "overlap") entry.Extents.Add(new ApfsRecovery.Extent { LogicalOffset = 0, Length = 10, ImageOffset = 4096, PhysicalBlockNumber = 1 });
                if (mode == "outside") entry.Extents[0].ImageOffset = Int64.MaxValue;
                bool failed = false; try { Write(image,root,entry); } catch (IOException) { failed = true; }
                Check(failed && entry.Output == null,"invalid "+mode+" mapping cannot become a recovered file");
            }
            var index = RecoveryCatalog.Build(root,CancellationToken.None,null);
            Check(index.Candidates == 2 && index.Items.Count == 1 && index.Items[0].Method == "APFS", "real catalog includes APFS payloads, deduplicates contents and excludes reports/partials/state");
            string fixtures = Path.GetFullPath(args[1]),parsed = Path.Combine(root,"parsed");
            ApfsRecovery.Recover(Path.Combine(fixtures,"apfs-deleted-single.dd"),parsed,CancellationToken.None);
            var report = new JavaScriptSerializer().Deserialize<ApfsRecovery.Report>(File.ReadAllText(Path.Combine(parsed,"apfs","report.json"),Encoding.UTF8));
            Check(report.Entries.Count > 0 && report.Entries.All(x => !x.ContentAuthenticityVerified && x.DeletionEvidence == null),"live and unreferenced metadata do not authenticate content or assert deletion");
            Check(report.Entries.Any(x => x.Status == "unreferenced_apfs_candidate"),"unreferenced rows use an explicit candidate status");
            Check(Hash(image) == sha,"output safety tests leave source unchanged");
            Console.WriteLine("PASS ApfsOutputSafety: "+checks+" checks; supplied maps and structural parser, no native-device claim"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
