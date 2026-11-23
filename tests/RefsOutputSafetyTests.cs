// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class RefsOutputSafetyTests
{
    static int checks;
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b) => { }); }
    public static int Main(string[] args)
    {
        try {
            string root = Path.Combine(Path.GetFullPath(args[0]),".build","refs-output-safety-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            string image = Path.Combine(Path.GetFullPath(args[1]),"refs-v314-minimal.dd"),sha = Hash(image);
            string reference = Path.Combine(root,"reference"); Directory.CreateDirectory(reference);
            RefsRecovery.Recover(image,reference,CancellationToken.None);
            var report = new JavaScriptSerializer().Deserialize<RefsRecovery.Report>(File.ReadAllText(Path.Combine(reference,"refs","report.json"),Encoding.UTF8));
            var entry = report.Entries.First(x => x.Output != null); string output = entry.Output;
            Check(entry.RecoveredBytes > 0,"control fixture produces a real candidate before the output collision");
            string run = Path.Combine(root,"foreign-partial"); Directory.CreateDirectory(run);
            string partial = Path.Combine(run,"refs",output.Replace('/',Path.DirectorySeparatorChar))+".partial";
            bool created = false,failed = false; string before = null;
            try { RefsRecovery.Recover(image,run,CancellationToken.None,m => {
                if (created) return; created = true; Directory.CreateDirectory(Path.GetDirectoryName(partial));
                File.WriteAllText(partial,"owned marker representing an existing different unfinished file",Encoding.UTF8); before = Hash(partial);
            }); } catch (IOException) { failed = true; }
            Check(created && failed,"CreateNew collision fails instead of overwriting a previous partial");
            Check(File.Exists(partial) && Hash(partial) == before,"failed CreateNew must preserve a pre-existing partial that this call never owned");
            Check(!File.Exists(partial.Substring(0,partial.Length-8)) && Hash(image) == sha,"collision publishes no payload and leaves source unchanged");
            Console.WriteLine("PASS RefsOutputSafety: "+checks+" checks; owned regular files only"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
