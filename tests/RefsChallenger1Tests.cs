// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class RefsChallenger1Tests
{
    static int assertions;
    static void Assert(bool value, string message) { assertions++; if (!value) throw new Exception(message); }
    static string Hash(string path) { using (var f=File.OpenRead(path)) using(var h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant(); }
    public static int Main(string[] args)
    {
        try
        {
            string fixture=Path.GetFullPath(args.Length>0?args[0]:".build/refs-adversarial-fixtures");
            string output=Path.GetFullPath(args.Length>1?args[1]:".build/refs-adversarial-"+Guid.NewGuid().ToString("N"));
            var json=new JavaScriptSerializer { MaxJsonLength=64*1024*1024 };
            var manifest=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(fixture,"manifest.json")));
            foreach(Dictionary<string,object> sample in (IEnumerable)manifest["cases"])
            {
                string name=(string)sample["name"], source=Path.Combine(fixture,(string)sample["image"]), target=Path.Combine(output,name);
                string before=Hash(source);Assert(before==(string)sample["sha256"],name+": input recorded");
                RefsRecovery.Recover(source,target,CancellationToken.None);
                var r=json.Deserialize<RefsRecovery.Report>(File.ReadAllText(Path.Combine(target,"refs","report.json")));
                Assert(!r.Failed && !r.Cancelled && r.SourceUnchanged && Hash(source)==before,name+": clean read-only termination");
                Assert(r.Entries.Count(e=>e.Status=="recovered_live")==Convert.ToInt32(sample["files"]),name+": live output count");
                Assert(!r.Entries.Any(e=>e.Status=="unreferenced_refs_candidate" && e.MetadataChecksumVerified),name+": unreferenced checksum never invented");
                Assert(!Directory.GetFiles(target,"*.partial",SearchOption.AllDirectories).Any(),name+": no partial file");
                if(sample.ContainsKey("volumes"))Assert(r.Volumes.Count==Convert.ToInt32(sample["volumes"]),name+": volume count");
                if(sample.ContainsKey("reason"))Assert(r.Volumes.Any(v=>v.Reason==(string)sample["reason"]),name+": rejection reason");
                if(sample.ContainsKey("skip"))Assert(r.Skipped.ContainsKey((string)sample["skip"]),name+": explicit decline");
                if(sample.ContainsKey("warning"))Assert(r.Warnings.Contains((string)sample["warning"]),name+": integrity warning");
            }
            Console.WriteLine("PASS RefsChallenger1: "+assertions+" assertions on malformed synthetic metadata.");return 0;
        }
        catch(Exception e) { Console.Error.WriteLine(e);return 1; }
    }
}
