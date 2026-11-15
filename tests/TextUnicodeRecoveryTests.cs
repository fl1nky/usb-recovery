using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class TextUnicodeRecoveryTests
{
    static int checks;
    static string work;
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static void Case(bool bigEndian, bool boundary, bool broken)
    {
        string label = (bigEndian ? "be" : "le") + (boundary ? "-boundary" : "-odd") + (broken ? "-broken" : "-valid");
        string source = Path.Combine(work, label + ".dd"), output = Path.Combine(work, label);
        string text = "секрет🥧пирожков из собственной тестовой записки\n";
        byte[] raw = new UnicodeEncoding(bigEndian, false, true).GetBytes(text);
        if (broken) raw[14 + (bigEndian ? 0 : 1)] = 4; // unpaired high surrogate, not a replacement character
        int offset = boundary ? 1024 * 1024 - 14 : 513;
        byte[] image = new byte[offset + raw.Length + 2048];
        Buffer.BlockCopy(raw, 0, image, offset, raw.Length);
        File.WriteAllBytes(source, image);
        string before = Hash(source);
        Directory.CreateDirectory(output);
        int found = RawTextSearch.Recover(source, output, "секрет пирожков", CancellationToken.None, (a, b) => { });
        var json = new JavaScriptSerializer();
        var report = json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(output, "text-search.json")));
        var records = ((IEnumerable)report["files"]).Cast<Dictionary<string, object>>().ToArray();
        if (broken)
            Check(found == 0 && records.Length == 0, label + ": broken surrogate cannot join unrelated text runs");
        else
        {
            Check(found == 1 && records.Length == 1, label + ": both keywords survive the emoji in one UTF16 fragment");
            var record = records[0];
            Check(Convert.ToInt64(record["offset"]) == offset && Convert.ToInt64(record["sourceBytes"]) == raw.Length,
                label + ": exact byte offset/extent preserved at arbitrary alignment and chunk boundary");
            string file = RecoveryCatalog.SafeFile(output, (string)record["path"]);
            Check(File.ReadAllText(file, Encoding.UTF8) == text, label + ": recovered Unicode text is exact");
            Check((string)record["status"] == "text_fragment" && (string)record["deletedState"] == "unknown",
                label + ": no message attribution or deletion claim invented");
        }
        Check(Hash(source) == before, label + ": source bytes unchanged");
    }
    public static int Main(string[] args)
    {
        try
        {
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "text-unicode-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            foreach (bool bigEndian in new[] { false, true })
                foreach (bool boundary in new[] { false, true })
                    foreach (bool broken in new[] { false, true }) Case(bigEndian, boundary, broken);
            Console.WriteLine("PASS TextUnicodeRecovery: " + checks + " checks; UTF16 LE/BE emoji, odd offsets, chunk boundaries and broken-surrogate negatives; owned dumps only");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
