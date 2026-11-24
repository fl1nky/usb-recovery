// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public class MediaBoundaryRecoveryTests
{
    public class Target { public string extension, sha256; public long offset, size; }
    public class Layout { public string name, mode, source_sha256; public List<Target> expected; }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a,b) => {}); }

    public static int Main(string[] args)
    {
        string fixtures = Path.GetFullPath(args[0]), output = Path.GetFullPath(args[1]);
        var json = new JavaScriptSerializer();
        var layouts = json.Deserialize<List<Layout>>(File.ReadAllText(Path.Combine(fixtures, "manifest.json")));
        int passed = 0;
        foreach (var layout in layouts)
        {
            string image = Path.Combine(fixtures, layout.name + ".dd"), run = Path.Combine(output, layout.name);
            if (Directory.Exists(run) || Hash(image) != layout.source_sha256) throw new IOException("Fixture or output changed");
            Directory.CreateDirectory(run);
            bool photos = layout.mode == "photos";
            if (photos) ExtraPhotoSearch.Recover(image, run, CancellationToken.None, null);
            else ContainerCarver.Recover(image, run, new RecoveryOptions(), CancellationToken.None, null);
            string report = Path.Combine(run, photos ? "extra-photo-search.json" : "container-search.json");
            var rows = json.Deserialize<Report>(File.ReadAllText(report)).files;
            bool ok = rows.Count == layout.expected.Count && layout.expected.All(t => rows.Any(r =>
                r.offset == t.offset && Path.GetExtension(r.path) == t.extension && r.sha256 == t.sha256 &&
                Hash(RecoveryCatalog.SafeFile(run, r.path)) == t.sha256)) && Hash(image) == layout.source_sha256;
            if (ok) passed++;
            Console.WriteLine("{0} {1} expected={2} actual={3}", ok ? "PASS" : "FAIL", layout.name, layout.expected.Count, rows.Count);
        }
        Console.WriteLine("{0}/{1} layouts passed", passed, layouts.Count);
        return passed == layouts.Count ? 0 : 1;
    }
    public class Row { public string path, sha256; public long offset; }
    public class Report { public List<Row> files; }
}
