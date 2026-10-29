using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class PhotoCatalogTests
{
    static int passed, failed;
    static string root;
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static void Test(string name, Action body)
    {
        try { body(); passed++; Console.WriteLine("PASS " + name); }
        catch (Exception ex) { failed++; Console.WriteLine("FAIL " + name + ": " + ex.GetType().Name + ": " + ex.Message); }
    }
    static string Child(string run, string path) { string full = Path.Combine(run, path); Directory.CreateDirectory(Path.GetDirectoryName(full)); return full; }
    static string NewRun(string name) { string run = Path.Combine(root, name); Directory.CreateDirectory(run); return run; }
    static byte[] Photo(ImageFormat format)
    {
        using (var bitmap = new Bitmap(48, 32))
        using (Graphics graphics = Graphics.FromImage(bitmap))
        using (var memory = new MemoryStream())
        {
            graphics.Clear(Color.SkyBlue);
            graphics.FillRectangle(Brushes.Orange, 7, 8, 18, 15);
            bitmap.Save(memory, format);
            return memory.ToArray();
        }
    }
    static List<Dictionary<string, object>> Items(string run)
    {
        var serializer = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
        var catalog = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(run, "photo-catalog.json")));
        return ((System.Collections.IEnumerable)catalog["items"]).Cast<Dictionary<string, object>>().ToList();
    }
    static Dictionary<string, object> Named(List<Dictionary<string, object>> items, string name) { return items.Single(i => (string)i["Name"] == name); }
    static byte[] ExifJpeg(byte[] jpg)
    {
        // EXIF DateTimeOriginal in a valid little-endian TIFF IFD.
        using (var output = new MemoryStream())
        using (var payload = new MemoryStream())
        {
            var writer = new BinaryWriter(payload);
            writer.Write(Encoding.ASCII.GetBytes("Exif\0\0II")); writer.Write((ushort)42); writer.Write((uint)8);
            writer.Write((ushort)1); writer.Write((ushort)0x8769); writer.Write((ushort)4); writer.Write((uint)1); writer.Write((uint)26); writer.Write((uint)0);
            writer.Write((ushort)1); writer.Write((ushort)0x9003); writer.Write((ushort)2); writer.Write((uint)20); writer.Write((uint)44); writer.Write((uint)0);
            writer.Write(Encoding.ASCII.GetBytes("2001:07:14 13:25:09\0")); writer.Flush();
            byte[] app1 = payload.ToArray(); int segmentLength = app1.Length + 2;
            output.Write(jpg, 0, 2); output.WriteByte(255); output.WriteByte(225); output.WriteByte((byte)(segmentLength >> 8)); output.WriteByte((byte)segmentLength);
            output.Write(app1, 0, app1.Length); output.Write(jpg, 2, jpg.Length - 2);
            return output.ToArray();
        }
    }
    public static int Main()
    {
        root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PhotoCatalog-data-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(root);
        Console.WriteLine("Synthetic output only: " + root);
        byte[] jpeg = Photo(ImageFormat.Jpeg), png = Photo(ImageFormat.Png);
        string main = NewRun("mixed");
        string named = "Бабушка ' & фото.jpg";
        string original = Child(main, Path.Combine("filesystem", "files", named));
        File.WriteAllBytes(original, ExifJpeg(jpeg));
        File.Copy(original, Child(main, Path.Combine("files.1", "f00001.jpg")));
        File.WriteAllBytes(Child(main, Path.Combine("ntfs", "partition-0", "data", "photo.png")), png);
        File.WriteAllBytes(Child(main, Path.Combine("extra-photos", "truncated.jpg")), jpeg.Take(jpeg.Length - 2).ToArray());
        File.WriteAllBytes(Child(main, Path.Combine("extra-photos", "broken.png")), new byte[] { 137, 80, 78, 71, 1, 2, 3 });
        File.WriteAllBytes(Child(main, Path.Combine("files.1", "photo.heic")), Encoding.ASCII.GetBytes("unsupported photo candidate"));
        File.WriteAllText(Child(main, Path.Combine("files.1", "random.jpg")), "False JPEG signature candidate.");
        File.WriteAllBytes(Child(main, Path.Combine("tests", "synthetic.jpg")), jpeg);
        File.WriteAllBytes(Child(main, Path.Combine("filesystem", "report.jpg")), jpeg);
        File.WriteAllBytes(Child(main, Path.Combine("ntfs", "partition-0", "report.jpg")), jpeg);
        File.WriteAllBytes(Child(main, Path.Combine("files.1", "unsafe.exe")), jpeg);
        File.WriteAllText(Child(main, Path.Combine("files.1", "report.xml")), "report");
        Test("Builds offline HTML and machine-readable catalogs from every actual output root", delegate {
            int notifications = 0;
            string gallery = PhotoCatalog.Build(main, CancellationToken.None, delegate(string message) { notifications++; });
            Assert(gallery == Path.Combine(main, "Фото.html") && File.Exists(gallery), "Missing gallery");
            Assert(File.Exists(Path.Combine(main, "photo-catalog.json")) && File.Exists(Path.Combine(main, "photo-catalog.csv")), "Missing catalogs");
            Assert(notifications >= 2, "Missing progress");
            Assert(Items(main).Count == 6, "Wrong unique candidate count or reports/tests/executable included");
        });
        Test("Byte-identical duplicate keeps filesystem filename and preserves all originals", delegate {
            var duplicate = Named(Items(main), named);
            Assert(Convert.ToInt32(duplicate["Copies"]) == 2, "Duplicate not grouped");
            Assert(((string)duplicate["Path"]).StartsWith("filesystem/files/"), "Filesystem name not preferred");
            Assert(File.ReadAllBytes(original).SequenceEqual(ExifJpeg(jpeg)), "Original changed");
            Assert(File.ReadAllBytes(Path.Combine(main, "files.1", "f00001.jpg")).SequenceEqual(File.ReadAllBytes(original)), "Duplicate removed/changed");
        });
        Test("Valid JPEG/PNG decode and thumbnails are small with known dimensions", delegate {
            var catalog = Items(main);
            foreach (var item in new[] { Named(catalog, named), Named(catalog, "photo.png") })
            {
                Assert((string)item["Status"] == "decoded", "Complete image not decoded");
                Assert(Convert.ToInt32(item["Width"]) == 48 && Convert.ToInt32(item["Height"]) == 32, "Wrong dimensions");
                string thumbnail = Path.Combine(main, ((string)item["Thumbnail"]).Replace('/', Path.DirectorySeparatorChar));
                using (var decoded = Image.FromFile(thumbnail)) Assert(decoded.Width <= 360 && decoded.Height <= 260, "Oversize thumbnail");
                Assert(new FileInfo(thumbnail).Length < 100000, "Thumbnail unexpectedly large");
            }
        });
        Test("DateTimeOriginal is read from actual EXIF, not output modification time", delegate {
            Assert((string)Named(Items(main), named)["Captured"] == "2001-07-14 13:25:09", "EXIF date missing/wrong");
            Assert((string)Named(Items(main), "photo.png")["Captured"] == "", "Invented date from mtime");
        });
        Test("JPEG without EOI is never reported as normally decoded", delegate {
            string state = (string)Named(Items(main), "truncated.jpg")["Status"];
            Assert(state == "partial" || state == "unreadable", "Truncated image misclassified");
            Console.WriteLine("Truncated JPEG decoder status: " + state);
        });
        Test("False headers rejected while unsupported HEIC remains explicitly unverified", delegate {
            var catalog = Items(main);
            Assert((string)Named(catalog, "broken.png")["Status"] == "unreadable", "False PNG accepted");
            Assert((string)Named(catalog, "random.jpg")["Status"] == "unreadable", "False JPEG accepted");
            var heic = Named(catalog, "photo.heic");
            Assert((string)heic["Status"] == "viewer" && (string)heic["Thumbnail"] == "", "Unsupported HEIC falsely decoded");
        });
        Test("Unicode links encoded, HTML data escaped, no network dependency, DOM bounded to 100 cards", delegate {
            string html = File.ReadAllText(Path.Combine(main, "Фото.html"));
            var item = Named(Items(main), named);
            Assert(((string)item["Url"]).Contains("%26") && ((string)item["Url"]).Contains("%27") && ((string)item["Url"]).Contains("%D0"), "Unsafe/unencoded local URL");
            Assert(html.Contains("\\u0026") && !html.Contains("src='http") && !html.Contains("src=\"http"), "HTML network/raw data problem");
            Assert(html.Contains("pageSize=100") && html.Contains(".slice(page*pageSize,(page+1)*pageSize)"), "Cards not bounded");
            Assert(html.Contains(".textContent=text") && html.Contains("connect-src 'none'"), "DOM/CSP protections missing");
            MethodInfo generator = typeof(PhotoCatalog).GetMethod("Html", BindingFlags.Static | BindingFlags.NonPublic);
            string injected = (string)generator.Invoke(null, new object[] { "[{\"Name\":\"</script><script>alert(1)</script>\"}]", 1, 1 });
            Assert(!injected.Contains("</script><script>alert(1)") && injected.Contains("\\u003c/script\\u003e"), "Script injection not escaped");
        });
        Test("Oversize pixel header and oversize file skipped before pixel decode", delegate {
            string run = NewRun("limits");
            byte[] bomb = new byte[54]; bomb[0] = 66; bomb[1] = 77; Array.Copy(BitConverter.GetBytes((uint)40), 0, bomb, 14, 4); Array.Copy(BitConverter.GetBytes(100000), 0, bomb, 18, 4); Array.Copy(BitConverter.GetBytes(100000), 0, bomb, 22, 4);
            File.WriteAllBytes(Child(run, Path.Combine("extra-photos", "bomb.bmp")), bomb);
            using (var stream = new FileStream(Child(run, Path.Combine("extra-photos", "large.jpg")), FileMode.CreateNew)) stream.SetLength(PhotoCatalog.MaximumFileBytes + 1);
            PhotoCatalog.Build(run, CancellationToken.None, null);
            Assert(Items(run).All(i => (string)i["Status"] == "limited" && (string)i["Thumbnail"] == ""), "Limits not enforced");
        });
        Test("PNG missing IEND or with a corrupted CRC never classified as complete", delegate {
            string run = NewRun("png-damage");
            File.WriteAllBytes(Child(run, Path.Combine("extra-photos", "no-iend.png")), png.Take(png.Length - 12).ToArray());
            byte[] badCrc = (byte[])png.Clone(); badCrc[badCrc.Length - 1] ^= 32;
            File.WriteAllBytes(Child(run, Path.Combine("extra-photos", "bad-crc.png")), badCrc);
            PhotoCatalog.Build(run, CancellationToken.None, null);
            foreach (var item in Items(run)) Assert((string)item["Status"] == "partial" || (string)item["Status"] == "unreadable", "Bad PNG classified complete");
        });
        Test("Pre-cancelled build writes nothing", delegate {
            string run = NewRun("cancelled"); File.WriteAllBytes(Child(run, Path.Combine("extra-photos", "photo.jpg")), jpeg);
            var cancellation = new CancellationTokenSource(); cancellation.Cancel(); bool thrown = false;
            try { PhotoCatalog.Build(run, cancellation.Token, null); } catch (OperationCanceledException) { thrown = true; }
            Assert(thrown && !File.Exists(Path.Combine(run, "Фото.html")) && !Directory.Exists(Path.Combine(run, "photo-thumbnails")), "Cancellation writes outputs");
        });
        Test("Empty catalog and repeated builds complete without phantom files", delegate {
            string run = NewRun("empty"); PhotoCatalog.Build(run, CancellationToken.None, null); Assert(Items(run).Count == 0, "Empty run not empty");
            PhotoCatalog.Build(main, CancellationToken.None, null); Assert(Items(main).Count == 6, "Repeat build ingested catalog/thumbnails");
        });
        Test("Filesystem reconstruction uncertainty and partial marker survive decoder success without leaking through hash cache", delegate {
            string run = NewRun("filesystem-hints");
            File.WriteAllBytes(Child(run, Path.Combine("filesystem", "files", "contiguous-guess", "_PARTIAL_Grandma.jpg")), jpeg);
            File.WriteAllBytes(Child(run, Path.Combine("extra-photos", "complete.jpg")), jpeg);
            File.WriteAllBytes(Child(run, Path.Combine("filesystem", "files", "retained-fat-uncertain", "Retained.png")), png);
            PhotoCatalog.Build(run, CancellationToken.None, null);
            var catalog = Items(run);
            Assert((string)Named(catalog, "complete.jpg")["Status"] == "decoded", "Filesystem uncertainty leaked into byte-identical complete source");
            Assert(((string)Named(catalog, "Retained.png")["Detail"]).Contains("предположительно"), "Retained FAT uncertainty hidden");
            string csv = File.ReadAllText(Path.Combine(run, "photo-catalog.csv"));
            Assert(csv.Contains("_PARTIAL_Grandma.jpg\";\"partial\"") && csv.Contains("неполном восстановлении"), "Partial filename falsely treated as fully decoded");
            Assert(csv.Contains("Порядок фрагментов восстановлен предположительно"), "Filesystem guess hidden");
        });
        Console.WriteLine("RESULT: " + passed + " passed, " + failed + " failed");
        return failed == 0 ? 0 : 1;
    }
}
