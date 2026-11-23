using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using UsbRecovery;

public static class BitcoinTraceScanTests
{
    const string Legacy = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const string P2sh = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    const string Segwit = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
    const string Taproot = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    static int checks;
    static void Check(bool ok, string message)
    {
        if (!ok) throw new Exception(message);
        checks++;
    }
    static BitcoinTraceScan Scan(byte[] bytes)
    {
        using (var input = new MemoryStream(bytes, false))
            return BitcoinTraceScan.Read(input, CancellationToken.None, null);
    }

    [STAThread]
    public static void Main(string[] args)
    {
        foreach (string address in new[] { Legacy, P2sh, Segwit, Taproot, "BC1SW50QGDZ25J" })
        {
            foreach (var encoding in new[] { Encoding.ASCII, Encoding.Unicode })
            {
                byte[] text = encoding.GetBytes(address);
                // A wiped header and surviving text at an odd offset across two read blocks.
                int offset = BitcoinTraceScan.Chunk - 9;
                byte[] image = new byte[offset + text.Length];
                text.CopyTo(image, offset);
                var result = Scan(image);
                Check(result.Matches.Count == 1 && result.Matches[0].Offset == offset &&
                    result.Matches[0].Text == address && !result.Matches[0].IsWalletName, "boundary " + address);
            }
        }
        // Invalid BIP350 vectors, mixed case, embedded substrings, invalid Base58 checksum.
        foreach (string bad in new[] { "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "bc1pw5dgrnzv", "BC1QR508D6QEJXTDG4Y5RZARVARYV98GJ9P",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            "b" + Segwit.Substring(1), Legacy.Substring(0, Legacy.Length-1) + "b",
            "0" + Legacy, Legacy + "X", "mywallet.dat", "xprv" + new string('A', 100) })
            foreach (var encoding in new[] { Encoding.ASCII, Encoding.Unicode })
                Check(Scan(encoding.GetBytes(bad)).Matches.Count == 0, "false positive");

        var names = Scan(Encoding.Unicode.GetBytes("WALLET.DAT " + Legacy + " " + Legacy));
        Check(names.Matches.Count == 3 && names.Matches[0].IsWalletName, "filename is a separate type");
        Check(names.Matches[1].Offset != names.Matches[2].Offset, "locations preserved");
        Check(Scan(new byte[BitcoinTraceScan.Chunk + 10]).Matches.Count == 0, "zeroed image");
        Check(Scan(new byte[0]).Matches.Count == 0, "empty file");
        string many = String.Concat(Enumerable.Repeat(Legacy + " ", BitcoinTraceScan.Limit));
        Check(!Scan(Encoding.ASCII.GetBytes(many)).Limited, "exactly at limit");
        var limited = Scan(Encoding.ASCII.GetBytes(many + Legacy));
        Check(limited.Limited && limited.Matches.Count == BitcoinTraceScan.Limit, "reported cap");

        byte[] original = Encoding.ASCII.GetBytes(Legacy);
        string path = Path.Combine(args[0], ".build", "public-address-" + Guid.NewGuid().ToString("N") + ".img");
        try
        {
            File.WriteAllBytes(path, original);
            Check(BitcoinTraceScan.ReadFile(path, CancellationToken.None, null).Matches.Count == 1, "read-only file scan");
            Check(File.ReadAllBytes(path).SequenceEqual(original), "source unchanged");
            try { BitcoinTraceScan.ReadFile(path, new CancellationToken(true), null); throw new Exception("ignored cancellation"); }
            catch (OperationCanceledException) { checks++; }
        }
        finally { File.Delete(path); }
        using (var form = new RecoveryForm(false))
            Check(form.Controls.Find("analyze-data", true).OfType<Button>().Single().Enabled, "analysis accessible without a device");
        Console.WriteLine("PASS Bitcoin public trace scan: " + checks + " checks");
    }
}
