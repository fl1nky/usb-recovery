// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class BitcoinWalletContainerTests
{
    static int checks;

    static void Check(bool ok, string label)
    {
        if (!ok) throw new Exception(label);
        checks++;
    }

    static byte[] Fixture(string repo, string name, string expected)
    {
        string file = Path.Combine(repo, "tests", "fixtures", "bitcoin-public-metadata", name + ".gz.b64");
        using (var input = new MemoryStream(Convert.FromBase64String(File.ReadAllText(file))))
        using (var gzip = new GZipStream(input, CompressionMode.Decompress))
        using (var output = new MemoryStream())
        using (var hash = SHA256.Create())
        {
            gzip.CopyTo(output);
            byte[] data = output.ToArray();
            Check(BitConverter.ToString(hash.ComputeHash(data)).Replace("-", "").ToLowerInvariant() == expected, name);
            return data;
        }
    }

    static BitcoinTraceScan Scan(byte[] bytes)
    {
        using (var image = new MemoryStream(bytes, false))
            return BitcoinTraceScan.Read(image, CancellationToken.None, null);
    }

    static void Found(byte[] part, int offset, string format)
    {
        var image = new byte[offset + part.Length];
        part.CopyTo(image, offset);
        var result = Scan(image);
        Check(result.Wallets.Count == 1 && result.Wallets[0].Offset == offset &&
            result.Wallets[0].Format.Contains(format) && !result.WalletSearchLimited, format + " at " + offset);
    }

    static void Absent(byte[] bytes, string label)
    {
        Check(Scan(bytes).Wallets.Count == 0, label);
    }

    public static void Main(string[] args)
    {
        byte[] bdb = Fixture(args[0], "core-bdb", "c52f8e02b363fa82b51f24233dd00e659f823f31d3b0054dcd3e39d290b86bdd");
        byte[] sqlite = Fixture(args[0], "core-schema", "1a6cc841ac4b44145f58fa56c80170520d78a8b683159384b929b8f4a1fe84bd");
        byte[] other = Fixture(args[0], "other-bdb", "f419cfaa02a634666bee3368c6b0d28b8c5a6e949eab5c9364033bc34ba0d89c");
        Found(bdb, BitcoinTraceScan.Chunk - 13, "Berkeley");
        Found(sqlite, BitcoinTraceScan.Chunk - 5, "SQLite");
        Check(Scan(bdb).Matches.Count == 0, "legacy container has no readable address");
        Absent(other, "generic database with the same BDB header and main table");
        Absent(bdb.Take(8192).ToArray(), "missing pointed-to BDB pages");
        byte[] wrongVersion = (byte[])bdb.Clone();
        wrongVersion[16] = 10;
        Absent(wrongVersion, "unknown B-tree format");
        byte[] wrongNetwork = (byte[])sqlite.Clone();
        wrongNetwork[68] ^= 1;
        Absent(wrongNetwork, "wrong SQLite application id");
        byte[] deletedSchema = (byte[])sqlite.Clone();
        deletedSchema[103] = deletedSchema[104] = 0;
        Absent(deletedSchema, "schema text survives only in unreferenced page space");
        byte[] wrongPointer = (byte[])sqlite.Clone();
        wrongPointer[108] = wrongPointer[109] = 255;
        Absent(wrongPointer, "invalid schema cell pointer");

        byte[] prefix = Encoding.ASCII.GetBytes("\n\u0016org.bitcoin.production");
        byte[] bitcoinj = prefix.Concat(new byte[] { 0x38, 1, 0x60, 45 }).ToArray();
        Found(bitcoinj, BitcoinTraceScan.Chunk - 3, "bitcoinj");
        Absent(prefix, "network marker alone");
        Absent(prefix.Concat(new byte[] { 0x12, 32, 1 }).ToArray(), "truncated block hash");

        const string json = "{\"wallet_type\":\"old\",\"seed_version\":4,\"accounts\":{}}";
        Found(Encoding.UTF8.GetBytes(json), 0, "Electrum");
        Found(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(" \n" + json)).ToArray(), 0, "Electrum");
        foreach (string value in new[] { json.Substring(0, json.Length - 1), json + "{}", "{\"nested\":" + json + "}",
            json.Replace("\"old\"", "true"), json.Replace("\"accounts\":{}", "\"accounts\":2") })
            Absent(Encoding.UTF8.GetBytes(value), "invalid or unrelated Electrum JSON");

        const string address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa ";
        byte[] many = Encoding.ASCII.GetBytes(String.Concat(Enumerable.Repeat(address, BitcoinTraceScan.Limit + 1)));
        var saturated = Scan(many.Concat(bdb).ToArray());
        Check(saturated.Limited && saturated.Wallets.Count == 1 && saturated.Wallets[0].Offset == many.Length,
            "wallet survives the text result limit");
        Absent(Encoding.ASCII.GetBytes("wallet.dat bestblock " + address), "public text is not a wallet container");
        Absent(new byte[BitcoinTraceScan.Chunk + 1024], "zero-filled sectors");
        Console.WriteLine("PASS BitcoinWalletContainerTests: " + checks + " checks");
    }
}
