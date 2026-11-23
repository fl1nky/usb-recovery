using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using UsbRecovery;

// Independent directory records exercise evidence handling after the journal
// parser. These are structural controls, not native JBD2 transaction fixtures.
public static class Ext4DirectoryEvidenceTests
{
    sealed class Block
    {
        public uint Directory, Sequence = 7;
        public ulong Target = 11, Journal = 23;
        public readonly List<Tuple<uint, string>> Names = new List<Tuple<uint, string>>();
    }
    static int checks, failures;
    static readonly Type Engine = typeof(Ext4Recovery);
    static Type Private(string name) { return Engine.GetNestedType(name, BindingFlags.NonPublic); }
    static void Set(object value, string field, object data) { value.GetType().GetField(field).SetValue(value, data); }
    static object Get(object value, string field) { var f = value.GetType().GetField(field); return f == null ? null : f.GetValue(value); }
    static void Check(bool value, string label)
    {
        checks++; if (!value) { failures++; Console.WriteLine("FAIL " + label); }
    }
    static void Put16(byte[] data, int at, int value) { Buffer.BlockCopy(BitConverter.GetBytes((ushort)value), 0, data, at, 2); }
    static void Put32(byte[] data, int at, uint value) { Buffer.BlockCopy(BitConverter.GetBytes(value), 0, data, at, 4); }
    static byte[] Bytes(Block block)
    {
        var data = new byte[1024]; int at = 0;
        var names = new List<Tuple<uint, string>> { Tuple.Create(block.Directory, "."), Tuple.Create(2U, "..") };
        names.AddRange(block.Names);
        for (int index = 0; index < names.Count; index++)
        {
            byte[] name = Encoding.UTF8.GetBytes(names[index].Item2);
            int length = index == names.Count - 1 ? data.Length - 12 - at : (8 + name.Length + 3) & ~3;
            Put32(data, at, names[index].Item1); Put16(data, at + 4, length);
            data[at + 6] = (byte)name.Length; data[at + 7] = 1;
            Buffer.BlockCopy(name, 0, data, at + 8, name.Length); at += length;
        }
        Put16(data, data.Length - 8, 12); data[data.Length - 5] = 0xde;
        // A recognizable tail with a deliberately invalid checksum. A tail
        // shape alone cannot establish directory inode/generation or CRC.
        Put32(data, data.Length - 4, 0xdeadbeef);
        return data;
    }
    static Dictionary<uint, List<Ext4Recovery.NameLink>> Names(IEnumerable<Block> blocks,
        out object context, int maximum = 100, int used = 0, bool cancel = false, bool currentDirectory = false)
    {
        context = Activator.CreateInstance(Private("Context"), true);
        Set(context, "Report", new Ext4Recovery.Report());
        Set(context, "Limits", new Ext4Recovery.Limits { MaximumNames = maximum });
        Set(context, "Cancel", new CancellationToken(cancel)); Set(context, "NameCount", used);
        var volume = Activator.CreateInstance(Private("Volume"), true);
        Set(volume, "Offset", 4096L); Set(volume, "BlockBytes", 1024);
        Set(volume, "Inodes", 128U); Set(volume, "Incompat", 2U); Set(volume, "Csum", true);
        var directories = (IDictionary)Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(typeof(uint), Private("Inode")));
        if (currentDirectory)
        {
            var inode = Activator.CreateInstance(Private("Inode"), true);
            Set(inode, "Number", 12U); Set(inode, "Flags", 4U);
            directories.Add(12U, inode); // unsupported mapping; no current parent reference
        }
        MethodInfo method = Engine.GetMethod("DirectoryNames", BindingFlags.NonPublic | BindingFlags.Static);
        Type listType = method.GetParameters()[3].ParameterType;
        Type blockType = listType.GetGenericArguments()[0]; var list = (IList)Activator.CreateInstance(listType);
        foreach (var block in blocks)
        {
            object row;
            if (blockType.IsGenericType) row = Activator.CreateInstance(blockType, block.Target, Bytes(block));
            else
            {
                row = Activator.CreateInstance(blockType, true);
                Set(row, "TargetDiskBlock", block.Target); Set(row, "JournalBlock", block.Journal);
                Set(row, "TransactionSequence", block.Sequence); Set(row, "Bytes", Bytes(block));
            }
            list.Add(row);
        }
        try { return (Dictionary<uint, List<Ext4Recovery.NameLink>>)method.Invoke(null, new[] { context, volume, directories, list }); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }
    static Block Example(uint directory, uint target, string name)
    {
        var block = new Block { Directory = directory }; block.Names.Add(Tuple.Create(target, name)); return block;
    }
    public static int Main()
    {
        try
        {
            object context;
            var one = Example(2, 42, "recipe.jpg"); var result = Names(new[] { one }, out context);
            var link = result[42].Single();
            Check(link.Name == "recipe.jpg" && link.Status == "historical_journal_directory_reference", "historical candidate remains separately labelled");
            Check(!link.DirectoryChecksumVerified, "tail shape does not certify an unchecked directory checksum");
            Check(link.DirectoryPath == null, "unbound historical directory does not inherit the current root path");
            Check(link.EntryOffset == 4096 + 23 * 1024 + 24, "historical entry offset points into journal bytes, not the destination block");
            Check(Convert.ToString(Get(link, "JournalBlockOffset")) == (4096 + 23 * 1024).ToString() &&
                Convert.ToString(Get(link, "TargetBlockOffset")) == (4096 + 11 * 1024).ToString() &&
                Convert.ToString(Get(link, "JournalTransactionSequence")) == "7", "journal and destination provenance remain distinct");

            var many = Example(2, 42, "a.jpg"); many.Names.Add(Tuple.Create(43U, "b.jpg")); many.Names.Add(Tuple.Create(44U, "c.jpg"));
            result = Names(new[] { many }, out context, 2, 1);
            Check(result.Values.Sum(x => x.Count) == 1 && (int)Get(context, "NameCount") == 2, "historical references share the cumulative name budget");
            Check(((Ext4Recovery.Report)Get(context, "Report")).Limited, "historical name truncation is explicit");

            var parent = Example(2, 12, "old-parent"); var child = Example(12, 42, "recipe.jpg"); child.Journal = 24;
            result = Names(new[] { parent, child }, out context, currentDirectory: true);
            Check(result[42].Single().DirectoryPath == null, "history cannot manufacture a current directory ancestry");
            var later = Example(2, 42, "recipe.jpg"); later.Journal = 25; later.Sequence = 8;
            result = Names(new[] { one, one, later }, out context);
            Check(result[42].Count == 2 && (int)Get(context, "NameCount") == 2, "only exact historical records merge; different transactions retain provenance");

            bool cancelled = false;
            try { Names(new[] { one }, out context, cancel: true); } catch (OperationCanceledException) { cancelled = true; }
            Check(cancelled, "historical directory parsing honors cancellation");
            Console.WriteLine((failures == 0 ? "PASS" : "FAIL") + " Ext4DirectoryEvidence: " + checks + " checks, " + failures + " failures; structural directory controls only, no native/device claim");
            return failures == 0 ? 0 : 1;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 2; }
    }
}
