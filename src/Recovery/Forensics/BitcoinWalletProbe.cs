using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace UsbRecovery
{
    internal sealed class BitcoinWalletFinding
    {
        public readonly long Offset;
        public readonly string Format, Evidence;
        public BitcoinWalletFinding(long offset, string format, string evidence)
        {
            Offset = offset; Format = format; Evidence = evidence;
        }
    }

    // File-format recognition only. Read public database structure and skip record values.
    // All offsets are relative to the file/image the operator explicitly selected.
    internal sealed class BitcoinWalletProbe
    {
        const int MaximumFindings = 256;
        const int MaximumProbes = 8192;
        readonly Stream input;
        readonly CancellationToken cancel;
        readonly List<BitcoinWalletFinding> findings;
        int probes;
        long remaining = 64L * 1024 * 1024;
        internal bool Limited { get; private set; }

        static readonly Regex Headers = new Regex(
            @"\x62\x31\x05\x00|\x00\x05\x31\x62|SQLite format 3\x00|\x0a\x16org\.bitcoin\.production",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
        static readonly byte[] MainName = Encoding.ASCII.GetBytes("main");
        static readonly byte[][] WalletMetadata = Array.ConvertAll(
            new[] { "bestblock", "bestblock_nomerkle", "orderposnext", "walletflags" }, Encoding.ASCII.GetBytes);

        public BitcoinWalletProbe(Stream input, CancellationToken cancel, List<BitcoinWalletFinding> findings)
        {
            this.input = input; this.cancel = cancel; this.findings = findings;
        }

        public void Inspect(string block, long blockStart, long first, long stop)
        {
            if (Limited) return;
            long saved = input.Position;
            try
            {
                foreach (Match match in Headers.Matches(block))
                {
                    long marker = blockStart + match.Index;
                    if (marker < first) continue;
                    if (marker >= stop) break;
                    cancel.ThrowIfCancellationRequested();
                    if (++probes > MaximumProbes) { Limited = true; break; }
                    BitcoinWalletFinding hit;
                    if (match.Length == 4)
                        hit = marker < 12 ? null : Berkeley(marker - 12, match.Value[0] == '\x62');
                    else if (match.Value[0] == 'S') hit = Sqlite(marker);
                    else hit = Bitcoinj(marker);
                    if (hit != null)
                    {
                        if (findings.Count == MaximumFindings) { Limited = true; break; }
                        findings.Add(hit);
                    }
                    if (Limited) break;
                }
            }
            finally { input.Position = saved; }
        }

        byte[] Bytes(long offset, int count)
        {
            cancel.ThrowIfCancellationRequested();
            if (offset < 0 || count < 0 || offset > input.Length - count) return null;
            if (count > remaining) { Limited = true; return null; }
            remaining -= count;
            var bytes = new byte[count];
            input.Position = offset;
            int read = 0;
            while (read < count)
            {
                int n = input.Read(bytes, read, count - read);
                if (n == 0) throw new EndOfStreamException();
                read += n;
            }
            return bytes;
        }

        static uint U32(byte[] data, int i, bool little)
        {
            return little ? (uint)(data[i] | data[i+1] << 8 | data[i+2] << 16 | data[i+3] << 24)
                : (uint)(data[i] << 24 | data[i+1] << 16 | data[i+2] << 8 | data[i+3]);
        }

        static int U16(byte[] data, int i, bool little)
        {
            return little ? data[i] | data[i+1] << 8 : data[i] << 8 | data[i+1];
        }

        static bool PageSize(uint size)
        {
            return size >= 512 && size <= 65536 && (size & (size - 1)) == 0;
        }

        static bool MetadataPage(byte[] data, uint number, bool little)
        {
            return data != null && U32(data, 8, little) == number &&
                U32(data, 12, little) == 0x53162 && U32(data, 16, little) == 9 &&
                data[24] == 0 && data[25] == 9 && PageSize(U32(data, 20, little));
        }

        // Offsets in a BDB leaf's index refer to length/type/payload records.
        static int Item(byte[] page, int slot, int entries, int length, bool little)
        {
            int endIndex = 26 + 2 * entries;
            if (endIndex > page.Length || slot >= entries) return -1;
            int offset = U16(page, 26 + slot * 2, little);
            if (offset < endIndex || offset > page.Length - 3 - length ||
                page[offset + 2] != 1 || U16(page, offset, little) != length) return -1;
            return offset + 3;
        }

        static bool EqualsAt(byte[] data, int offset, byte[] value)
        {
            if (offset < 0 || offset > data.Length - value.Length) return false;
            for (int i = 0; i < value.Length; i++) if (data[offset+i] != value[i]) return false;
            return true;
        }

        BitcoinWalletFinding Berkeley(long start, bool little)
        {
            byte[] outer = Bytes(start, 92);
            if (!MetadataPage(outer, 0, little) || U32(outer, 48, little) != 0x20) return null;
            int size = (int)U32(outer, 20, little);
            uint last = U32(outer, 32, little), root = U32(outer, 88, little);
            if (last < 3 || root == 0 || root > last || root >= (input.Length - start) / size) return null;
            byte[] directory = Bytes(start + (long)root * size, size);
            if (directory == null || U32(directory, 8, little) != root || directory[25] != 5 ||
                directory[24] != 1 || U16(directory, 20, little) != 2) return null;
            int name = Item(directory, 0, 2, 4, little), pointer = Item(directory, 1, 2, 4, little);
            if (!EqualsAt(directory, name, MainName) || pointer < 0 || pointer == name) return null;
            // BDB stores the subdatabase page number in network byte order on both architectures.
            uint sub = U32(directory, pointer, false);
            if (sub == 0 || sub == root || sub > last || sub >= (input.Length - start) / size) return null;
            byte[] inner = Bytes(start + (long)sub * size, 92);
            if (!MetadataPage(inner, sub, little) || U32(inner, 20, little) != size) return null;
            uint page = U32(inner, 88, little);
            if (!Array.Exists(WalletMetadata, field => HasField(start, size, page, last, little, field))) return null;
            return new BitcoinWalletFinding(start, "Bitcoin Core · Berkeley DB",
                "Таблица main и служебная запись кошелька в связанной странице B-tree");
        }

        // BDB separator keys may be shortened to their distinguishing prefix.
        static int CompareField(byte[] data, int offset, int length, byte[] field)
        {
            int targetLength = field.Length + 1;
            for (int i = 0; i < Math.Min(length, targetLength); i++)
            {
                int target = i == 0 ? field.Length : field[i - 1];
                int diff = data[offset + i] - target;
                if (diff != 0) return diff;
            }
            return length - targetLength;
        }

        bool HasField(long start, int size, uint page, uint last, bool little, byte[] field)
        {
            var seen = new HashSet<uint>();
            while (page > 0 && page <= last && page < (input.Length - start) / size &&
                   seen.Count < 16 && seen.Add(page))
            {
                byte[] data = Bytes(start + (long)page * size, size);
                if (data == null || U32(data, 8, little) != page) break;
                int entries = U16(data, 20, little);
                if (entries == 0 || 26 + entries * 2 > size) break;
                if (data[25] == 3 && data[24] > 1)
                {
                    uint child = 0;
                    for (int i = 0; i < entries; i++)
                    {
                        int at = U16(data, 26 + i * 2, little);
                        if (at < 26 + entries * 2 || at > size - 12 || data[at + 2] != 1) return false;
                        int length = U16(data, at, little);
                        if (length > size - at - 12) return false;
                        if (i > 0 && CompareField(data, at + 12, length, field) > 0) break;
                        child = U32(data, at + 4, little);
                    }
                    page = child;
                    continue;
                }
                if (data[25] != 5 || data[24] != 1 || (entries & 1) != 0) break;
                for (int i = 0; i < entries; i += 2)
                {
                    int at = Item(data, i, entries, field.Length + 1, little);
                    if (at >= 0 && data[at] == field.Length && EqualsAt(data, at + 1, field)) return true;
                }
                break;
            }
            return false;
        }

        BitcoinWalletFinding Sqlite(long start)
        {
            byte[] header = Bytes(start, 101);
            if (header == null || U32(header, 68, false) != 0xf9beb4d9 ||
                (header[18] != 1 && header[18] != 2) || (header[19] != 1 && header[19] != 2) ||
                header[21] != 64 || header[22] != 32 || header[23] != 32 || header[100] != 13) return null;
            uint size = (uint)U16(header, 16, false);
            if (size == 1) size = 65536;
            if (!PageSize(size)) return null;
            byte[] page = Bytes(start, (int)size);
            if (page == null) return null;
            int cells = U16(page, 103, false), usable = page.Length - page[20];
            int indexEnd = 108 + 2 * cells;
            if (indexEnd > usable || U32(page, 56, false) != 1) return null;
            for (int slot = 0; slot < cells; slot++)
            {
                int cell = U16(page, 108 + 2 * slot, false);
                if (cell >= indexEnd && IsWalletSchemaCell(page, cell, usable))
                    return new BitcoinWalletFinding(start, "Bitcoin Core · SQLite",
                        "Идентификатор основной сети и действующая запись таблицы main в sqlite_schema");
            }
            return null;
        }

        // SQLite varints are big endian. A schema cell on this page fits in 16 bits.
        static int SchemaNumber(byte[] page, ref int at, int end)
        {
            int value = 0;
            for (int i = 0; i < 3 && at < end; i++)
            {
                int next = page[at++];
                value = (value << 7) | (next & 127);
                if (next < 128) return value;
            }
            return -1;
        }

        static bool IsWalletSchemaCell(byte[] page, int cell, int end)
        {
            int pos = cell;
            int payload = SchemaNumber(page, ref pos, end);
            if (payload <= 0 || SchemaNumber(page, ref pos, end) <= 0 || payload > end - pos) return false;
            int recordStart = pos, recordEnd = pos + payload;
            int header = SchemaNumber(page, ref pos, recordEnd);
            if (header <= 0 || header > payload) return false;
            int headerEnd = recordStart + header;
            // sqlite_schema record: type, name, tbl_name, rootpage, sql.
            if (SchemaNumber(page, ref pos, headerEnd) != 23 || SchemaNumber(page, ref pos, headerEnd) != 21 ||
                SchemaNumber(page, ref pos, headerEnd) != 21) return false;
            int rootType = SchemaNumber(page, ref pos, headerEnd), sqlType = SchemaNumber(page, ref pos, headerEnd);
            if (pos != headerEnd || rootType < 1 || rootType > 4 || sqlType < 13 || (sqlType & 1) == 0) return false;
            int length = (sqlType - 13) / 2;
            if (recordEnd - pos != 13 + rootType + length ||
                Encoding.ASCII.GetString(page, pos, 13) != "tablemainmain") return false;
            pos += 13;
            uint tablePage = 0;
            for (int i = 0; i < rootType; i++) tablePage = (tablePage << 8) | page[pos++];
            if (tablePage < 2 || tablePage > U32(page, 28, false)) return false;
            string sql = Encoding.ASCII.GetString(page, pos, length);
            return Regex.IsMatch(sql, @"^CREATE\s+TABLE\s+[""']?main[""']?\s*\(\s*key\s+BLOB\s+PRIMARY\s+KEY[^)]*,\s*value\s+BLOB\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        BitcoinWalletFinding Bitcoinj(long start)
        {
            // The bitcoinj protobuf starts with its network identifier. Look for
            // additional public chain/format fields. Skip length-delimited data opaquely.
            long pos = start + 24;
            bool version = false, height = false;
            for (int fields = 0; fields < 48 && pos < input.Length && pos - start < 8 * 1024 * 1024; fields++)
            {
                byte[] prefix = Bytes(pos, (int)Math.Min(20, input.Length - pos));
                if (prefix == null) break;
                int used = 0;
                uint tag, value;
                if (!Varint(prefix, ref used, out tag) || tag == 0 || !Varint(prefix, ref used, out value)) break;
                int wire = (int)(tag & 7), field = (int)(tag >> 3);
                if (field == 0 || field > 32 || (wire != 0 && wire != 2)) break;
                pos += used;
                if (wire == 2)
                {
                    if (value > input.Length - pos) break;
                    if (field == 2 && value == 32) return BitcoinjFinding(start);
                    pos += value;
                }
                else
                {
                    if (field == 7 && value <= 100) version = true;
                    if (field == 12 && value <= Int32.MaxValue) height = true;
                    if (version && height) return BitcoinjFinding(start);
                }
            }
            return null;
        }

        static bool Varint(byte[] data, ref int at, out uint value)
        {
            value = 0;
            for (int shift = 0; shift < 32 && at < data.Length; shift += 7)
            {
                byte part = data[at++];
                if (shift == 28 && (part & 0xf0) != 0) return false;
                value |= (uint)(part & 127) << shift;
                if (part < 128) return true;
            }
            return false;
        }

        static BitcoinWalletFinding BitcoinjFinding(long offset)
        {
            return new BitcoinWalletFinding(offset, "bitcoinj · совместим с MultiBit Classic",
                "Поле основной сети и дополнительные поля формата protobuf");
        }
    }
}
