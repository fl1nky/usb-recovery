using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace UsbRecovery
{
    public sealed class DdrescueBlock
    {
        public long Offset { get; set; }
        public long Length { get; set; }
        public char Status { get; set; }

        public bool IsFinished { get { return Status == '+'; } }
        public bool IsBad { get { return Status == '-'; } }
        public bool IsNonTried { get { return Status == '?'; } }
        public bool IsNonTrimmed { get { return Status == '*'; } }
        public bool IsNonScraped { get { return Status == '/'; } }

        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture, "0x{0:X8} +0x{1:X8} [{2}]", Offset, Length, Status);
        }
    }

    public sealed class DdrescueMap
    {
        readonly List<DdrescueBlock> blocks;

        public List<DdrescueBlock> Blocks { get { return blocks; } }

        public long CurrentPos { get; set; }
        public char CurrentStatus { get; set; }
        public int CurrentPass { get; set; }

        public long TotalRescuedBytes { get; private set; }
        public long TotalBadBytes { get; private set; }
        public long TotalNonTriedBytes { get; private set; }
        public long TotalMapSpan { get; private set; }

        public DdrescueMap(IEnumerable<DdrescueBlock> inputBlocks)
        {
            blocks = inputBlocks != null ? inputBlocks.OrderBy(b => b.Offset).ToList() : new List<DdrescueBlock>();
            RecalculateStats();
        }

        void RecalculateStats()
        {
            long rescued = 0;
            long bad = 0;
            long nonTried = 0;
            long maxExtent = 0;

            foreach (var b in blocks)
            {
                if (b.IsFinished) rescued += b.Length;
                else if (b.IsBad) bad += b.Length;
                else nonTried += b.Length;

                long extent = b.Offset + b.Length;
                if (extent > maxExtent) maxExtent = extent;
            }

            TotalRescuedBytes = rescued;
            TotalBadBytes = bad;
            TotalNonTriedBytes = nonTried;
            TotalMapSpan = maxExtent;
        }

        public static DdrescueMap Parse(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return new DdrescueMap(new DdrescueBlock[0]);

            var parsedBlocks = new List<DdrescueBlock>();
            long currentPos = 0;
            char currentStatus = '?';
            int currentPass = 0;

            using (var reader = new StringReader(text))
            {
                string line;
                bool readingHeader = true;

                while ((line = reader.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                        continue;

                    string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 0) continue;

                    if (readingHeader && (parts.Length == 2 || parts.Length == 3))
                    {
                        long pos;
                        if (TryParseNumber(parts[0], out pos) && parts[1].Length == 1)
                        {
                            currentPos = pos;
                            currentStatus = parts[1][0];
                            int pass;
                            if (parts.Length > 2 && int.TryParse(parts[2], out pass))
                                currentPass = pass;

                            readingHeader = false;
                            continue;
                        }
                    }

                    if (parts.Length >= 3)
                    {
                        long offset;
                        long length;
                        if (TryParseNumber(parts[0], out offset) &&
                            TryParseNumber(parts[1], out length) &&
                            parts[2].Length > 0)
                        {
                            char status = parts[2][0];
                            parsedBlocks.Add(new DdrescueBlock
                            {
                                Offset = offset,
                                Length = length,
                                Status = status
                            });
                            readingHeader = false;
                        }
                    }
                }
            }

            var map = new DdrescueMap(parsedBlocks);
            map.CurrentPos = currentPos;
            map.CurrentStatus = currentStatus;
            map.CurrentPass = currentPass;
            return map;
        }

        public static DdrescueMap Load(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                throw new FileNotFoundException("ddrescue mapfile not found: " + filePath);

            string text = File.ReadAllText(filePath, Encoding.UTF8);
            return Parse(text);
        }

        public bool IsRangeRescued(long offset, long length)
        {
            if (length <= 0) return true;
            if (blocks.Count == 0) return true;

            long end = offset + length;
            int low = 0, high = blocks.Count - 1;
            while (low <= high)
            {
                int mid = (low + high) / 2;
                var b = blocks[mid];
                if (b.Offset + b.Length <= offset)
                {
                    low = mid + 1;
                }
                else if (b.Offset >= end)
                {
                    high = mid - 1;
                }
                else
                {
                    int idx = mid;
                    while (idx > 0 && blocks[idx - 1].Offset + blocks[idx - 1].Length > offset)
                        idx--;

                    long current = offset;
                    while (idx < blocks.Count && current < end)
                    {
                        var curBlock = blocks[idx];
                        if (curBlock.Offset > current)
                            return false;
                        if (!curBlock.IsFinished)
                            return false;

                        current = curBlock.Offset + curBlock.Length;
                        idx++;
                    }
                    return current >= end;
                }
            }

            return false;
        }

        public bool HasBadSectors(long offset, long length)
        {
            if (length <= 0 || blocks.Count == 0) return false;
            long end = offset + length;

            foreach (var b in blocks)
            {
                if (b.Offset >= end) break;
                if (b.Offset + b.Length > offset && b.IsBad)
                    return true;
            }
            return false;
        }

        static bool TryParseNumber(string s, out long result)
        {
            if (string.IsNullOrEmpty(s))
            {
                result = 0;
                return false;
            }

            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return long.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result);
            }
            return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out result);
        }
    }
}
