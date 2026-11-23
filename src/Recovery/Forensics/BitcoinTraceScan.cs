using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace UsbRecovery
{
    internal sealed class BitcoinTrace
    {
        public readonly long Offset;
        public readonly string Text;
        public readonly bool IsWalletName;
        public BitcoinTrace(long offset, string text, bool isWalletName)
        {
            Offset = offset; Text = text; IsWalletName = isWalletName;
        }
    }

    internal sealed class BitcoinTraceScan
    {
        public readonly List<BitcoinTrace> Matches = new List<BitcoinTrace>();
        public bool Limited { get; private set; }

        internal const int Chunk = 1024 * 1024;
        internal const int Limit = 1000;
        const int MaxTokenBytes = 90 * 2;
        const int BoundaryBytes = 2;
        const int Overlap = MaxTokenBytes + 2 * BoundaryBytes;
        static readonly Regex Candidates = new Regex(
            @"(?<![A-Za-z0-9])(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|(?:bc1|BC1)[A-Za-z0-9]{8,87}|(?i:wallet\.dat))(?![A-Za-z0-9])" +
            @"|(?<![A-Za-z0-9]\x00)(?<wide>[13]\x00(?:[1-9A-HJ-NP-Za-km-z]\x00){25,34}|(?:b\x00c\x00|B\x00C\x00)1\x00(?:[A-Za-z0-9]\x00){8,87}|(?i:w\x00a\x00l\x00l\x00e\x00t\x00\.\x00d\x00a\x00t\x00))(?![A-Za-z0-9]\x00)",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);

        public static BitcoinTraceScan ReadFile(string path, CancellationToken token, IProgress<int> progress)
        {
            string full = Path.GetFullPath(path);
            if (full.StartsWith(@"\\", StringComparison.Ordinal) || full.IndexOf(':', 2) >= 0 ||
                new DriveInfo(Path.GetPathRoot(full)).DriveType == DriveType.Network)
                throw new IOException("Выбери обычный файл на локальном диске.");
            for (FileSystemInfo item = new FileInfo(full); item != null; item = Directory.GetParent(item.FullName))
                if ((item.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                    throw new IOException("Выбери локальный файл без перенаправлений.");
            using (var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan))
                return Read(stream, token, progress);
        }

        internal static BitcoinTraceScan Read(Stream stream, CancellationToken token, IProgress<int> progress)
        {
            var result = new BitcoinTraceScan();
            byte[] buffer = new byte[Chunk + Overlap];
            int carry = 0, lastPercent = -1;
            long length = stream.Length, read = 0, nextStart = 0;
            using (var hash = SHA256.Create())
            {
                do
                {
                    token.ThrowIfCancellationRequested();
                    int wanted = (int)Math.Min(Chunk, length - read);
                    int got = 0;
                    while (got < wanted)
                    {
                        int n = stream.Read(buffer, carry + got, wanted - got);
                        if (n == 0) throw new EndOfStreamException();
                        got += n;
                    }
                    long blockStart = read - carry;
                    read += got;
                    int count = carry + got;
                    long stop = read == length ? length : read - MaxTokenBytes - BoundaryBytes;
                    string block = Encoding.ASCII.GetString(buffer, 0, count);
                    for (Match match = Candidates.Match(block); match.Success; match = match.NextMatch())
                    {
                        token.ThrowIfCancellationRequested();
                        long offset = blockStart + match.Index;
                        if (offset < nextStart) continue;
                        if (offset >= stop) break;
                        string text = match.Groups["wide"].Success ? match.Value.Replace("\0", "") : match.Value;
                        bool name = text.Equals("wallet.dat", StringComparison.OrdinalIgnoreCase);
                        if (!name && !BitcoinPublicAddress.IsValid(text, hash)) continue;
                        if (result.Matches.Count == Limit) { result.Limited = true; return result; }
                        result.Matches.Add(new BitcoinTrace(offset, text, name));
                    }
                    nextStart = stop;
                    carry = Math.Min(count, Overlap);
                    Buffer.BlockCopy(buffer, count - carry, buffer, 0, carry);
                    int percent = length == 0 ? 100 : (int)(100.0 * read / length);
                    if (progress != null && percent != lastPercent) progress.Report(percent);
                    lastPercent = percent;
                } while (read < length);
            }
            return result;
        }
    }
}
