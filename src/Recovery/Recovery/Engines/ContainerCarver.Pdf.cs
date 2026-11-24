// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace UsbRecovery
{
    public static partial class ContainerCarver
    {
        const int PdfTrailerWindow = 32768;
        static readonly Regex StartXref = new Regex(@"(?:^|[\r\n])[ \t]*startxref[ \t]*[\r\n]+[ \t]*(\d{1,19})[ \t\r\n]*\z", RegexOptions.CultureInvariant);
        static readonly Regex XrefTable = new Regex(@"\Axref[\t\r\n ]+[0-9]+[\t ]+[0-9]+[\t \r\n]", RegexOptions.CultureInvariant);
        static readonly Regex Subsection = new Regex(@"\A[0-9]{1,10}[ \t]+([0-9]{1,10})[ \t]*(?:\r\n|\r|\n)", RegexOptions.CultureInvariant);
        static readonly Regex XrefRow = new Regex(@"\A[0-9]{10} [0-9]{5} [nf][ \t]?(?:\r\n|\r|\n)", RegexOptions.CultureInvariant);
        static readonly Regex XrefObject = new Regex(@"\A[0-9]+[\t\r\n ]+[0-9]+[\t\r\n ]+obj\b", RegexOptions.CultureInvariant);
        static readonly Regex EndObject = new Regex(@"(?:\A|[\s>])endobj[ \t\r\n]*\z", RegexOptions.CultureInvariant);

        static bool PdfSpace(char c) { return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32; }
        static bool Delimiter(char c) { return PdfSpace(c) || "()<>[]{}/%".IndexOf(c) >= 0; }

        static int PdfTrivia(string s, int pos)
        {
            while (pos < s.Length)
            {
                if (PdfSpace(s[pos])) { pos++; continue; }
                if (s[pos] != '%') break;
                while (pos < s.Length && s[pos] != '\n' && s[pos] != '\r') pos++;
            }
            return pos;
        }

        static int TokenEnd(string text, int at)
        {
            while (at < text.Length && !Delimiter(text[at])) at++;
            return at;
        }

        static bool Natural(string text, int start, int end, out long number)
        {
            return Int64.TryParse(text.Substring(start, end - start), NumberStyles.None, CultureInfo.InvariantCulture, out number);
        }

        // Skip one complete PDF value. A name used as a value is never a trailer key.
        static int ValueEnd(string s, int start, int depth)
        {
            if (depth > 32 || start >= s.Length) return -1;
            int at = start + 1;
            char c = s[start];
            if (c == '/') return TokenEnd(s, at);
            if (c == '(')
            {
                int nested = 1;
                while (at < s.Length && nested > 0)
                {
                    c = s[at++];
                    if (c == '\\') { if (at < s.Length) at++; }
                    else if (c == '(') nested++;
                    else if (c == ')') nested--;
                }
                return nested == 0 ? at : -1;
            }
            bool dictionary = c == '<' && at < s.Length && s[at] == '<';
            if (c == '[' || dictionary)
            {
                if (dictionary) at++;
                while ((at = PdfTrivia(s, at)) < s.Length)
                {
                    if (dictionary && s[at] == '>' && at + 1 < s.Length && s[at + 1] == '>') return at + 2;
                    if (!dictionary && s[at] == ']') return at + 1;
                    at = ValueEnd(s, at, depth + 1);
                    if (at < 0) return -1;
                }
                return -1;
            }
            if (c == '<')
            {
                int close = s.IndexOf('>', at);
                return close < 0 ? -1 : close + 1;
            }
            if (Delimiter(c)) return -1;
            int firstEnd = TokenEnd(s, at);
            long number;
            if (Natural(s, start, firstEnd, out number))
            {
                int second = PdfTrivia(s, firstEnd), secondEnd = TokenEnd(s, second);
                if (secondEnd > second && Natural(s, second, secondEnd, out number))
                {
                    int r = PdfTrivia(s, secondEnd);
                    if (r < s.Length && s[r] == 'R' && (r + 1 == s.Length || Delimiter(s[r + 1]))) return r + 1;
                }
            }
            return firstEnd;
        }

        static bool PdfTrailer(string s, int pos, out long previous, out bool xrefStream, out long length, out int end)
        {
            previous = -1; length = -1; xrefStream = false; end = 0;
            pos = PdfTrivia(s, pos);
            if (pos + 2 > s.Length || s[pos] != '<' || s[pos + 1] != '<') return false;
            pos += 2;
            while ((pos = PdfTrivia(s, pos)) < s.Length)
            {
                if (s[pos] == '>' && pos + 1 < s.Length && s[pos + 1] == '>') { end = pos + 2; return true; }
                if (s[pos++] != '/') return false;
                int nameEnd = TokenEnd(s, pos);
                string key = s.Substring(pos, nameEnd - pos);
                int value = PdfTrivia(s, nameEnd);
                pos = ValueEnd(s, value, 0);
                if (pos < 0) return false;
                if (key == "Prev" && (previous >= 0 || !Natural(s, value, pos, out previous))) return false;
                if (key == "Length" && (length >= 0 || !Natural(s, value, pos, out length))) return false;
                if (key == "Type") xrefStream = pos - value == 5 && String.CompareOrdinal(s, value, "/XRef", 0, 5) == 0;
            }
            return false;
        }

        // Locate the trailer from the referenced xref table, rather than searching
        // backwards for a word that can also be part of a string in the trailer.
        static long TableTrailer(FileStream stream, long at, long limit, CancellationToken cancel)
        {
            bool found = false;
            for (int section = 0; section < 4096 && at < limit; section++)
            {
                cancel.ThrowIfCancellationRequested();
                string text = Encoding.ASCII.GetString(Read(stream, at, (int)Math.Min(128, limit - at)));
                int pos = PdfTrivia(text, 0);
                at += pos;
                if (pos == text.Length) continue;
                text = text.Substring(pos);
                if (found && text.Length > 7 && text.StartsWith("trailer", StringComparison.Ordinal) && Delimiter(text[7])) return at;
                Match head = Subsection.Match(text);
                long count;
                if (!head.Success || !Int64.TryParse(head.Groups[1].Value, out count) || count <= 0) return -1;
                at += head.Length;
                Match first = XrefRow.Match(Encoding.ASCII.GetString(Read(stream, at, (int)Math.Min(24, limit - at))));
                if (!first.Success || count > (limit - at) / first.Length) return -1;
                at += count * first.Length;
                string last = Encoding.ASCII.GetString(Read(stream, at - first.Length, first.Length));
                if (XrefRow.Match(last).Length != first.Length) return -1;
                found = true;
            }
            return -1;
        }

        static bool PdfRevision(FileStream stream, long start, long marker, string tail, CancellationToken cancel, out long xref, out long previous)
        {
            xref = previous = -1;
            Match suffix = StartXref.Match(tail);
            if (!suffix.Success || !Int64.TryParse(suffix.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out xref) ||
                xref <= 0 || xref >= marker - start) return false;
            long address = start + xref;
            string head = Encoding.ASCII.GetString(Read(stream, address, (int)Math.Min(PdfTrailerWindow, marker - address)));
            bool streamType;
            int end; long length;
            if (XrefTable.IsMatch(head))
            {
                long tailStart = marker - tail.Length;
                long trailer = TableTrailer(stream, address + 4, tailStart + suffix.Index, cancel);
                if (trailer < tailStart || trailer + 7 > tailStart + suffix.Index) return false;
                int dictStart = (int)(trailer - tailStart + 7);
                string dictionary = tail.Substring(dictStart, suffix.Index - dictStart);
                return PdfTrailer(dictionary, 0, out previous, out streamType, out length, out end) &&
                    PdfTrivia(dictionary, end) == dictionary.Length;
            }
            Match obj = XrefObject.Match(head);
            if (!obj.Success || !PdfTrailer(head, obj.Length, out previous, out streamType, out length, out end) || !streamType || length < 0) return false;
            int data = PdfTrivia(head, end);
            if (data + 6 >= head.Length || String.CompareOrdinal(head, data, "stream", 0, 6) != 0) return false;
            data += 6;
            if (head[data] == '\r') data++;
            if (data >= head.Length || head[data++] != '\n') return false;
            long footer = marker - tail.Length + suffix.Index;
            if (length > footer - address - data) return false;
            long closing = address + data + length, closingBytes = footer - closing;
            if (closingBytes > 1024) return false;
            string terminators = Encoding.ASCII.GetString(Read(stream, closing, (int)closingBytes));
            return Regex.IsMatch(terminators, @"\A[\r\n \t]*endstream[\r\n \t]+endobj[\r\n \t]*\z", RegexOptions.CultureInvariant);
        }

        static long PdfLineEnd(FileStream stream, long after, long limit)
        {
            byte[] bytes = Read(stream, after, (int)Math.Min(64, limit - after));
            int i = 0;
            while (i < bytes.Length && (bytes[i] == ' ' || bytes[i] == '\t')) i++;
            if (i < bytes.Length && bytes[i] == '\r') return after + i + 1 + (i + 1 < bytes.Length && bytes[i + 1] == '\n' ? 1 : 0);
            if (i < bytes.Length && bytes[i] == '\n') return after + i + 1;
            // A file without a final line break may be followed by any disk byte.
            return after;
        }

        static bool PdfUpdateAhead(FileStream stream, long end, long limit)
        {
            string probe = Encoding.ASCII.GetString(Read(stream, end, (int)Math.Min(PdfTrailerWindow, limit - end)));
            int pos = 0;
            while (pos < probe.Length)
            {
                char c = probe[pos];
                if (c == ' ' || c == '\r' || c == '\n' || c == '\t' || c == '\f') { pos++; continue; }
                if (c != '%') break;
                if (pos + 5 <= probe.Length && String.CompareOrdinal(probe, pos, "%PDF-", 0, 5) == 0) return false;
                while (pos < probe.Length && probe[pos] != '\n' && probe[pos] != '\r') pos++;
            }
            string next = probe.Substring(pos);
            return XrefObject.IsMatch(next) || XrefTable.IsMatch(next);
        }

        static bool PdfHeaderAt(byte[] data, int offset)
        {
            return data != null && offset + 8 <= data.Length && Is(data, offset, "%PDF-") &&
                data[offset + 5] >= '1' && data[offset + 5] <= '2' && data[offset + 6] == '.' &&
                data[offset + 7] >= '0' && data[offset + 7] <= '9';
        }

        static long PdfEnd(FileStream stream, long start, CancellationToken cancel)
        {
            byte[] header = Read(stream, start, 8);
            if (!PdfHeaderAt(header, 0)) return -1;
            long limit = start + Math.Min(128L * 1024 * 1024, stream.Length - start);
            long lastEnd = -1, lastXref = -1, fallback = -1;
            bool objectFound = false, anotherHeader = false;
            const int blockSize = 256 * 1024;
            int probes = 0;
            for (long pos = start; pos < limit; pos += blockSize)
            {
                cancel.ThrowIfCancellationRequested();
                byte[] block = Read(stream, pos, (int)Math.Min(blockSize + 7, limit - pos));
                for (int i = 0; i < blockSize && i + 5 <= block.Length; i++)
                {
                    if (Is(block, i, " obj")) objectFound = true;
                    // An embedded PDF may be valid inside a verified outer file. Its
                    // footer alone cannot complete a damaged neighbouring document.
                    if (block[i] == '%' && pos + i != start && PdfHeaderAt(block, i)) anotherHeader = true;
                    if (block[i] != '%' || !Is(block, i, "%%EOF")) continue;
                    if (i > 0 && block[i - 1] != '\r' && block[i - 1] != '\n' && block[i - 1] != ' ' && block[i - 1] != '\t') continue;
                    long marker = pos + i;
                    if (++probes > 1024) return lastEnd >= 0 ? lastEnd : fallback;
                    int lookback = (int)Math.Min(PdfTrailerWindow, marker - start);
                    string tail = Encoding.ASCII.GetString(Read(stream, marker - lookback, lookback));
                    int line = tail.Length - 1;
                    while (line >= 0 && (tail[line] == ' ' || tail[line] == '\t')) line--;
                    if (line < 0 || tail[line] != '\n' && tail[line] != '\r') continue;
                    long end = PdfLineEnd(stream, marker + 5, limit);
                    long xref, previous;
                    if (PdfRevision(stream, start, marker, tail, cancel, out xref, out previous) &&
                        (lastXref < 0 || previous == lastXref && xref > previous && start + xref >= lastEnd))
                    {
                        lastXref = xref; lastEnd = end;
                        if (!PdfUpdateAhead(stream, end, limit)) return end;
                    }
                    else if (lastEnd < 0 && fallback < 0 && objectFound && !anotherHeader &&
                             (EndObject.IsMatch(tail) || StartXref.IsMatch(tail)))
                    {
                        // Preserve a bounded salvage candidate when the xref is missing.
                        fallback = end;
                    }
                }
            }
            return lastEnd >= 0 ? lastEnd : fallback;
        }
    }
}
