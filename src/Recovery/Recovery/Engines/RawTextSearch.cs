using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace UsbRecovery
{
    // String carving, not document reconstruction. Source offsets remain bytes.
    public static class RawTextSearch
    {
        const int Chunk = 1024 * 1024, Overlap = 65536, CheckpointInterval = 8 * Chunk;
        internal const int MaximumResults = 5000;
        static readonly Encoding Binary = Encoding.GetEncoding(28591);
        static readonly Encoding Utf8 = new UTF8Encoding(false, true);
        static readonly Encoding Le = new UnicodeEncoding(false, false, true);
        static readonly Encoding Be = new UnicodeEncoding(true, false, true);
        static Regex Bytes(string pattern)
        {
            return new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
        }
        static readonly Regex Utf8Runs = Bytes(@"(?:[\x09\x0a\x0d\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee-\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2}){8,8192}");
        static readonly Regex LeRuns = Bytes(@"(?:[\x09\x0a\x0d\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x01-\x05]){8,8192}");
        static readonly Regex BeRuns = Bytes(@"(?:\x00[\x09\x0a\x0d\x20-\x7e\xa0-\xff]|[\x01-\x05][\x00-\xff]){8,8192}");

        internal static string[] Terms(string query)
        {
            var terms = (query ?? "").Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
            if (terms.Length == 0 || terms.Length > 8 || query.Length > 256)
                throw new IOException("Укажи до 8 ключевых слов для текстового поиска.");
            return terms;
        }
        internal static Encoding SourceEncoding(string name)
        {
            switch (name)
            {
                case "utf-8": return Utf8;
                case "utf-16-le": return Le;
                case "utf-16-be": return Be;
                default: throw new IOException("TEXT_CHECKPOINT_ENCODING_INVALID");
            }
        }
        internal static bool Accept(string text, string[] terms)
        {
            int letters = text.Count(Char.IsLetter);
            return letters >= 5 && letters * 100 >= text.Length * 40 &&
                !text.Any(c => Char.IsControl(c) && c != '\r' && c != '\n' && c != '\t') &&
                terms.All(term => text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0);
        }
        public static int Recover(string image, string directory, string query, CancellationToken cancel, Action<long, long> progress)
        {
            return Recover(image, directory, query, cancel, progress, null, null, null);
        }
        internal static int Recover(string image, string directory, string query, CancellationToken cancel,
            Action<long, long> progress, RecoveryMethodCheckpoint resume,
            Action<RecoveryMethodCheckpoint> checkpoint, string expectedSourceSha256)
        {
            if (!File.Exists(image) || image.StartsWith(@"\\", StringComparison.Ordinal) || Path.GetFullPath(image).IndexOf(':', 2) >= 0)
                throw new IOException("Текст ищется только в обычном локальном образе.");
            string[] terms = Terms(query);
            cancel.ThrowIfCancellationRequested();
            string output = Path.GetDirectoryName(RecoveryCatalog.SafeFile(directory, "text-fragments/guard"));
            Directory.CreateDirectory(output);
            var journal = new TextRecoveryCheckpoint(directory, image, query, expectedSourceSha256, resume, checkpoint, cancel);
            var patterns = new[] { Utf8Runs, LeRuns, BeRuns };
            var encodings = new[] { Utf8, Le, Be };
            var names = new[] { "utf-8", "utf-16-le", "utf-16-be" };
            var records = journal.State.Records;
            var lastEnd = (long[])journal.State.LastEnd.Clone();
            long position = journal.State.Position, savedPosition = position;
            string status = "incomplete";
            try
            {
                if (journal.Resumed && progress != null) progress(position, journal.State.SourceBytes);
                if (journal.State.Complete) { status = "complete"; return records.Count; }
                if (records.Count >= MaximumResults) { status = "limited"; throw new IOException("TEXT_FRAGMENT_LIMIT"); }
                if (journal.Enabled && resume == null) journal.Save(0, lastEnd, false);
                using (var source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, Chunk))
                {
                    byte[] block = new byte[Chunk + 2 * Overlap];
                    int carry = (int)Math.Min(position, 2 * Overlap);
                    source.Position = position - carry;
                    int restored = 0;
                    while (restored < carry)
                    {
                        int read = source.Read(block, restored, carry - restored);
                        if (read == 0) throw new IOException("TEXT_SOURCE_TRUNCATED");
                        restored += read;
                    }
                    while (true)
                    {
                        cancel.ThrowIfCancellationRequested();
                        int read = source.Read(block, carry, Chunk), length = read + carry;
                        bool final = read == 0;
                        int safe = final ? length : Math.Max(0, length - Overlap);
                        long start = position - carry;
                        string binary = Binary.GetString(block, 0, length);
                        var pending = new List<KeyValuePair<TextRecoveryRecord, byte[]>>();
                        bool limited = false;
                        for (int kind = 0; kind < patterns.Length && !limited; kind++)
                        {
                            foreach (Match match in patterns[kind].Matches(binary))
                            {
                                cancel.ThrowIfCancellationRequested();
                                long at = start + match.Index, end = at + match.Length;
                                if (match.Index >= safe || at < lastEnd[kind] || !final && match.Index + match.Length > safe) continue;
                                lastEnd[kind] = end;
                                string text;
                                try { text = encodings[kind].GetString(block, match.Index, match.Length); }
                                catch (DecoderFallbackException) { continue; }
                                if (!Accept(text, terms)) continue;
                                byte[] bytes = TextRecoveryCheckpoint.OutputBytes(text);
                                var record = TextRecoveryCheckpoint.Record(at, match.Length, names[kind], bytes);
                                records.Add(record);
                                pending.Add(new KeyValuePair<TextRecoveryRecord, byte[]>(record, bytes));
                                if (records.Count >= MaximumResults) { limited = true; break; }
                            }
                        }
                        position += read;
                        if (final || pending.Count != 0 || position - savedPosition >= CheckpointInterval)
                        {
                            // Persist the complete write-ahead plan before publishing files.
                            journal.Save(position, lastEnd, final && !limited);
                            savedPosition = position;
                        }
                        foreach (var item in pending) journal.WriteCandidate(item.Key, item.Value);
                        if (limited)
                        {
                            status = "limited";
                            throw new IOException("Текстовый поиск достиг 5000 фрагментов. Найденное сохранено; сузь ключевые слова.");
                        }
                        if (final) break;
                        carry = Math.Min(length, 2 * Overlap);
                        Buffer.BlockCopy(block, length - carry, block, 0, carry);
                        if (progress != null) progress(position, source.Length);
                    }
                }
                status = "complete";
                return records.Count;
            }
            catch (RegexMatchTimeoutException)
            {
                status = "limited";
                throw new IOException("Сложный участок данных: текстовый проход остановлен по времени. Уже найденное сохранено.");
            }
            catch (OperationCanceledException) { status = "cancelled"; throw; }
            finally
            {
                try
                {
                    RecoveryCore.SaveJson(Path.Combine(directory, "text-search.json"), new
                    {
                        status = status, image = Path.GetFullPath(image), query = query, files = records,
                        maximumFragments = MaximumResults, resumedFromCheckpoint = journal.Resumed,
                        resumedBytes = journal.ResumedBytes, checkpointSequence = journal.State.Sequence,
                        note = "No full-file or deletion-state claim. Image digest is retained in usb.dd.sha256 or source-image.sha256."
                    });
                }
                catch (IOException) { if (status == "complete") throw; }
                catch (UnauthorizedAccessException) { if (status == "complete") throw; }
            }
        }
    }
}
