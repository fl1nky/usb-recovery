using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace UsbRecovery
{
    // Finds complete JPEG/PNG streams at arbitrary byte offsets, including embedded thumbnails.
    // It does not infer missing fragments or manufacture missing image content.
    public static class ExtraPhotoSearch
    {
        const long MaximumPhoto = 128L * 1024 * 1024;
        static readonly byte[] PngSignature = { 137, 80, 78, 71, 13, 10, 26, 10 };

        public static int Recover(string image, string runDirectory, CancellationToken cancel, Action<long, long> progress)
        {
            return Recover(image, runDirectory, cancel, progress, null);
        }
        internal static int Recover(string image, string runDirectory, CancellationToken cancel,
            Action<long, long> progress, RecoveryCheckpointContext checkpoint)
        {
            cancel.ThrowIfCancellationRequested();
            if (image.StartsWith(@"\\.\") || image.StartsWith(@"\\?\") || !File.Exists(image)) throw new IOException("Дополнительный поиск работает только с обычным файлом копии.");
            const int blockBytes = 4 * 1024 * 1024;
            string reportPath = RecoveryCatalog.SafeFile(runDirectory, "extra-photo-search.json");
            if (String.Equals(Path.GetFullPath(image), reportPath, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Исходный образ не может быть отчётом поиска.");
            var journal = new RecoveryMethodJournal<RecoveryRangeScanState>(image,
                new RecoveryRangeScanState(), checkpoint, cancel);
            var state = journal.Payload;
            var ledger = new RecoveryOutputLedger<RecoveryRangeRecord>(checkpoint, state.Output, 100000, cancel);
            using (var scan = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 4 * 1024 * 1024))
            using (var parser = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024))
            {
                if (state.Position < 0 || state.Position > scan.Length || state.SkipUntil != 0 || state.Probes != 0 ||
                    state.Complete && state.Position != scan.Length || state.Complete && state.Limited ||
                    !state.Complete && !state.Limited && state.Position % blockBytes != 0 ||
                    ledger.Records.Any(r => r.Format != ".jpg" && r.Format != ".png"))
                    throw new IOException("PHOTO_SCAN_CHECKPOINT_INVALID");
                var output = new RecoveryRangeOutput(runDirectory, "extra-photos", parser, MaximumPhoto, cancel);
                output.RestoreAll(ledger.Records, state.Position);
                if (state.Limited) throw new IOException("Дополнительный поиск ранее достиг ограничения. Найденные файлы проверены; начни отдельный поиск с меньшей областью.");
                if (journal.Resumed && progress != null) progress(state.Position, scan.Length);
                if (journal.Enabled && !journal.Resumed) journal.Save(state);
                byte[] block = new byte[blockBytes + 7];
                while (!state.Complete && state.Position < scan.Length)
                {
                    cancel.ThrowIfCancellationRequested();
                    scan.Position = state.Position;
                    int length = (int)Math.Min(block.Length, scan.Length - state.Position);
                    if (!ReadExact(scan, block, length)) throw new IOException("PHOTO_SOURCE_TRUNCATED");
                    int limit = (int)Math.Min(blockBytes, scan.Length - state.Position);
                    var pending = new List<RecoveryRangeRecord>();
                    for (int i = 0; i < limit; i++)
                    {
                        if ((i & 65535) == 0) cancel.ThrowIfCancellationRequested();
                        bool jpeg = i + 2 < length && block[i] == 255 && block[i + 1] == 216 && block[i + 2] == 255;
                        bool png = i + 7 < length && IsPng(block, i);
                        if (!jpeg && !png) continue;
                        long offset = state.Position + i;
                        long end = jpeg ? JpegEnd(parser, offset, cancel) : PngStructure.Read(parser, offset, offset + Math.Min(MaximumPhoto, parser.Length - offset), cancel).End;
                        if (end <= offset) continue;
                        if (ledger.Records.Count + pending.Count >= 100000)
                        {
                            state.Position += i;
                            state.Limited = true;
                            state.Output = ledger.Append(state.Output, pending);
                            journal.Save(state);
                            ledger.Accept(pending);
                            foreach (var record in pending) output.Restore(record);
                            SaveReport(reportPath, ledger.Records, "limited", journal.Resumed);
                            throw new IOException("Дополнительный поиск достиг ограничения 100 000 изображений. Уже подтверждённые файлы сохранены.");
                        }
                        pending.Add(output.Plan(offset, end - offset, jpeg ? ".jpg" : ".png"));
                    }
                    state.Position += limit;
                    state.Complete = state.Position == scan.Length;
                    state.Output = ledger.Append(state.Output, pending);
                    journal.Save(state); // The parent acknowledges every range before its named output.
                    ledger.Accept(pending);
                    foreach (var record in pending) output.Restore(record);
                    if (progress != null) progress(state.Position, scan.Length);
                }
                if (!state.Complete) { state.Complete = true; journal.Save(state); }
            }
            cancel.ThrowIfCancellationRequested();
            SaveReport(reportPath, ledger.Records, "complete", journal.Resumed);
            return ledger.Records.Count;
        }
        static void SaveReport(string path, IList<RecoveryRangeRecord> records, string status, bool resumed)
        {
            RecoveryCore.SaveJson(path, new { status = status, candidates = records.Count,
                maximumFileBytes = MaximumPhoto, resumedFromCheckpoint = resumed,
                files = records.Select(r => new { path = r.Path, offset = r.Offset, size = r.Bytes,
                    sha256 = r.Sha256, method = "byte-offset-structural",
                    check = r.Format == ".jpg" ? "JPEG markers and EOI" : "PNG critical chunks, CRC32 and zlib header" }).ToList() });
        }

        static bool IsPng(byte[] data, int index)
        {
            for (int j = 0; j < PngSignature.Length; j++) if (data[index + j] != PngSignature[j]) return false;
            return true;
        }

        static long JpegEnd(FileStream stream, long start, CancellationToken cancel)
        {
            stream.Position = start + 2;
            long limit = Math.Min(stream.Length, start + MaximumPhoto);
            bool frame = false, scan = false;
            int pending = -1, markers = 0;
            while (stream.Position < limit && markers++ < 10000)
            {
                cancel.ThrowIfCancellationRequested();
                int marker;
                if (pending >= 0) { marker = pending; pending = -1; }
                else
                {
                    if (stream.ReadByte() != 255) return -1;
                    do { marker = stream.ReadByte(); } while (marker == 255 && stream.Position < limit);
                }
                if (marker < 0 || marker == 0 || marker == 216) return -1;
                if (marker == 217) return frame && scan ? stream.Position : -1;
                if (marker == 1 || (marker >= 208 && marker <= 215)) continue;
                if (marker < 192 || marker > 254) return -1;
                int high = stream.ReadByte(), low = stream.ReadByte();
                if (high < 0 || low < 0) return -1;
                int size = (high << 8) | low;
                if (size < 2 || stream.Position + size - 2 > limit) return -1;
                long next = stream.Position + size - 2;
                if (IsFrame(marker))
                {
                    if (size < 8) return -1;
                    int precision = stream.ReadByte(); int height = ReadBig16(stream), width = ReadBig16(stream);
                    if (precision <= 0 || precision > 16 || width <= 0 || height <= 0 || (long)width * height > 100000000L) return -1;
                    frame = true;
                }
                stream.Position = next;
                if (marker != 218) continue;
                if (!frame || size < 6) return -1;
                scan = true;
                while (stream.Position < limit)
                {
                    if ((stream.Position & 65535) == 0) cancel.ThrowIfCancellationRequested();
                    if (stream.ReadByte() != 255) continue;
                    int value;
                    do { value = stream.ReadByte(); } while (value == 255 && stream.Position < limit);
                    if (value < 0) return -1;
                    if (value == 0 || (value >= 208 && value <= 215)) continue;
                    if (value == 217) return stream.Position;
                    pending = value; break;
                }
                if (pending < 0) return -1;
            }
            return -1;
        }

        static bool IsFrame(int marker) { return marker >= 192 && marker <= 207 && marker != 196 && marker != 200 && marker != 204; }
        static int ReadBig16(Stream stream) { int a = stream.ReadByte(), b = stream.ReadByte(); return a < 0 || b < 0 ? -1 : (a << 8) | b; }
        static bool ReadExact(Stream stream, byte[] buffer, int length)
        {
            int total = 0;
            while (total < length) { int read = stream.Read(buffer, total, length - total); if (read == 0) return false; total += read; }
            return true;
        }
    }
}
