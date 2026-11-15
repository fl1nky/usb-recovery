using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class TextRecoveryRecord
    {
        public string path, encoding, sha256;
        public long offset, sourceBytes, bytes;
        public string status = "text_fragment", deletedState = "unknown";
        public string note = "Text only. Original document boundaries, author and date unknown. Stored TXT is UTF-8; source encoding is recorded separately.";
    }

    public sealed class TextRecoveryState
    {
        public int Schema = 1;
        public long Sequence, Position, SourceBytes;
        public string SourceSha256, EngineSha256, Query;
        public bool Complete;
        public long[] LastEnd = { -1, -1, -1 };
        public List<TextRecoveryRecord> Records = new List<TextRecoveryRecord>();
    }

    // The parent commits an immutable plan BEFORE any new named candidate is
    // published. Missing planned output can therefore be reconstructed after a
    // crash; unexpected or changed output is never silently overwritten.
    internal sealed class TextRecoveryCheckpoint
    {
        const int MaximumStateBytes = 16 * 1024 * 1024;
        readonly string root, image;
        readonly Action<RecoveryMethodCheckpoint> publish;
        readonly CancellationToken cancel;
        public readonly TextRecoveryState State;
        public readonly bool Resumed;
        public readonly long ResumedBytes;
        public bool Enabled { get { return publish != null; } }

        static string Hash(string path, CancellationToken cancel)
        {
            return RecoveryCore.HashFile(path, cancel, (done, total) => { });
        }
        static bool ValidHash(string hash)
        {
            return hash != null && hash.Length == 64 && hash.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f');
        }
        static string Relative(long offset, string encoding)
        {
            return "text-fragments/offset-" + offset.ToString("D16", CultureInfo.InvariantCulture) + "-" + encoding + ".txt";
        }
        internal static byte[] OutputBytes(string text)
        {
            var utf8 = new UTF8Encoding(true, true);
            byte[] body = utf8.GetBytes(text), preamble = utf8.GetPreamble();
            byte[] result = new byte[preamble.Length + body.Length];
            Buffer.BlockCopy(preamble, 0, result, 0, preamble.Length);
            Buffer.BlockCopy(body, 0, result, preamble.Length, body.Length);
            return result;
        }
        internal static TextRecoveryRecord Record(long offset, int sourceBytes, string encoding, byte[] bytes)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
                return new TextRecoveryRecord { path = Relative(offset, encoding), offset = offset,
                    sourceBytes = sourceBytes, encoding = encoding, bytes = bytes.Length,
                    sha256 = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant() };
        }

        public TextRecoveryCheckpoint(string directory, string source, string query, string sourceHash,
            RecoveryMethodCheckpoint resume, Action<RecoveryMethodCheckpoint> committed, CancellationToken token)
        {
            root = Path.GetFullPath(directory);
            image = Path.GetFullPath(source);
            publish = committed;
            cancel = token;
            if (resume != null && !Enabled) throw new IOException("TEXT_CHECKPOINT_CALLBACK_REQUIRED");
            string engineHash = Enabled ? Hash(typeof(RawTextSearch).Assembly.Location, cancel) : null;
            if (Enabled && !ValidHash(sourceHash)) throw new IOException("TEXT_SOURCE_BINDING_REQUIRED");
            if (resume == null)
            {
                State = new TextRecoveryState { SourceBytes = new FileInfo(image).Length,
                    SourceSha256 = sourceHash, EngineSha256 = engineHash, Query = query };
                return;
            }
            string file = RecoveryCatalog.SafeFile(root, "text.state/checkpoint-" +
                resume.Sequence.ToString("D12", CultureInfo.InvariantCulture) + ".json");
            if (!String.Equals(file, Path.GetFullPath(resume.Path), StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(file) || new FileInfo(file).Length > MaximumStateBytes || Hash(file, cancel) != resume.Sha256)
                throw new IOException("TEXT_CHECKPOINT_CHANGED");
            try
            {
                State = new JavaScriptSerializer { MaxJsonLength = MaximumStateBytes }
                    .Deserialize<TextRecoveryState>(File.ReadAllText(file, new UTF8Encoding(false, true)));
            }
            catch (ArgumentException) { throw new IOException("TEXT_CHECKPOINT_INVALID"); }
            catch (InvalidOperationException) { throw new IOException("TEXT_CHECKPOINT_INVALID"); }
            if (State == null || State.Schema != 1 || State.Sequence != resume.Sequence ||
                State.SourceBytes != new FileInfo(image).Length || State.SourceSha256 != sourceHash ||
                State.EngineSha256 != engineHash || State.Query != query || State.Position < 0 ||
                State.Position > State.SourceBytes || State.Complete && State.Position != State.SourceBytes ||
                State.LastEnd == null || State.LastEnd.Length != 3 || State.LastEnd.Any(x => x < -1 || x > State.Position) ||
                State.Records == null || State.Records.Count > RawTextSearch.MaximumResults)
                throw new IOException("TEXT_CHECKPOINT_BINDING_MISMATCH");
            Resumed = true;
            ResumedBytes = State.Position;
            RestoreFiles();
        }

        void RestoreFiles()
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] terms = RawTextSearch.Terms(State.Query);
            using (var source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                foreach (var record in State.Records)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (record == null || record.offset < 0 || record.sourceBytes < 8 || record.sourceBytes > 32768 ||
                        record.offset > State.Position - record.sourceBytes || record.bytes <= 0 || record.bytes > 65536 ||
                        !ValidHash(record.sha256) || record.path != Relative(record.offset, record.encoding) ||
                        record.status != "text_fragment" || record.deletedState != "unknown" || !names.Add(record.path))
                        throw new IOException("TEXT_CHECKPOINT_RECORD_INVALID");
                    Encoding encoding = RawTextSearch.SourceEncoding(record.encoding);
                    source.Position = record.offset;
                    byte[] raw = new byte[(int)record.sourceBytes];
                    int done = 0;
                    while (done < raw.Length)
                    {
                        int read = source.Read(raw, done, raw.Length - done);
                        if (read == 0) throw new IOException("TEXT_SOURCE_TRUNCATED");
                        done += read;
                    }
                    string text;
                    try { text = encoding.GetString(raw); }
                    catch (DecoderFallbackException) { throw new IOException("TEXT_CHECKPOINT_ENCODING_CHANGED"); }
                    if (!RawTextSearch.Accept(text, terms)) throw new IOException("TEXT_CHECKPOINT_CONTENT_CHANGED");
                    byte[] bytes = OutputBytes(text);
                    var actual = Record(record.offset, raw.Length, record.encoding, bytes);
                    if (actual.bytes != record.bytes || actual.sha256 != record.sha256)
                        throw new IOException("TEXT_CHECKPOINT_CONTENT_CHANGED");
                    WriteCandidate(record, bytes);
                }
            }
            string output = RecoveryCatalog.SafeFile(root, "text-fragments/guard");
            output = Path.GetDirectoryName(output);
            if (Directory.Exists(output))
            {
                if (Directory.EnumerateDirectories(output).Any()) throw new IOException("TEXT_OUTPUT_CHANGED");
                foreach (string path in Directory.EnumerateFiles(output))
                    if (!path.EndsWith(".partial", StringComparison.OrdinalIgnoreCase) &&
                        !names.Contains("text-fragments/" + Path.GetFileName(path)))
                        throw new IOException("TEXT_OUTPUT_CHANGED");
            }
        }

        public void WriteCandidate(TextRecoveryRecord record, byte[] bytes)
        {
            string target = RecoveryCatalog.SafeFile(root, record.path);
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            if (File.Exists(target))
            {
                if (new FileInfo(target).Length != record.bytes || Hash(target, cancel) != record.sha256)
                    throw new IOException("TEXT_OUTPUT_CHANGED");
                return;
            }
            string partial = RecoveryCatalog.SafeFile(root, record.path + ".partial");
            // Unlink only the private stale name; never truncate a possible alias.
            if (File.Exists(partial)) File.Delete(partial);
            using (var stream = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
            File.Move(partial, target);
        }

        public void Save(long position, long[] lastEnd, bool complete)
        {
            State.Position = position;
            State.LastEnd = (long[])lastEnd.Clone();
            State.Complete = complete;
            if (!Enabled) return;
            cancel.ThrowIfCancellationRequested();
            string folder = Path.GetDirectoryName(RecoveryCatalog.SafeFile(root, "text.state/guard"));
            Directory.CreateDirectory(folder);
            long next = State.Sequence + 1;
            foreach (string file in Directory.EnumerateFiles(folder, "checkpoint-*.json"))
            {
                long sequence;
                string name = Path.GetFileNameWithoutExtension(file);
                if (name.Length == 23 && Int64.TryParse(name.Substring(11), out sequence) && sequence > 0 &&
                    name == "checkpoint-" + sequence.ToString("D12", CultureInfo.InvariantCulture))
                    next = Math.Max(next, sequence + 1);
            }
            if (next <= 0 || next > 999999999999L) throw new IOException("TEXT_CHECKPOINT_SEQUENCE_LIMIT");
            long previousAnchor = State.Sequence;
            State.Sequence = next;
            string path = RecoveryCatalog.SafeFile(root, "text.state/checkpoint-" + next.ToString("D12", CultureInfo.InvariantCulture) + ".json");
            RecoveryCore.SaveJsonBounded(path, State, MaximumStateBytes);
            publish(new RecoveryMethodCheckpoint { Path = path, Sha256 = Hash(path, cancel), Sequence = next });
            // Retain the actual prior anchor, even if abandoned generations
            // made the sequence jump. Prune only after successful anchoring.
            foreach (string file in Directory.EnumerateFiles(folder, "checkpoint-*.json"))
            {
                long sequence;
                string name = Path.GetFileNameWithoutExtension(file);
                if (name.Length == 23 && Int64.TryParse(name.Substring(11), out sequence) &&
                    sequence > 0 && sequence < next && sequence != previousAnchor &&
                    name == "checkpoint-" + sequence.ToString("D12", CultureInfo.InvariantCulture))
                {
                    RecoveryCatalog.SafeFile(root, "text.state/" + Path.GetFileName(file));
                    try { File.Delete(file); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                }
            }
        }
    }
}
