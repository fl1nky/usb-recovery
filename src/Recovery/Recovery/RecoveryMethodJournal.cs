using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // The pipeline supplies the already verified source digest and owns the
    // durable parent anchor. Individual engines own their cursor and payload.
    // Settings describes public search parameters; never include passwords/keys.
    internal sealed class RecoveryCheckpointContext
    {
        public string Directory, Method, SourceSha256, Settings;
        public RecoveryMethodCheckpoint Resume;
        public Action<RecoveryMethodCheckpoint> Commit;
    }

    internal sealed class RecoveryMethodEnvelope<T> where T : class
    {
        public int Schema = 1;
        public string Method, SourceSha256, EngineSha256, Settings;
        public long Sequence, SourceBytes;
        public T Payload;
    }

    // Immutable child generations are written before the parent acknowledges
    // them. An unacknowledged generation is never selected during recovery.
    // Output publication belongs after Save; engines must validate/repair their
    // own planned files before resuming the cursor.
    internal sealed class RecoveryMethodJournal<T> where T : class
    {
        const int MaximumStateBytes = 16 * 1024 * 1024;
        const long MaximumSequence = 999999999999L;
        readonly RecoveryCheckpointContext context;
        readonly CancellationToken cancel;
        readonly string sourceHash, engineHash, folder;
        readonly long sourceBytes;
        long sequence;

        public T Payload { get; private set; }
        public bool Resumed { get; private set; }
        public bool Enabled { get { return context != null; } }

        static bool Digest(string value)
        {
            return value != null && value.Length == 64 && value.All(c =>
                c >= '0' && c <= '9' || c >= 'a' && c <= 'f');
        }

        string Hash(string path)
        {
            return RecoveryCore.HashFile(path, cancel, (done, total) => { });
        }

        static string Name(long value)
        {
            return "checkpoint-" + value.ToString("D12", CultureInfo.InvariantCulture) + ".json";
        }

        static long Generation(string path)
        {
            string name = Path.GetFileName(path);
            long value;
            return name.Length == 28 && Int64.TryParse(name.Substring(11, 12),
                NumberStyles.None, CultureInfo.InvariantCulture, out value) &&
                value > 0 && value <= MaximumSequence && name == Name(value) ? value : 0;
        }

        string CheckpointPath(long value)
        {
            return RecoveryCatalog.SafeFile(context.Directory, context.Method + ".state/" + Name(value));
        }

        public RecoveryMethodJournal(string image, T initial, RecoveryCheckpointContext checkpoint,
            CancellationToken token)
        {
            Payload = initial;
            cancel = token;
            context = checkpoint;
            if (!Enabled) return;
            if (context.Commit == null || !RecoveryStageFiles.Keys.Contains(context.Method) ||
                context.Settings == null || context.Settings.Length > 64 * 1024)
                throw new IOException("METHOD_CHECKPOINT_CONTEXT_INVALID");
            sourceHash = (context.SourceSha256 ?? "").ToLowerInvariant();
            if (!Digest(sourceHash)) throw new IOException("METHOD_SOURCE_BINDING_REQUIRED");
            sourceBytes = new FileInfo(image).Length;
            engineHash = Hash(typeof(RecoveryMethodJournal<T>).Assembly.Location);
            folder = Path.GetDirectoryName(RecoveryCatalog.SafeFile(context.Directory, context.Method + ".state/guard"));
            var resume = context.Resume;
            if (resume == null) return;
            if (resume.Sequence <= 0 || resume.Sequence > MaximumSequence ||
                !String.Equals(Path.GetFullPath(resume.Path), CheckpointPath(resume.Sequence), StringComparison.OrdinalIgnoreCase))
                throw new IOException("METHOD_CHECKPOINT_PATH_INVALID");
            string file = CheckpointPath(resume.Sequence);
            using (var guard = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (guard.Length <= 0 || guard.Length > MaximumStateBytes ||
                    !String.Equals(Hash(file), resume.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("METHOD_CHECKPOINT_CHANGED");
                RecoveryMethodEnvelope<T> saved;
                try
                {
                    saved = new JavaScriptSerializer { MaxJsonLength = MaximumStateBytes }
                        .Deserialize<RecoveryMethodEnvelope<T>>(File.ReadAllText(file, new UTF8Encoding(false, true)));
                }
                catch (ArgumentException) { throw new IOException("METHOD_CHECKPOINT_INVALID"); }
                catch (InvalidOperationException) { throw new IOException("METHOD_CHECKPOINT_INVALID"); }
                if (saved == null || saved.Schema != 1 || saved.Sequence != resume.Sequence ||
                    saved.Method != context.Method || saved.SourceBytes != sourceBytes ||
                    saved.SourceSha256 != sourceHash || saved.EngineSha256 != engineHash ||
                    saved.Settings != context.Settings || saved.Payload == null)
                    throw new IOException("METHOD_CHECKPOINT_BINDING_MISMATCH");
                Payload = saved.Payload;
                sequence = saved.Sequence;
                Resumed = true;
            }
        }

        public void Save(T payload)
        {
            if (!Enabled) { Payload = payload; return; }
            if (payload == null) throw new ArgumentNullException("payload");
            cancel.ThrowIfCancellationRequested();
            Directory.CreateDirectory(folder);
            long next = sequence + 1;
            int inspected = 0;
            foreach (string file in Directory.EnumerateFiles(folder, "checkpoint-*.json"))
            {
                if (++inspected > 100000) throw new IOException("METHOD_CHECKPOINT_DIRECTORY_LIMIT");
                next = Math.Max(next, Generation(file) + 1);
            }
            if (next <= 0 || next > MaximumSequence) throw new IOException("METHOD_CHECKPOINT_SEQUENCE_LIMIT");
            var saved = new RecoveryMethodEnvelope<T> { Method = context.Method,
                SourceSha256 = sourceHash, SourceBytes = sourceBytes, EngineSha256 = engineHash,
                Settings = context.Settings, Sequence = next, Payload = payload };
            string target = CheckpointPath(next);
            RecoveryCore.SaveJsonBounded(target, saved, MaximumStateBytes);
            context.Commit(new RecoveryMethodCheckpoint { Path = target, Sha256 = Hash(target), Sequence = next });
            long prior = sequence;
            sequence = next;
            Payload = payload;
            foreach (string file in Directory.EnumerateFiles(folder, "checkpoint-*.json"))
            {
                long old = Generation(file);
                if (old <= 0 || old >= next || old == prior) continue;
                RecoveryCatalog.SafeFile(context.Directory, context.Method + ".state/" + Path.GetFileName(file));
                try { File.Delete(file); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }
}
