using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // Completed methods are hash-bound. The photo helper additionally anchors
    // immutable within-method checkpoints; unsupported methods retain history.
    public sealed class RecoverySession
    {
        public const string FileName = "recovery-session.json";
        public static IDisposable AcquireRunLock(string directory)
        {
            string file = RecoveryCatalog.SafeFile(directory, "recovery-run.lock");
            Directory.CreateDirectory(Path.GetDirectoryName(file));
            try
            {
                return new FileStream(file, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                throw new IOException("В этой папке уже идёт поиск либо файл блокировки недоступен. Выбери отдельную папку или дождись завершения текущего поиска.");
            }
        }

        public readonly RecoverySessionState State;
        readonly string root;
        readonly object gate = new object ();
        static readonly string[] Keys = RecoveryStageFiles.Keys;
        RecoverySession(string directory, RecoverySessionState state)
        {
            root = Path.GetFullPath(directory);
            State = state;
        }

        static bool Hash(string value)
        {
            return value != null && value.Length == 64 && value.All(Uri.IsHexDigit);
        }

        static void SourceLocation(string root, string source)
        {
            if (!Path.IsPathRooted(source))
                throw new IOException("Путь образа в сессии должен быть абсолютным.");
            string folder = Path.GetFullPath(root).TrimEnd('\\', '/'), image = Path.GetFullPath(source);
            bool prepared = String.Equals(image, ForensicImageSource.WorkingPath(root), StringComparison.OrdinalIgnoreCase) && ForensicImageSource.HasRequest(root);
            if (image.StartsWith(folder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && !String.Equals(image, Path.Combine(folder, "usb.dd"), StringComparison.OrdinalIgnoreCase) && !prepared)
                throw new IOException("Внутри папки поиска допускается только рабочий usb.dd или зарегистрированная логическая копия образа.");
        }

        public static RecoverySessionState Read(string root)
        {
            string file = RecoveryCatalog.SafeFile(root, FileName);
            if (!File.Exists(file) || new FileInfo(file).Length > 64L * 1024 * 1024)
                throw new IOException("Сохранённая сессия не найдена или слишком велика.");
            try
            {
                var state = new JavaScriptSerializer
                {
                    MaxJsonLength = 64 * 1024 * 1024
                }.Deserialize<RecoverySessionState>(File.ReadAllText(file, Encoding.UTF8));
                if (state == null || state.Schema != 1 || state.Options == null || !Hash(state.SourceSha256) || state.SourceBytes <= 0 || String.IsNullOrEmpty(state.SourcePath) || state.Stages == null || state.Stages.Count > Keys.Length)
                    throw new IOException("Сессия повреждена или имеет неподдерживаемую версию.");
                if (state.SourceInWorkingDirectory)
                {
                    string relative = state.RelativeSourcePath ?? "usb.dd";
                    if (relative != "usb.dd" && relative != "source-preparation/working.dd")
                        throw new IOException("Недопустимый относительный источник сессии.");
                    state.SourcePath = RecoveryCatalog.SafeFile(root, relative);
                }

                if (!new[]
                {
                    "running",
                    "cancelled",
                    "error",
                    "finished",
                    "finished_with_warnings"
                }.Contains(state.Status))
                    throw new IOException("Неизвестное состояние сессии.");
                state.Options.Validate();
                SourceLocation(root, state.SourcePath);
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var stage in state.Stages)
                {
                    if (stage == null || !Keys.Contains(stage.Key) || !seen.Add(stage.Key) || stage.Artifacts == null || stage.Artifacts.Count > 100000 || stage.Candidates < 0 || !new[]
                    {
                        "running",
                        "complete",
                        "incomplete",
                        "cancelled"
                    }.Contains(stage.Status))
                        throw new IOException("Некорректные этапы сохранённой сессии.");
                    var artifactNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var artifact in stage.Artifacts)
                    {
                        if (artifact == null || !artifactNames.Add(artifact.Path) || !Hash(artifact.Sha256) || artifact.Bytes < 0)
                            throw new IOException("Некорректная контрольная сумма результата.");
                        RecoveryCatalog.SafeFile(root, artifact.Path);
                    }
                }

                foreach (var stage in state.Stages)
                    if (stage.CheckpointPath != null || stage.CheckpointSha256 != null || stage.CheckpointSequence != 0 || stage.CheckpointBytes != 0)
                    {
                        if (stage.Key != "fragmented-photos" || !CheckpointName(stage.CheckpointPath, stage.CheckpointSequence) || !Hash(stage.CheckpointSha256) || stage.CheckpointBytes <= 0 || stage.CheckpointBytes > 16L * 1024 * 1024)
                            throw new IOException("Некорректная точка продолжения поиска фотографий.");
                        RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
                    }

                if (state.ReadMapSha256 != null && !Hash(state.ReadMapSha256) || state.SourceReadMapSha256 != null && !Hash(state.SourceReadMapSha256))
                    throw new IOException("Некорректная карта пропусков сессии.");
                return state;
            }
            catch (ArgumentException)
            {
                throw new IOException("Не удалось прочитать сессию поиска.");
            }
            catch (InvalidOperationException)
            {
                throw new IOException("Не удалось прочитать сессию поиска.");
            }
        }

        public static RecoverySession Start(string root, string source, string sha, RecoveryOptions options, CancellationToken cancel)
        {
            SourceLocation(root, source);
            if (File.Exists(RecoveryCatalog.SafeFile(root, FileName)))
                throw new IOException("В этой папке уже есть сессия. Нажми «Продолжить…» или создай новый поиск.");
            if (Directory.Exists(RecoveryCatalog.SafeFile(root, "attempt-history")))
                throw new IOException("В папке есть история предыдущих попыток. Нужна новая папка поиска.");
            foreach (string key in Keys)
                if (Paths(root, key).Any())
                    throw new IOException("Папка уже содержит результаты. Для нового поиска нужна новая папка.");
            var state = new RecoverySessionState
            {
                SourcePath = Path.GetFullPath(source),
                SourceBytes = new FileInfo(source).Length,
                SourceSha256 = sha,
                Options = options,
                Status = "running",
                SourceInWorkingDirectory = String.Equals(Path.GetFullPath(source), RecoveryCatalog.SafeFile(root, "usb.dd"), StringComparison.OrdinalIgnoreCase)
            };
            if (String.Equals(Path.GetFullPath(source), ForensicImageSource.WorkingPath(root), StringComparison.OrdinalIgnoreCase))
            {
                state.SourceInWorkingDirectory = true;
                state.RelativeSourcePath = "source-preparation/working.dd";
            }

            string map = RecoveryCatalog.SafeFile(root, "source-read-errors.json");
            if (File.Exists(map))
                state.ReadMapSha256 = RecoveryCore.HashFile(map, cancel, (a, b) =>
                {
                });
            if (File.Exists(source + ".read-errors.json"))
                state.SourceReadMapSha256 = RecoveryCore.HashFile(source + ".read-errors.json", cancel, (a, b) =>
                {
                });
            var session = new RecoverySession(root, state);
            session.Save();
            return session;
        }

        public static RecoverySession Open(string root, string image, RecoveryOptions options, CancellationToken cancel, Action<string> progress)
        {
            var state = Read(root);
            if (state.SourceBytes != new FileInfo(image).Length || !String.Equals(state.SourcePath, Path.GetFullPath(image), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Источник сессии изменился.");
            string map = RecoveryCatalog.SafeFile(root, "source-read-errors.json");
            if ((state.ReadMapSha256 != null) != File.Exists(map) || (File.Exists(map) && !String.Equals(state.ReadMapSha256, RecoveryCore.HashFile(map, cancel, (a, b) =>
            {
            }), StringComparison.OrdinalIgnoreCase)))
                throw new IOException("Карта пропусков изменилась после поиска. Выполни новый анализ образа.");
            string sourceMap = image + ".read-errors.json";
            if ((state.SourceReadMapSha256 != null) != File.Exists(sourceMap) || File.Exists(sourceMap) && !String.Equals(state.SourceReadMapSha256, RecoveryCore.HashFile(sourceMap, cancel, (a, b) =>
            {
            }), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Карта пропусков рядом с образом изменилась. Создай новый поиск.");
            if (OptionSignature(options) != OptionSignature(state.Options))
                throw new IOException("Параметры сессии изменились. Для других методов нужен новый поиск.");
            var session = new RecoverySession(root, state);
            int checkedFiles = 0;
            foreach (var stage in state.Stages.Where(x => x.CheckpointPath != null))
                session.VerifyCheckpoint(stage, cancel);
            foreach (string key in Keys)
                if (!state.Stages.Any(s => s.Key == key) && Paths(root, key).Any())
                    throw new IOException("В папке появились результаты незаписанного этапа. Создай новый поиск, чтобы не смешивать данные.");
            foreach (var stage in state.Stages.Where(x => x.Status == "complete"))
            {
                var names = new HashSet<string>(stage.Artifacts.Select(x => x.Path), StringComparer.OrdinalIgnoreCase);
                var actual = session.Files(stage.Key).Select(x => x.Substring(session.root.TrimEnd('\\').Length + 1).Replace('\\', '/')).ToArray();
                if (actual.Length != names.Count || actual.Any(x => !names.Contains(x)))
                    throw new IOException("Состав сохранённого этапа изменился. Создай новый поиск; исходные результаты сохранены.");
                foreach (var artifact in stage.Artifacts)
                {
                    cancel.ThrowIfCancellationRequested();
                    string file = RecoveryCatalog.SafeFile(root, artifact.Path);
                    if (!File.Exists(file) || new FileInfo(file).Length != artifact.Bytes || !String.Equals(RecoveryCore.HashFile(file, cancel, (a, b) =>
                    {
                    }), artifact.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new IOException("Изменён сохранённый результат: " + artifact.Path + ". Сессия не продолжена; исходные файлы сохранены.");
                    if (progress != null && ++checkedFiles % 100 == 0)
                        progress("Проверка сохранённых результатов: " + checkedFiles);
                }
            }

            state.Status = "running";
            session.Save();
            return session;
        }

        public SessionStage Completed(string key)
        {
            return State.Stages.FirstOrDefault(x => x.Key == key && x.Status == "complete");
        }

        public void Begin(string key)
        {
            Begin(key, false);
        }

        public void Begin(string key, bool continueCheckpoint)
        {
            lock (gate)
            {
                SessionStage old = State.Stages.FirstOrDefault(x => x.Key == key);
                if (continueCheckpoint && (old == null || key != "fragmented-photos" || old.Status == "complete" || old.CheckpointPath == null))
                    throw new IOException("Нет подтверждённой точки продолжения фотографий.");
                if (continueCheckpoint)
                    VerifyCheckpoint(old, CancellationToken.None);
                if (old != null && old.Status != "complete" && !continueCheckpoint)
                    Archive(key);
                var next = new SessionStage
                {
                    Key = key,
                    Status = "running"
                };
                if (continueCheckpoint)
                {
                    next.CheckpointPath = old.CheckpointPath;
                    next.CheckpointSha256 = old.CheckpointSha256;
                    next.CheckpointSequence = old.CheckpointSequence;
                    next.CheckpointBytes = old.CheckpointBytes;
                }

                if (old != null)
                    State.Stages.Remove(old);
                State.Stages.Add(next);
                Save();
            }
        }

        static bool CheckpointName(string path, long sequence)
        {
            return sequence > 0 && sequence <= 999999999999L && path == "fragmented-photos.state/checkpoint-" + sequence.ToString("D12", System.Globalization.CultureInfo.InvariantCulture) + ".json";
        }

        void VerifyCheckpoint(SessionStage stage, CancellationToken cancel)
        {
            string file = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
            if (!File.Exists(file) || new FileInfo(file).Length != stage.CheckpointBytes || !String.Equals(RecoveryCore.HashFile(file, cancel, (a, b) =>
            {
            }), stage.CheckpointSha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Точка продолжения фотографий изменена или отсутствует. Результаты сохранены; начни отдельный поиск.");
        }

        public PhotoRecoveryCheckpoint PhotoCheckpoint()
        {
            lock (gate)
            {
                var stage = State.Stages.FirstOrDefault(x => x.Key == "fragmented-photos" && x.Status != "complete" && x.CheckpointPath != null);
                return stage == null ? null : new PhotoRecoveryCheckpoint
                {
                    Path = RecoveryCatalog.SafeFile(root, stage.CheckpointPath),
                    Sha256 = stage.CheckpointSha256,
                    Sequence = stage.CheckpointSequence
                };
            }
        }

        public void CapturePhotoCheckpoint(PhotoRecoveryCheckpoint checkpoint)
        {
            if (checkpoint == null || String.IsNullOrWhiteSpace(checkpoint.Path) || !Path.IsPathRooted(checkpoint.Path) || !Hash(checkpoint.Sha256))
                throw new IOException("Неверная точка продолжения фотографий.");
            string prefix = root.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, full = Path.GetFullPath(checkpoint.Path);
            if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Точка продолжения вне папки поиска.");
            string relative = full.Substring(prefix.Length).Replace('\\', '/');
            if (!CheckpointName(relative, checkpoint.Sequence))
                throw new IOException("Неверный путь точки продолжения.");
            string file = RecoveryCatalog.SafeFile(root, relative);
            long bytes = File.Exists(file) ? new FileInfo(file).Length : 0;
            if (bytes <= 0 || bytes > 16L * 1024 * 1024 || !String.Equals(RecoveryCore.HashFile(file, CancellationToken.None, (a, b) =>
            {
            }), checkpoint.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Контрольная сумма точки продолжения не совпала.");
            lock (gate)
            {
                var stage = State.Stages.FirstOrDefault(x => x.Key == "fragmented-photos");
                if (stage == null || stage.Status != "running" || checkpoint.Sequence < stage.CheckpointSequence)
                    throw new IOException("Точка продолжения получена вне текущего этапа.");
                if (checkpoint.Sequence == stage.CheckpointSequence)
                {
                    if (stage.CheckpointPath == relative && String.Equals(stage.CheckpointSha256, checkpoint.Sha256, StringComparison.OrdinalIgnoreCase))
                        return;
                    throw new IOException("Изменена уже сохранённая точка продолжения.");
                }

                stage.CheckpointPath = relative;
                stage.CheckpointSha256 = checkpoint.Sha256;
                stage.CheckpointSequence = checkpoint.Sequence;
                stage.CheckpointBytes = bytes;
                Save();
            }
        }

        public void Finish(string key, int count, bool warnings, CancellationToken cancel)
        {
            var stage = State.Stages.Single(x => x.Key == key);
            var artifacts = new List<SessionArtifact>();
            foreach (string file in Files(key))
            {
                cancel.ThrowIfCancellationRequested();
                if (artifacts.Count >= 100000)
                    throw new IOException("Слишком много файлов для безопасного сохранения этапа.");
                string relative = file.Substring(root.TrimEnd('\\').Length + 1).Replace('\\', '/');
                RecoveryCatalog.SafeFile(root, relative);
                artifacts.Add(new SessionArtifact { Path = relative, Bytes = new FileInfo(file).Length, Sha256 = RecoveryCore.HashFile(file, cancel, (a, b) =>
                {
                }) });
            }

            cancel.ThrowIfCancellationRequested();
            lock (gate)
            {
                stage.Artifacts = artifacts;
                stage.Candidates = count;
                stage.Warnings = warnings;
                stage.Status = "complete";
                Save();
            }
        }

        public void Fail(string key, string status, string message)
        {
            lock (gate)
            {
                var stage = State.Stages.FirstOrDefault(x => x.Key == key);
                if (stage != null)
                {
                    stage.Status = status;
                    stage.Message = message;
                }

                Save();
            }
        }

        public void Status(string value)
        {
            lock (gate)
            {
                State.Status = value;
                Save();
            }
        }

        public bool TryFail(string key, string status, string message)
        {
            try
            {
                Fail(key, status, message);
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        public bool TryStatus(string value)
        {
            try
            {
                Status(value);
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        static string OptionSignature(RecoveryOptions options)
        {
            var json = new JavaScriptSerializer();
            return Canonical(json.DeserializeObject(json.Serialize(options)), json);
        }

        static string Canonical(object value, JavaScriptSerializer json)
        {
            var row = value as IDictionary<string, object>;
            if (row != null)
                return "{" + String.Join(",", row.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => json.Serialize(pair.Key) + ":" + Canonical(pair.Value, json))) + "}";
            var sequence = value as System.Collections.IEnumerable;
            if (value != null && !(value is string) && sequence != null)
                return "[" + String.Join(",", sequence.Cast<object>().Select(item => Canonical(item, json))) + "]";
            return json.Serialize(value);
        }

        void Save()
        {
            lock (gate)
            {
                State.UpdatedUtc = DateTime.UtcNow.ToString("o");
                RecoveryCore.SaveJsonBounded(RecoveryCatalog.SafeFile(root, FileName), State, 64 * 1024 * 1024);
            }
        }

        static IEnumerable<string> Paths(string root, string key)
        {
            return RecoveryStageFiles.Paths(root, key);
        }

        IEnumerable<string> Files(string key)
        {
            return new RecoveryStageFiles(root).Files(key);
        }

        void Archive(string key)
        {
            new RecoveryStageFiles(root).Archive(key);
        }
    }
}
