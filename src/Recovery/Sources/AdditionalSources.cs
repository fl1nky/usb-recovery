using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace UsbRecovery
{
    // A backup has logical files, including Manifest.db/WAL and hashed payloads.
    // It never enters the FAT/NTFS sector recovery pipeline.
    public sealed class BackupRecoverySource : ILocalRecoverySource, IRecoverySourceWarnings
    {
        readonly LocalFolderSource files;
        readonly SourceInfo info;
        public BackupRecoverySource(string directory)
        {
            files = new LocalFolderSource(directory);
            info = new SourceInfo { Id = files.Info.Id, Name = files.Info.Name, Kind = "backup", Status = files.Info.Status };
        }
        public SourceInfo Info { get { return info; } }
        public string RootDirectory { get { return files.RootDirectory; } }
        public IList<string> Warnings { get { return files.Warnings; } }
        public string SelectedPath(string root) { return files.SelectedPath(root); }
        public IEnumerable<SourceEntry> Enumerate(string root, CancellationToken cancel) { return files.Enumerate(root, cancel); }
        public Stream OpenRead(SourceEntry entry, CancellationToken cancel) { return files.OpenRead(entry, cancel); }
    }

    // Exposes only a normal image file. Physical-device acquisition remains in
    // RecoveryCore, which validates USB identity and excludes system disks.
    public sealed class ImageRecoverySource : IRecoverySource
    {
        readonly string path;
        readonly SourceInfo info;
        public ImageRecoverySource(string path)
        {
            if (String.IsNullOrEmpty(path) || path.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Нужен обычный локальный файл образа.");
            this.path = Path.GetFullPath(path); SourcePaths.NoLinks(this.path);
            if (!File.Exists(this.path)) throw new FileNotFoundException("Файл образа не найден.");
            info = new SourceInfo { Id = this.path, Name = Path.GetFileName(this.path), Kind = "image", Status = "ready" };
        }
        public SourceInfo Info { get { return info; } }
        public IEnumerable<SourceEntry> Enumerate(string root, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();
            if (!String.IsNullOrEmpty(root) && root != path) throw new IOException("У образа нет логических папок до анализа файловой системы.");
            SourcePaths.NoLinks(path); var file = new FileInfo(path);
            yield return new SourceEntry { Id = path, OriginalPath = path, RelativePath = file.Name, Size = file.Length, Modified = file.LastWriteTimeUtc.ToString("o") };
        }
        public Stream OpenRead(SourceEntry entry, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested(); SourcePaths.NoLinks(path);
            if (entry == null || entry.Id != path) throw new IOException("Запись не принадлежит образу.");
            var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length != entry.Size || File.GetLastWriteTimeUtc(path).ToString("o") != entry.Modified) { stream.Dispose(); throw new IOException("Образ изменился после выбора."); }
            return stream;
        }
    }
}
