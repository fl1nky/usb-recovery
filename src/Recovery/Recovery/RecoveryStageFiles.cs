using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UsbRecovery
{
    internal sealed class RecoveryStageFiles
    {
        readonly string root;
        internal RecoveryStageFiles(string directory)
        {
            root = Path.GetFullPath(directory);
        }

        static readonly Dictionary<string, string[]> OutputNames = new Dictionary<string, string[]>
        {
            {
                "partitions",
                new[]
                {
                    "partition-search.json"
                }
            },
            {
                "fat",
                new[]
                {
                    "filesystem"
                }
            },
            {
                "ntfs",
                new[]
                {
                    "ntfs"
                }
            },
            {
                "ext4",
                new[]
                {
                    "ext4"
                }
            },
            {
                "refs",
                new[]
                {
                    "refs"
                }
            },
            {
                "apfs",
                new[]
                {
                    "apfs"
                }
            },
            {
                "ntfs-records",
                new[]
                {
                    "metadata-rescue"
                }
            },
            {
                "photorec",
                new[]
                {
                    "photorec.log",
                    "photorec.ses"
                }
            },
            {
                "photos",
                new[]
                {
                    "extra-photos",
                    "extra-photo-search.json"
                }
            },
            {
                "containers",
                new[]
                {
                    "containers",
                    "container-search.json"
                }
            },
            {
                "archive-members",
                new[]
                {
                    "salvage-content",
                    "archive-salvage.json"
                }
            },
            {
                "fragmented-zip",
                new[]
                {
                    "fragmented-archives",
                    "fragmented-zip.json"
                }
            },
            {
                "fragmented-photos",
                new[]
                {
                    "fragmented-photos",
                    "fragmented-photos.state",
                    "fragmented-photos.index",
                    "fragmented-photo-search.json"
                }
            },
            {
                "fragmented-media",
                new[]
                {
                    "fragmented-media",
                    "fragmented-media.json"
                }
            },
            {
                "user-signatures",
                new[]
                {
                    "user-signatures",
                    "user-signatures.json"
                }
            },
            {
                "text",
                new[]
                {
                    "text-fragments",
                    "text-search.json"
                }
            },
        };
        internal static readonly string[] Keys = OutputNames.Keys.ToArray();
        internal static IEnumerable<string> Paths(string root, string key)
        {
            string[] names;
            if (!OutputNames.TryGetValue(key, out names))
                names = OutputNames["photorec"];
            foreach (string name in names)
            {
                string path = RecoveryCatalog.SafeFile(root, name);
                if (File.Exists(path) || Directory.Exists(path))
                    yield return path;
            }

            if (key == "photorec")
                foreach (string path in Directory.EnumerateDirectories(root, "files.*"))
                {
                    RecoveryCatalog.SafeFile(root, Path.GetFileName(path) + "/guard");
                    yield return path;
                }
        }

        internal IEnumerable<string> Files(string key)
        {
            foreach (string path in Paths(root, key))
            {
                if (File.Exists(path))
                {
                    yield return path;
                    continue;
                }

                var todo = new Stack<string>();
                todo.Push(path);
                while (todo.Count > 0)
                {
                    string at = todo.Pop();
                    RecoveryCatalog.SafeFile(root, at.Substring(root.TrimEnd('\\').Length + 1) + "/guard");
                    foreach (string file in Directory.EnumerateFiles(at))
                        if (!file.EndsWith(".partial", StringComparison.OrdinalIgnoreCase))
                            yield return file;
                    foreach (string child in Directory.EnumerateDirectories(at))
                        todo.Push(child);
                }
            }
        }

        internal void Archive(string key)
        {
            string[] paths = Paths(root, key).ToArray();
            if (paths.Length == 0)
                return;
            int files = 0;
            foreach (string path in Files(key))
            {
                if (++files > 100000)
                    throw new IOException("Слишком много файлов предыдущей попытки. Создай новый поиск.");
                RecoveryCatalog.SafeFile(root, path.Substring(root.TrimEnd('\\').Length + 1));
            }

            string target = RecoveryCatalog.SafeFile(root, "attempt-history/" + key.Substring(0, Math.Min(4, key.Length)) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + "/note.json");
            foreach (string path in Files(key))
            {
                string start = paths.First(p => path == p || path.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
                string name = Path.GetFileName(start);
                string future = Path.Combine(Path.GetDirectoryName(target), name) + path.Substring(start.Length);
                if (future.Length > 32700)
                    throw new IOException("Путь предыдущей попытки слишком длинный. Перенеси всю папку съёма ближе к корню диска и продолжи.");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target));
            foreach (string path in paths)
            {
                string dest = RecoveryCatalog.SafeFile(root, Path.GetDirectoryName(target).Substring(root.TrimEnd('\\').Length + 1) + "/" + Path.GetFileName(path));
                if (Directory.Exists(path))
                    Directory.Move(path, dest);
                else
                    File.Move(path, dest);
            }

            RecoveryCore.SaveJson(target, new { stage = key, status = "previous_interrupted_attempt", note = "Completed candidates retained. An interrupted method restarted from its beginning; previous output may be partial." });
        }
    }
}
