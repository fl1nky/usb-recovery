using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UsbRecovery
{
    internal static class PhotoRecRunner
    {
        const string DefaultCommand = "partition_none,fileopt,everything,enable,wholespace,search";

        internal static string Arguments(string image, string directory, bool deep, RecoveryOptions options)
        {
            string command = deep ? AdvancedEngines.DeepPhotoRecCommand : DefaultCommand;
            if (options != null) command = options.PhotoRecCommand();
            return "/log /logname " + Quote(Path.Combine(directory, "photorec.log")) +
                " /d " + Quote(Path.Combine(directory, "files")) + " /cmd " + Quote(image) + " " + command;
        }

        private static Process StartImageScanner(ProcessStartInfo start)
        {
            try
            {
                return Process.Start(start);
            }
            catch (System.ComponentModel.Win32Exception error)
            {
                if (error.NativeErrorCode != 740) throw;
                throw new IOException("Windows требует права администратора для PhotoRec. Для этого метода открой программу от имени администратора и продолжи сохранённый поиск.", error);
            }
        }

        static string Quote(string path)
        {
            if (path.Contains("\"") || path.EndsWith("\\", StringComparison.Ordinal))
                throw new IOException("Недопустимый путь.");
            return "\"" + path + "\"";
        }

        internal static int Run(string image, string directory, bool deep, RecoveryOptions options,
            CancellationToken cancel, Action<int> progress)
        {
            cancel.ThrowIfCancellationRequested();
            if (!File.Exists(RecoveryCore.ToolPath))
                throw new IOException("Не найден PhotoRec. Скопируй всю папку программы вместе с tools.");
            image = Path.GetFullPath(image);
            directory = Path.GetFullPath(directory);
            if (image.StartsWith(@"\\.\") || image.StartsWith(@"\\?\") || !File.Exists(image))
                throw new IOException("Для поиска нужна обычная непустая копия usb.dd.");
            if (RecoveryStageFiles.Paths(directory, "photorec").Any())
                throw new IOException("В папке уже есть данные PhotoRec. Открой сохранённый поиск или выбери новую папку.");

            var start = new ProcessStartInfo(RecoveryCore.ToolPath, Arguments(image, directory, deep, options)) {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = directory,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            // Cygwin must preserve quoted Unicode paths as individual arguments.
            start.EnvironmentVariables["CYGWIN"] = "noglob";
            start.EnvironmentVariables["LANG"] = start.EnvironmentVariables["LC_ALL"] = "C.UTF-8";
            using (var source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (source.Length == 0) throw new IOException("Образ пуст.");
                RecoveryCore.CheckRecoveryReserve(directory);
                using (var job = ProcessJob.ForLifetimeOnly())
                using (var process = StartImageScanner(start))
                {
                    job.Attach(process);
                    try
                    {
                        Task output = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
                        Task errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
                        var clock = Stopwatch.StartNew();
                        long nextCount = 0;
                        while (!process.WaitForExit(1000))
                        {
                            cancel.ThrowIfCancellationRequested();
                            RecoveryCore.CheckRecoveryReserve(directory);
                            if (progress != null && clock.ElapsedMilliseconds >= nextCount)
                            {
                                long startCount = clock.ElapsedMilliseconds;
                                progress(CountCandidates(directory, cancel));
                                long elapsed = clock.ElapsedMilliseconds - startCount;
                                nextCount = clock.ElapsedMilliseconds + Math.Max(1000, 10 * elapsed);
                            }
                        }
                        cancel.ThrowIfCancellationRequested();
                        Task.WaitAll(new[] { output, errors }, cancel);
                        if (process.ExitCode != 0)
                            throw new IOException("PhotoRec завершился с кодом " + process.ExitCode + ". См. photorec.log.");
                    }
                    finally
                    {
                        if (!process.HasExited) { job.Stop(); process.WaitForExit(); }
                    }
                }
            }
            VerifyCompletion(directory, cancel);
            return CountCandidates(directory, cancel);
        }

        static int CountCandidates(string directory, CancellationToken cancel)
        {
            int count = 0;
            foreach (string root in Directory.EnumerateDirectories(directory, "files.*"))
                foreach (string path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    cancel.ThrowIfCancellationRequested();
                    if (!Path.GetFileName(path).Equals("report.xml", StringComparison.OrdinalIgnoreCase))
                        count++;
                }
            return count;
        }

        static readonly Regex Pass = new Regex(@"^Pass [0-9]+ \(blocksize=[0-9]+\) STATUS_[A-Z0-9_]+$");
        static readonly Regex Total = new Regex(@"^Total: [0-9]+ files? found$");

        internal static void VerifyCompletion(string directory, CancellationToken cancel)
        {
            string log = Path.Combine(directory, "photorec.log");
            if (File.Exists(Path.Combine(directory, "photorec.ses")) || !File.Exists(log))
                throw new IOException("Поиск PhotoRec прерван. Уже найденные файлы сохранены.");

            bool scanned = false, summarized = false;
            string last = null;
            foreach (string line in File.ReadLines(log, Encoding.UTF8))
            {
                cancel.ThrowIfCancellationRequested();
                if (String.IsNullOrWhiteSpace(line)) continue;
                last = line;
                if (line.StartsWith("Cannot write to file ", StringComparison.Ordinal) ||
                    line.StartsWith("Cannot create file ", StringComparison.Ordinal) ||
                    line.StartsWith("Syntax error ", StringComparison.Ordinal))
                    throw new IOException("PhotoRec сообщил об ошибке. Подробности в photorec.log.");
                if (Pass.IsMatch(line)) { scanned = true; summarized = false; }
                if (scanned && Total.IsMatch(line)) summarized = true;
            }
            if (!summarized || last != "PhotoRec exited normally.")
                throw new IOException("Полное завершение поиска не подтверждено журналом PhotoRec.");
        }
    }
}
