using System;
using System.IO;

namespace UsbRecovery
{
    internal static class RecoveryLongPath
    {
        // Keep ordinary paths in reports and checkpoint identities. Add the Windows
        // extended prefix only at I/O boundaries that exceed the legacy limit.
        static string ForIo(string path, int limit)
        {
            string full = Path.GetFullPath(path);
            if (full.Length >= limit && full[1] == ':' && full[2] == '\\')
                return @"\\?\" + full;
            return full;
        }

        internal static string FileName(string path) { return ForIo(path, 260); }
        internal static string DirectoryName(string path) { return ForIo(path, 248); }
        internal static string SearchDirectory(string path, string pattern)
        {
            return ForIo(path, Math.Min(248, 259 - pattern.Length));
        }

        internal static void Move(string source, string destination)
        {
            File.Move(FileName(source), FileName(destination));
        }

        internal static void Replace(string source, string destination)
        {
            File.Replace(FileName(source), FileName(destination), null);
        }

        internal static void CreateDirectory(string directory)
        {
            Directory.CreateDirectory(DirectoryName(directory));
        }
    }
}
