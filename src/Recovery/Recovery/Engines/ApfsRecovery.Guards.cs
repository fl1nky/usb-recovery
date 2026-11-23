// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
namespace UsbRecovery
{
    public static partial class ApfsRecovery
    {
        static string HashStream(Stream input,CancellationToken cancel)
        {
            input.Position = 0;
            using (var sha = SHA256.Create()) {
                byte[] bytes = new byte[65536]; int count;
                while ((count = input.Read(bytes,0,bytes.Length)) != 0) { cancel.ThrowIfCancellationRequested(); sha.TransformBlock(bytes,0,count,bytes,0); }
                sha.TransformFinalBlock(new byte[0],0,0); return Hex(sha.Hash);
            }
        }
        private static string LocalFile(string file)
        {
            string path = Path.GetFullPath(file);
            if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.IndexOf(':', 2) >= 0 ||
                !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.Directory) != 0)
                throw new IOException("Требуется обычный локальный образ apfs");
            NoLinks(path);
            return path;
        }

        private static void NoLinks(string path)
        {
            string current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                try
                {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Ссылки в пути apfs запрещены");
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
                string parent = Path.GetDirectoryName(current);
                if (parent == current) break;
                current = parent;
            }
        }

    }
}
