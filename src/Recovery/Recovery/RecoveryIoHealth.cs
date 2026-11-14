using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace UsbRecovery
{
    public sealed class RecoveryIoUnavailableException : IOException
    {
        public readonly string Code;
        public RecoveryIoUnavailableException(string code, string message, Exception inner) : base(message, inner)
        {
            Code = code;
        }
    }

    // The source and existing files remain unchanged. Probe only a fresh owned temporary.
    // This detects unavailable/replaced handles; a full SHA is still mandatory on resume.
    public sealed class RecoveryIoHealth
    {
        [StructLayout(LayoutKind.Sequential)]
        struct Identity
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Identity value);
        readonly FileStream source, runLock;
        readonly string sourcePath;
        readonly Identity originalSource, originalOutput;
        readonly long sourceBytes;
        static Identity ReadIdentity(FileStream file)
        {
            Identity value;
            if (file == null || !GetFileInformationByHandle(file.SafeFileHandle, out value))
                throw new IOException("Не удалось проверить доступность носителя.");
            return value;
        }

        static bool Same(Identity a, Identity b)
        {
            return a.Volume == b.Volume && a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow;
        }

        public RecoveryIoHealth(string path, Stream sourceStream, IDisposable outputLock)
        {
            sourcePath = Path.GetFullPath(path);
            source = sourceStream as FileStream;
            runLock = outputLock as FileStream;
            originalSource = ReadIdentity(source);
            originalOutput = ReadIdentity(runLock);
            sourceBytes = source.Length;
            if (Same(originalSource, originalOutput))
                throw new IOException("Источник не может совпадать с файлом блокировки результатов.");
        }

        public void Check(CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();
            try
            {
                Identity held = ReadIdentity(source);
                if (!Same(held, originalSource) || source.Length != sourceBytes || held.SizeHigh != originalSource.SizeHigh || held.SizeLow != originalSource.SizeLow || held.Written.dwHighDateTime != originalSource.Written.dwHighDateTime || held.Written.dwLowDateTime != originalSource.Written.dwLowDateTime)
                    throw new IOException("Идентификатор или размер исходного образа изменился.");
                using (var reopened = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (!Same(ReadIdentity(reopened), originalSource) || reopened.Length != sourceBytes)
                        throw new IOException("Путь указывает на другой исходный образ.");
                    if (sourceBytes > 0)
                    {
                        reopened.Position = sourceBytes - 1;
                        if (reopened.ReadByte() < 0)
                            throw new EndOfStreamException();
                    }
                }
            }
            catch (IOException error)
            {
                throw new RecoveryIoUnavailableException("RECOVERY_SOURCE_UNAVAILABLE", "Исходный образ недоступен или изменился. Подключи носитель и нажми «Продолжить». Ранее сохранённые результаты остаются в папке поиска.", error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw new RecoveryIoUnavailableException("RECOVERY_SOURCE_UNAVAILABLE", "Нет доступа к исходному образу. Восстанови доступ и продолжи сохранённую сессию.", error);
            }
            catch (ObjectDisposedException error)
            {
                throw new RecoveryIoUnavailableException("RECOVERY_SOURCE_UNAVAILABLE", "Источник отключён. Подключи носитель и продолжи сохранённую сессию.", error);
            }

            cancel.ThrowIfCancellationRequested();
            try
            {
                if (!Same(ReadIdentity(runLock), originalOutput))
                    throw new IOException("Носитель результатов изменился.");
                runLock.Flush(true);
                string folder = Path.GetDirectoryName(runLock.Name);
                string probe = RecoveryCatalog.SafeFile(folder, ".io-" + Guid.NewGuid().ToString("N") + ".partial");
                using (var temporary = new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose | FileOptions.WriteThrough))
                    temporary.Flush(true);
            }
            catch (IOException error)
            {
                throw new RecoveryIoUnavailableException("RECOVERY_OUTPUT_UNAVAILABLE", "Папка результатов недоступна. Подключи прежний носитель и продолжи сохранённую сессию.", error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw new RecoveryIoUnavailableException("RECOVERY_OUTPUT_UNAVAILABLE", "Нет доступа к папке результатов. Восстанови доступ и продолжи сохранённую сессию.", error);
            }
            catch (ObjectDisposedException error)
            {
                throw new RecoveryIoUnavailableException("RECOVERY_OUTPUT_UNAVAILABLE", "Носитель результатов отключён. Подключи его и продолжи сохранённую сессию.", error);
            }
        }
    }
}
