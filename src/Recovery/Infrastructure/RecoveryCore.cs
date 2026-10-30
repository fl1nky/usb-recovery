using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

namespace UsbRecovery
{
    public sealed class DiskInfo
    {
        public int Number;
        public string Name, Serial, UniqueId, BusType, Letters;
        public long Size;
        public int SectorSize;
        public bool IsBoot, IsSystem, IsOffline;
        public bool Eligible { get { return BusType == "USB" && !IsBoot && !IsSystem && !IsOffline && Size > 0 && (!String.IsNullOrWhiteSpace(UniqueId) || !String.IsNullOrWhiteSpace(Serial)); } }
        public override string ToString() { return String.Format("{0}  |  {1:0.0} ГБ  |  {2}  |  диск {3}", Name, Size / 1000000000.0, Letters, Number); }
        public bool SameDevice(DiskInfo other)
        {
            return other != null && other.Eligible && Eligible && Number == other.Number && Size == other.Size && SectorSize == other.SectorSize && Serial == other.Serial && UniqueId == other.UniqueId;
        }
    }

    public sealed class CaptureRequestInfo { public int Schema=1;public DiskInfo Disk;public bool TolerateErrors; }
    public static class RecoveryCore
    {
        const uint GenericRead = 0x80000000, ShareRead = 1, ShareWrite = 2, OpenExisting = 3;
        public const int ChunkSize = 4 * 1024 * 1024;
        public static string ToolPath { get { return ApplicationPaths.Tool("testdisk-7.2/photorec_win.exe"); } }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumePathName(string file, StringBuilder volume, uint length);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumeNameForVolumeMountPoint(string mount, StringBuilder volume, uint length);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumeInformation(string root, StringBuilder label, uint labelLength, out uint serial, out uint maxComponent, out uint flags, StringBuilder filesystem, uint fsLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetDiskFreeSpaceEx(string directory, out ulong available, out ulong total, out ulong free);

        static Exception WindowsError(string message)
        {
            return new IOException(message + " " + new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
        }

        public static List<DiskInfo> ListDisks()
        {
            const string script = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $r=@(Get-Disk | ForEach-Object { $d=$_; $letters=@(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter + ':' }); [pscustomobject]@{Number=[int]$d.Number;Name=[string]$d.FriendlyName;Serial=[string]$d.SerialNumber;UniqueId=[string]$d.UniqueId;BusType=[string]$d.BusType;Size=[long]$d.Size;SectorSize=[int]$d.LogicalSectorSize;IsBoot=[bool]$d.IsBoot;IsSystem=[bool]$d.IsSystem;IsOffline=[bool]$d.IsOffline;Letters=($letters -join ', ')} }); ConvertTo-Json -InputObject $r -Depth 3 -Compress";
            string powershell=Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe");
            var start = new ProcessStartInfo(powershell, "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.StandardOutputEncoding = Encoding.UTF8;
            using (var process = Process.Start(start))
            {
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(30000)) { process.Kill(); throw new IOException("Windows не ответила при поиске флешек. Попробуй обновить список."); }
                string output = outputTask.Result;
                string errors = errorTask.Result;
                if (process.ExitCode != 0) throw new IOException("Не удалось получить список дисков: " + errors);
                var values = new JavaScriptSerializer().DeserializeObject(output) as object[];
                if (values == null) throw new IOException("Не удалось проверить типы дисков.");
                var result = new List<DiskInfo>();
                foreach (Dictionary<string, object> item in values)
                {
                    result.Add(new DiskInfo {
                        Number = Convert.ToInt32(item["Number"]), Name = (string)item["Name"], Serial = (string)item["Serial"],
                        UniqueId = (string)item["UniqueId"], BusType = (string)item["BusType"], Size = Convert.ToInt64(item["Size"]),
                        SectorSize = Convert.ToInt32(item["SectorSize"]), IsBoot = (bool)item["IsBoot"], IsSystem = (bool)item["IsSystem"],
                        IsOffline = (bool)item["IsOffline"], Letters = (string)item["Letters"]
                    });
                }
                return result;
            }
        }

        // Resolve junctions before checking which physical disk receives all output.
        public static string CanonicalDirectory(string path)
        {
            if (!Directory.Exists(path)) throw new IOException("Сначала выбери существующую папку для результатов.");
            using (var handle = CreateFile(Path.GetFullPath(path), 0, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0x02000000, IntPtr.Zero))
            {
                if (handle.IsInvalid) throw WindowsError("Не удалось проверить папку результатов.");
                var result = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandle(handle, result, (uint)result.Capacity, 0);
                if (length == 0 || length >= result.Capacity) throw WindowsError("Не удалось определить реальную папку результатов.");
                string value = result.ToString();
                if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) throw new IOException("Выбери папку на локальном диске компьютера.");
                if (value.StartsWith(@"\\?\")) value = value.Substring(4);
                return value;
            }
        }

        public static int DiskForDirectory(string directory)
        {
            var mount = new StringBuilder(1024);
            var volume = new StringBuilder(1024);
            if (!GetVolumePathName(CanonicalDirectory(directory), mount, (uint)mount.Capacity) || !GetVolumeNameForVolumeMountPoint(mount.ToString(), volume, (uint)volume.Capacity))
                throw WindowsError("Не удалось проверить диск для сохранения.");
            using (var handle = CreateFile(volume.ToString().TrimEnd('\\'), 0, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero))
            {
                if (handle.IsInvalid) throw WindowsError("Не удалось проверить диск для сохранения.");
                byte[] data = new byte[4096]; uint returned;
                if (!DeviceIoControl(handle, 0x00560000, IntPtr.Zero, 0, data, (uint)data.Length, out returned, IntPtr.Zero))
                    throw WindowsError("Не удалось проверить физический диск для сохранения.");
                if (returned < 32 || BitConverter.ToUInt32(data, 0) != 1)
                    throw new IOException("Составной диск не поддерживается. Выбери обычный локальный диск.");
                return BitConverter.ToInt32(data, 8); // DISK_EXTENT is aligned to 8 bytes in this x64 build.
            }
        }

        public static void CheckSpace(string directory, long bytes)
        {CheckSpace(directory,bytes,bytes);}
        static void CheckSpace(string directory,long bytes,long imageBytes)
        {
            var root = new StringBuilder(1024);
            if (!GetVolumePathName(CanonicalDirectory(directory), root, (uint)root.Capacity)) throw WindowsError("Не удалось проверить свободное место.");
            uint serial, component, flags;
            var fs = new StringBuilder(128);
            if (!GetVolumeInformation(root.ToString(), null, 0, out serial, out component, out flags, fs, (uint)fs.Capacity)) throw WindowsError("Не удалось проверить файловую систему папки.");
            if (fs.ToString().Equals("FAT32", StringComparison.OrdinalIgnoreCase) && imageBytes >= 0x100000000L)
                throw new IOException("Копия больше 4 ГБ: выбери диск NTFS или exFAT для сохранения.");
            ulong available, capacity, free;
            if (!GetDiskFreeSpaceEx(root.ToString(), out available, out capacity, out free)) throw WindowsError("Не удалось проверить свободное место.");
            long needed = checked(bytes * 4 + 1024L * 1024 * 1024);
            if (available < (ulong)needed) throw new IOException(String.Format("Недостаточно места. Для копии и нескольких способов поиска нужно примерно {0:0.0} ГБ; свободно {1:0.0} ГБ. Выбери другой диск.", needed / 1000000000.0, available / 1000000000.0));
        }

        public static void ValidateDestination(DiskInfo source, int destinationDisk)
        {
            if (!source.Eligible) throw new IOException("Разрешены только USB-диски, с которых не запущена Windows.");
            if (source.Number == destinationDisk) throw new IOException("Нельзя сохранять копию или найденные файлы на исходную флешку. Выбери диск компьютера.");
            if (source.SectorSize <= 0 || ChunkSize % source.SectorSize != 0 || source.Size % source.SectorSize != 0)
                throw new IOException("Windows сообщила нестандартный размер секторов. Чтение остановлено.");
        }

        public static string CopyExact(Stream source, string partialPath, long size, int alignment, CancellationToken cancel, Action<long, long> progress)
        {
            cancel.ThrowIfCancellationRequested();
            if (size <= 0 || alignment <= 0 || ChunkSize % alignment != 0 || size % alignment != 0) throw new IOException("Некорректный размер источника.");
            byte[] buffer = new byte[ChunkSize]; long copied = 0;
            using (var hash = SHA256.Create())
            using (var destination = new FileStream(partialPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            {
                while (copied < size)
                {
                    cancel.ThrowIfCancellationRequested();
                    int requested = (int)Math.Min(buffer.Length, size - copied);
                    int read = source.Read(buffer, 0, requested);
                    if (read == 0) throw new IOException("Носитель перестал отдавать данные. Сохранена только неполная копия; поиск не запущен.");
                    if (read % alignment != 0) throw new IOException("Неполное чтение сектора. Поиск не запущен.");
                    destination.Write(buffer, 0, read);
                    hash.TransformBlock(buffer, 0, read, null, 0);
                    copied += read;
                    progress(copied, size);
                }
                cancel.ThrowIfCancellationRequested();
                destination.Flush(true);
                hash.TransformFinalBlock(new byte[0], 0, 0);
                return BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
            }
        }

        public static string Capture(DiskInfo selected, string runDirectory, CancellationToken cancel, Action<long, long> progress)
        { return Capture(selected, runDirectory, cancel, progress, false); }
        public static string Capture(DiskInfo selected, string runDirectory, CancellationToken cancel, Action<long, long> progress, bool tolerateErrors)
        { return CaptureInternal(selected,runDirectory,cancel,progress,tolerateErrors,false); }
        public static string CaptureIdentity(DiskInfo disk)
        {return new JavaScriptSerializer().Serialize(new{serial=disk.Serial,uniqueId=disk.UniqueId,size=disk.Size,sector=disk.SectorSize,bus=disk.BusType});}
        public static bool ResumeDeviceMatches(DiskInfo original,DiskInfo current)
        {return original!=null&&current!=null&&original.Eligible&&current.Eligible&&original.Size==current.Size&&original.SectorSize==current.SectorSize&&original.Serial==current.Serial&&original.UniqueId==current.UniqueId;}
        public static CaptureRequestInfo ReadCaptureRequest(string directory)
        {
            string file=RecoveryCatalog.SafeFile(directory,"capture-request.json");if(!File.Exists(file)||new FileInfo(file).Length>64*1024)throw new IOException("Сведения о съёме не найдены или повреждены.");
            try{var request=new JavaScriptSerializer().Deserialize<CaptureRequestInfo>(File.ReadAllText(file));if(request==null||request.Schema!=1||request.Disk==null||!request.Disk.Eligible||request.Disk.SectorSize<512||request.Disk.SectorSize>4096)throw new IOException("Некорректный источник сохранённого съёма.");return request;}
            catch(ArgumentException){throw new IOException("Не удалось прочитать сведения о съёме.");}catch(InvalidOperationException){throw new IOException("Не удалось прочитать сведения о съёме.");}
        }
        public static string ResumeCapture(string runDirectory,CancellationToken cancel,Action<long,long> progress)
        {
            var request=ReadCaptureRequest(runDirectory);var candidates=ListDisks().Where(d=>ResumeDeviceMatches(request.Disk,d)).ToArray();if(candidates.Length!=1)throw new IOException("Не удалось однозначно найти исходную флешку. Подключи её и проверь список устройств.");
            return CaptureInternal(candidates[0],runDirectory,cancel,progress,request.TolerateErrors,true);
        }
        public static string CompleteSavedCapture(string directory,CancellationToken cancel)
        {
            var request=ReadCaptureRequest(directory);string checkpoint=RecoveryCatalog.SafeFile(directory,"capture-resume.json"),image=RecoveryCatalog.SafeFile(directory,"usb.dd"),partial=RecoveryCatalog.SafeFile(directory,"usb.dd.partial");
            if(File.Exists(image)&&File.Exists(partial))throw new IOException("В папке одновременно полный и неполный образ. Они оставлены без изменений.");
            string candidate=File.Exists(image)?image:partial;if(!File.Exists(candidate)||new FileInfo(candidate).Length!=request.Disk.Size)throw new IOException("Размер образа не соответствует носителю; неполная копия не считается завершённой.");
            var info=ResumableCapture.Inspect(checkpoint);if(info.Size!=request.Disk.Size||info.SectorSize!=request.Disk.SectorSize||info.Identity!=CaptureIdentity(request.Disk))throw new IOException("Источник и контрольная точка съёма не совпадают.");
            var verified=ResumableCapture.VerifyCompletedImage(checkpoint,candidate,cancel);cancel.ThrowIfCancellationRequested();
            string checksum=image+".sha256";bool writeChecksum=!File.Exists(checksum);
            if(!writeChecksum&&(new FileInfo(checksum).Length>4096||!String.Equals(File.ReadAllText(checksum).Split((char[])null,StringSplitOptions.RemoveEmptyEntries).FirstOrDefault(),verified.Sha256,StringComparison.OrdinalIgnoreCase)))throw new IOException("Контрольная сумма готового образа изменилась.");
            if(candidate==partial)File.Move(partial,image);
            if(writeChecksum)File.WriteAllText(checksum,verified.Sha256+"  usb.dd\r\n",new UTF8Encoding(false));
            string state=verified.UnreadBytes>0?"complete_with_read_errors":"complete";SaveJson(image+".read-errors.json",new{status=state,size=request.Disk.Size,copied=request.Disk.Size,unreadBytes=verified.UnreadBytes,ranges=verified.Ranges,note="Unread ranges are placeholders. Reverified completed image against committed acquisition chunk journal."});
            SaveJson(RecoveryCatalog.SafeFile(directory,"capture.json"),new{status=state,utc=DateTime.UtcNow.ToString("o"),size=request.Disk.Size,sha256=verified.Sha256,unreadBytes=verified.UnreadBytes,sourceDisk=request.Disk.Number,sourceSerial=request.Disk.Serial,sourceUniqueId=request.Disk.UniqueId,sourceName=request.Disk.Name,access="GENERIC_READ",completion="verified_chunk_journal"});return image;
        }
        public static void ValidateSavedCaptureDestination(string directory)
        {
            var request=ReadCaptureRequest(directory);string image=RecoveryCatalog.SafeFile(directory,"usb.dd");
            if(File.Exists(image)&&new FileInfo(image).Length!=request.Disk.Size)throw new IOException("Размер образа не соответствует исходному носителю.");
            int number=DiskForDirectory(directory);var target=ListDisks().FirstOrDefault(d=>d.Number==number);if(target==null)throw new IOException("Не удалось проверить диск папки сохранённого съёма.");
            if(!String.IsNullOrEmpty(request.Disk.UniqueId)&&request.Disk.UniqueId==target.UniqueId||!String.IsNullOrEmpty(request.Disk.Serial)&&request.Disk.Serial==target.Serial)throw new IOException("Папка находится на исходной флешке. Перенеси всю папку на другой диск перед продолжением.");
        }
        static string CaptureInternal(DiskInfo selected,string runDirectory,CancellationToken cancel,Action<long,long> progress,bool tolerateErrors,bool resuming)
        {
            DiskInfo current = ListDisks().FirstOrDefault(d => d.Number == selected.Number);
            if (!selected.SameDevice(current)) throw new IOException("Флешка изменилась или отключена. Обнови список и выбери её заново.");
            ValidateDestination(current, DiskForDirectory(runDirectory));
            string partial = RecoveryCatalog.SafeFile(runDirectory, "usb.dd.partial"),image=RecoveryCatalog.SafeFile(runDirectory,"usb.dd"),checkpoint=RecoveryCatalog.SafeFile(runDirectory,"capture-resume.json");
            if(File.Exists(image))throw new IOException("Полный образ уже существует. Продолжи поиск по нему.");
            CheckSpace(runDirectory,resuming?Math.Max(current.SectorSize,current.Size-(File.Exists(partial)?new FileInfo(partial).Length:0)):current.Size,current.Size);
            if(resuming){var request=ReadCaptureRequest(runDirectory);if(!ResumeDeviceMatches(request.Disk,current))throw new IOException("Подключена другая флешка.");}
            else {if(File.Exists(partial)||File.Exists(checkpoint))throw new IOException("В папке есть незавершённый съём. Используй «Продолжить…».");SaveJson(RecoveryCatalog.SafeFile(runDirectory,"capture-request.json"),new CaptureRequestInfo{Disk=current,TolerateErrors=tolerateErrors});}
            using (var handle = CreateFile(@"\\.\PhysicalDrive" + current.Number, GenericRead, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero))
            {
                if (handle.IsInvalid) throw WindowsError("Не удалось открыть флешку для чтения. Нужны права администратора.");
                byte[] data = new byte[12]; uint returned;
                if (!DeviceIoControl(handle, 0x002D1080, IntPtr.Zero, 0, data, (uint)data.Length, out returned, IntPtr.Zero) || returned < 12 || BitConverter.ToInt32(data, 4) != current.Number)
                    throw new IOException("Не удалось проверить открытый USB-диск.");
                if (!current.SameDevice(ListDisks().FirstOrDefault(d => d.Number == current.Number))) throw new IOException("Флешка изменилась перед чтением. Обнови список.");
                string digest;
                long unread = 0;
                using (var source = new FileStream(handle, FileAccess.Read, ChunkSize, false))
                {
                    var copy=ResumableCapture.Copy(source,partial,current.Size,current.SectorSize,CaptureIdentity(current),checkpoint,image+".read-errors.json",cancel,progress,()=>current.SameDevice(ListDisks().FirstOrDefault(d=>d.Number==current.Number)),resuming,tolerateErrors,true);
                    digest=copy.Sha256;unread=copy.UnreadBytes;
                }
                cancel.ThrowIfCancellationRequested();
                File.Move(partial, image);
                File.WriteAllText(image + ".sha256", digest + "  usb.dd\r\n", new UTF8Encoding(false));
                SaveJson(Path.Combine(runDirectory, "capture.json"), new { status = unread > 0 ? "complete_with_read_errors" : "complete", unreadBytes = unread, utc = DateTime.UtcNow.ToString("o"), size = current.Size, sha256 = digest, access = "GENERIC_READ", sourceDisk = current.Number, sourceSerial=current.Serial,sourceUniqueId=current.UniqueId, sourceName = current.Name });
                return image;
            }
        }

        public static void SaveJson(string path, object data)
        {
            string temporary=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path)),".r"+Guid.NewGuid().ToString("N").Substring(0,12)+".partial");
            try {
                byte[] bytes=new UTF8Encoding(false).GetBytes(new JavaScriptSerializer{MaxJsonLength=256*1024*1024}.Serialize(data));
                using(var output=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(bytes,0,bytes.Length);output.Flush(true);}
                for(int attempt=0;;attempt++){
                    try{if(File.Exists(path))File.Replace(temporary,path,null);else File.Move(temporary,path);break;}
                    catch(IOException error){
                        uint code=unchecked((uint)error.HResult);
                        if(attempt>=3||!File.Exists(temporary)||(code!=0x80070020U&&code!=0x80070021U&&code!=0x80070497U))throw;
                        // Brief readers/security filters may deny delete sharing.
                        // Retry the same atomic operation; never delete the target.
                        Thread.Sleep(25<<attempt);
                    }
                }
            } finally {if(File.Exists(temporary))File.Delete(temporary);}
        }

        public static string HashFile(string path, CancellationToken cancel, Action<long, long> progress)
        {
            cancel.ThrowIfCancellationRequested();
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var hash = SHA256.Create())
            {
                byte[] buffer = new byte[ChunkSize]; long total = stream.Length, done = 0; int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    cancel.ThrowIfCancellationRequested(); hash.TransformBlock(buffer, 0, count, null, 0); done += count; progress(done, total);
                }
                cancel.ThrowIfCancellationRequested();
                hash.TransformFinalBlock(new byte[0], 0, 0);
                return BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
            }
        }

        public static void VerifyImage(string image, CancellationToken cancel, Action<long, long> progress)
        { VerifyImage(image, image + ".sha256", cancel, progress); }
        public static void VerifyImage(string image, string checksumPath, CancellationToken cancel, Action<long, long> progress)
        {
            if (!File.Exists(checksumPath)) throw new IOException("Нет файла .sha256 для проверки копии.");
            string[] tokens = File.ReadAllText(checksumPath, Encoding.UTF8).Split(new[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0 || tokens[0].Length != 64 || tokens[0].Any(c => !Uri.IsHexDigit(c))) throw new IOException("Файл контрольной суммы копии повреждён.");
            if (HashFile(image, cancel, progress) != tokens[0].ToLowerInvariant()) throw new IOException("Проверка копии не прошла: содержимое отличается от сохранённой контрольной суммы.");
        }

        public static string PhotoRecArguments(string image, string runDirectory)
        {
            return PhotoRecArguments(image, runDirectory, false);
        }
        public static string PhotoRecArguments(string image, string runDirectory, bool deep)
        {
            // No physical device is ever passed to PhotoRec. Scan the entire regular image.
            return "/log /logname " + Quote(Path.Combine(runDirectory, "photorec.log")) + " /d " + Quote(Path.Combine(runDirectory, "files")) + " /cmd " + Quote(image) + " " + (deep ? AdvancedEngines.DeepPhotoRecCommand : "partition_none,fileopt,everything,enable,wholespace,search");
        }

        static string Quote(string value)
        {
            if (value.IndexOf('"') >= 0 || value.EndsWith("\\")) throw new IOException("Недопустимый путь.");
            return "\"" + value + "\"";
        }

        public static int Recover(string image, string runDirectory, CancellationToken cancel, Action<int> progress)
        {
            return Recover(image, runDirectory, false, cancel, progress);
        }
        public static int Recover(string image, string runDirectory, bool deep, CancellationToken cancel, Action<int> progress)
        { return Recover(image, runDirectory, deep, cancel, progress, null); }
        public static int Recover(string image, string runDirectory, bool deep, CancellationToken cancel, Action<int> progress, RecoveryOptions options)
        {
            cancel.ThrowIfCancellationRequested();
            if (!File.Exists(ToolPath)) throw new IOException("Не найден PhotoRec. Скопируй всю папку программы вместе с tools.");
            if (!File.Exists(image) || new FileInfo(image).Length == 0 || image.StartsWith(@"\\.\") || image.StartsWith(@"\\?\"))
                throw new IOException("Для поиска нужна обычная непустая копия usb.dd.");
            string arguments = options == null ? PhotoRecArguments(image, runDirectory, deep) : "/log /logname " + Quote(Path.Combine(runDirectory,"photorec.log")) + " /d " + Quote(Path.Combine(runDirectory,"files")) + " /cmd " + Quote(image) + " " + options.PhotoRecCommand();
            var start = new ProcessStartInfo(ToolPath, arguments);
            start.UseShellExecute = false; start.CreateNoWindow = true; start.WorkingDirectory = runDirectory;
            start.RedirectStandardOutput = start.RedirectStandardError = true;
            // Old Cygwin argv/glob handling otherwise retains quotes around paths with spaces.
            start.EnvironmentVariables["CYGWIN"] = "noglob";
            start.EnvironmentVariables["LANG"] = "C.UTF-8";
            start.EnvironmentVariables["LC_ALL"] = "C.UTF-8";
            using (var process = Process.Start(start))
            {
                // Keep the legacy console UI inside the modern application.
                // Drain both streams without accumulating terminal output.
                Task stdout=Task.Run(()=>{char[] data=new char[4096];while(process.StandardOutput.Read(data,0,data.Length)>0){};});
                Task stderr=Task.Run(()=>{char[] data=new char[4096];while(process.StandardError.Read(data,0,data.Length)>0){};});
                try
                {
                    while (!process.WaitForExit(1000))
                    {
                        cancel.ThrowIfCancellationRequested();
                        progress(PhotoRecFiles(runDirectory).Count());
                    }
                    cancel.ThrowIfCancellationRequested();
                    if (process.ExitCode != 0) throw new IOException("PhotoRec завершился с кодом " + process.ExitCode + ". См. photorec.log в папке результата.");
                }
                catch { if (!process.HasExited) { process.Kill(); process.WaitForExit(); } throw; }
                finally {try{Task.WaitAll(new[]{stdout,stderr},3000);}catch(AggregateException){}}
            }
            string logPath = Path.Combine(runDirectory, "photorec.log");
            bool normalExit = false, hasSummary = false;
            if (File.Exists(logPath)) foreach (string line in File.ReadLines(logPath, Encoding.UTF8)) { if (line.Contains("PhotoRec exited normally.")) normalExit = true; if (line.StartsWith("Total: ")) hasSummary = true; }
            if (File.Exists(Path.Combine(runDirectory, "photorec.ses")) || !normalExit || !hasSummary)
                throw new IOException("Полное завершение поиска не подтверждено. Уже найденные файлы сохранены; для нового поиска выбери полную usb.dd.");
            return PhotoRecFiles(runDirectory).Count();
        }

        static IEnumerable<string> PhotoRecFiles(string runDirectory)
        {
            return Directory.EnumerateDirectories(runDirectory, "files.*").SelectMany(d => Directory.EnumerateFiles(d, "*", SearchOption.AllDirectories)).Where(p => !Path.GetFileName(p).Equals("report.xml", StringComparison.OrdinalIgnoreCase));
        }

        public static IEnumerable<string> RecoveredFiles(string runDirectory)
        {return RecoveredFilesCore(runDirectory,0);}
        static IEnumerable<string> RecoveredFilesCore(string runDirectory,int depth)
        {
            var roots = Directory.EnumerateDirectories(runDirectory, "files.*").ToList();
            string fs = Path.Combine(runDirectory, "filesystem", "files"), extra = Path.Combine(runDirectory, "extra-photos"), ntfs = Path.Combine(runDirectory, "ntfs");
            if (Directory.Exists(fs)) roots.Add(fs);
            if (Directory.Exists(extra)) roots.Add(extra);
            string apfs=Path.Combine(runDirectory,"apfs-files");if(Directory.Exists(apfs))roots.Add(apfs);
            string containers = Path.Combine(runDirectory, "containers"); if (Directory.Exists(containers)) roots.Add(containers);
            string fragments = Path.Combine(runDirectory, "text-fragments"); if (Directory.Exists(fragments)) roots.Add(fragments);
            string records = Path.Combine(runDirectory, "metadata-rescue", "files"); if (Directory.Exists(records)) roots.Add(records);
            string ext4 = Path.Combine(runDirectory, "ext4", "files"); if (Directory.Exists(ext4)) roots.Add(ext4);
            string members = Path.Combine(runDirectory, "salvage-content"); if (Directory.Exists(members)) roots.Add(members);
            string assembled = Path.Combine(runDirectory, "fragmented-archives"); if (Directory.Exists(assembled)) roots.Add(assembled);
            string photoPieces=Path.Combine(runDirectory,"fragmented-photos"),videoPieces=Path.Combine(runDirectory,"fragmented-media");
            if(Directory.Exists(photoPieces))roots.Add(photoPieces);if(Directory.Exists(videoPieces))roots.Add(videoPieces);
            string custom = Path.Combine(runDirectory, "user-signatures"); if (Directory.Exists(custom)) roots.Add(custom);
            if (Directory.Exists(ntfs)) foreach (string partition in Directory.EnumerateDirectories(ntfs, "partition-*")) if (Directory.Exists(Path.Combine(partition, "data"))) roots.Add(Path.Combine(partition, "data"));
            IEnumerable<string> files=roots.SelectMany(d=>Directory.EnumerateFiles(d,"*",SearchOption.AllDirectories)).Where(p=>!Path.GetFileName(p).Equals("report.xml",StringComparison.OrdinalIgnoreCase)&&!p.EndsWith(".partial",StringComparison.OrdinalIgnoreCase)&&!String.Equals(p,Path.Combine(photoPieces,"report.json"),StringComparison.OrdinalIgnoreCase)&&!String.Equals(p,Path.Combine(photoPieces,"job.incomplete"),StringComparison.OrdinalIgnoreCase));
            string history=RecoveryCatalog.SafeFile(runDirectory,"attempt-history");
            if(depth==0&&Directory.Exists(history)){
                var prior=Directory.EnumerateDirectories(history).Take(257).ToArray();if(prior.Length>256)throw new IOException("Слишком много предыдущих попыток поиска.");
                foreach(string attempt in prior){RecoveryCatalog.SafeFile(runDirectory,"attempt-history/"+Path.GetFileName(attempt)+"/guard");files=files.Concat(RecoveredFilesCore(attempt,1));}
            }
            return files;
        }
    }
}
