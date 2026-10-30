using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Threading;

namespace UsbRecovery
{
    // Native WPD definitions follow Microsoft's PortableDeviceApi.h / PortableDeviceTypes.h.
    // Only the read operations needed below are exposed. No device write/delete interfaces exist here.
    internal static class WpdInterop
    {
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        internal struct PropertyKey
        {
            internal Guid Format;
            internal uint Id;
            internal PropertyKey(string format, uint id) { Format = new Guid(format); Id = id; }
        }

        // PROPVARIANT is 24 bytes in the application's Windows x64 build.
        [StructLayout(LayoutKind.Explicit, Size = 24)]
        internal struct PropVariant
        {
            [FieldOffset(0)] internal ushort Type;
            [FieldOffset(8)] internal ulong Unsigned;
            [FieldOffset(8)] internal long Signed;
            [FieldOffset(8)] internal double Date;
            [FieldOffset(8)] internal IntPtr Pointer;
        }

        [ComImport, Guid("a1567595-4c2f-4574-a6fa-ecef917b9a40"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface Manager
        {
            [PreserveSig] int GetDevices(IntPtr ids, ref uint count);
            [PreserveSig] int RefreshDeviceList();
            [PreserveSig] int GetDeviceFriendlyName([MarshalAs(UnmanagedType.LPWStr)] string id, IntPtr name, ref uint characters);
        }

        [ComImport, Guid("625e2df8-6392-4cf0-9ad1-3cfa5f17775c"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface Device
        {
            [PreserveSig] int Open([MarshalAs(UnmanagedType.LPWStr)] string id, Values client);
            [PreserveSig] int SendCommand(uint flags, Values parameters, out Values results);
            [PreserveSig] int Content(out Content content);
            [PreserveSig] int Capabilities(out IntPtr capabilities);
            [PreserveSig] int Cancel();
            [PreserveSig] int Close();
        }

        [ComImport, Guid("6a96ed84-7c73-4480-9938-bf5af477d426"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface Content
        {
            [PreserveSig] int EnumObjects(uint flags, [MarshalAs(UnmanagedType.LPWStr)] string parent, Values filter, out ObjectEnumerator enumerator);
            [PreserveSig] int Properties(out Properties properties);
            [PreserveSig] int Transfer(out Resources resources);
        }

        [ComImport, Guid("10ece955-cf41-4728-bfa0-41eedf1bbf19"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface ObjectEnumerator
        {
            [PreserveSig] int Next(uint count, IntPtr ids, out uint fetched);
        }

        [ComImport, Guid("7f6d695c-03df-4439-a809-59266beee3a6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface Properties
        {
            [PreserveSig] int GetSupportedProperties([MarshalAs(UnmanagedType.LPWStr)] string id, out IntPtr keys);
            [PreserveSig] int GetPropertyAttributes([MarshalAs(UnmanagedType.LPWStr)] string id, ref PropertyKey key, out Values attributes);
            [PreserveSig] int GetValues([MarshalAs(UnmanagedType.LPWStr)] string id, IntPtr keys, out Values values);
        }

        [ComImport, Guid("fd8878ac-d841-4d17-891c-e6829cdb6934"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface Resources
        {
            [PreserveSig] int GetSupportedResources([MarshalAs(UnmanagedType.LPWStr)] string id, out IntPtr keys);
            [PreserveSig] int GetResourceAttributes([MarshalAs(UnmanagedType.LPWStr)] string id, ref PropertyKey key, out Values attributes);
            [PreserveSig] int GetStream([MarshalAs(UnmanagedType.LPWStr)] string id, ref PropertyKey key, uint mode, ref uint optimal, out IStream stream);
        }

        [ComImport, Guid("6848f6f2-3155-4f86-b6f5-263eeeab3143"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface Values
        {
            [PreserveSig] int GetCount(out uint count);
            [PreserveSig] int GetAt(uint index, ref PropertyKey key, ref PropVariant value);
            [PreserveSig] int SetValue(ref PropertyKey key, ref PropVariant value);
            [PreserveSig] int GetValue(ref PropertyKey key, out PropVariant value);
            [PreserveSig] int SetStringValue(ref PropertyKey key, [MarshalAs(UnmanagedType.LPWStr)] string value);
            [PreserveSig] int GetStringValue(ref PropertyKey key, [MarshalAs(UnmanagedType.LPWStr)] out string value);
            [PreserveSig] int SetUnsignedIntegerValue(ref PropertyKey key, uint value);
        }

        [DllImport("ole32.dll")] static extern int PropVariantClear(ref PropVariant value);

        const string ObjectFormat = "EF6B490D-5CD8-437A-AFFC-DA8B60EE4A3C";
        const string ClientFormat = "204D9F0C-2292-4080-9F42-40664E70F859";
        static readonly Guid FolderType = new Guid("27E2E392-A111-48E0-AB0C-E17705A05F85");
        static readonly Guid FunctionalType = new Guid("99ED0160-17FF-4C44-9D98-1D7A6F941921");

        static T Activate<T>(string classId)
        {
            return (T)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid(classId), true));
        }

        internal static void Release(object instance)
        {
            if (instance != null && Marshal.IsComObject(instance)) Marshal.FinalReleaseComObject(instance);
        }

        internal static void Check(int result, string action)
        {
            if (result < 0) throw new IOException(action + " Код Windows: 0x" + result.ToString("X8", CultureInfo.InvariantCulture) + ". Разблокируйте телефон и разрешите передачу файлов.");
        }

        internal static List<SourceInfo> Discover()
        {
            var result = new List<SourceInfo>();
            Manager manager = null;
            IntPtr ids = IntPtr.Zero;
            uint allocated = 0;
            try
            {
                manager = Activate<Manager>("0af10cec-2ecd-4b92-9581-34f6ae0637f3");
                Check(manager.RefreshDeviceList(), "Не удалось обновить устройства WPD.");
                uint count = 0;
                Check(manager.GetDevices(IntPtr.Zero, ref count), "Не удалось перечислить устройства WPD.");
                if (count > 256) throw new IOException("Windows вернула слишком много переносных устройств.");
                if (count == 0) return result;
                allocated = count;
                ids = Marshal.AllocCoTaskMem(checked((int)count * IntPtr.Size));
                for (int i = 0; i < count; i++) Marshal.WriteIntPtr(ids, i * IntPtr.Size, IntPtr.Zero);
                Check(manager.GetDevices(ids, ref count), "Не удалось получить идентификаторы WPD.");
                if (count > allocated) throw new IOException("Список устройств изменился. Обновите его.");
                for (int i = 0; i < count; i++)
                {
                    string id = Marshal.PtrToStringUni(Marshal.ReadIntPtr(ids, i * IntPtr.Size));
                    if (String.IsNullOrEmpty(id)) continue;
                    string name = "Переносное устройство";
                    uint length = 0;
                    manager.GetDeviceFriendlyName(id, IntPtr.Zero, ref length);
                    if (length > 0 && length <= 4096)
                    {
                        IntPtr text = Marshal.AllocCoTaskMem(checked((int)length * 2));
                        try { if (manager.GetDeviceFriendlyName(id, text, ref length) >= 0) name = Marshal.PtrToStringUni(text); }
                        finally { Marshal.FreeCoTaskMem(text); }
                    }
                    result.Add(new SourceInfo { Id = id, Name = name, Kind = "wpd", Status = "detected" });
                }
                return result;
            }
            finally
            {
                if (ids != IntPtr.Zero)
                {
                    for (int i = 0; i < allocated; i++) { IntPtr id = Marshal.ReadIntPtr(ids, i * IntPtr.Size); if (id != IntPtr.Zero) Marshal.FreeCoTaskMem(id); }
                    Marshal.FreeCoTaskMem(ids);
                }
                Release(manager);
            }
        }

        internal sealed class Node
        {
            internal string Id, Name, Modified;
            internal long Size;
            internal bool Folder;
        }

        static object ReadValue(Values values, uint property)
        {
            var key = new PropertyKey(ObjectFormat, property);
            PropVariant value = new PropVariant();
            try
            {
                if (values.GetValue(ref key, out value) < 0) return null;
                switch (value.Type)
                {
                    case 31: return Marshal.PtrToStringUni(value.Pointer);
                    case 8: return Marshal.PtrToStringBSTR(value.Pointer);
                    case 19: return (long)(uint)value.Unsigned;
                    case 21: return value.Unsigned <= Int64.MaxValue ? (object)(long)value.Unsigned : null;
                    case 3: return (long)(int)value.Signed;
                    case 20: return value.Signed;
                    case 72: return value.Pointer == IntPtr.Zero ? null : (object)(Guid)Marshal.PtrToStructure(value.Pointer, typeof(Guid));
                    case 7: return DateTime.FromOADate(value.Date).ToString("o", CultureInfo.InvariantCulture);
                    default: return null;
                }
            }
            finally { PropVariantClear(ref value); }
        }

        internal sealed class Session : IDisposable
        {
            Device device;
            Content content;
            Properties properties;
            Resources resources;
            bool disposed;

            internal Session(string deviceId)
            {
                Values client = null;
                try
                {
                    // Free-threaded WPD COM implementation supports the background worker.
                    device = Activate<Device>("f7c0039a-4762-488a-b4b3-760ef9a1ba9b");
                    client = Activate<Values>("0c15d503-d017-47ce-9016-7b3f978721cc");
                    var name = new PropertyKey(ClientFormat, 2);
                    var readAccess = new PropertyKey(ClientFormat, 9);
                    Check(client.SetStringValue(ref name, "USB-Recovery"), "Не удалось создать параметры WPD.");
                    Check(client.SetUnsignedIntegerValue(ref readAccess, 0x80000000), "Не удалось установить режим чтения WPD.");
                    Check(device.Open(deviceId, client), "Телефон WPD недоступен.");
                    Check(device.Content(out content), "Не удалось открыть список файлов телефона.");
                    Check(content.Properties(out properties), "Не удалось получить сведения о файлах телефона.");
                    Check(content.Transfer(out resources), "Не удалось открыть чтение файлов телефона.");
                }
                catch { Dispose(); throw; }
                finally { Release(client); }
            }

            internal void Cancel()
            {
                try { if (!disposed && device != null) device.Cancel(); }
                catch (COMException) { }
            }

            internal Node ReadNode(string id)
            {
                Values values = null;
                try
                {
                    Check(properties.GetValues(id, IntPtr.Zero, out values), "Не удалось прочитать сведения об объекте телефона.");
                    var name = ReadValue(values, 12) as string;
                    if (String.IsNullOrEmpty(name)) name = ReadValue(values, 4) as string;
                    if (String.IsNullOrEmpty(name)) name = "Объект";
                    object type = ReadValue(values, 7);
                    object size = ReadValue(values, 11);
                    return new Node { Id = id, Name = name, Modified = ReadValue(values, 19) as string ?? "", Size = size is long ? (long)size : -1, Folder = type is Guid && ((Guid)type == FolderType || (Guid)type == FunctionalType) };
                }
                finally { Release(values); }
            }

            internal List<string> Children(string parent, CancellationToken cancel)
            {
                ObjectEnumerator enumerator = null;
                IntPtr pointers = IntPtr.Zero;
                const uint batch = 32;
                var ids = new List<string>();
                try
                {
                    Check(content.EnumObjects(0, parent, null, out enumerator), "Не удалось перечислить папку телефона.");
                    pointers = Marshal.AllocCoTaskMem((int)batch * IntPtr.Size);
                    while (true)
                    {
                        cancel.ThrowIfCancellationRequested();
                        for (int i = 0; i < batch; i++) Marshal.WriteIntPtr(pointers, i * IntPtr.Size, IntPtr.Zero);
                        uint fetched = 0;
                        int code = enumerator.Next(batch, pointers, out fetched);
                        try
                        {
                            Check(code, "Телефон прервал перечисление файлов.");
                            if (fetched > batch) throw new IOException("Телефон вернул некорректный список объектов.");
                            for (int i = 0; i < fetched; i++)
                            {
                                string id = Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointers, i * IntPtr.Size));
                                if (!String.IsNullOrEmpty(id)) ids.Add(id);
                            }
                            if (ids.Count > SourceLimits.MaximumEntries) throw new IOException("Превышен предел объектов в папке. Выберите меньшую папку.");
                        }
                        finally
                        {
                            for (int i = 0; i < batch; i++) { IntPtr id = Marshal.ReadIntPtr(pointers, i * IntPtr.Size); if (id != IntPtr.Zero) Marshal.FreeCoTaskMem(id); }
                        }
                        if (fetched == 0 || code == 1) break;
                    }
                    return ids;
                }
                finally { if (pointers != IntPtr.Zero) Marshal.FreeCoTaskMem(pointers); Release(enumerator); }
            }

            internal Stream OpenRead(SourceEntry entry, CancellationToken cancel)
            {
                cancel.ThrowIfCancellationRequested();
                var key = new PropertyKey("E81E79BE-34F0-41BF-B53F-F1A06AE87842", 0);
                IStream stream;
                uint optimum = 65536;
                Check(resources.GetStream(entry.Id, ref key, 0 /* STGM_READ */, ref optimum, out stream), "Не удалось открыть файл телефона для чтения.");
                return new ComReadStream(this, stream, entry.Size, cancel);
            }

            public void Dispose()
            {
                if (disposed) return;
                disposed = true;
                try { if (device != null) device.Close(); }
                catch (COMException) { }
                finally { Release(resources); Release(properties); Release(content); Release(device); resources = null; properties = null; content = null; device = null; }
            }
        }

        sealed class ComReadStream : Stream
        {
            Session session;
            IStream stream;
            readonly long length;
            readonly CancellationToken cancel;
            CancellationTokenRegistration registration;
            long position;
            internal ComReadStream(Session session, IStream stream, long length, CancellationToken cancel)
            {
                this.session = session; this.stream = stream; this.length = length; this.cancel = cancel;
                registration = cancel.Register(session.Cancel);
            }
            public override bool CanRead { get { return stream != null; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { if (length < 0) throw new NotSupportedException(); return length; } }
            public override long Position { get { return position; } set { throw new NotSupportedException(); } }
            public override int Read(byte[] buffer, int offset, int count)
            {
                if (stream == null) throw new ObjectDisposedException("WPD stream");
                if (buffer == null) throw new ArgumentNullException("buffer");
                if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException("count");
                cancel.ThrowIfCancellationRequested();
                if (count == 0) return 0;
                int requested = Math.Min(count, 1024 * 1024);
                byte[] data = offset == 0 && requested == buffer.Length ? buffer : new byte[requested];
                IntPtr fetched = Marshal.AllocCoTaskMem(4);
                try
                {
                    Marshal.WriteInt32(fetched, 0);
                    try { stream.Read(data, requested, fetched); }
                    catch (COMException) { cancel.ThrowIfCancellationRequested(); throw new IOException("Телефон прервал чтение файла. Копия осталась неполной."); }
                    cancel.ThrowIfCancellationRequested();
                    int read = Marshal.ReadInt32(fetched);
                    if (read < 0 || read > requested) throw new IOException("Некорректная длина чтения WPD.");
                    if (!Object.ReferenceEquals(data, buffer)) Buffer.BlockCopy(data, 0, buffer, offset, read);
                    position += read;
                    return read;
                }
                finally { Marshal.FreeCoTaskMem(fetched); }
            }
            protected override void Dispose(bool disposing)
            {
                registration.Dispose();
                Release(stream); stream = null;
                if (session != null) { session.Dispose(); session = null; }
                base.Dispose(disposing);
            }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException("Источник открыт только для чтения."); }
        }
    }
}
