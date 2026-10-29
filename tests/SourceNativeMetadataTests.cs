using System;
using System.Runtime.InteropServices;
using UsbRecovery;

// Enumerates connected-device IDs/names only. Never opens phone files or reads user data.
public static class SourceNativeMetadataTests
{
    [DllImport("ole32.dll")] static extern int PropVariantClear(ref WpdInterop.PropVariant value);
    public static int Main()
    {
        try
        {
            if (Marshal.SizeOf(typeof(WpdInterop.PropertyKey)) != 20 || Marshal.SizeOf(typeof(WpdInterop.PropVariant)) != 24) throw new Exception("WPD x64 ABI layout mismatch");
            var values = (WpdInterop.Values)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("0c15d503-d017-47ce-9016-7b3f978721cc"), true));
            try
            {
                var key = new WpdInterop.PropertyKey("204D9F0C-2292-4080-9F42-40664E70F859", 9);
                WpdInterop.Check(values.SetUnsignedIntegerValue(ref key, 0x80000000), "client value test");
                WpdInterop.PropVariant variant; WpdInterop.Check(values.GetValue(ref key, out variant), "client value read test");
                try { if (variant.Type != 19 || variant.Unsigned != 0x80000000) throw new Exception("WPD values vtable mismatch"); }
                finally { PropVariantClear(ref variant); }
            }
            finally { WpdInterop.Release(values); }
            var devices = SourceDiscovery.ListWpdDevices();
            Console.WriteLine("WPD native manager enumeration passed; detected devices: " + devices.Count);
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
