using System;
using System.Threading;
using UsbRecovery;

// Only synthetic paths supplied by ReviewEngineTests.py; never discovers devices.
public static class ReviewSnapshot
{
    public static int Main(string[] paths)
    {
        if (paths.Length != 2) return 2;
        try {
            string snapshot = SourceAcquisition.Copy(new LocalFolderSource(paths[0]), "", paths[1], CancellationToken.None, null);
            Console.WriteLine(snapshot); return 0;
        } catch { Console.WriteLine("COPY_FAILED"); return 1; }
    }
}
