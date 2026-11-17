// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Threading;

namespace UsbRecovery
{
    // One verified, write-denying lease can be shared by child operations in
    // the same invocation. A boolean 'already hashed' cannot provide this.
    internal sealed class RecoveryVerifiedImage : IDisposable
    {
        readonly FileStream lease;
        readonly string path;
        public readonly string Sha256;
        public readonly long Bytes;
        bool disposed;

        public RecoveryVerifiedImage(FileStream source, string expected, CancellationToken cancel)
        {
            if (source == null || source.CanWrite) throw new IOException("VERIFIED_IMAGE_CONTEXT_INVALID");
            path = Path.GetFullPath(source.Name);
            lease = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try {
                Bytes = lease.Length;
                Sha256 = RecoveryCore.HashFile(path, cancel, (done,total) => { });
                Validate(source, expected);
            } catch { lease.Dispose(); throw; }
        }
        public void Validate(FileStream source, string expected)
        {
            if (disposed || source == null || source.CanWrite || !String.Equals(Path.GetFullPath(source.Name), path, StringComparison.OrdinalIgnoreCase) ||
                source.Length != Bytes || !String.Equals(Sha256, expected, StringComparison.OrdinalIgnoreCase))
                throw new IOException("VERIFIED_IMAGE_BINDING_CHANGED");
        }
        public void Dispose() { if (disposed) return; disposed = true; lease.Dispose(); }
    }
}
