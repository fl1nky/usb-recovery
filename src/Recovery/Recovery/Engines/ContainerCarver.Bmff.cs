// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    public static partial class ContainerCarver
    {
        static readonly HashSet<string> MovieBoxes = new HashSet<string>(StringComparer.Ordinal)
        {
            "moov", "mdat", "free", "skip", "wide", "meta", "uuid", "pdin", "moof", "mfra",
            "sidx", "styp", "emsg", "prft"
        };

        static bool ReadBox(FileStream stream, long at, long limit, out string kind, out long size, out int header)
        {
            kind = null; size = 0; header = 8;
            if (limit - at < 8) return false;
            byte[] raw = Read(stream, at, header);
            if (raw == null) return false;
            kind = Encoding.ASCII.GetString(raw, 4, 4);
            size = BE(raw, 0);
            if (size == 1)
            {
                header = 16;
                if (limit - at < header) return false;
                raw = Read(stream, at + 8, 8);
                if (raw == null || (raw[0] & 128) != 0) return false;
                size = (long)BE(raw, 0) << 32 | BE(raw, 4);
            }
            // A size of zero cannot establish where the file ends on a raw disk.
            return size >= header && size <= limit - at;
        }

        static string BmffFormat(byte[] brands)
        {
            string major = Encoding.ASCII.GetString(brands, 0, 4);
            var compatible = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 8; i < brands.Length; i += 4) compatible.Add(Encoding.ASCII.GetString(brands, i, 4));
            if (major == "avif" || major == "avis") return ".avif";
            if (major == "heic" || major == "heix" || major == "hevc" || major == "hevx") return ".heic";
            if (major == "mif1" || major == "msf1")
                return compatible.Contains("avif") || compatible.Contains("avis") ? ".avif" : ".heic";
            if (major == "qt  ") return ".mov";
            if (major == "M4A " || compatible.Contains("M4A ")) return ".m4a";
            return ".mp4";
        }

        static long BmffEnd(FileStream stream, long start, CancellationToken cancel, out string extension)
        {
            extension = null;
            long limit = start + Math.Min(Maximum, stream.Length - start);
            string kind;
            long size;
            int header;
            if (!ReadBox(stream, start, limit, out kind, out size, out header) || kind != "ftyp") return -1;
            long brandBytes = size - header;
            if (brandBytes < 8 || brandBytes > 65536 || brandBytes % 4 != 0) return -1;
            byte[] brands = Read(stream, start + header, (int)brandBytes);
            if (brands == null) return -1;
            extension = BmffFormat(brands);
            string metadata = extension == ".heic" || extension == ".avif" ? "meta" : "moov";
            bool hasMedia = false, hasMetadata = false;
            long at = start + size;
            for (int boxes = 0; boxes < 100000 && ReadBox(stream, at, limit, out kind, out size, out header); boxes++)
            {
                cancel.ThrowIfCancellationRequested();
                // A second top-level ftyp begins a different file. Signatures inside mdat are opaque.
                if (!MovieBoxes.Contains(kind)) break;
                if (kind == "mdat" && size > header) hasMedia = true;
                if (kind == metadata) hasMetadata = true;
                at += size;
            }
            return hasMedia && hasMetadata ? at : -1;
        }
    }
}
