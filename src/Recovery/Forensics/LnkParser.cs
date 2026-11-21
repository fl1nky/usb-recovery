using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public sealed class LnkArtifact
    {
        public string TargetPath { get; set; }
        public long TargetFileSize { get; set; }
        public DateTime CreationTimeUtc { get; set; }
        public DateTime AccessTimeUtc { get; set; }
        public DateTime WriteTimeUtc { get; set; }
        public uint FileAttributes { get; set; }
        public string DriveType { get; set; }
        public string DriveSerialNumber { get; set; }
        public string VolumeLabel { get; set; }
        public string MachineId { get; set; }
        public string MacAddress { get; set; }
        public string Description { get; set; }
        public string RelativePath { get; set; }
        public string WorkingDirectory { get; set; }
        public string CommandLineArguments { get; set; }
        public string IconLocation { get; set; }

        public LnkArtifact()
        {
            TargetPath = String.Empty;
            DriveType = String.Empty;
            DriveSerialNumber = String.Empty;
            VolumeLabel = String.Empty;
            MachineId = String.Empty;
            MacAddress = String.Empty;
            Description = String.Empty;
            RelativePath = String.Empty;
            WorkingDirectory = String.Empty;
            CommandLineArguments = String.Empty;
            IconLocation = String.Empty;
        }
    }

    public sealed class ShellbagArtifact
    {
        public int SlotId { get; set; }
        public string FolderPath { get; set; }
        public int AccessOrder { get; set; }
        public DateTime CreatedUtc { get; set; }
        public DateTime ModifiedUtc { get; set; }
        public DateTime AccessedUtc { get; set; }
        public string DriveType { get; set; }
        public string VolumeSerialNumber { get; set; }
        public string VolumeLabel { get; set; }

        public ShellbagArtifact()
        {
            FolderPath = String.Empty;
            DriveType = String.Empty;
            VolumeSerialNumber = String.Empty;
            VolumeLabel = String.Empty;
        }
    }

    public static class LnkParser
    {
        private static readonly Guid ExpectedClsid = new Guid("00021401-0000-0000-c000-000000000046");

        public static LnkArtifact ParseFile(string filePath)
        {
            if (filePath == null) throw new ArgumentNullException("filePath");
            if (!File.Exists(filePath)) throw new FileNotFoundException("LNK file not found", filePath);

            byte[] buffer = File.ReadAllBytes(filePath);
            return Parse(buffer);
        }

        public static LnkArtifact Parse(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException("stream");

            byte[] buffer;
            if (stream is MemoryStream)
            {
                buffer = ((MemoryStream)stream).ToArray();
            }
            else
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    byte[] temp = new byte[65536];
                    int bytesRead;
                    while ((bytesRead = stream.Read(temp, 0, temp.Length)) > 0)
                    {
                        ms.Write(temp, 0, bytesRead);
                        if (ms.Length > 16 * 1024 * 1024) break; // Guard against unbounded stream memory clogging
                    }
                    buffer = ms.ToArray();
                }
            }

            return Parse(buffer);
        }

        public static LnkArtifact Parse(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (buffer.Length < 76)
            {
                throw new InvalidDataException("Buffer too small for Shell Link header (less than 76 bytes)");
            }

            // 1. HeaderSize (MUST be 0x0000004C)
            uint headerSize = BitConverter.ToUInt32(buffer, 0);
            if (headerSize != 0x0000004C)
            {
                throw new InvalidDataException("Invalid Shell Link HeaderSize. Expected 0x4C (76), got: " + headerSize);
            }

            // 2. LinkCLSID (MUST be 00021401-0000-0000-C000-000000000046)
            byte[] clsidBytes = new byte[16];
            Buffer.BlockCopy(buffer, 4, clsidBytes, 0, 16);
            Guid clsid = new Guid(clsidBytes);
            if (clsid != ExpectedClsid)
            {
                throw new InvalidDataException("Invalid Shell Link CLSID: " + clsid.ToString());
            }

            // 3. LinkFlags
            uint linkFlags = BitConverter.ToUInt32(buffer, 20);

            // 4. FileAttributes
            uint fileAttributes = BitConverter.ToUInt32(buffer, 24);

            // 5. Timestamps
            long creationTime = BitConverter.ToInt64(buffer, 28);
            long accessTime = BitConverter.ToInt64(buffer, 36);
            long writeTime = BitConverter.ToInt64(buffer, 44);

            // 6. FileSize
            uint fileSize = BitConverter.ToUInt32(buffer, 52);

            LnkArtifact artifact = new LnkArtifact();
            artifact.FileAttributes = fileAttributes;
            artifact.TargetFileSize = fileSize;

            try { artifact.CreationTimeUtc = (creationTime > 0) ? DateTime.FromFileTimeUtc(creationTime) : DateTime.MinValue; } catch { }
            try { artifact.AccessTimeUtc = (accessTime > 0) ? DateTime.FromFileTimeUtc(accessTime) : DateTime.MinValue; } catch { }
            try { artifact.WriteTimeUtc = (writeTime > 0) ? DateTime.FromFileTimeUtc(writeTime) : DateTime.MinValue; } catch { }

            int cursor = 76;
            List<string> idListPathParts = new List<string>();

            // 7. LinkTargetIDList
            if ((linkFlags & 0x01) != 0 && cursor + 2 <= buffer.Length)
            {
                ushort idListSize = BitConverter.ToUInt16(buffer, cursor);
                cursor += 2;
                int idListEnd = cursor + idListSize;
                if (idListEnd > buffer.Length) idListEnd = buffer.Length;

                while (cursor + 2 <= idListEnd)
                {
                    ushort itemSize = BitConverter.ToUInt16(buffer, cursor);
                    if (itemSize == 0 || cursor + itemSize > idListEnd) break;

                    string partName = ParseShellItem(buffer, cursor + 2, itemSize - 2);
                    if (!String.IsNullOrEmpty(partName))
                    {
                        idListPathParts.Add(partName);
                    }

                    cursor += itemSize;
                }

                cursor = idListEnd;
            }

            if (idListPathParts.Count > 0)
            {
                artifact.TargetPath = CombineShellPath(idListPathParts);
            }

            // 8. LinkInfo
            if ((linkFlags & 0x02) != 0 && (linkFlags & 0x100) == 0 && cursor + 4 <= buffer.Length)
            {
                uint linkInfoSize = BitConverter.ToUInt32(buffer, cursor);
                int linkInfoEnd = cursor + (int)linkInfoSize;
                if (linkInfoEnd > buffer.Length) linkInfoEnd = buffer.Length;

                if (linkInfoSize >= 28 && cursor + 28 <= buffer.Length)
                {
                    uint volumeIdOffset = BitConverter.ToUInt32(buffer, cursor + 12);
                    uint localBasePathOffset = BitConverter.ToUInt32(buffer, cursor + 16);

                    // VolumeID
                    if (volumeIdOffset > 0 && cursor + volumeIdOffset + 16 <= linkInfoEnd)
                    {
                        int vCursor = cursor + (int)volumeIdOffset;
                        uint driveType = BitConverter.ToUInt32(buffer, vCursor + 4);
                        uint driveSerial = BitConverter.ToUInt32(buffer, vCursor + 8);
                        uint volLabelOffset = BitConverter.ToUInt32(buffer, vCursor + 12);

                        artifact.DriveType = FormatDriveType(driveType);
                        artifact.DriveSerialNumber = String.Format("{0:X4}-{1:X4}", (driveSerial >> 16) & 0xFFFF, driveSerial & 0xFFFF);

                        if (volLabelOffset > 0 && vCursor + volLabelOffset < linkInfoEnd)
                        {
                            artifact.VolumeLabel = ReadNullTerminatedString(buffer, vCursor + (int)volLabelOffset, linkInfoEnd);
                        }
                    }

                    // LocalBasePath
                    if (localBasePathOffset > 0 && cursor + localBasePathOffset < linkInfoEnd)
                    {
                        string localBasePath = ReadNullTerminatedString(buffer, cursor + (int)localBasePathOffset, linkInfoEnd);
                        if (!String.IsNullOrEmpty(localBasePath) && String.IsNullOrEmpty(artifact.TargetPath))
                        {
                            artifact.TargetPath = localBasePath;
                        }
                    }
                }

                cursor = linkInfoEnd;
            }

            // 9. StringData (Name, RelativePath, WorkingDir, Arguments, IconLocation)
            bool isUnicode = (linkFlags & 0x80) != 0;

            if ((linkFlags & 0x04) != 0) artifact.Description = ReadCountedString(buffer, ref cursor, isUnicode);
            if ((linkFlags & 0x08) != 0) artifact.RelativePath = ReadCountedString(buffer, ref cursor, isUnicode);
            if ((linkFlags & 0x10) != 0) artifact.WorkingDirectory = ReadCountedString(buffer, ref cursor, isUnicode);
            if ((linkFlags & 0x20) != 0) artifact.CommandLineArguments = ReadCountedString(buffer, ref cursor, isUnicode);
            if ((linkFlags & 0x40) != 0) artifact.IconLocation = ReadCountedString(buffer, ref cursor, isUnicode);

            // 10. ExtraData Blocks
            while (cursor + 8 <= buffer.Length)
            {
                uint blockSize = BitConverter.ToUInt32(buffer, cursor);
                if (blockSize < 4 || cursor + blockSize > buffer.Length) break;

                uint blockSig = BitConverter.ToUInt32(buffer, cursor + 4);
                if (blockSig == 0xA0000003) // TrackerDataBlock
                {
                    ParseTrackerDataBlock(buffer, cursor, (int)blockSize, artifact);
                }

                cursor += (int)blockSize;
            }

            return artifact;
        }

        private static string ParseShellItem(byte[] buffer, int offset, int size)
        {
            if (size < 1) return String.Empty;

            byte type = buffer[offset];

            // 0x1F: Root folder (My Computer, Network, etc.)
            if (type == 0x1F)
            {
                if (size >= 18)
                {
                    byte[] guidBytes = new byte[16];
                    Buffer.BlockCopy(buffer, offset + 2, guidBytes, 0, 16);
                    Guid guid = new Guid(guidBytes);
                    if (guid == new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D"))
                    {
                        return String.Empty;
                    }
                    return "{" + guid.ToString() + "}";
                }
                return String.Empty;
            }

            // 0x20..0x2F: Volume Shell Item (Drive letter like C:\)
            if (type >= 0x20 && type <= 0x2F)
            {
                string volStr = ReadNullTerminatedString(buffer, offset + 1, offset + size);
                return volStr.TrimEnd('\\');
            }

            // 0x30..0x3F: File or Directory Shell Item
            if (type >= 0x30 && type <= 0x3F)
            {
                string shortName = String.Empty;
                if (size >= 14)
                {
                    shortName = ReadNullTerminatedString(buffer, offset + 12, offset + size);
                }

                // Look for 0xBEEF0004 Unicode extension block
                string unicodeName = FindUnicodeExtensionName(buffer, offset, size);
                if (!String.IsNullOrEmpty(unicodeName))
                {
                    return unicodeName;
                }

                return shortName;
            }

            return String.Empty;
        }

        private static string FindUnicodeExtensionName(byte[] buffer, int offset, int size)
        {
            int end = offset + size;
            int cursor = offset + 12;

            // Skip primary ANSI name
            while (cursor < end && buffer[cursor] != 0) cursor++;
            cursor++;

            while (cursor + 8 <= end)
            {
                ushort extSize = BitConverter.ToUInt16(buffer, cursor);
                if (extSize < 8 || cursor + extSize > end)
                {
                    cursor++;
                    continue;
                }

                uint extSig = BitConverter.ToUInt32(buffer, cursor + 4);

                if (extSig == 0xBEEF0004)
                {
                    int strStart = cursor + 14;
                    if (strStart + 4 <= cursor + extSize)
                    {
                        string ustr = ReadNullTerminatedUnicodeString(buffer, strStart, cursor + extSize);
                        if (!String.IsNullOrEmpty(ustr)) return ustr;
                    }
                    if (cursor + 28 < cursor + extSize)
                    {
                        string ustr = ReadNullTerminatedUnicodeString(buffer, cursor + 28, cursor + extSize);
                        if (!String.IsNullOrEmpty(ustr)) return ustr;
                    }
                }

                cursor += extSize;
            }

            return String.Empty;
        }

        private static string CombineShellPath(List<string> parts)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parts.Count; i++)
            {
                string part = parts[i];
                if (String.IsNullOrEmpty(part)) continue;

                if (sb.Length == 0)
                {
                    sb.Append(part);
                    if (part.EndsWith(":")) sb.Append("\\");
                }
                else
                {
                    if (sb.Length > 0 && sb[sb.Length - 1] != '\\') sb.Append("\\");
                    sb.Append(part);
                }
            }
            return sb.ToString();
        }

        private static void ParseTrackerDataBlock(byte[] buffer, int offset, int size, LnkArtifact artifact)
        {
            if (size < 88) return;

            string machine = Encoding.ASCII.GetString(buffer, offset + 16, 16).TrimEnd('\0');
            artifact.MachineId = machine;

            byte[] mac = new byte[6];
            Buffer.BlockCopy(buffer, offset + 58, mac, 0, 6);
            artifact.MacAddress = String.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }

        private static string FormatDriveType(uint driveType)
        {
            switch (driveType)
            {
                case 1: return "NoRootDirectory";
                case 2: return "Removable";
                case 3: return "Fixed";
                case 4: return "Remote";
                case 5: return "CD-ROM";
                case 6: return "RAMDisk";
                default: return "Unknown";
            }
        }

        private static string ReadCountedString(byte[] buffer, ref int cursor, bool isUnicode)
        {
            if (cursor + 2 > buffer.Length) return String.Empty;
            ushort charCount = BitConverter.ToUInt16(buffer, cursor);
            cursor += 2;

            if (charCount == 0) return String.Empty;

            if (isUnicode)
            {
                int byteLen = charCount * 2;
                if (cursor + byteLen > buffer.Length) byteLen = buffer.Length - cursor;
                string s = Encoding.Unicode.GetString(buffer, cursor, byteLen);
                cursor += byteLen;
                return s;
            }
            else
            {
                int byteLen = charCount;
                if (cursor + byteLen > buffer.Length) byteLen = buffer.Length - cursor;
                string s = Encoding.ASCII.GetString(buffer, cursor, byteLen);
                cursor += byteLen;
                return s;
            }
        }

        private static string ReadNullTerminatedString(byte[] buffer, int start, int maxEnd)
        {
            if (start >= maxEnd || start >= buffer.Length) return String.Empty;
            int end = start;
            while (end < maxEnd && end < buffer.Length && buffer[end] != 0) end++;
            return Encoding.ASCII.GetString(buffer, start, end - start);
        }

        private static string ReadNullTerminatedUnicodeString(byte[] buffer, int start, int maxEnd)
        {
            if (start + 2 > maxEnd || start + 2 > buffer.Length) return String.Empty;
            int end = start;
            while (end + 1 < maxEnd && end + 1 < buffer.Length && !(buffer[end] == 0 && buffer[end + 1] == 0))
            {
                end += 2;
            }
            return Encoding.Unicode.GetString(buffer, start, end - start);
        }

        public static List<ShellbagArtifact> ParseShellbags(byte[] mruListExData, Dictionary<int, byte[]> childItemLists)
        {
            List<ShellbagArtifact> artifacts = new List<ShellbagArtifact>();
            if (mruListExData == null || childItemLists == null) return artifacts;

            int cursor = 0;
            int order = 0;

            while (cursor + 4 <= mruListExData.Length)
            {
                uint slot = BitConverter.ToUInt32(mruListExData, cursor);
                cursor += 4;

                if (slot == 0xFFFFFFFF) break;

                int slotId = (int)slot;
                if (childItemLists.ContainsKey(slotId))
                {
                    byte[] itemBytes = childItemLists[slotId];
                    ShellbagArtifact bag = ParseSingleShellbag(slotId, order++, itemBytes);
                    if (bag != null)
                    {
                        artifacts.Add(bag);
                    }
                }
            }

            return artifacts;
        }

        private static ShellbagArtifact ParseSingleShellbag(int slotId, int accessOrder, byte[] itemBytes)
        {
            if (itemBytes == null || itemBytes.Length < 2) return null;

            ShellbagArtifact artifact = new ShellbagArtifact();
            artifact.SlotId = slotId;
            artifact.AccessOrder = accessOrder;

            int cursor = 0;
            List<string> parts = new List<string>();

            while (cursor + 2 <= itemBytes.Length)
            {
                ushort itemSize = BitConverter.ToUInt16(itemBytes, cursor);
                if (itemSize == 0 || cursor + itemSize > itemBytes.Length) break;

                string part = ParseShellItem(itemBytes, cursor + 2, itemSize - 2);
                if (!String.IsNullOrEmpty(part))
                {
                    parts.Add(part);
                }

                cursor += itemSize;
            }

            artifact.FolderPath = CombineShellPath(parts);
            return artifact;
        }
    }
}
