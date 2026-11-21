using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public enum RegistryValueType : uint
    {
        None = 0,
        String = 1,              // REG_SZ (UTF-16LE null-terminated)
        ExpandString = 2,        // REG_EXPAND_SZ
        Binary = 3,              // REG_BINARY
        DWord = 4,               // REG_DWORD (32-bit LE)
        DWordBigEndian = 5,      // REG_DWORD_BIG_ENDIAN
        Link = 6,                // REG_LINK
        MultiString = 7,         // REG_MULTI_SZ (list of UTF-16LE strings)
        ResourceList = 8,        // REG_RESOURCE_LIST
        FullResourceDesc = 9,    // REG_FULL_RESOURCE_DESCRIPTOR
        ResourceRequirements = 10,
        QWord = 11,              // REG_QWORD (64-bit LE)
        Unknown = 0xFFFFFFFF
    }

    public sealed class RegistryValue
    {
        public string Name { get; set; }
        public RegistryValueType ValueType { get; set; }
        public byte[] RawData { get; set; }
        public object Value { get; set; }
        public bool IsDeleted { get; set; }
        public long CellOffset { get; set; }

        public RegistryValue()
        {
            Name = String.Empty;
            ValueType = RegistryValueType.None;
            RawData = new byte[0];
            Value = null;
            IsDeleted = false;
            CellOffset = 0;
        }

        public string ValueAsString()
        {
            if (Value == null) return String.Empty;
            if (Value is string) return (string)Value;
            if (Value is string[]) return String.Join("; ", (string[])Value);
            if (Value is uint) return string.Format(System.Globalization.CultureInfo.InvariantCulture, "0x{0:X8} ({0})", (uint)Value);
            if (Value is ulong) return string.Format(System.Globalization.CultureInfo.InvariantCulture, "0x{0:X16} ({0})", (ulong)Value);
            if (Value is byte[])
            {
                byte[] bytes = (byte[])Value;
                if (bytes.Length == 0) return String.Empty;
                int len = Math.Min(bytes.Length, 32);
                StringBuilder sb = new StringBuilder(len * 3);
                for (int i = 0; i < len; i++)
                {
                    if (i > 0) sb.Append(" ");
                    sb.Append(bytes[i].ToString("X2"));
                }
                if (bytes.Length > 32) sb.Append("...");
                return sb.ToString();
            }
            return Value.ToString();
        }

        public override string ToString()
        {
            string displayName = String.IsNullOrEmpty(Name) ? "(Default)" : Name;
            return displayName + " [" + ValueType.ToString() + "] = " + ValueAsString();
        }
    }

    public sealed class RegistryKey
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public DateTime LastWriteTimeUtc { get; set; }
        public bool IsDeleted { get; set; }
        public long CellOffset { get; set; }
        public uint SubkeyCount { get; set; }
        public uint ValueCount { get; set; }

        public List<RegistryKey> Subkeys { get; set; }
        public List<RegistryValue> Values { get; set; }

        public RegistryKey()
        {
            Name = String.Empty;
            Path = String.Empty;
            LastWriteTimeUtc = DateTime.MinValue;
            IsDeleted = false;
            CellOffset = 0;
            SubkeyCount = 0;
            ValueCount = 0;
            Subkeys = new List<RegistryKey>();
            Values = new List<RegistryValue>();
        }

        public RegistryValue GetValue(string valueName)
        {
            string target = valueName ?? String.Empty;
            for (int i = 0; i < Values.Count; i++)
            {
                if (String.Equals(Values[i].Name, target, StringComparison.OrdinalIgnoreCase))
                {
                    return Values[i];
                }
            }
            return null;
        }

        public RegistryKey GetSubkey(string subkeyName)
        {
            if (String.IsNullOrEmpty(subkeyName)) return null;
            for (int i = 0; i < Subkeys.Count; i++)
            {
                if (String.Equals(Subkeys[i].Name, subkeyName, StringComparison.OrdinalIgnoreCase))
                {
                    return Subkeys[i];
                }
            }
            return null;
        }

        public override string ToString()
        {
            return (String.IsNullOrEmpty(Path) ? Name : Path) + " (" + Subkeys.Count + " keys, " + Values.Count + " values)";
        }
    }

    public sealed class RegistrySystemSummary
    {
        public string ProductName { get; set; }
        public string CurrentVersion { get; set; }
        public string CurrentBuild { get; set; }
        public string InstallDateUtc { get; set; }
        public string ComputerName { get; set; }
        public string TimeZoneStandardName { get; set; }
        public string CurrentControlSet { get; set; }
        public List<string> UsbDevices { get; set; }
        public List<string> UserAccounts { get; set; }
        public List<string> RunKeys { get; set; }

        public RegistrySystemSummary()
        {
            ProductName = String.Empty;
            CurrentVersion = String.Empty;
            CurrentBuild = String.Empty;
            InstallDateUtc = String.Empty;
            ComputerName = String.Empty;
            TimeZoneStandardName = String.Empty;
            CurrentControlSet = String.Empty;
            UsbDevices = new List<string>();
            UserAccounts = new List<string>();
            RunKeys = new List<string>();
        }
    }

    /// <summary>
    /// Pure C# native parser for Windows Registry Hive files (REGF format).
    /// Supports SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, and UsrClass.dat hives.
    /// Provides hierarchical key traversal, value decoding, slack cell carving for deleted keys/values,
    /// checksum validation, fast search, and forensic system summary extraction with zero external dependencies.
    /// </summary>
    public sealed class RegistryHive : IDisposable
    {
        private const uint RegfMagic = 0x66676572U; // "regf" in little-endian
        private const uint HbinMagic = 0x6E696268U; // "hbin" in little-endian
        private const ushort NkSignature = 0x6B6E; // "nk" in little-endian
        private const ushort VkSignature = 0x6B76; // "vk" in little-endian
        private const ushort LfSignature = 0x666C; // "lf" fast leaf
        private const ushort LhSignature = 0x686C; // "lh" hash leaf
        private const ushort LiSignature = 0x696C; // "li" index leaf
        private const ushort RiSignature = 0x6972; // "ri" root index
        private const ushort SkSignature = 0x6B73; // "sk" security key
        private const ushort DbSignature = 0x6264; // "db" big data

        private const int HiveHeaderSize = 4096;

        private byte[] hiveBuffer;
        private readonly bool isBufferOwner;
        private bool isDisposed;

        // Header fields
        public uint PrimarySequenceNumber { get; private set; }
        public uint SecondarySequenceNumber { get; private set; }
        public DateTime LastWriteTimeUtc { get; private set; }
        public uint MajorVersion { get; private set; }
        public uint MinorVersion { get; private set; }
        public uint RootCellOffset { get; private set; }
        public uint HiveBinsLength { get; private set; }
        public string EmbeddedFileName { get; private set; }
        public uint HeaderChecksum { get; private set; }
        public bool IsChecksumValid { get; private set; }

        public RegistryKey RootKey { get; private set; }

        private RegistryHive(byte[] buffer, bool ownsBuffer)
        {
            this.hiveBuffer = buffer;
            this.isBufferOwner = ownsBuffer;
        }

        public static bool IsRegistryHive(string filePath)
        {
            if (String.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    return IsRegistryHive(fs);
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool IsRegistryHive(Stream stream)
        {
            if (stream == null || !stream.CanRead) return false;
            long origPos = stream.CanSeek ? stream.Position : 0;
            try
            {
                byte[] magic = new byte[4];
                int r = stream.Read(magic, 0, 4);
                if (r < 4) return false;
                return (BitConverter.ToUInt32(magic, 0) == RegfMagic);
            }
            finally
            {
                if (stream.CanSeek) stream.Position = origPos;
            }
        }

        public static RegistryHive Open(string filePath)
        {
            if (filePath == null) throw new ArgumentNullException("filePath");
            if (!File.Exists(filePath)) throw new FileNotFoundException("Registry hive not found: " + filePath, filePath);

            byte[] data;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
            {
                long len = fs.Length;
                if (len < HiveHeaderSize) throw new InvalidDataException("File is too small to be a registry hive.");
                if (len > 512L * 1024 * 1024) throw new InvalidDataException("Registry hive exceeds 512 MB safety limit.");
                data = new byte[(int)len];
                int total = 0;
                while (total < data.Length)
                {
                    int r = fs.Read(data, total, data.Length - total);
                    if (r <= 0) break;
                    total += r;
                }
            }

            return ParseInternal(data, true);
        }

        public static RegistryHive Open(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable", "stream");

            byte[] data;
            if (stream is MemoryStream)
            {
                data = ((MemoryStream)stream).ToArray();
            }
            else
            {
                using (var ms = new MemoryStream())
                {
                    byte[] buf = new byte[65536];
                    int r;
                    while ((r = stream.Read(buf, 0, buf.Length)) > 0)
                    {
                        ms.Write(buf, 0, r);
                        if (ms.Length > 512L * 1024 * 1024) throw new InvalidDataException("Hive stream exceeds 512 MB limit.");
                    }
                    data = ms.ToArray();
                }
            }

            return ParseInternal(data, true);
        }

        public static RegistryHive Open(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            return ParseInternal(buffer, false);
        }

        private static RegistryHive ParseInternal(byte[] buffer, bool ownsBuffer)
        {
            if (buffer.Length < HiveHeaderSize)
            {
                throw new InvalidDataException("Buffer too small to contain a valid registry hive header.");
            }

            uint magic = BitConverter.ToUInt32(buffer, 0);
            if (magic != RegfMagic)
            {
                throw new InvalidDataException(string.Format(System.Globalization.CultureInfo.InvariantCulture,
                    "Invalid registry hive signature. Expected 'regf' (0x{0:X8}), got 0x{1:X8}.", RegfMagic, magic));
            }

            var hive = new RegistryHive(buffer, ownsBuffer);
            hive.ParseHeader();
            hive.BuildKeyTree();
            return hive;
        }

        private void ParseHeader()
        {
            PrimarySequenceNumber = BitConverter.ToUInt32(hiveBuffer, 4);
            SecondarySequenceNumber = BitConverter.ToUInt32(hiveBuffer, 8);

            long ft = BitConverter.ToInt64(hiveBuffer, 12);
            try
            {
                LastWriteTimeUtc = (ft > 0 && ft < 0x24C85A5EDB04000L) ? DateTime.FromFileTimeUtc(ft) : DateTime.MinValue;
            }
            catch
            {
                LastWriteTimeUtc = DateTime.MinValue;
            }

            MajorVersion = BitConverter.ToUInt32(hiveBuffer, 20);
            MinorVersion = BitConverter.ToUInt32(hiveBuffer, 24);
            RootCellOffset = BitConverter.ToUInt32(hiveBuffer, 36);
            HiveBinsLength = BitConverter.ToUInt32(hiveBuffer, 40);

            // Embedded file name at offset 48 (up to 64 bytes UTF-16LE)
            EmbeddedFileName = ReadUtf16String(hiveBuffer, 48, 64);

            HeaderChecksum = BitConverter.ToUInt32(hiveBuffer, 508);
            uint computedChecksum = 0;
            for (int i = 0; i < 508; i += 4)
            {
                computedChecksum ^= BitConverter.ToUInt32(hiveBuffer, i);
            }
            IsChecksumValid = (computedChecksum == HeaderChecksum);
        }

        private void BuildKeyTree()
        {
            long rootOffset = HiveHeaderSize + (long)RootCellOffset;
            if (rootOffset < HiveHeaderSize || rootOffset >= hiveBuffer.Length)
            {
                RootKey = new RegistryKey { Name = "ROOT", Path = "ROOT" };
                return;
            }

            var visited = new HashSet<long>();
            RootKey = ParseKeyCell(rootOffset, "ROOT", visited);
            if (RootKey == null)
            {
                RootKey = new RegistryKey { Name = "ROOT", Path = "ROOT" };
            }
        }

        private RegistryKey ParseKeyCell(long cellOffset, string currentPath, HashSet<long> visited)
        {
            if (cellOffset < HiveHeaderSize || cellOffset + 76 > hiveBuffer.Length) return null;
            if (!visited.Add(cellOffset)) return null; // Avoid cycle traps

            int cellSize = BitConverter.ToInt32(hiveBuffer, (int)cellOffset);
            if (cellSize >= 0) return null; // Positive size = unallocated cell

            int absSize = -cellSize;
            if (cellOffset + absSize > hiveBuffer.Length) return null;

            ushort sig = BitConverter.ToUInt16(hiveBuffer, (int)cellOffset + 4);
            if (sig != NkSignature) return null;

            ushort flags = BitConverter.ToUInt16(hiveBuffer, (int)cellOffset + 6);
            long ft = BitConverter.ToInt64(hiveBuffer, (int)cellOffset + 8);
            DateTime lastWrite = DateTime.MinValue;
            try
            {
                if (ft > 0 && ft < 0x24C85A5EDB04000L) lastWrite = DateTime.FromFileTimeUtc(ft);
            }
            catch { }

            uint subkeyCount = BitConverter.ToUInt32(hiveBuffer, (int)cellOffset + 24);
            uint subkeyListOffset = BitConverter.ToUInt32(hiveBuffer, (int)cellOffset + 28);
            uint valueCount = BitConverter.ToUInt32(hiveBuffer, (int)cellOffset + 36);
            uint valueListOffset = BitConverter.ToUInt32(hiveBuffer, (int)cellOffset + 40);

            ushort nameLen = BitConverter.ToUInt16(hiveBuffer, (int)cellOffset + 72);
            ushort classLen = BitConverter.ToUInt16(hiveBuffer, (int)cellOffset + 74);

            string name = String.Empty;
            if (cellOffset + 76 + nameLen <= hiveBuffer.Length)
            {
                bool isAscii = (flags & 0x0020) != 0 || (flags & 0x0080) != 0;
                if (isAscii)
                {
                    name = Encoding.GetEncoding(28591).GetString(hiveBuffer, (int)cellOffset + 76, nameLen); // Latin-1 / ASCII
                }
                else
                {
                    name = Encoding.Unicode.GetString(hiveBuffer, (int)cellOffset + 76, nameLen);
                }
            }

            if (String.IsNullOrEmpty(name))
            {
                name = (flags & 0x0004) != 0 ? "ROOT" : string.Format(System.Globalization.CultureInfo.InvariantCulture, "Key_0x{0:X8}", cellOffset);
            }

            string fullPath = String.IsNullOrEmpty(currentPath) ? name : currentPath;

            RegistryKey key = new RegistryKey
            {
                Name = name,
                Path = fullPath,
                LastWriteTimeUtc = lastWrite,
                CellOffset = cellOffset,
                SubkeyCount = subkeyCount,
                ValueCount = valueCount
            };

            // Parse Values
            if (valueCount > 0 && valueCount < 65536 && valueListOffset != 0xFFFFFFFFU)
            {
                long valListAbs = HiveHeaderSize + (long)valueListOffset;
                if (valListAbs >= HiveHeaderSize && valListAbs + 4 + (valueCount * 4) <= hiveBuffer.Length)
                {
                    for (int vi = 0; vi < valueCount; vi++)
                    {
                        uint valOffset = BitConverter.ToUInt32(hiveBuffer, (int)valListAbs + 4 + (vi * 4));
                        if (valOffset == 0xFFFFFFFFU) continue;
                        long valAbs = HiveHeaderSize + (long)valOffset;
                        RegistryValue val = ParseValueCell(valAbs);
                        if (val != null)
                        {
                            key.Values.Add(val);
                        }
                    }
                }
            }

            // Parse Subkeys
            if (subkeyCount > 0 && subkeyCount < 100000 && subkeyListOffset != 0xFFFFFFFFU)
            {
                long subListAbs = HiveHeaderSize + (long)subkeyListOffset;
                List<long> subOffsets = ParseSubkeyList(subListAbs, visited);
                for (int si = 0; si < subOffsets.Count; si++)
                {
                    long subOffset = subOffsets[si];
                    string childPath = fullPath + "\\" + (si.ToString()); // provisional
                    RegistryKey sub = ParseKeyCell(subOffset, childPath, visited);
                    if (sub != null)
                    {
                        sub.Path = fullPath + "\\" + sub.Name;
                        key.Subkeys.Add(sub);
                    }
                }
            }

            return key;
        }

        private List<long> ParseSubkeyList(long listOffset, HashSet<long> visited)
        {
            var result = new List<long>();
            if (listOffset < HiveHeaderSize || listOffset + 8 > hiveBuffer.Length) return result;
            if (!visited.Add(listOffset)) return result;

            int listSize = BitConverter.ToInt32(hiveBuffer, (int)listOffset);
            if (listSize >= 0) return result; // unallocated

            ushort sig = BitConverter.ToUInt16(hiveBuffer, (int)listOffset + 4);
            ushort count = BitConverter.ToUInt16(hiveBuffer, (int)listOffset + 6);

            if (sig == LfSignature || sig == LhSignature)
            {
                // lf / lh: pairs of [uint cell_offset, uint hash_or_name_prefix]
                int cursor = (int)listOffset + 8;
                for (int i = 0; i < count; i++)
                {
                    if (cursor + 8 > hiveBuffer.Length) break;
                    uint cellOff = BitConverter.ToUInt32(hiveBuffer, cursor);
                    if (cellOff != 0xFFFFFFFFU)
                    {
                        result.Add(HiveHeaderSize + (long)cellOff);
                    }
                    cursor += 8;
                }
            }
            else if (sig == LiSignature)
            {
                // li: list of uint cell_offset
                int cursor = (int)listOffset + 8;
                for (int i = 0; i < count; i++)
                {
                    if (cursor + 4 > hiveBuffer.Length) break;
                    uint cellOff = BitConverter.ToUInt32(hiveBuffer, cursor);
                    if (cellOff != 0xFFFFFFFFU)
                    {
                        result.Add(HiveHeaderSize + (long)cellOff);
                    }
                    cursor += 4;
                }
            }
            else if (sig == RiSignature)
            {
                // ri: list of sublist offsets (points to lf, lh, or li)
                int cursor = (int)listOffset + 8;
                for (int i = 0; i < count; i++)
                {
                    if (cursor + 4 > hiveBuffer.Length) break;
                    uint subListOff = BitConverter.ToUInt32(hiveBuffer, cursor);
                    if (subListOff != 0xFFFFFFFFU)
                    {
                        long subListAbs = HiveHeaderSize + (long)subListOff;
                        var nested = ParseSubkeyList(subListAbs, visited);
                        result.AddRange(nested);
                    }
                    cursor += 4;
                }
            }

            return result;
        }

        private RegistryValue ParseValueCell(long cellOffset)
        {
            if (cellOffset < HiveHeaderSize || cellOffset + 24 > hiveBuffer.Length) return null;

            int cellSize = BitConverter.ToInt32(hiveBuffer, (int)cellOffset);
            if (cellSize >= 0) return null; // unallocated

            ushort sig = BitConverter.ToUInt16(hiveBuffer, (int)cellOffset + 4);
            if (sig != VkSignature) return null;

            ushort nameLen = BitConverter.ToUInt16(hiveBuffer, (int)cellOffset + 6);
            uint dataLenRaw = BitConverter.ToUInt32(hiveBuffer, (int)cellOffset + 8);
            uint dataOffset = BitConverter.ToUInt32(hiveBuffer, (int)cellOffset + 12);
            uint dataTypeRaw = BitConverter.ToUInt32(hiveBuffer, (int)cellOffset + 16);
            ushort flags = BitConverter.ToUInt16(hiveBuffer, (int)cellOffset + 20);

            string name = String.Empty;
            if (nameLen > 0 && cellOffset + 24 + nameLen <= hiveBuffer.Length)
            {
                bool isAscii = (flags & 0x0001) != 0;
                if (isAscii)
                {
                    name = Encoding.GetEncoding(28591).GetString(hiveBuffer, (int)cellOffset + 24, nameLen);
                }
                else
                {
                    name = Encoding.Unicode.GetString(hiveBuffer, (int)cellOffset + 24, nameLen);
                }
            }

            RegistryValueType valType = Enum.IsDefined(typeof(RegistryValueType), dataTypeRaw)
                ? (RegistryValueType)dataTypeRaw
                : RegistryValueType.Unknown;

            byte[] rawData = new byte[0];
            bool isInline = (dataLenRaw & 0x80000000U) != 0;
            int actualDataLen = (int)(dataLenRaw & 0x7FFFFFFFU);

            if (isInline)
            {
                // Small values <= 4 bytes stored directly in the dataOffset field
                int len = Math.Min(4, actualDataLen);
                rawData = new byte[len];
                byte[] offsetBytes = BitConverter.GetBytes(dataOffset);
                Array.Copy(offsetBytes, 0, rawData, 0, len);
            }
            else
            {
                if (dataOffset != 0xFFFFFFFFU && actualDataLen > 0 && actualDataLen <= 16 * 1024 * 1024)
                {
                    long dataCellAbs = HiveHeaderSize + (long)dataOffset;
                    if (dataCellAbs >= HiveHeaderSize && dataCellAbs + 4 + actualDataLen <= hiveBuffer.Length)
                    {
                        rawData = new byte[actualDataLen];
                        Array.Copy(hiveBuffer, (int)dataCellAbs + 4, rawData, 0, actualDataLen);
                    }
                }
            }

            object parsedValue = InterpretValueData(valType, rawData);

            return new RegistryValue
            {
                Name = name,
                ValueType = valType,
                RawData = rawData,
                Value = parsedValue,
                CellOffset = cellOffset,
                IsDeleted = false
            };
        }

        private static object InterpretValueData(RegistryValueType type, byte[] data)
        {
            if (data == null || data.Length == 0) return null;

            switch (type)
            {
                case RegistryValueType.String:
                case RegistryValueType.ExpandString:
                case RegistryValueType.Link:
                    string str = Encoding.Unicode.GetString(data);
                    int nullIdx = str.IndexOf('\0');
                    return nullIdx >= 0 ? str.Substring(0, nullIdx) : str;

                case RegistryValueType.DWord:
                    return data.Length >= 4 ? BitConverter.ToUInt32(data, 0) : 0U;

                case RegistryValueType.DWordBigEndian:
                    if (data.Length >= 4)
                    {
                        return ((uint)data[0] << 24) | ((uint)data[1] << 16) | ((uint)data[2] << 8) | (uint)data[3];
                    }
                    return 0U;

                case RegistryValueType.QWord:
                    return data.Length >= 8 ? BitConverter.ToUInt64(data, 0) : 0UL;

                case RegistryValueType.MultiString:
                    string full = Encoding.Unicode.GetString(data);
                    string[] parts = full.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                    return parts;

                case RegistryValueType.Binary:
                default:
                    return data;
            }
        }

        public RegistryKey GetKey(string keyPath)
        {
            if (String.IsNullOrEmpty(keyPath)) return RootKey;
            string normalized = keyPath.Trim('\\').Replace('/', '\\');
            string[] segments = normalized.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);

            RegistryKey current = RootKey;
            int startIdx = 0;
            if (segments.Length > 0 && String.Equals(segments[0], "ROOT", StringComparison.OrdinalIgnoreCase))
            {
                startIdx = 1;
            }

            for (int i = startIdx; i < segments.Length; i++)
            {
                if (current == null) return null;
                current = current.GetSubkey(segments[i]);
            }
            return current;
        }

        public List<RegistryKey> SearchKeys(string pattern, bool searchValues = false)
        {
            var results = new List<RegistryKey>();
            if (String.IsNullOrEmpty(pattern) || RootKey == null) return results;

            SearchKeyRecursive(RootKey, pattern.ToLowerInvariant(), searchValues, results);
            return results;
        }

        private void SearchKeyRecursive(RegistryKey current, string queryLower, bool searchValues, List<RegistryKey> results)
        {
            if (current == null) return;

            bool matched = current.Name.ToLowerInvariant().Contains(queryLower) ||
                           current.Path.ToLowerInvariant().Contains(queryLower);

            if (!matched && searchValues)
            {
                for (int i = 0; i < current.Values.Count; i++)
                {
                    if (current.Values[i].Name.ToLowerInvariant().Contains(queryLower) ||
                        current.Values[i].ValueAsString().ToLowerInvariant().Contains(queryLower))
                    {
                        matched = true;
                        break;
                    }
                }
            }

            if (matched)
            {
                results.Add(current);
            }

            for (int i = 0; i < current.Subkeys.Count; i++)
            {
                SearchKeyRecursive(current.Subkeys[i], queryLower, searchValues, results);
            }
        }

        public List<RegistryValue> SearchValues(string pattern)
        {
            var results = new List<RegistryValue>();
            if (String.IsNullOrEmpty(pattern) || RootKey == null) return results;

            string queryLower = pattern.ToLowerInvariant();
            SearchValuesRecursive(RootKey, queryLower, results);
            return results;
        }

        private void SearchValuesRecursive(RegistryKey current, string queryLower, List<RegistryValue> results)
        {
            if (current == null) return;

            for (int i = 0; i < current.Values.Count; i++)
            {
                var val = current.Values[i];
                if (val.Name.ToLowerInvariant().Contains(queryLower) ||
                    val.ValueAsString().ToLowerInvariant().Contains(queryLower))
                {
                    results.Add(val);
                }
            }

            for (int i = 0; i < current.Subkeys.Count; i++)
            {
                SearchValuesRecursive(current.Subkeys[i], queryLower, results);
            }
        }

        /// <summary>
        /// Carves unallocated cells and slack space across all hive bins for deleted keys and values.
        /// </summary>
        public List<RegistryKey> CarveDeletedKeys()
        {
            var results = new List<RegistryKey>();
            long cursor = HiveHeaderSize;
            long limit = hiveBuffer.Length;

            while (cursor + 32 <= limit)
            {
                // Scan for hbin
                if (cursor + 32 <= limit &&
                    hiveBuffer[cursor] == 0x68 && hiveBuffer[cursor + 1] == 0x62 &&
                    hiveBuffer[cursor + 2] == 0x69 && hiveBuffer[cursor + 3] == 0x6E)
                {
                    uint binSize = BitConverter.ToUInt32(hiveBuffer, (int)cursor + 8);
                    if (binSize < 32 || cursor + binSize > limit)
                    {
                        cursor += 4096;
                        continue;
                    }

                    long binLimit = cursor + binSize;
                    long cellCursor = cursor + 32;

                    while (cellCursor + 8 <= binLimit)
                    {
                        int cellSize = BitConverter.ToInt32(hiveBuffer, (int)cellCursor);
                        if (cellSize == 0)
                        {
                            cellCursor += 4;
                            continue;
                        }

                        int absSize = Math.Abs(cellSize);
                        if (absSize < 8 || cellCursor + absSize > binLimit)
                        {
                            cellCursor += 4;
                            continue;
                        }

                        // Check for deleted key signature (nk)
                        ushort sig = BitConverter.ToUInt16(hiveBuffer, (int)cellCursor + 4);
                        if (sig == NkSignature)
                        {
                            ushort flags = BitConverter.ToUInt16(hiveBuffer, (int)cellCursor + 6);
                            ushort nameLen = BitConverter.ToUInt16(hiveBuffer, (int)cellCursor + 72);
                            if (nameLen > 0 && nameLen < 512 && cellCursor + 76 + nameLen <= binLimit)
                            {
                                bool isAscii = (flags & 0x0020) != 0 || (flags & 0x0080) != 0;
                                string name = isAscii
                                    ? Encoding.GetEncoding(28591).GetString(hiveBuffer, (int)cellCursor + 76, nameLen)
                                    : Encoding.Unicode.GetString(hiveBuffer, (int)cellCursor + 76, nameLen);

                                long ft = BitConverter.ToInt64(hiveBuffer, (int)cellCursor + 8);
                                DateTime lastWrite = DateTime.MinValue;
                                try { if (ft > 0 && ft < 0x24C85A5EDB04000L) lastWrite = DateTime.FromFileTimeUtc(ft); } catch { }

                                var delKey = new RegistryKey
                                {
                                    Name = name,
                                    Path = "[CARVED_DELETED]\\" + name,
                                    LastWriteTimeUtc = lastWrite,
                                    CellOffset = cellCursor,
                                    IsDeleted = true
                                };
                                results.Add(delKey);
                            }
                        }

                        cellCursor += absSize;
                    }

                    cursor += binSize;
                }
                else
                {
                    cursor += 512;
                }
            }

            return results;
        }

        public List<RegistryValue> CarveDeletedValues()
        {
            var results = new List<RegistryValue>();
            long cursor = HiveHeaderSize;
            long limit = hiveBuffer.Length;

            while (cursor + 32 <= limit)
            {
                if (hiveBuffer[cursor] == 0x68 && hiveBuffer[cursor + 1] == 0x62 &&
                    hiveBuffer[cursor + 2] == 0x69 && hiveBuffer[cursor + 3] == 0x6E)
                {
                    uint binSize = BitConverter.ToUInt32(hiveBuffer, (int)cursor + 8);
                    if (binSize < 32 || cursor + binSize > limit)
                    {
                        cursor += 4096;
                        continue;
                    }

                    long binLimit = cursor + binSize;
                    long cellCursor = cursor + 32;

                    while (cellCursor + 24 <= binLimit)
                    {
                        int cellSize = BitConverter.ToInt32(hiveBuffer, (int)cellCursor);
                        if (cellSize == 0) { cellCursor += 4; continue; }
                        int absSize = Math.Abs(cellSize);
                        if (absSize < 8 || cellCursor + absSize > binLimit) { cellCursor += 4; continue; }

                        ushort sig = BitConverter.ToUInt16(hiveBuffer, (int)cellCursor + 4);
                        if (sig == VkSignature)
                        {
                            ushort nameLen = BitConverter.ToUInt16(hiveBuffer, (int)cellCursor + 6);
                            uint dataLenRaw = BitConverter.ToUInt32(hiveBuffer, (int)cellCursor + 8);
                            uint dataOffset = BitConverter.ToUInt32(hiveBuffer, (int)cellCursor + 12);
                            uint dataTypeRaw = BitConverter.ToUInt32(hiveBuffer, (int)cellCursor + 16);
                            ushort flags = BitConverter.ToUInt16(hiveBuffer, (int)cellCursor + 20);

                            if (nameLen < 256 && cellCursor + 24 + nameLen <= binLimit)
                            {
                                bool isAscii = (flags & 0x0001) != 0;
                                string name = nameLen > 0
                                    ? (isAscii ? Encoding.GetEncoding(28591).GetString(hiveBuffer, (int)cellCursor + 24, nameLen)
                                               : Encoding.Unicode.GetString(hiveBuffer, (int)cellCursor + 24, nameLen))
                                    : "(Default)";

                                RegistryValueType vType = Enum.IsDefined(typeof(RegistryValueType), dataTypeRaw)
                                    ? (RegistryValueType)dataTypeRaw
                                    : RegistryValueType.Unknown;

                                int dataLen = (int)(dataLenRaw & 0x7FFFFFFFU);
                                byte[] raw = new byte[0];
                                if ((dataLenRaw & 0x80000000U) != 0)
                                {
                                    int len = Math.Min(4, dataLen);
                                    raw = new byte[len];
                                    Array.Copy(BitConverter.GetBytes(dataOffset), 0, raw, 0, len);
                                }
                                else if (dataOffset != 0xFFFFFFFFU && dataLen > 0 && dataLen < 65536)
                                {
                                    long dAbs = HiveHeaderSize + (long)dataOffset;
                                    if (dAbs >= HiveHeaderSize && dAbs + 4 + dataLen <= limit)
                                    {
                                        raw = new byte[dataLen];
                                        Array.Copy(hiveBuffer, (int)dAbs + 4, raw, 0, dataLen);
                                    }
                                }

                                var delVal = new RegistryValue
                                {
                                    Name = name,
                                    ValueType = vType,
                                    RawData = raw,
                                    Value = InterpretValueData(vType, raw),
                                    CellOffset = cellCursor,
                                    IsDeleted = true
                                };
                                results.Add(delVal);
                            }
                        }

                        cellCursor += absSize;
                    }
                    cursor += binSize;
                }
                else
                {
                    cursor += 512;
                }
            }

            return results;
        }

        public RegistrySystemSummary ExtractSystemSummary()
        {
            var summary = new RegistrySystemSummary();

            // 1. SOFTWARE hive artifacts
            var cvKey = GetKey("Microsoft\\Windows NT\\CurrentVersion");
            if (cvKey != null)
            {
                var prod = cvKey.GetValue("ProductName");
                if (prod != null && prod.Value is string) summary.ProductName = (string)prod.Value;

                var ver = cvKey.GetValue("CurrentVersion");
                if (ver != null && ver.Value is string) summary.CurrentVersion = (string)ver.Value;

                var build = cvKey.GetValue("CurrentBuild") ?? cvKey.GetValue("CurrentBuildNumber");
                if (build != null && build.Value is string) summary.CurrentBuild = (string)build.Value;

                var inst = cvKey.GetValue("InstallDate");
                if (inst != null && inst.Value is uint)
                {
                    try
                    {
                        DateTime dt = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds((uint)inst.Value);
                        summary.InstallDateUtc = dt.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
                    }
                    catch { }
                }
            }

            // 2. SYSTEM hive artifacts: Select (CurrentControlSet)
            string ccs = "ControlSet001";
            var selectKey = GetKey("Select");
            if (selectKey != null)
            {
                var cur = selectKey.GetValue("Current");
                if (cur != null && cur.Value is uint)
                {
                    ccs = string.Format(System.Globalization.CultureInfo.InvariantCulture, "ControlSet{0:D3}", (uint)cur.Value);
                }
            }
            summary.CurrentControlSet = ccs;

            // ComputerName
            var compKey = GetKey(ccs + "\\Control\\ComputerName\\ComputerName")
                       ?? GetKey("CurrentControlSet\\Control\\ComputerName\\ComputerName");
            if (compKey != null)
            {
                var nameVal = compKey.GetValue("ComputerName");
                if (nameVal != null && nameVal.Value is string) summary.ComputerName = (string)nameVal.Value;
            }

            // TimeZone
            var tzKey = GetKey(ccs + "\\Control\\TimeZoneInformation")
                     ?? GetKey("CurrentControlSet\\Control\\TimeZoneInformation");
            if (tzKey != null)
            {
                var tzVal = tzKey.GetValue("StandardName") ?? tzKey.GetValue("TimeZoneKeyName");
                if (tzVal != null && tzVal.Value is string) summary.TimeZoneStandardName = (string)tzVal.Value;
            }

            // USB Storage Devices
            var usbKey = GetKey(ccs + "\\Enum\\USBSTOR")
                      ?? GetKey("CurrentControlSet\\Enum\\USBSTOR");
            if (usbKey != null)
            {
                for (int i = 0; i < usbKey.Subkeys.Count; i++)
                {
                    var devKey = usbKey.Subkeys[i];
                    for (int j = 0; j < devKey.Subkeys.Count; j++)
                    {
                        var instKey = devKey.Subkeys[j];
                        var friendly = instKey.GetValue("FriendlyName");
                        string desc = friendly != null ? friendly.ValueAsString() : devKey.Name;
                        summary.UsbDevices.Add(desc + " (ID: " + instKey.Name + ")");
                    }
                }
            }

            // 3. SAM hive artifacts: User Accounts
            var usersKey = GetKey("SAM\\Domains\\Account\\Users\\Names");
            if (usersKey != null)
            {
                for (int i = 0; i < usersKey.Subkeys.Count; i++)
                {
                    summary.UserAccounts.Add(usersKey.Subkeys[i].Name);
                }
            }

            // 4. Persistence Run keys
            var runKey = GetKey("Microsoft\\Windows\\CurrentVersion\\Run");
            if (runKey != null)
            {
                for (int i = 0; i < runKey.Values.Count; i++)
                {
                    summary.RunKeys.Add(runKey.Values[i].Name + " -> " + runKey.Values[i].ValueAsString());
                }
            }

            return summary;
        }

        private static string ReadUtf16String(byte[] buffer, int offset, int maxBytes)
        {
            if (offset < 0 || offset + maxBytes > buffer.Length) return String.Empty;
            string str = Encoding.Unicode.GetString(buffer, offset, maxBytes);
            int nullIdx = str.IndexOf('\0');
            return nullIdx >= 0 ? str.Substring(0, nullIdx) : str;
        }

        public void Dispose()
        {
            if (!isDisposed)
            {
                isDisposed = true;
                if (isBufferOwner)
                {
                    hiveBuffer = null;
                }
            }
        }
    }
}
