using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public sealed class PrefetchArtifact
    {
        public string ExecutableName { get; set; }
        public string Hash { get; set; }
        public uint Version { get; set; }
        public uint RunCount { get; set; }
        public List<DateTime> LastRunTimes { get; set; }
        public List<string> LoadedFiles { get; set; }
        public List<string> VolumeSerials { get; set; }

        public PrefetchArtifact()
        {
            ExecutableName = String.Empty;
            Hash = String.Empty;
            LastRunTimes = new List<DateTime>();
            LoadedFiles = new List<string>();
            VolumeSerials = new List<string>();
        }
    }

    public static class PrefetchParser
    {
        private const uint SccaSignature = 0x41434353; // "SCCA" in little-endian (0x53, 0x43, 0x43, 0x41)
        private const uint MamSignature = 0x044D414D;  // "MAM\x04" in little-endian (0x4D, 0x41, 0x4D, 0x04)

        public static PrefetchArtifact ParseFile(string filePath)
        {
            if (filePath == null) throw new ArgumentNullException("filePath");
            if (!File.Exists(filePath)) throw new FileNotFoundException("Prefetch file not found", filePath);

            byte[] buffer = File.ReadAllBytes(filePath);
            return Parse(buffer);
        }

        public static PrefetchArtifact Parse(Stream stream)
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
                    }
                    buffer = ms.ToArray();
                }
            }

            return Parse(buffer);
        }

        public static PrefetchArtifact Parse(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (buffer.Length < 84)
            {
                throw new InvalidDataException("Prefetch buffer too small (less than 84 bytes)");
            }

            // Check for Windows 10/11 MAM compression header
            uint magic = BitConverter.ToUInt32(buffer, 0);
            if (magic == MamSignature)
            {
                uint uncompressedSize = BitConverter.ToUInt32(buffer, 4);
                if (uncompressedSize < 84 || uncompressedSize > 10 * 1024 * 1024)
                {
                    throw new InvalidDataException("MAM prefetch uncompressed size out of bounds: " + uncompressedSize);
                }

                buffer = MsXpressHuffman.Decompress(buffer, 8, buffer.Length - 8, (int)uncompressedSize);
            }

            // Verify SCCA signature at offset 4
            uint sig = BitConverter.ToUInt32(buffer, 4);
            if (sig != SccaSignature)
            {
                throw new InvalidDataException("Invalid prefetch signature. Expected SCCA (0x41434353), got: 0x" + sig.ToString("X8"));
            }

            uint version = BitConverter.ToUInt32(buffer, 0);

            PrefetchArtifact artifact = new PrefetchArtifact();
            artifact.Version = version;

            // Executable filename: 60 bytes UTF-16LE at offset 16 (max 29 chars + null)
            string exeName = Encoding.Unicode.GetString(buffer, 16, 60);
            int nullIdx = exeName.IndexOf('\0');
            artifact.ExecutableName = (nullIdx >= 0) ? exeName.Substring(0, nullIdx) : exeName.TrimEnd('\0');

            // Hash: 4 bytes at offset 76
            uint hash = BitConverter.ToUInt32(buffer, 76);
            artifact.Hash = hash.ToString("X8");

            // Version-specific metadata parsing
            switch (version)
            {
                case 17: // Windows XP / 2003
                    ParseVersion17(buffer, artifact);
                    break;
                case 23: // Windows Vista / 7
                    ParseVersion23(buffer, artifact);
                    break;
                case 26: // Windows 8 / 8.1
                    ParseVersion26(buffer, artifact);
                    break;
                case 30: // Windows 10 / 11
                    ParseVersion30(buffer, artifact);
                    break;
                default:
                    ParseVersion30(buffer, artifact);
                    break;
            }

            return artifact;
        }

        private static void ParseVersion17(byte[] buffer, PrefetchArtifact artifact)
        {
            // Last execution FILETIME at offset 120 (0x78)
            if (buffer.Length >= 128)
            {
                long ft = BitConverter.ToInt64(buffer, 120);
                if (ft > 0)
                {
                    try { artifact.LastRunTimes.Add(DateTime.FromFileTimeUtc(ft)); } catch { }
                }
            }

            // Run count at offset 144 (0x90)
            if (buffer.Length >= 148)
            {
                artifact.RunCount = BitConverter.ToUInt32(buffer, 144);
            }

            ParseSections(buffer, 84, artifact);
        }

        private static void ParseVersion23(byte[] buffer, PrefetchArtifact artifact)
        {
            // Last execution FILETIME at offset 128 (0x80)
            if (buffer.Length >= 136)
            {
                long ft = BitConverter.ToInt64(buffer, 128);
                if (ft > 0)
                {
                    try { artifact.LastRunTimes.Add(DateTime.FromFileTimeUtc(ft)); } catch { }
                }
            }

            // Run count at offset 152 (0x98)
            if (buffer.Length >= 156)
            {
                artifact.RunCount = BitConverter.ToUInt32(buffer, 152);
            }

            ParseSections(buffer, 84, artifact);
        }

        private static void ParseVersion26(byte[] buffer, PrefetchArtifact artifact)
        {
            // 8 execution timestamps at offset 128 (0x80) to 192 (0xC0)
            if (buffer.Length >= 192)
            {
                for (int i = 0; i < 8; i++)
                {
                    long ft = BitConverter.ToInt64(buffer, 128 + i * 8);
                    if (ft > 0)
                    {
                        try { artifact.LastRunTimes.Add(DateTime.FromFileTimeUtc(ft)); } catch { }
                    }
                }
            }

            // Run count at offset 208 (0xD0)
            if (buffer.Length >= 212)
            {
                artifact.RunCount = BitConverter.ToUInt32(buffer, 208);
            }

            ParseSections(buffer, 84, artifact);
        }

        private static void ParseVersion30(byte[] buffer, PrefetchArtifact artifact)
        {
            // 8 execution timestamps at offset 128 (0x80) to 192 (0xC0)
            if (buffer.Length >= 192)
            {
                for (int i = 0; i < 8; i++)
                {
                    long ft = BitConverter.ToInt64(buffer, 128 + i * 8);
                    if (ft > 0)
                    {
                        try { artifact.LastRunTimes.Add(DateTime.FromFileTimeUtc(ft)); } catch { }
                    }
                }
            }

            // Run count at offset 208 (0xD0)
            if (buffer.Length >= 212)
            {
                artifact.RunCount = BitConverter.ToUInt32(buffer, 208);
            }

            ParseSections(buffer, 84, artifact);
        }

        private static void ParseSections(byte[] buffer, int headerSectionOffsets, PrefetchArtifact artifact)
        {
            if (buffer.Length < headerSectionOffsets + 36) return;

            // Section C: Filename strings table
            uint secCOffset = BitConverter.ToUInt32(buffer, headerSectionOffsets + 16);
            uint secCSize = BitConverter.ToUInt32(buffer, headerSectionOffsets + 20);

            if (secCOffset > 0 && secCSize > 0 && secCOffset + secCSize <= buffer.Length)
            {
                string rawStrings = Encoding.Unicode.GetString(buffer, (int)secCOffset, (int)secCSize);
                string[] parts = rawStrings.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < parts.Length; i++)
                {
                    string trimmed = parts[i].Trim();
                    if (trimmed.Length > 0)
                    {
                        artifact.LoadedFiles.Add(trimmed);
                    }
                }
            }

            // Section D: Volumes information
            uint secDOffset = BitConverter.ToUInt32(buffer, headerSectionOffsets + 24);
            uint secDCount = BitConverter.ToUInt32(buffer, headerSectionOffsets + 28);
            uint secDSize = BitConverter.ToUInt32(buffer, headerSectionOffsets + 32);

            if (secDOffset > 0 && secDCount > 0 && secDOffset + secDSize <= buffer.Length)
            {
                int cursor = (int)secDOffset;
                for (uint v = 0; v < secDCount; v++)
                {
                    if (cursor + 32 > buffer.Length) break;
                    uint volSerial = BitConverter.ToUInt32(buffer, cursor + 16);

                    string serialFormatted = String.Format("{0:X4}-{1:X4}", (volSerial >> 16) & 0xFFFF, volSerial & 0xFFFF);
                    artifact.VolumeSerials.Add(serialFormatted);

                    cursor += 96;
                }
            }
        }
    }

    public static class MsXpressHuffman
    {
        public static byte[] Decompress(byte[] input, int offset, int length, int uncompressedSize)
        {
            if (input == null) throw new ArgumentNullException("input");
            if (offset < 0 || length < 0 || offset + length > input.Length)
            {
                throw new ArgumentOutOfRangeException("offset/length out of bounds");
            }
            if (uncompressedSize <= 0) return new byte[0];

            byte[] output = new byte[uncompressedSize];
            int currentInputPos = offset;
            int currentOutputPos = 0;
            int inputEnd = offset + length;

            ushort[] decodingTable = new ushort[32768];
            byte[] bitLengths = new byte[512];

            while (currentOutputPos < uncompressedSize && currentInputPos < inputEnd)
            {
                // Each block begins with 256 bytes containing 512 4-bit nibbles for bit lengths
                if (currentInputPos + 256 > inputEnd)
                {
                    throw new InvalidDataException("Truncated MS-XCA Huffman block header (expected 256 bytes)");
                }

                for (int i = 0; i < 256; i++)
                {
                    byte b = input[currentInputPos + i];
                    bitLengths[i * 2] = (byte)(b & 0x0F);
                    bitLengths[i * 2 + 1] = (byte)(b >> 4);
                }
                currentInputPos += 256;

                // Build Canonical Huffman Decoding Table (32,768 entries)
                int currentTableEntry = 0;
                for (int bitLength = 1; bitLength <= 15; bitLength++)
                {
                    for (int symbol = 0; symbol < 512; symbol++)
                    {
                        if (bitLengths[symbol] == bitLength)
                        {
                            int entryCount = 1 << (15 - bitLength);
                            for (int e = 0; e < entryCount; e++)
                            {
                                if (currentTableEntry >= 32768)
                                {
                                    throw new InvalidDataException("Invalid MS-XCA Huffman table: entry count exceeded 32768");
                                }
                                decodingTable[currentTableEntry++] = (ushort)symbol;
                            }
                        }
                    }
                }

                if (currentTableEntry != 32768)
                {
                    throw new InvalidDataException("Invalid MS-XCA Huffman table: total entries " + currentTableEntry + " != 32768");
                }

                // Initialize 32-bit bitstream register with two 16-bit words
                if (currentInputPos + 4 > inputEnd)
                {
                    throw new InvalidDataException("Truncated MS-XCA bitstream header");
                }

                uint nextBits = (uint)BitConverter.ToUInt16(input, currentInputPos);
                currentInputPos += 2;
                nextBits <<= 16;
                nextBits |= (uint)BitConverter.ToUInt16(input, currentInputPos);
                currentInputPos += 2;
                int extraBitCount = 16;

                int blockEnd = Math.Min(currentOutputPos + 65536, uncompressedSize);

                while (currentOutputPos < blockEnd)
                {
                    int next15Bits = (int)(nextBits >> 17); // 32 - 15 = 17
                    int symbol = decodingTable[next15Bits];
                    int symbolBitLen = bitLengths[symbol];

                    nextBits <<= symbolBitLen;
                    extraBitCount -= symbolBitLen;

                    if (extraBitCount < 0)
                    {
                        ushort word = (currentInputPos + 2 <= inputEnd) ? BitConverter.ToUInt16(input, currentInputPos) : (ushort)0;
                        currentInputPos += 2;
                        nextBits |= (uint)word << (-extraBitCount);
                        extraBitCount += 16;
                    }

                    if (symbol < 256)
                    {
                        // Literal byte
                        output[currentOutputPos++] = (byte)symbol;
                    }
                    else if (symbol == 256 && currentInputPos >= inputEnd && currentOutputPos >= uncompressedSize)
                    {
                        // End of stream marker
                        break;
                    }
                    else
                    {
                        // Match reference
                        int matchSymbol = symbol - 256;
                        int matchLength = matchSymbol % 16;
                        int matchOffsetBitLength = matchSymbol / 16;

                        if (matchLength == 15)
                        {
                            if (currentInputPos < inputEnd)
                            {
                                matchLength = input[currentInputPos++];
                                if (matchLength == 255)
                                {
                                    if (currentInputPos + 2 <= inputEnd)
                                    {
                                        matchLength = BitConverter.ToUInt16(input, currentInputPos);
                                        currentInputPos += 2;
                                        if (matchLength < 15)
                                        {
                                            throw new InvalidDataException("Invalid MS-XCA match length");
                                        }
                                        matchLength -= 15;
                                    }
                                }
                                matchLength += 15;
                            }
                        }
                        matchLength += 3;

                        int matchOffset;
                        if (matchOffsetBitLength == 0)
                        {
                            matchOffset = 1;
                        }
                        else
                        {
                            matchOffset = (int)(nextBits >> (32 - matchOffsetBitLength));
                            matchOffset += (1 << matchOffsetBitLength);
                            nextBits <<= matchOffsetBitLength;
                            extraBitCount -= matchOffsetBitLength;

                            if (extraBitCount < 0)
                            {
                                ushort word = (currentInputPos + 2 <= inputEnd) ? BitConverter.ToUInt16(input, currentInputPos) : (ushort)0;
                                currentInputPos += 2;
                                nextBits |= (uint)word << (-extraBitCount);
                                extraBitCount += 16;
                            }
                        }

                        if (currentOutputPos - matchOffset < 0)
                        {
                            throw new InvalidDataException("MS-XCA match offset points before start of output buffer: " + matchOffset);
                        }

                        // Copy 1 byte at a time to handle overlapping runs correctly
                        for (int i = 0; i < matchLength; i++)
                        {
                            if (currentOutputPos < uncompressedSize)
                            {
                                output[currentOutputPos] = output[currentOutputPos - matchOffset];
                                currentOutputPos++;
                            }
                        }
                    }
                }
            }

            return output;
        }

        public static byte[] CompressLiteralOnly(byte[] uncompressed)
        {
            if (uncompressed == null) throw new ArgumentNullException("uncompressed");

            using (MemoryStream ms = new MemoryStream())
            {
                int cursor = 0;
                int total = uncompressed.Length;

                while (cursor < total)
                {
                    int blockSize = Math.Min(65536, total - cursor);

                    // 256-byte header: all 256 literals have length 8 (0x88 for first 128 bytes), matches have length 0 (0x00 for next 128 bytes)
                    byte[] header = new byte[256];
                    for (int i = 0; i < 128; i++) header[i] = 0x88;
                    for (int i = 128; i < 256; i++) header[i] = 0x00;
                    ms.Write(header, 0, 256);

                    // Write literal symbols packed into 16-bit little endian words
                    List<byte> bitBuffer = new List<byte>();
                    uint currentWord = 0;
                    int bitsInWord = 0;

                    for (int i = 0; i < blockSize; i++)
                    {
                        byte b = uncompressed[cursor + i];
                        currentWord = (currentWord << 8) | b;
                        bitsInWord += 8;

                        while (bitsInWord >= 16)
                        {
                            int shift = bitsInWord - 16;
                            ushort word16 = (ushort)((currentWord >> shift) & 0xFFFF);
                            bitBuffer.Add((byte)(word16 & 0xFF));
                            bitBuffer.Add((byte)((word16 >> 8) & 0xFF));
                            bitsInWord -= 16;
                        }
                    }

                    if (bitsInWord > 0)
                    {
                        ushort word16 = (ushort)((currentWord << (16 - bitsInWord)) & 0xFFFF);
                        bitBuffer.Add((byte)(word16 & 0xFF));
                        bitBuffer.Add((byte)((word16 >> 8) & 0xFF));
                    }

                    // Pad with two trailing zero words so decoder does not underflow
                    bitBuffer.Add(0); bitBuffer.Add(0);
                    bitBuffer.Add(0); bitBuffer.Add(0);

                    byte[] blockBytes = bitBuffer.ToArray();
                    ms.Write(blockBytes, 0, blockBytes.Length);

                    cursor += blockSize;
                }

                return ms.ToArray();
            }
        }
    }
}
