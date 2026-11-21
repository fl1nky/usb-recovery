using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public enum CarvedRecordOrigin
    {
        ActiveCell = 1,
        Freeblock = 2,
        UnallocatedGap = 3,
        FreelistLeaf = 4,
        HeuristicScan = 5
    }

    public enum SqliteColumnType
    {
        Null = 0,
        Integer = 1,
        Float = 2,
        Text = 3,
        Blob = 4
    }

    public enum SqliteBtreePageType : byte
    {
        InteriorIndex = 0x02,
        InteriorTable = 0x05,
        LeafIndex = 0x0A,
        LeafTable = 0x0D,
        Unknown = 0x00
    }

    public sealed class SqliteColumnValue
    {
        public int ColumnIndex { get; set; }
        public long SerialType { get; set; }
        public SqliteColumnType Type { get; set; }
        public string TypeName { get; set; }
        public object Value { get; set; }
        public int DataLength { get; set; }
        public byte[] RawBytes { get; set; }

        public SqliteColumnValue()
        {
            TypeName = String.Empty;
        }

        public string AsString()
        {
            if (Value == null) return String.Empty;
            return Value.ToString();
        }

        public long AsLong(long defaultValue)
        {
            if (Value == null) return defaultValue;
            if (Value is long) return (long)Value;
            if (Value is int) return (long)(int)Value;
            if (Value is short) return (long)(short)Value;
            if (Value is sbyte) return (long)(sbyte)Value;
            if (Value is byte) return (long)(byte)Value;
            long parsed;
            if (Int64.TryParse(Value.ToString(), out parsed)) return parsed;
            return defaultValue;
        }

        public double AsDouble(double defaultValue)
        {
            if (Value == null) return defaultValue;
            if (Value is double) return (double)Value;
            if (Value is float) return (double)(float)Value;
            if (Value is long) return (double)(long)Value;
            if (Value is int) return (double)(int)Value;
            double parsed;
            if (Double.TryParse(Value.ToString(), out parsed)) return parsed;
            return defaultValue;
        }
    }

    public sealed class CarvedSqliteRecord
    {
        public uint PageNumber { get; set; }
        public int PageOffset { get; set; }
        public long AbsoluteOffset { get; set; }
        public CarvedRecordOrigin Origin { get; set; }
        public long? RowId { get; set; }
        public int PayloadSize { get; set; }
        public int HeaderLength { get; set; }
        public List<SqliteColumnValue> Columns { get; set; }
        public byte[] RawPayload { get; set; }

        public object[] ColumnValues
        {
            get { return GetColumnValues(); }
        }

        public CarvedSqliteRecord()
        {
            Columns = new List<SqliteColumnValue>();
        }

        public object[] GetColumnValues()
        {
            object[] result = new object[Columns.Count];
            for (int i = 0; i < Columns.Count; i++)
            {
                result[i] = Columns[i].Value;
            }
            return result;
        }
    }

    public sealed class SqliteDatabaseHeader
    {
        public int PageSize { get; set; }
        public byte WriteVersion { get; set; }
        public byte ReadVersion { get; set; }
        public byte ReservedSpace { get; set; }
        public uint FileChangeCounter { get; set; }
        public uint PageCount { get; set; }
        public uint FirstFreelistTrunkPage { get; set; }
        public uint TotalFreelistPages { get; set; }
        public uint SchemaCookie { get; set; }
        public uint SchemaFormat { get; set; }
        public uint TextEncoding { get; set; }
        public uint UserVersion { get; set; }
        public uint ApplicationId { get; set; }
    }

    public sealed class SqliteBtreePageHeader
    {
        public SqliteBtreePageType PageType { get; set; }
        public ushort FirstFreeblockOffset { get; set; }
        public ushort CellCount { get; set; }
        public int CellContentAreaStart { get; set; } // 0 denotes 65536
        public byte FragmentedFreeBytes { get; set; }
        public uint RightChildPage { get; set; }
        public int HeaderOffset { get; set; }
        public int HeaderSize { get; set; }
    }

    public static class SqliteCarver
    {
        private static readonly byte[] SqliteMagic = new byte[]
        {
            0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00
        };

        public static List<CarvedSqliteRecord> CarveDatabase(string dbPath)
        {
            if (dbPath == null) throw new ArgumentNullException("dbPath");
            if (!File.Exists(dbPath)) throw new FileNotFoundException("Database file not found.", dbPath);

            using (FileStream fs = new FileStream(dbPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return CarveDatabase(fs);
            }
        }

        public static List<CarvedSqliteRecord> CarveDatabase(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable.", "stream");

            List<CarvedSqliteRecord> results = new List<CarvedSqliteRecord>();

            // Read database header
            byte[] headerBuffer = new byte[100];
            stream.Position = 0;
            int bytesRead = stream.Read(headerBuffer, 0, 100);

            SqliteDatabaseHeader dbHeader = null;
            bool validHeader = (bytesRead == 100 && TryParseHeader(headerBuffer, out dbHeader));

            if (!validHeader)
            {
                // Fallback to stream-wide heuristic sliding-window carving with bounded memory
                stream.Position = 0;
                int blockSize = 65536;
                int overlap = 2048;
                byte[] block = new byte[blockSize];
                long currentOffset = 0;
                int buffered = 0;
                HashSet<long> seenOffsets = new HashSet<long>();
                List<CarvedSqliteRecord> chunkResults = new List<CarvedSqliteRecord>();

                while (true)
                {
                    int needed = blockSize - buffered;
                    int read = stream.Read(block, buffered, needed);
                    int totalInBlock = buffered + read;
                    if (totalInBlock <= 4) break;

                    chunkResults.Clear();
                    CarveBufferInternal(block, 0, totalInBlock, 0, currentOffset, CarvedRecordOrigin.HeuristicScan, chunkResults);
                    for (int i = 0; i < chunkResults.Count; i++)
                    {
                        if (seenOffsets.Add(chunkResults[i].AbsoluteOffset))
                        {
                            results.Add(chunkResults[i]);
                        }
                    }

                    if (read <= 0 || read < needed)
                    {
                        break;
                    }

                    int retain = Math.Min(overlap, totalInBlock);
                    Buffer.BlockCopy(block, totalInBlock - retain, block, 0, retain);
                    buffered = retain;
                    currentOffset += (totalInBlock - retain);
                }
                return results;
            }

            int pageSize = dbHeader.PageSize;
            int reservedSpace = dbHeader.ReservedSpace;
            long streamLength = stream.Length;
            uint totalPages = (uint)(streamLength / pageSize);
            if (dbHeader.PageCount > 0 && dbHeader.PageCount < totalPages)
            {
                totalPages = dbHeader.PageCount;
            }

            HashSet<uint> freelistPages = new HashSet<uint>();

            // 1. Freelist Traversal
            if (dbHeader.FirstFreelistTrunkPage > 0)
            {
                TraverseFreelist(stream, dbHeader, freelistPages, results);
            }

            // 2. Page-by-Page Traversal
            byte[] pageBuffer = new byte[pageSize];
            for (uint pageNum = 1; pageNum <= totalPages; pageNum++)
            {
                if (freelistPages.Contains(pageNum))
                {
                    continue;
                }

                long pageOffset = (long)(pageNum - 1) * pageSize;
                if (pageOffset + pageSize > streamLength)
                {
                    break;
                }

                stream.Position = pageOffset;
                int read = stream.Read(pageBuffer, 0, pageSize);
                if (read < pageSize) break;

                int headerOffset = (pageNum == 1) ? 100 : 0;
                SqliteBtreePageHeader pageHeader;
                if (TryParseBtreeHeader(pageBuffer, headerOffset, out pageHeader))
                {
                    if (pageHeader.PageType == SqliteBtreePageType.LeafTable)
                    {
                        CarveLeafTablePage(pageBuffer, pageNum, pageOffset, pageHeader, reservedSpace, results);
                    }
                    else if (pageHeader.PageType == SqliteBtreePageType.LeafIndex)
                    {
                        CarveLeafIndexPage(pageBuffer, pageNum, pageOffset, pageHeader, reservedSpace, results);
                    }
                    else
                    {
                        CarvePageSlack(pageBuffer, pageNum, pageOffset, headerOffset + pageHeader.HeaderSize, pageSize - reservedSpace, results);
                    }
                }
                else
                {
                    CarveBufferInternal(pageBuffer, 0, pageSize - reservedSpace, pageNum, pageOffset, CarvedRecordOrigin.HeuristicScan, results);
                }
            }

            return results;
        }

        public static List<CarvedSqliteRecord> CarvePage(byte[] pageBuffer, uint pageNumber, long pageOffset)
        {
            List<CarvedSqliteRecord> results = new List<CarvedSqliteRecord>();
            if (pageBuffer == null || pageBuffer.Length < 8) return results;

            int headerOffset = (pageNumber == 1 && pageBuffer.Length >= 108) ? 100 : 0;
            SqliteBtreePageHeader pageHeader;
            if (TryParseBtreeHeader(pageBuffer, headerOffset, out pageHeader))
            {
                if (pageHeader.PageType == SqliteBtreePageType.LeafTable)
                {
                    CarveLeafTablePage(pageBuffer, pageNumber, pageOffset, pageHeader, 0, results);
                }
                else if (pageHeader.PageType == SqliteBtreePageType.LeafIndex)
                {
                    CarveLeafIndexPage(pageBuffer, pageNumber, pageOffset, pageHeader, 0, results);
                }
                else
                {
                    CarvePageSlack(pageBuffer, pageNumber, pageOffset, headerOffset + pageHeader.HeaderSize, pageBuffer.Length, results);
                }
            }
            else
            {
                CarveBufferInternal(pageBuffer, 0, pageBuffer.Length, pageNumber, pageOffset, CarvedRecordOrigin.HeuristicScan, results);
            }

            return results;
        }

        public static List<CarvedSqliteRecord> CarveBuffer(byte[] buffer, long baseOffset)
        {
            List<CarvedSqliteRecord> results = new List<CarvedSqliteRecord>();
            if (buffer == null || buffer.Length < 4) return results;
            CarveBufferInternal(buffer, 0, buffer.Length, 0, baseOffset, CarvedRecordOrigin.HeuristicScan, results);
            return results;
        }

        public static bool TryParseHeader(byte[] buffer, out SqliteDatabaseHeader header)
        {
            header = null;
            if (buffer == null || buffer.Length < 100) return false;

            for (int i = 0; i < 16; i++)
            {
                if (buffer[i] != SqliteMagic[i]) return false;
            }

            int rawPageSize = (buffer[16] << 8) | buffer[17];
            int pageSize = (rawPageSize == 1) ? 65536 : rawPageSize;
            if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0)
            {
                return false;
            }

            header = new SqliteDatabaseHeader();
            header.PageSize = pageSize;
            header.WriteVersion = buffer[18];
            header.ReadVersion = buffer[19];
            header.ReservedSpace = buffer[20];
            header.FileChangeCounter = ReadUInt32BE(buffer, 24);
            header.PageCount = ReadUInt32BE(buffer, 28);
            header.FirstFreelistTrunkPage = ReadUInt32BE(buffer, 32);
            header.TotalFreelistPages = ReadUInt32BE(buffer, 36);
            header.SchemaCookie = ReadUInt32BE(buffer, 40);
            header.SchemaFormat = ReadUInt32BE(buffer, 44);
            header.TextEncoding = ReadUInt32BE(buffer, 56);
            header.UserVersion = ReadUInt32BE(buffer, 60);
            header.ApplicationId = ReadUInt32BE(buffer, 68);

            return true;
        }

        public static bool TryParseBtreeHeader(byte[] buffer, int offset, out SqliteBtreePageHeader header)
        {
            header = null;
            if (buffer == null || offset < 0 || offset + 8 > buffer.Length) return false;

            byte typeByte = buffer[offset];
            SqliteBtreePageType pageType = SqliteBtreePageType.Unknown;
            int headerSize = 8;

            if (typeByte == 0x02) { pageType = SqliteBtreePageType.InteriorIndex; headerSize = 12; }
            else if (typeByte == 0x05) { pageType = SqliteBtreePageType.InteriorTable; headerSize = 12; }
            else if (typeByte == 0x0A) { pageType = SqliteBtreePageType.LeafIndex; headerSize = 8; }
            else if (typeByte == 0x0D) { pageType = SqliteBtreePageType.LeafTable; headerSize = 8; }
            else return false;

            if (offset + headerSize > buffer.Length) return false;

            header = new SqliteBtreePageHeader();
            header.PageType = pageType;
            header.HeaderOffset = offset;
            header.HeaderSize = headerSize;
            header.FirstFreeblockOffset = (ushort)((buffer[offset + 1] << 8) | buffer[offset + 2]);
            header.CellCount = (ushort)((buffer[offset + 3] << 8) | buffer[offset + 4]);
            int contentStart = (buffer[offset + 5] << 8) | buffer[offset + 6];
            header.CellContentAreaStart = (contentStart == 0) ? 65536 : contentStart;
            header.FragmentedFreeBytes = buffer[offset + 7];

            if (headerSize == 12)
            {
                header.RightChildPage = ReadUInt32BE(buffer, offset + 8);
            }

            return true;
        }

        private static void TraverseFreelist(Stream stream, SqliteDatabaseHeader dbHeader, HashSet<uint> freelistPages, List<CarvedSqliteRecord> results)
        {
            uint currentTrunk = dbHeader.FirstFreelistTrunkPage;
            HashSet<uint> visitedTrunks = new HashSet<uint>();
            byte[] pageBuf = new byte[dbHeader.PageSize];

            int maxLeavesPerTrunk = (dbHeader.PageSize - 8) / 4;

            while (currentTrunk > 0)
            {
                if (visitedTrunks.Contains(currentTrunk))
                {
                    break;
                }
                visitedTrunks.Add(currentTrunk);

                long trunkOffset = (long)(currentTrunk - 1) * dbHeader.PageSize;
                if (trunkOffset + dbHeader.PageSize > stream.Length)
                {
                    break;
                }

                stream.Position = trunkOffset;
                int read = stream.Read(pageBuf, 0, dbHeader.PageSize);
                if (read < dbHeader.PageSize) break;

                uint nextTrunk = ReadUInt32BE(pageBuf, 0);
                uint leafCount = ReadUInt32BE(pageBuf, 4);

                if (leafCount > (uint)maxLeavesPerTrunk)
                {
                    leafCount = (uint)maxLeavesPerTrunk;
                }

                for (int i = 0; i < (int)leafCount; i++)
                {
                    uint leafPage = ReadUInt32BE(pageBuf, 8 + i * 4);
                    if (leafPage == 0) continue;
                    if (dbHeader.PageCount > 0 && leafPage > dbHeader.PageCount) continue;

                    if (freelistPages.Add(leafPage))
                    {
                        long leafOffset = (long)(leafPage - 1) * dbHeader.PageSize;
                        if (leafOffset + dbHeader.PageSize <= stream.Length)
                        {
                            byte[] leafBuf = new byte[dbHeader.PageSize];
                            stream.Position = leafOffset;
                            if (stream.Read(leafBuf, 0, dbHeader.PageSize) == dbHeader.PageSize)
                            {
                                int usable = dbHeader.PageSize - dbHeader.ReservedSpace;
                                CarveBufferInternal(leafBuf, 0, usable, leafPage, leafOffset, CarvedRecordOrigin.FreelistLeaf, results);
                            }
                        }
                    }
                }

                currentTrunk = nextTrunk;
            }
        }

        private static void CarveLeafTablePage(byte[] page, uint pageNum, long baseOffset, SqliteBtreePageHeader pageHeader, int reservedSpace, List<CarvedSqliteRecord> results)
        {
            int usableSize = page.Length - reservedSpace;
            int cellPointerArrayStart = pageHeader.HeaderOffset + pageHeader.HeaderSize;
            int cellCount = pageHeader.CellCount;
            int cellPointerArrayEnd = cellPointerArrayStart + cellCount * 2;

            if (cellPointerArrayEnd > usableSize)
            {
                cellCount = Math.Max(0, (usableSize - cellPointerArrayStart) / 2);
                cellPointerArrayEnd = cellPointerArrayStart + cellCount * 2;
            }

            // 1. Active Cells
            for (int i = 0; i < cellCount; i++)
            {
                int ptrOffset = cellPointerArrayStart + i * 2;
                int cellOffset = (page[ptrOffset] << 8) | page[ptrOffset + 1];
                if (cellOffset >= cellPointerArrayEnd && cellOffset < usableSize)
                {
                    ParseLeafTableCell(page, cellOffset, usableSize, pageNum, baseOffset, CarvedRecordOrigin.ActiveCell, results);
                }
            }

            // 2. Freeblock Linked List
            int fbOffset = pageHeader.FirstFreeblockOffset;
            HashSet<int> visitedFb = new HashSet<int>();
            while (fbOffset > 0)
            {
                if (visitedFb.Contains(fbOffset)) break;
                visitedFb.Add(fbOffset);

                if (fbOffset < cellPointerArrayEnd || fbOffset + 4 > usableSize) break;

                int nextFb = (page[fbOffset] << 8) | page[fbOffset + 1];
                int fbSize = (page[fbOffset + 2] << 8) | page[fbOffset + 3];

                if (fbSize < 4 || fbOffset + fbSize > usableSize) break;

                int fbPayloadOffset = fbOffset + 4;
                int fbPayloadLen = fbSize - 4;
                if (fbPayloadLen > 0)
                {
                    CarveBufferInternal(page, fbPayloadOffset, fbPayloadLen, pageNum, baseOffset, CarvedRecordOrigin.Freeblock, results);
                }

                fbOffset = nextFb;
            }

            // 3. Unallocated Gap
            int gapStart = cellPointerArrayEnd;
            int gapEnd = pageHeader.CellContentAreaStart;
            if (gapEnd > usableSize) gapEnd = usableSize;

            if (gapEnd > gapStart)
            {
                int gapLen = gapEnd - gapStart;
                CarveBufferInternal(page, gapStart, gapLen, pageNum, baseOffset, CarvedRecordOrigin.UnallocatedGap, results);
            }
        }

        private static void CarveLeafIndexPage(byte[] page, uint pageNum, long baseOffset, SqliteBtreePageHeader pageHeader, int reservedSpace, List<CarvedSqliteRecord> results)
        {
            int usableSize = page.Length - reservedSpace;
            int cellPointerArrayStart = pageHeader.HeaderOffset + pageHeader.HeaderSize;
            int cellCount = pageHeader.CellCount;
            int cellPointerArrayEnd = cellPointerArrayStart + cellCount * 2;

            if (cellPointerArrayEnd > usableSize)
            {
                cellCount = Math.Max(0, (usableSize - cellPointerArrayStart) / 2);
                cellPointerArrayEnd = cellPointerArrayStart + cellCount * 2;
            }

            for (int i = 0; i < cellCount; i++)
            {
                int ptrOffset = cellPointerArrayStart + i * 2;
                int cellOffset = (page[ptrOffset] << 8) | page[ptrOffset + 1];
                if (cellOffset >= cellPointerArrayEnd && cellOffset < usableSize)
                {
                    long payloadSize;
                    int v1 = ReadVarint(page, cellOffset, out payloadSize);
                    if (v1 > 0 && payloadSize > 0)
                    {
                        int pOffset = cellOffset + v1;
                        int avail = Math.Min((int)payloadSize, usableSize - pOffset);
                        List<SqliteColumnValue> cols;
                        int hLen;
                        int consumed;
                        if (TryParseRecord(page, pOffset, avail, out cols, out hLen, out consumed))
                        {
                            CarvedSqliteRecord rec = new CarvedSqliteRecord();
                            rec.PageNumber = pageNum;
                            rec.PageOffset = cellOffset;
                            rec.AbsoluteOffset = baseOffset + cellOffset;
                            rec.Origin = CarvedRecordOrigin.ActiveCell;
                            rec.RowId = null;
                            rec.PayloadSize = (int)payloadSize;
                            rec.HeaderLength = hLen;
                            rec.Columns = cols;

                            byte[] raw = new byte[consumed];
                            Array.Copy(page, pOffset, raw, 0, consumed);
                            rec.RawPayload = raw;

                            results.Add(rec);
                        }
                    }
                }
            }

            int gapStart = cellPointerArrayEnd;
            int gapEnd = pageHeader.CellContentAreaStart;
            if (gapEnd > usableSize) gapEnd = usableSize;

            if (gapEnd > gapStart)
            {
                int gapLen = gapEnd - gapStart;
                CarveBufferInternal(page, gapStart, gapLen, pageNum, baseOffset, CarvedRecordOrigin.UnallocatedGap, results);
            }
        }

        private static void CarvePageSlack(byte[] page, uint pageNum, long baseOffset, int slackStart, int slackLimit, List<CarvedSqliteRecord> results)
        {
            if (slackLimit > slackStart)
            {
                CarveBufferInternal(page, slackStart, slackLimit - slackStart, pageNum, baseOffset, CarvedRecordOrigin.UnallocatedGap, results);
            }
        }

        private static void ParseLeafTableCell(byte[] buffer, int cellOffset, int maxOffset, uint pageNum, long baseOffset, CarvedRecordOrigin origin, List<CarvedSqliteRecord> results)
        {
            long payloadSize;
            int v1 = ReadVarint(buffer, cellOffset, out payloadSize);
            if (v1 <= 0 || payloadSize <= 0) return;

            long rowId;
            int v2 = ReadVarint(buffer, cellOffset + v1, out rowId);
            if (v2 <= 0) return;

            int payloadOffset = cellOffset + v1 + v2;
            if (payloadOffset >= maxOffset) return;

            int availablePayload = Math.Min((int)payloadSize, maxOffset - payloadOffset);

            List<SqliteColumnValue> columns;
            int headerLen;
            int consumed;
            if (TryParseRecord(buffer, payloadOffset, availablePayload, out columns, out headerLen, out consumed))
            {
                CarvedSqliteRecord rec = new CarvedSqliteRecord();
                rec.PageNumber = pageNum;
                rec.PageOffset = cellOffset;
                rec.AbsoluteOffset = baseOffset + cellOffset;
                rec.Origin = origin;
                rec.RowId = rowId;
                rec.PayloadSize = (int)payloadSize;
                rec.HeaderLength = headerLen;
                rec.Columns = columns;

                byte[] raw = new byte[consumed];
                Array.Copy(buffer, payloadOffset, raw, 0, consumed);
                rec.RawPayload = raw;

                results.Add(rec);
            }
        }

        public static int ReadVarint(byte[] buffer, int offset, out long value)
        {
            value = 0;
            if (buffer == null || offset < 0 || offset >= buffer.Length)
            {
                return 0;
            }

            long acc = 0;
            for (int i = 0; i < 8; i++)
            {
                int idx = offset + i;
                if (idx >= buffer.Length)
                {
                    value = 0;
                    return 0;
                }
                byte b = buffer[idx];
                acc = (acc << 7) | (long)(uint)(b & 0x7F);
                if ((b & 0x80) == 0)
                {
                    value = acc;
                    return i + 1;
                }
            }

            if (offset + 8 >= buffer.Length)
            {
                value = 0;
                return 0;
            }
            byte b9 = buffer[offset + 8];
            acc = (acc << 8) | (long)(uint)b9;
            value = acc;
            return 9;
        }

        public static bool GetSerialTypeContentLength(long serialType, out int length)
        {
            length = 0;
            if (serialType < 0) return false;

            if (serialType == 0 || serialType == 8 || serialType == 9) { length = 0; return true; }
            if (serialType == 1) { length = 1; return true; }
            if (serialType == 2) { length = 2; return true; }
            if (serialType == 3) { length = 3; return true; }
            if (serialType == 4) { length = 4; return true; }
            if (serialType == 5) { length = 6; return true; }
            if (serialType == 6 || serialType == 7) { length = 8; return true; }
            if (serialType == 10 || serialType == 11) return false;

            long len = (serialType - 12) / 2;
            if (len > 1048576) return false; // Max single column safety cap (1 MB)
            length = (int)len;
            return true;
        }

        public static bool TryParseRecord(byte[] buffer, int offset, int maxBytes, out List<SqliteColumnValue> columns, out int headerLength, out int totalBytesConsumed)
        {
            columns = null;
            headerLength = 0;
            totalBytesConsumed = 0;

            if (buffer == null || offset < 0 || maxBytes <= 0 || offset >= buffer.Length) return false;

            long hLen;
            int hvLen = ReadVarint(buffer, offset, out hLen);
            if (hvLen <= 0 || hLen < hvLen || hLen > maxBytes) return false;

            int hSize = (int)hLen;
            List<long> serialTypes = new List<long>();
            int cursor = hvLen;

            while (cursor < hSize)
            {
                long st;
                int stLen = ReadVarint(buffer, offset + cursor, out st);
                if (stLen <= 0) return false;
                if (st == 10 || st == 11) return false;

                int colDataLen;
                if (!GetSerialTypeContentLength(st, out colDataLen)) return false;

                serialTypes.Add(st);
                cursor += stLen;
            }

            if (cursor != hSize) return false;
            if (serialTypes.Count == 0 || serialTypes.Count > 300) return false;

            int totalDataLen = 0;
            for (int i = 0; i < serialTypes.Count; i++)
            {
                int dLen;
                GetSerialTypeContentLength(serialTypes[i], out dLen);
                totalDataLen += dLen;
            }

            if (hSize + totalDataLen > maxBytes) return false;

            columns = new List<SqliteColumnValue>(serialTypes.Count);
            int dataCursor = offset + hSize;

            for (int i = 0; i < serialTypes.Count; i++)
            {
                long st = serialTypes[i];
                int dLen;
                GetSerialTypeContentLength(st, out dLen);

                SqliteColumnValue col = new SqliteColumnValue();
                col.ColumnIndex = i;
                col.SerialType = st;
                col.DataLength = dLen;

                DecodeColumnValue(buffer, dataCursor, st, dLen, col);
                columns.Add(col);

                dataCursor += dLen;
            }

            headerLength = hSize;
            totalBytesConsumed = hSize + totalDataLen;
            return true;
        }

        private static void DecodeColumnValue(byte[] buffer, int offset, long st, int length, SqliteColumnValue col)
        {
            if (st == 0)
            {
                col.Type = SqliteColumnType.Null;
                col.TypeName = "NULL";
                col.Value = null;
            }
            else if (st == 1)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                col.Value = (long)(sbyte)buffer[offset];
            }
            else if (st == 2)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                short val = (short)((buffer[offset] << 8) | buffer[offset + 1]);
                col.Value = (long)val;
            }
            else if (st == 3)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                int val = (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
                if ((val & 0x800000) != 0) val |= unchecked((int)0xFF000000); // Sign extend 24-bit
                col.Value = (long)val;
            }
            else if (st == 4)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                int val = (buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];
                col.Value = (long)val;
            }
            else if (st == 5)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                long val = ((long)buffer[offset] << 40)
                         | ((long)buffer[offset + 1] << 32)
                         | ((long)buffer[offset + 2] << 24)
                         | ((long)buffer[offset + 3] << 16)
                         | ((long)buffer[offset + 4] << 8)
                         | (long)buffer[offset + 5];
                if ((val & 0x800000000000L) != 0) val |= unchecked((long)0xFFFF000000000000L); // Sign extend 48-bit
                col.Value = val;
            }
            else if (st == 6)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                long val = ((long)buffer[offset] << 56)
                         | ((long)buffer[offset + 1] << 48)
                         | ((long)buffer[offset + 2] << 40)
                         | ((long)buffer[offset + 3] << 32)
                         | ((long)buffer[offset + 4] << 24)
                         | ((long)buffer[offset + 5] << 16)
                         | ((long)buffer[offset + 6] << 8)
                         | (long)buffer[offset + 7];
                col.Value = val;
            }
            else if (st == 7)
            {
                col.Type = SqliteColumnType.Float;
                col.TypeName = "FLOAT";
                byte[] raw = new byte[8];
                for (int b = 0; b < 8; b++) raw[7 - b] = buffer[offset + b]; // Big-endian to little-endian
                col.Value = BitConverter.ToDouble(raw, 0);
            }
            else if (st == 8)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                col.Value = 0L;
            }
            else if (st == 9)
            {
                col.Type = SqliteColumnType.Integer;
                col.TypeName = "INTEGER";
                col.Value = 1L;
            }
            else if (st >= 12 && (st % 2 == 0))
            {
                col.Type = SqliteColumnType.Blob;
                col.TypeName = "BLOB";
                byte[] blob = new byte[length];
                Array.Copy(buffer, offset, blob, 0, length);
                col.Value = blob;
                col.RawBytes = blob;
            }
            else if (st >= 13 && (st % 2 == 1))
            {
                col.Type = SqliteColumnType.Text;
                col.TypeName = "TEXT";
                col.Value = Encoding.UTF8.GetString(buffer, offset, length);
            }
        }

        private static void CarveBufferInternal(byte[] buffer, int startOffset, int length, uint pageNum, long baseOffset, CarvedRecordOrigin origin, List<CarvedSqliteRecord> results)
        {
            if (buffer == null || length <= 4) return;
            int limit = startOffset + length;

            int cursor = startOffset;
            while (cursor < limit - 4)
            {
                // Pattern A: Look for Cell structure [payload_size varint] [rowid varint] [record header...]
                long payloadSize;
                int v1 = ReadVarint(buffer, cursor, out payloadSize);
                if (v1 > 0 && payloadSize > 0 && payloadSize < (limit - cursor))
                {
                    long rowId;
                    int v2 = ReadVarint(buffer, cursor + v1, out rowId);
                    if (v2 > 0)
                    {
                        int pOffset = cursor + v1 + v2;
                        int avail = Math.Min((int)payloadSize, limit - pOffset);

                        List<SqliteColumnValue> cols;
                        int hLen;
                        int consumed;
                        if (TryParseRecord(buffer, pOffset, avail, out cols, out hLen, out consumed) && consumed == (int)payloadSize)
                        {
                            CarvedSqliteRecord rec = new CarvedSqliteRecord();
                            rec.PageNumber = pageNum;
                            rec.PageOffset = cursor;
                            rec.AbsoluteOffset = baseOffset + cursor;
                            rec.Origin = origin;
                            rec.RowId = rowId;
                            rec.PayloadSize = (int)payloadSize;
                            rec.HeaderLength = hLen;
                            rec.Columns = cols;

                            byte[] raw = new byte[consumed];
                            Array.Copy(buffer, pOffset, raw, 0, consumed);
                            rec.RawPayload = raw;

                            results.Add(rec);
                            cursor += v1 + v2 + consumed;
                            continue;
                        }
                    }
                }

                // Pattern B: Raw record header [header_length varint] [serial_types...] [body...]
                List<SqliteColumnValue> rawCols;
                int rawHLen;
                int rawConsumed;
                if (TryParseRecord(buffer, cursor, limit - cursor, out rawCols, out rawHLen, out rawConsumed))
                {
                    bool nonTrivial = false;
                    for (int c = 0; c < rawCols.Count; c++)
                    {
                        if (rawCols[c].Type == SqliteColumnType.Text || rawCols[c].Type == SqliteColumnType.Blob ||
                            (rawCols[c].Type == SqliteColumnType.Integer && rawCols[c].DataLength > 0))
                        {
                            nonTrivial = true;
                            break;
                        }
                    }

                    if (nonTrivial)
                    {
                        CarvedSqliteRecord rec = new CarvedSqliteRecord();
                        rec.PageNumber = pageNum;
                        rec.PageOffset = cursor;
                        rec.AbsoluteOffset = baseOffset + cursor;
                        rec.Origin = origin;
                        rec.RowId = null;
                        rec.PayloadSize = rawConsumed;
                        rec.HeaderLength = rawHLen;
                        rec.Columns = rawCols;

                        byte[] raw = new byte[rawConsumed];
                        Array.Copy(buffer, cursor, raw, 0, rawConsumed);
                        rec.RawPayload = raw;

                        results.Add(rec);
                        cursor += rawConsumed;
                        continue;
                    }
                }

                cursor++;
            }
        }


        private static uint ReadUInt32BE(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset] << 24)
                 | ((uint)buffer[offset + 1] << 16)
                 | ((uint)buffer[offset + 2] << 8)
                 | (uint)buffer[offset + 3];
        }
    }
}
